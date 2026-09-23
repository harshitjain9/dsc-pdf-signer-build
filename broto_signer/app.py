"""
Broto DSC Signer — a small Windows desktop app to sign files with a Digital
Signature Certificate on a USB token.

Flow: enter the token PIN -> Connect -> drop files in -> Sign.
PDFs get an embedded PAdES signature; .be/.sb flat files get the ICEGATE
append-format signature (<START-SIGNATURE>/<START-CERTIFICATE>/<SIGNER-VERSION>);
.json (ICEGATE Open API CACHI01/CACHE01) payloads get a digSign object appended
as the schema-form third top-level key. Everything happens on this machine;
nothing is uploaded.

UI: CustomTkinter (rounded, light/dark aware) + optional tkinterdnd2 for
drag-and-drop. Both are pure-pip; the app still runs if tkinterdnd2 is missing
(drag-and-drop is simply off).

Run from source:  python app.py
Build a .exe:     see README.md
"""
from __future__ import annotations

import os
import queue
import subprocess
import sys
import threading
from datetime import datetime, timezone
from tkinter import filedialog
from typing import List, Optional

import customtkinter as ctk

try:  # drag-and-drop is a nicety, never a hard dependency
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:  # noqa: BLE001
    DND_FILES = None
    TkinterDnD = None

from signer_core import CertInfo, DscSigner, discover_module, list_certificates, sign_one

APP_TITLE = "Broto DSC Signer"
SIGNABLE_EXTS = (".pdf", ".be", ".sb", ".json")

# ------------------------------------------------------------------ palette
# (light, dark) pairs — CustomTkinter picks the right one for the OS theme.
BG = ("#F4F4EF", "#0A1120")
CARD = ("#FFFFFF", "#111A2C")
BORDER = ("#E3E5E9", "#223049")
ROW = ("#F7F8FA", "#172238")
ROW_HOVER = ("#EEF1F5", "#1C2942")
TEXT = ("#0D1F3C", "#E8ECF4")
MUTED = ("#69748A", "#8E99AF")
FIELD = ("#F7F8FA", "#0D1526")
NAVY = "#0D1F3C"
LIME = "#C8E645"
LIME_HOVER = "#B6D431"
OK = ("#13795B", "#3DD598")
ERR = ("#DC2626", "#F87171")
WARN = ("#B45309", "#FBBF24")

# File-type chips: (label, text colour, chip background)
KIND = {
    ".pdf": ("PDF", ("#B42318", "#FCA5A5"), ("#FDECEC", "#3A1C22")),
    ".be": ("BE", ("#1D4ED8", "#93B4FD"), ("#E8EFFD", "#1B2A4A")),
    ".sb": ("SB", ("#13795B", "#6EE7B7"), ("#E3F3EC", "#15332B")),
    ".json": ("JSON", ("#B45309", "#FCD34D"), ("#FDF1E1", "#3A2C16")),
}


def _font(size: int, weight: str = "normal") -> ctk.CTkFont:
    family = "Segoe UI" if sys.platform == "win32" else None
    if family:
        return ctk.CTkFont(family=family, size=size, weight=weight)
    return ctk.CTkFont(size=size, weight=weight)


def _resource(*parts: str) -> str:
    """Path to a bundled asset — works from source and inside a PyInstaller exe."""
    base = getattr(sys, "_MEIPASS", os.path.dirname(os.path.abspath(__file__)))
    return os.path.join(base, *parts)


def _open_folder(path: str) -> None:
    try:
        if sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]
        elif sys.platform == "darwin":
            subprocess.Popen(["open", path])
        else:
            subprocess.Popen(["xdg-open", path])
    except Exception:  # noqa: BLE001
        pass


if TkinterDnD is not None:
    class _Root(ctk.CTk, TkinterDnD.DnDWrapper):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__()
            try:
                self.TkdndVersion = TkinterDnD._require(self)
                self.dnd_ok = True
            except Exception:  # noqa: BLE001 - tkdnd binary missing → no drag-and-drop
                self.dnd_ok = False
else:
    class _Root(ctk.CTk):  # type: ignore[no-redef]
        def __init__(self) -> None:
            super().__init__()
            self.dnd_ok = False


# ------------------------------------------------------------------ widgets
class Card(ctk.CTkFrame):
    def __init__(self, master, **kw) -> None:
        super().__init__(master, fg_color=CARD, corner_radius=16, border_width=1,
                         border_color=BORDER, **kw)


def step_title(master, number: str, title: str, hint: str = "") -> ctk.CTkFrame:
    row = ctk.CTkFrame(master, fg_color="transparent")
    ctk.CTkLabel(row, text=number, width=26, height=26, corner_radius=13,
                 fg_color=(NAVY, LIME), text_color=("#FFFFFF", NAVY),
                 font=_font(12, "bold")).pack(side="left")
    ctk.CTkLabel(row, text=title, text_color=TEXT, font=_font(15, "bold")).pack(side="left", padx=(10, 0))
    if hint:
        ctk.CTkLabel(row, text=hint, text_color=MUTED, font=_font(12)).pack(side="left", padx=(8, 0))
    return row


def secondary_button(master, text: str, command, width: int = 0) -> ctk.CTkButton:
    kw = {"width": width} if width else {}
    return ctk.CTkButton(master, text=text, command=command, height=34, corner_radius=10,
                         fg_color="transparent", hover_color=ROW_HOVER, border_width=1,
                         border_color=BORDER, text_color=TEXT, font=_font(13), **kw)


class FileRow(ctk.CTkFrame):
    """One file in the queue: type chip · name/folder · status · remove."""

    def __init__(self, master, path: str, on_remove) -> None:
        super().__init__(master, fg_color=ROW, corner_radius=12, height=54)
        self.path = path
        ext = os.path.splitext(path)[1].lower()
        label, fg, bg = KIND.get(ext, ("FILE", MUTED, ROW_HOVER))
        self.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(self, text=label, width=48, height=26, corner_radius=8, fg_color=bg,
                     text_color=fg, font=_font(11, "bold")).grid(row=0, column=0, rowspan=2,
                                                                 padx=(12, 12), pady=10)
        ctk.CTkLabel(self, text=os.path.basename(path), anchor="w", text_color=TEXT,
                     font=_font(13, "bold")).grid(row=0, column=1, sticky="sw", pady=(9, 0))
        self.detail = ctk.CTkLabel(self, text=os.path.dirname(path), anchor="w",
                                   text_color=MUTED, font=_font(11))
        self.detail.grid(row=1, column=1, sticky="nw", pady=(0, 9))
        self.status = ctk.CTkLabel(self, text="Ready", text_color=MUTED, font=_font(12))
        self.status.grid(row=0, column=2, rowspan=2, padx=(8, 4))
        self.remove_btn = ctk.CTkButton(self, text="✕", width=30, height=30, corner_radius=8,
                                        fg_color="transparent", hover_color=ROW_HOVER,
                                        text_color=MUTED, font=_font(13),
                                        command=lambda: on_remove(self))
        self.remove_btn.grid(row=0, column=3, rowspan=2, padx=(0, 10))

    def set_state(self, state: str, detail: str = "") -> None:
        if state == "working":
            self.status.configure(text="Signing…", text_color=MUTED)
        elif state == "ok":
            self.status.configure(text="✓ Signed", text_color=OK)
            if detail:
                self.detail.configure(text="→ " + detail, text_color=OK)
        elif state == "fail":
            self.status.configure(text="✕ Failed", text_color=ERR)
            if detail:
                self.detail.configure(text=detail, text_color=ERR)
        else:
            self.status.configure(text="Ready", text_color=MUTED)
            self.detail.configure(text=os.path.dirname(self.path), text_color=MUTED)


# ------------------------------------------------------------------ app
class SignerApp:
    def __init__(self, root: _Root) -> None:
        self.root = root
        root.title(APP_TITLE)
        root.geometry("980x640")
        root.minsize(820, 560)
        root.configure(fg_color=BG)
        self._set_icon()

        self.module_var = ctk.StringVar(value=discover_module() or "")
        self.pin_var = ctk.StringVar()
        self.out_var = ctk.StringVar()
        self.cert_choice = ctk.StringVar()
        self.rows: List[FileRow] = []
        self.certs: List[CertInfo] = []
        self.q: "queue.Queue" = queue.Queue()
        self._busy = False
        self._driver_open = False
        self._last_out: Optional[str] = None

        self._build()
        self._refresh()
        self._poll()
        if self.module_var.get():
            self._log("Token driver: " + self.module_var.get())
        else:
            self._log("Couldn't find a token driver automatically — open Driver settings "
                      "and pick your token's DLL.")
            self._toggle_driver(True)

    # ---------------------------------------------------------- chrome
    def _set_icon(self) -> None:
        ico, png = _resource("assets", "broto.ico"), _resource("assets", "broto.png")
        try:
            if sys.platform == "win32" and os.path.exists(ico):
                # CustomTkinter swaps in its own icon ~200 ms after start; set ours after.
                self.root.after(250, lambda: self.root.iconbitmap(ico))
            elif os.path.exists(png):
                import tkinter as tk
                self._icon_img = tk.PhotoImage(file=png)
                self.root.iconphoto(True, self._icon_img)
        except Exception:  # noqa: BLE001
            pass

    def _build(self) -> None:
        r = self.root
        r.grid_columnconfigure(0, weight=1)
        r.grid_rowconfigure(1, weight=1)

        # Header ------------------------------------------------------
        head = ctk.CTkFrame(r, fg_color="transparent")
        head.grid(row=0, column=0, sticky="ew", padx=24, pady=(20, 14))
        head.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(head, text="b", width=44, height=44, corner_radius=12,
                     fg_color=(NAVY, LIME), text_color=("#FFFFFF", NAVY),
                     font=_font(24, "bold")).grid(row=0, column=0, rowspan=2, padx=(0, 14))
        ctk.CTkLabel(head, text="Broto DSC Signer", text_color=TEXT, font=_font(20, "bold"),
                     anchor="w").grid(row=0, column=1, sticky="sw")
        ctk.CTkLabel(head, text="Sign PDFs, flat files and ICEGATE JSON with your USB token. "
                                "Nothing leaves this computer.",
                     text_color=MUTED, font=_font(12), anchor="w").grid(row=1, column=1, sticky="nw")
        self.pill = ctk.CTkLabel(head, text="", height=30, corner_radius=15, fg_color=CARD,
                                 font=_font(12, "bold"))
        self.pill.grid(row=0, column=2, rowspan=2, sticky="e")

        # Body --------------------------------------------------------
        body = ctk.CTkFrame(r, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=24)
        body.grid_columnconfigure(0, weight=0, minsize=340)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(1, weight=1)

        self._build_token_card(body)
        self._build_activity_card(body)
        self._build_files_card(body)

        # Footer ------------------------------------------------------
        self._build_footer(r)

    def _build_token_card(self, parent) -> None:
        card = Card(parent)
        card.grid(row=0, column=0, sticky="new", padx=(0, 16), pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)
        step_title(card, "1", "Your DSC token").grid(row=0, column=0, sticky="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(card, text="Plug in the token and enter its PIN.", text_color=MUTED,
                     font=_font(12), anchor="w").grid(row=1, column=0, sticky="w", padx=18)

        pin_row = ctk.CTkFrame(card, fg_color="transparent")
        pin_row.grid(row=2, column=0, sticky="ew", padx=18, pady=(12, 0))
        pin_row.grid_columnconfigure(0, weight=1)
        self.pin_entry = ctk.CTkEntry(pin_row, textvariable=self.pin_var, show="•", height=40,
                                      corner_radius=10, placeholder_text="Token PIN",
                                      fg_color=FIELD, border_color=BORDER, text_color=TEXT,
                                      font=_font(14))
        self.pin_entry.grid(row=0, column=0, sticky="ew")
        self.pin_entry.bind("<Return>", lambda _e: self._connect())
        self.connect_btn = ctk.CTkButton(pin_row, text="Connect", width=100, height=40,
                                         corner_radius=10, fg_color=NAVY, hover_color="#1B3160",
                                         text_color="#FFFFFF", font=_font(13, "bold"),
                                         command=self._connect)
        self.connect_btn.grid(row=0, column=1, padx=(8, 0))

        # Certificate panel (filled after Connect)
        self.cert_box = ctk.CTkFrame(card, fg_color=ROW, corner_radius=12)
        self.cert_box.grid(row=3, column=0, sticky="ew", padx=18, pady=(12, 0))
        self.cert_box.grid_columnconfigure(0, weight=1)
        self.cert_menu = ctk.CTkOptionMenu(self.cert_box, variable=self.cert_choice, values=[""],
                                           height=32, corner_radius=8, fg_color=CARD,
                                           button_color=BORDER, button_hover_color=ROW_HOVER,
                                           text_color=TEXT, font=_font(12),
                                           command=lambda _v: self._show_cert())
        self.cert_name = ctk.CTkLabel(self.cert_box, text="No certificate yet", anchor="w",
                                      text_color=MUTED, font=_font(14, "bold"), wraplength=280,
                                      justify="left")
        self.cert_name.grid(row=1, column=0, sticky="ew", padx=14, pady=(12, 0))
        self.cert_issuer = ctk.CTkLabel(self.cert_box, text="Connect to read the certificate on your token.",
                                        anchor="w", text_color=MUTED, font=_font(12),
                                        wraplength=280, justify="left")
        self.cert_issuer.grid(row=2, column=0, sticky="ew", padx=14)
        self.cert_expiry = ctk.CTkLabel(self.cert_box, text="", anchor="w", text_color=MUTED,
                                        font=_font(12, "bold"))
        self.cert_expiry.grid(row=3, column=0, sticky="ew", padx=14, pady=(0, 12))

        # Driver settings (collapsed unless auto-detect failed)
        self.driver_toggle = ctk.CTkButton(card, text="▸ Driver settings", anchor="w", height=26,
                                           fg_color="transparent", hover_color=ROW_HOVER,
                                           text_color=MUTED, font=_font(12),
                                           command=lambda: self._toggle_driver(not self._driver_open))
        self.driver_toggle.grid(row=4, column=0, sticky="w", padx=12, pady=(10, 12))
        self.driver_box = ctk.CTkFrame(card, fg_color="transparent")
        self.driver_box.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.driver_box, text="PKCS#11 driver (DLL)", text_color=MUTED,
                     font=_font(11), anchor="w").grid(row=0, column=0, columnspan=3, sticky="w")
        ctk.CTkEntry(self.driver_box, textvariable=self.module_var, height=32, corner_radius=8,
                     fg_color=FIELD, border_color=BORDER, text_color=TEXT,
                     font=_font(11)).grid(row=1, column=0, sticky="ew")
        secondary_button(self.driver_box, "Detect", self._detect, width=64).grid(row=1, column=1, padx=(6, 0))
        secondary_button(self.driver_box, "Browse", self._browse_module, width=64).grid(row=1, column=2, padx=(6, 0))

    def _build_activity_card(self, parent) -> None:
        card = Card(parent)
        card.grid(row=1, column=0, sticky="nsew", padx=(0, 16), pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)
        ctk.CTkLabel(card, text="Activity", text_color=TEXT, font=_font(13, "bold"),
                     anchor="w").grid(row=0, column=0, sticky="w", padx=18, pady=(12, 4))
        self.log = ctk.CTkTextbox(card, fg_color="transparent", text_color=MUTED, wrap="word",
                                  font=ctk.CTkFont(family="Consolas" if sys.platform == "win32" else "Menlo",
                                                   size=11),
                                  activate_scrollbars=True, state="disabled")
        self.log.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))

    def _build_files_card(self, parent) -> None:
        card = Card(parent)
        card.grid(row=0, column=1, rowspan=2, sticky="nsew", pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)
        card.grid_rowconfigure(1, weight=1)
        self.files_card = card

        top = ctk.CTkFrame(card, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=18, pady=(16, 10))
        top.grid_columnconfigure(0, weight=1)
        self.files_title = step_title(top, "2", "Files to sign", hint=" ")
        self.files_title.grid(row=0, column=0, sticky="w")
        self.count_lbl = self.files_title.winfo_children()[-1]
        btns = ctk.CTkFrame(top, fg_color="transparent")
        btns.grid(row=0, column=1, sticky="e")
        self.add_files_btn = secondary_button(btns, "+  Add files", self._add_files)
        self.add_files_btn.pack(side="left")
        self.add_folder_btn = secondary_button(btns, "Add folder", self._add_folder)
        self.add_folder_btn.pack(side="left", padx=(8, 0))
        self.clear_btn = secondary_button(btns, "Clear", self._clear)
        self.clear_btn.pack(side="left", padx=(8, 0))

        self.list = ctk.CTkScrollableFrame(card, fg_color="transparent", corner_radius=0,
                                           scrollbar_button_color=BORDER,
                                           scrollbar_button_hover_color=MUTED)
        self.list.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 12))
        self.list.grid_columnconfigure(0, weight=1)

        # Empty state
        self.empty = ctk.CTkFrame(self.list, fg_color=ROW, corner_radius=14, height=260)
        self.empty.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.empty, text="⇪", text_color=MUTED, font=_font(40)).grid(row=0, column=0, pady=(48, 0))
        drop = "Drop files here" if self.root.dnd_ok else "No files yet"
        ctk.CTkLabel(self.empty, text=drop, text_color=TEXT, font=_font(16, "bold")).grid(row=1, column=0, pady=(4, 2))
        ctk.CTkLabel(self.empty, text="or use Add files / Add folder above", text_color=MUTED,
                     font=_font(12)).grid(row=2, column=0)
        chips = ctk.CTkFrame(self.empty, fg_color="transparent")
        chips.grid(row=3, column=0, pady=(18, 48))
        for ext, what in ((".pdf", "signed PDF"), (".be", "ICEGATE flat file"),
                          (".sb", "ICEGATE flat file"), (".json", "ICEGATE API")):
            label, fg, bg = KIND[ext]
            ctk.CTkLabel(chips, text="%s  ·  %s" % (label, what), height=26, corner_radius=8,
                         fg_color=bg, text_color=fg, font=_font(11, "bold")).pack(side="left", padx=4)

        self._make_drop_target(card)
        self._make_drop_target(self.list)
        self._make_drop_target(getattr(self.list, "_parent_canvas", None))
        self._make_drop_target(self.empty)
        for w in self.empty.winfo_children():
            self._make_drop_target(w)

    def _build_footer(self, r) -> None:
        foot = Card(r)
        foot.grid(row=2, column=0, sticky="ew", padx=24, pady=(0, 20))
        foot.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(foot, text="Save signed files to", text_color=MUTED, font=_font(12)).grid(
            row=0, column=0, sticky="w", padx=(18, 10), pady=(14, 0))
        out_row = ctk.CTkFrame(foot, fg_color="transparent")
        out_row.grid(row=1, column=0, columnspan=2, sticky="ew", padx=(18, 10), pady=(4, 14))
        out_row.grid_columnconfigure(0, weight=1)
        ctk.CTkEntry(out_row, textvariable=self.out_var, height=36, corner_radius=10,
                     placeholder_text="A 'signed' folder next to your files", fg_color=FIELD,
                     border_color=BORDER, text_color=TEXT, font=_font(12)).grid(row=0, column=0, sticky="ew")
        self.browse_out_btn = secondary_button(out_row, "Change…", self._browse_out, width=90)
        self.browse_out_btn.grid(row=0, column=1, padx=(8, 0))
        self.open_btn = secondary_button(out_row, "Open folder", self._open_out, width=110)

        right = ctk.CTkFrame(foot, fg_color="transparent")
        right.grid(row=0, column=2, rowspan=2, sticky="e", padx=(10, 18), pady=14)
        self.status_lbl = ctk.CTkLabel(right, text="", text_color=MUTED, font=_font(12), anchor="e")
        self.status_lbl.pack(side="top", anchor="e")
        self.progress = ctk.CTkProgressBar(right, width=220, height=6, corner_radius=3,
                                           progress_color=(NAVY, LIME), fg_color=BORDER)
        self.progress.set(0)
        self.sign_btn = ctk.CTkButton(right, text="Sign", width=200, height=46, corner_radius=12,
                                      fg_color=LIME, hover_color=LIME_HOVER, text_color=NAVY,
                                      text_color_disabled=("#7A8699", "#5A6782"),
                                      font=_font(15, "bold"), command=self._start_sign)
        self.sign_btn.pack(side="top", anchor="e", pady=(4, 0))

    # ---------------------------------------------------------- helpers
    def _make_drop_target(self, w) -> None:
        if not (self.root.dnd_ok and w is not None and DND_FILES):
            return
        try:
            w.drop_target_register(DND_FILES)
            w.dnd_bind("<<Drop>>", self._on_drop)
        except Exception:  # noqa: BLE001
            pass

    def _on_drop(self, event) -> None:
        if self._busy:
            return
        paths: List[str] = []
        for p in self.root.tk.splitlist(event.data):
            if os.path.isdir(p):
                paths.extend(os.path.join(p, f) for f in sorted(os.listdir(p))
                             if f.lower().endswith(SIGNABLE_EXTS) and os.path.isfile(os.path.join(p, f)))
            elif os.path.isfile(p):
                paths.append(p)
        skipped = [p for p in paths if not p.lower().endswith(SIGNABLE_EXTS)]
        self._add([p for p in paths if p.lower().endswith(SIGNABLE_EXTS)])
        if skipped:
            self._log("Skipped %d file(s) that aren't PDF / .be / .sb / .json." % len(skipped))

    def _selected_cert(self) -> Optional[CertInfo]:
        labels = [c.display for c in self.certs]
        if not self.certs:
            return None
        try:
            return self.certs[labels.index(self.cert_choice.get())]
        except ValueError:
            return self.certs[0]

    def _refresh(self) -> None:
        """Re-derive every enabled/disabled state and label from the model."""
        n = len(self.rows)
        self.count_lbl.configure(text="%d file%s" % (n, "" if n == 1 else "s") if n else "")
        if n:
            self.empty.grid_forget()
        else:
            self.empty.grid(row=0, column=0, sticky="nsew", padx=4, pady=4)
        cert = self._selected_cert()
        if self.certs:
            self.pill.configure(text="  ●  Token connected  ", text_color=OK)
        else:
            self.pill.configure(text="  ●  Token not connected  ", text_color=MUTED)
        ready = bool(cert and n and self.pin_var.get().strip()) and not self._busy
        if self._busy:
            self.sign_btn.configure(text="Signing…", state="disabled")
        else:
            self.sign_btn.configure(text=("Sign %d file%s" % (n, "" if n == 1 else "s")) if n else "Sign",
                                    state="normal" if ready else "disabled")
        state = "disabled" if self._busy else "normal"
        for b in (self.add_files_btn, self.add_folder_btn, self.clear_btn, self.connect_btn,
                  self.browse_out_btn):
            b.configure(state=state)
        for row in self.rows:
            row.remove_btn.configure(state=state)
        if not self._busy:
            if not self.certs:
                self.status_lbl.configure(text="Connect your token to start", text_color=MUTED)
            elif not n:
                self.status_lbl.configure(text="Add the files you want to sign", text_color=MUTED)

    def _show_cert(self) -> None:
        c = self._selected_cert()
        if not c:
            self.cert_name.configure(text="No certificate yet", text_color=MUTED)
            self.cert_issuer.configure(text="Connect to read the certificate on your token.")
            self.cert_expiry.configure(text="")
            return
        self.cert_name.configure(text=c.common_name or c.display, text_color=TEXT)
        self.cert_issuer.configure(text=("Issued by " + c.issuer) if c.issuer else (c.label or "Certificate on token"))
        if c.not_after:
            exp = c.not_after if c.not_after.tzinfo else c.not_after.replace(tzinfo=timezone.utc)
            days = (exp - datetime.now(timezone.utc)).days
            when = exp.strftime("%d %b %Y")
            if days < 0:
                self.cert_expiry.configure(text="Expired on " + when, text_color=ERR)
            elif days <= 30:
                self.cert_expiry.configure(text="Expires %s — %d days left" % (when, days), text_color=WARN)
            else:
                self.cert_expiry.configure(text="✓ Valid until " + when, text_color=OK)
        else:
            self.cert_expiry.configure(text="")
        self._refresh()

    def _toggle_driver(self, open_: bool) -> None:
        self._driver_open = open_
        if open_:
            self.driver_toggle.configure(text="▾ Driver settings")
            self.driver_box.grid(row=5, column=0, sticky="ew", padx=18, pady=(0, 16))
        else:
            self.driver_toggle.configure(text="▸ Driver settings")
            self.driver_box.grid_forget()

    # ---------------------------------------------------------- token
    def _detect(self) -> None:
        m = discover_module()
        if m:
            self.module_var.set(m)
            self._log("Detected driver: " + m)
        else:
            self._log("No known token driver found — use Browse to pick the DLL.")

    def _browse_module(self) -> None:
        p = filedialog.askopenfilename(title="Token PKCS#11 driver",
                                       filetypes=[("Driver", "*.dll *.so *.dylib"), ("All files", "*.*")])
        if p:
            self.module_var.set(p)

    def _connect(self) -> None:
        if self._busy:
            return
        mod = self.module_var.get().strip()
        if not mod or not os.path.exists(mod):
            self._toggle_driver(True)
            self._flash("Pick your token's driver first (Driver settings).", ERR)
            return
        self._busy = True
        self.connect_btn.configure(text="…")
        self._refresh()
        self._log("Reading certificates from the token…")
        pin = self.pin_var.get().strip() or None

        def work() -> None:
            try:
                self.q.put(("certs", list_certificates(mod, pin)))
            except Exception as e:  # noqa: BLE001 - surface the real error
                self.q.put(("certs_err", str(e) or repr(e)))
        threading.Thread(target=work, daemon=True).start()

    # ---------------------------------------------------------- files
    def _add_files(self) -> None:
        self._add(filedialog.askopenfilenames(
            title="Select files to sign",
            filetypes=[("Signable files", "*.pdf *.be *.sb *.json"), ("PDF", "*.pdf"),
                       ("Flat files", "*.be *.sb"), ("ICEGATE JSON", "*.json"),
                       ("All files", "*.*")]))

    def _add_folder(self) -> None:
        d = filedialog.askdirectory(title="Select a folder — its PDF/.be/.sb/.json files are added")
        if not d:
            return
        self._add([os.path.join(d, f) for f in sorted(os.listdir(d))
                   if os.path.isfile(os.path.join(d, f)) and f.lower().endswith(SIGNABLE_EXTS)])

    def _add(self, paths) -> None:
        have = {r.path for r in self.rows}
        for p in paths:
            p = os.path.normpath(p) if p else p
            if p and p not in have:
                row = FileRow(self.list, p, self._remove_row)
                row.grid(row=len(self.rows), column=0, sticky="ew", padx=4, pady=4)
                self._make_drop_target(row)
                self.rows.append(row)
                have.add(p)
        if self.rows and not self.out_var.get():
            self.out_var.set(os.path.join(os.path.dirname(self.rows[0].path), "signed"))
        self._refresh()

    def _regrid(self) -> None:
        for i, row in enumerate(self.rows):
            row.grid(row=i, column=0, sticky="ew", padx=4, pady=4)

    def _remove_row(self, row: FileRow) -> None:
        if self._busy:
            return
        self.rows.remove(row)
        row.destroy()
        self._regrid()
        self._refresh()

    def _clear(self) -> None:
        for row in self.rows:
            row.destroy()
        self.rows.clear()
        self.open_btn.grid_forget()
        self._refresh()

    def _browse_out(self) -> None:
        d = filedialog.askdirectory(title="Save signed files to")
        if d:
            self.out_var.set(d)

    def _open_out(self) -> None:
        if self._last_out and os.path.isdir(self._last_out):
            _open_folder(self._last_out)

    # ---------------------------------------------------------- signing
    def _start_sign(self) -> None:
        if self._busy:
            return
        cert = self._selected_cert()
        pin = self.pin_var.get().strip()
        problem = ("Connect your token first." if not cert
                   else "Add at least one file." if not self.rows
                   else "Enter the token PIN." if not pin else "")
        if problem:
            self._flash(problem, ERR)
            return
        out_dir = self.out_var.get().strip() or os.path.join(os.path.dirname(self.rows[0].path), "signed")
        self.out_var.set(out_dir)
        for row in self.rows:
            row.set_state("ready")
        self._busy = True
        self.open_btn.grid_forget()
        self.progress.set(0)
        self.progress.pack(side="top", anchor="e", pady=(4, 2), before=self.sign_btn)
        self._refresh()
        args = (self.module_var.get().strip(), cert.cert_id, cert.label, cert.slot_index, pin,
                [r.path for r in self.rows], out_dir)
        threading.Thread(target=self._sign_worker, args=args, daemon=True).start()

    def _sign_worker(self, module, cert_id, cert_label, slot_index, pin, files, out_dir) -> None:
        ok = fail = 0
        signer = None
        try:
            self._log("Opening token session…")
            signer = DscSigner(module, pin, cert_id=cert_id, cert_label=cert_label, slot_index=slot_index)
            for i, p in enumerate(files):
                self.q.put(("file", i, "working", ""))
                try:
                    out = sign_one(signer, p, out_dir)
                    ok += 1
                    self.q.put(("file", i, "ok", os.path.basename(out)))
                    self._log("✓ %s  →  %s" % (os.path.basename(p), os.path.basename(out)))
                except Exception as e:  # noqa: BLE001 - per-file failure shouldn't abort the batch
                    fail += 1
                    self.q.put(("file", i, "fail", str(e) or repr(e)))
                    self._log("✕ %s  —  %s" % (os.path.basename(p), e))
                self.q.put(("progress", (i + 1) / float(len(files))))
        except Exception as e:  # noqa: BLE001 - session-level failure (wrong PIN, locked token, …)
            fail = len(files) - ok
            self._log("ERROR: " + repr(e))
            self.q.put(("session_err", str(e) or repr(e)))
        finally:
            if signer:
                signer.close()
        self._log("Done — %d signed, %d failed. Saved to %s" % (ok, fail, out_dir))
        self.q.put(("done", ok, fail, out_dir))

    # ---------------------------------------------------------- queue / log
    def _poll(self) -> None:
        try:
            while True:
                self._handle(self.q.get_nowait())
        except queue.Empty:
            pass
        self.root.after(100, self._poll)

    def _handle(self, item) -> None:
        kind = item[0]
        if kind == "log":
            self._write(item[1])
        elif kind == "certs":
            self._busy = False
            self.connect_btn.configure(text="Connect")
            self.certs = item[1]
            if not self.certs:
                self._log("No certificates found. Is the token plugged in? Some tokens need the PIN first.")
                self._flash("No certificate found on the token.", ERR)
            else:
                labels = [c.display for c in self.certs]
                self.cert_menu.configure(values=labels)
                self.cert_choice.set(labels[0])
                if len(self.certs) > 1:
                    self.cert_menu.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 0))
                else:
                    self.cert_menu.grid_forget()
                self._log("Found %d certificate%s." % (len(self.certs), "" if len(self.certs) == 1 else "s"))
                self.connect_btn.configure(text="Reconnect", fg_color="transparent", border_width=1,
                                           border_color=BORDER, text_color=TEXT, hover_color=ROW_HOVER)
            self._show_cert()
            self._refresh()
        elif kind == "certs_err":
            self._busy = False
            self.connect_btn.configure(text="Connect")
            self._log("ERROR reading the token: " + item[1])
            self._flash("Couldn't read the token — see Activity.", ERR)
            self._refresh()
        elif kind == "file":
            _, i, state, detail = item
            if 0 <= i < len(self.rows):
                self.rows[i].set_state(state, detail)
        elif kind == "progress":
            self.progress.set(item[1])
        elif kind == "session_err":
            self._flash("Couldn't open the token: " + item[1][:80], ERR)
        elif kind == "done":
            _, ok, fail, out_dir = item
            self._busy = False
            self._last_out = out_dir
            self.progress.pack_forget()
            self._refresh()
            if fail == 0 and ok:
                self._flash("✓  %d file%s signed" % (ok, "" if ok == 1 else "s"), OK)
            elif ok or fail:
                self._flash("%d signed · %d failed" % (ok, fail), ERR if not ok else WARN)
            if ok and os.path.isdir(out_dir):
                self.open_btn.grid(row=0, column=2, padx=(8, 0))

    def _flash(self, msg: str, color) -> None:
        self.status_lbl.configure(text=msg, text_color=color)

    def _log(self, msg: str) -> None:
        self.q.put(("log", msg))

    def _write(self, msg: str) -> None:
        self.log.configure(state="normal")
        self.log.insert("end", datetime.now().strftime("%H:%M:%S  ") + msg + "\n")
        self.log.see("end")
        self.log.configure(state="disabled")


def main() -> None:
    ctk.set_appearance_mode("system")      # follows Windows light/dark
    ctk.set_default_color_theme("blue")
    root = _Root()
    app = SignerApp(root)
    app.pin_var.trace_add("write", lambda *_: app._refresh())
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Surface startup crashes even in a --windowed build: write a log the user
        # can send us, and try to show it in a dialog before exiting.
        import tempfile
        import traceback
        report = traceback.format_exc()
        log_path = os.path.join(tempfile.gettempdir(), "BrotoSigner-error.log")
        try:
            with open(log_path, "w", encoding="utf-8") as fh:
                fh.write(report)
        except Exception:
            log_path = "(could not write log file)"
        try:
            from tkinter import messagebox
            messagebox.showerror(APP_TITLE + " — startup error",
                                 report[-1500:] + "\n\nSaved to:\n" + log_path)
        except Exception:
            pass
        raise
