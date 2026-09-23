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

import secure_store as store
from bridge import BRIDGE_PORT, BridgeServer, SignRequest
from signer_core import CertInfo, DscSigner, discover_module, list_certificates, pin_error_kind, sign_one

APP_TITLE = "Broto DSC Signer"
# Bump on every release — the planned self-updater compares this with the
# server's "latest" record. 1.x = original Tk UI; 2.0 = redesign; 2.1 = one-click bridge + saved PIN.
APP_VERSION = "2.1.0"
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


def _fmt_job_date(raw: str) -> str:
    """ICEGATE job dates are 8 digits; show them as '22 Sep 2026' when the
    order is unambiguous (YYYYMMDD or DDMMYYYY), else as sent."""
    s = (raw or "").strip()
    for fmt in ("%Y%m%d", "%d%m%Y"):
        try:
            d = datetime.strptime(s, fmt)
            if 2000 <= d.year <= 2100:
                return d.strftime("%d %b %Y")
        except ValueError:
            pass
    return s


def _popup_on_top(win) -> None:
    """Bring a dialog to the front even when the main window is minimised."""
    try:
        win.attributes("-topmost", True)
        win.lift()
        win.focus_force()
        win.bell()
    except Exception:  # noqa: BLE001
        pass


class ApprovalDialog(ctk.CTkToplevel):
    """'Broto wants to sign this filing' — nothing is signed without a click here."""

    def __init__(self, app: "SignerApp", req: SignRequest) -> None:
        super().__init__(app.root)
        self.app, self.req = app, req
        self._working = False
        s = req.summary
        filing = req.action == "sign_and_file"
        self.title("Broto wants to sign a filing")
        self.geometry("500x560")
        self.resizable(False, False)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self.cancel)
        self.grid_columnconfigure(0, weight=1)

        top = ctk.CTkFrame(self, fg_color="transparent")
        top.grid(row=0, column=0, sticky="ew", padx=22, pady=(20, 10))
        top.grid_columnconfigure(1, weight=1)
        ctk.CTkLabel(top, text="b", width=40, height=40, corner_radius=11, fg_color=(NAVY, LIME),
                     text_color=("#FFFFFF", NAVY), font=_font(21, "bold")).grid(row=0, column=0, rowspan=2, padx=(0, 12))
        ctk.CTkLabel(top, text=("Sign & file this %s?" if filing else "Sign this %s?") % s["kind"],
                     text_color=TEXT, font=_font(17, "bold"), anchor="w").grid(row=0, column=1, sticky="sw")
        host = req.origin.split("//")[-1]
        ctk.CTkLabel(top, text="Requested by Broto (%s) in your browser" % host, text_color=MUTED,
                     font=_font(12), anchor="w").grid(row=1, column=1, sticky="nw")

        card = Card(self)
        card.grid(row=1, column=0, sticky="ew", padx=22)
        card.grid_columnconfigure(1, weight=1)
        party_label = "Importer" if s["message_id"] == "CACHI01" else "Exporter"
        job = str(s.get("job_number") or "—")
        if s.get("job_date"):
            job += "  ·  " + _fmt_job_date(s["job_date"])
        counts = "%d invoice%s  ·  %d item%s" % (s["invoices"], "" if s["invoices"] == 1 else "s",
                                                 s["items"], "" if s["items"] == 1 else "s")
        rows = [(party_label, s.get("party") or "—"), ("IEC", s.get("iec") or "—"), ("Job no.", job),
                ("Contents", counts), ("ICEGATE ID", s.get("sender_id") or "—"), ("File", req.filename)]
        for i, (k, v) in enumerate(rows):
            ctk.CTkLabel(card, text=k, text_color=MUTED, font=_font(12), anchor="w").grid(
                row=i, column=0, sticky="nw", padx=(16, 12), pady=(12 if i == 0 else 3, 12 if i == len(rows) - 1 else 3))
            ctk.CTkLabel(card, text=v, text_color=TEXT, font=_font(13, "bold" if i == 0 else "normal"), anchor="w",
                         justify="left", wraplength=300).grid(
                row=i, column=1, sticky="nw", padx=(0, 16), pady=(12 if i == 0 else 3, 12 if i == len(rows) - 1 else 3))
        if s.get("test_mode"):
            ctk.CTkLabel(card, text="TEST FILING (ICEGATE test system)", height=24, corner_radius=8,
                         fg_color=KIND[".json"][2], text_color=WARN, font=_font(11, "bold")).grid(
                row=len(rows), column=0, columnspan=2, sticky="w", padx=16, pady=(0, 12))

        cert = app._selected_cert()
        cert_text = ("Signing as %s" % (cert.common_name or cert.display)) if cert else \
            "Your certificate will be read from the token after you enter the PIN."
        ctk.CTkLabel(self, text=cert_text, text_color=TEXT if cert else MUTED, font=_font(12, "bold" if cert else "normal"),
                     anchor="w", wraplength=450, justify="left").grid(row=2, column=0, sticky="ew", padx=24, pady=(14, 6))

        self.pin_box = ctk.CTkFrame(self, fg_color="transparent")
        self.pin_box.grid(row=3, column=0, sticky="ew", padx=22)
        self.pin_box.grid_columnconfigure(0, weight=1)
        self.pin_entry = ctk.CTkEntry(self.pin_box, show="•", height=40, corner_radius=10,
                                      placeholder_text="Token PIN", fg_color=FIELD, border_color=BORDER,
                                      text_color=TEXT, font=_font(14))
        self.remember = ctk.BooleanVar(value=False)
        self.remember_cb = ctk.CTkCheckBox(self.pin_box, text="Remember my PIN on this computer",
                                           variable=self.remember, text_color=TEXT, font=_font(12),
                                           checkbox_width=18, checkbox_height=18, corner_radius=5,
                                           fg_color=(NAVY, LIME), hover_color=("#1B3160", LIME_HOVER),
                                           checkmark_color=("#FFFFFF", NAVY))
        self.saved_lbl = ctk.CTkLabel(self.pin_box, text="●  Using the PIN saved on this computer",
                                      text_color=OK, font=_font(12, "bold"), anchor="w")
        self._use_saved = bool(app._saved_pin)
        self._layout_pin()

        self.err = ctk.CTkLabel(self, text="", text_color=ERR, font=_font(12), anchor="w",
                                wraplength=450, justify="left")
        self.err.grid(row=4, column=0, sticky="ew", padx=24, pady=(8, 0))

        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.grid(row=5, column=0, sticky="ew", padx=22, pady=(10, 20))
        btns.grid_columnconfigure(0, weight=1)
        self.cancel_btn = secondary_button(btns, "Cancel", self.cancel, width=110)
        self.cancel_btn.grid(row=0, column=1, padx=(0, 10))
        self.ok_btn = ctk.CTkButton(btns, text="Sign & file" if filing else "Sign", width=170, height=44,
                                    corner_radius=12, fg_color=LIME, hover_color=LIME_HOVER, text_color=NAVY,
                                    font=_font(14, "bold"), command=self.approve)
        self.ok_btn.grid(row=0, column=2)

        self.bind("<Return>", lambda _e: self.approve())
        self.bind("<Escape>", lambda _e: self.cancel())
        _popup_on_top(self)
        self.after(150, lambda: (self.pin_entry.focus_set() if not self._use_saved else self.ok_btn.focus_set()))
        self.after(1000, self._watch)

    def _layout_pin(self) -> None:
        for w in (self.pin_entry, self.remember_cb, self.saved_lbl):
            w.grid_forget()
        if self._use_saved:
            self.saved_lbl.grid(row=0, column=0, sticky="w", padx=2)
        else:
            self.pin_entry.grid(row=0, column=0, sticky="ew")
            if store.pin_saving_supported():
                self.remember_cb.grid(row=1, column=0, sticky="w", padx=2, pady=(10, 0))

    def _watch(self) -> None:
        """Close if the browser gave up (bridge timeout) while we were open."""
        if not self.winfo_exists():
            return
        if self.req.done and not self._working:
            self.app._flash("A signing request from Broto timed out.", WARN)
            self.destroy()
            return
        self.after(1000, self._watch)

    def approve(self) -> None:
        if self._working:
            return
        pin = self.app._saved_pin if self._use_saved else self.pin_entry.get().strip()
        if not pin:
            self.show_error("Enter the token PIN.")
            return
        self._working = True
        self.ok_btn.configure(text="Signing…", state="disabled")
        self.cancel_btn.configure(state="disabled")
        self.err.configure(text="")
        remember = bool(self.remember.get()) and not self._use_saved
        self.app._start_bridge_sign(self.req, pin, self._use_saved, remember)

    def show_error(self, msg: str, need_pin: bool = False) -> None:
        self._working = False
        self.ok_btn.configure(text="Sign & file" if self.req.action == "sign_and_file" else "Sign", state="normal")
        self.cancel_btn.configure(state="normal")
        if need_pin and self._use_saved:
            self._use_saved = False
            self._layout_pin()
        if need_pin:
            self.pin_entry.delete(0, "end")
            self.pin_entry.focus_set()
        self.err.configure(text=msg)

    def cancel(self) -> None:
        if self._working:
            return
        self.req.fail("cancelled", "Cancelled in the Broto Signer.")
        self.app._log("Declined a signing request from Broto.")
        self.destroy()


class SavePinDialog(ctk.CTkToplevel):
    """Asked once after the PIN has been proven correct — never saved silently."""

    def __init__(self, app: "SignerApp", pin: str) -> None:
        super().__init__(app.root)
        self.app, self.pin = app, pin
        self.title("Save your token PIN?")
        self.geometry("460x250")
        self.resizable(False, False)
        self.configure(fg_color=BG)
        self.protocol("WM_DELETE_WINDOW", self.later)
        self.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self, text="Save your token PIN on this computer?", text_color=TEXT,
                     font=_font(16, "bold"), anchor="w").grid(row=0, column=0, sticky="ew", padx=22, pady=(20, 6))
        ctk.CTkLabel(self, text="You won't have to type it again, here or when Broto asks for a signature. "
                                "It is locked to your Windows login on this PC. Anyone who uses this Windows "
                                "login while the token is plugged in could sign with it — you still confirm "
                                "every signature. You can forget it any time in Settings.",
                     text_color=MUTED, font=_font(12), anchor="w", justify="left", wraplength=416).grid(
            row=1, column=0, sticky="ew", padx=22)
        btns = ctk.CTkFrame(self, fg_color="transparent")
        btns.grid(row=2, column=0, sticky="ew", padx=22, pady=(18, 20))
        btns.grid_columnconfigure(0, weight=1)
        ctk.CTkButton(btns, text="Don't ask again", width=120, height=36, fg_color="transparent",
                      hover_color=ROW_HOVER, text_color=MUTED, font=_font(12), command=self.never).grid(row=0, column=0, sticky="w")
        secondary_button(btns, "Not now", self.later, width=96).grid(row=0, column=1, padx=(0, 10))
        ctk.CTkButton(btns, text="Save PIN", width=120, height=40, corner_radius=12, fg_color=LIME,
                      hover_color=LIME_HOVER, text_color=NAVY, font=_font(14, "bold"),
                      command=self.save).grid(row=0, column=2)
        _popup_on_top(self)

    def save(self) -> None:
        self.app._remember_pin(self.pin)
        self.destroy()

    def later(self) -> None:
        self.destroy()

    def never(self) -> None:
        store.update_settings(never_ask_pin=True)
        self.destroy()


# ------------------------------------------------------------------ app
class SignerApp:
    def __init__(self, root: _Root) -> None:
        self.root = root
        root.title("%s  v%s" % (APP_TITLE, APP_VERSION))
        root.geometry("980x640")
        root.minsize(820, 560)
        root.configure(fg_color=BG)
        self._set_icon()

        self.settings = store.load_settings()
        saved_mod = self.settings.get("module") or ""
        self.module_var = ctk.StringVar(value=saved_mod if os.path.exists(saved_mod) else (discover_module() or ""))
        self.out_var = ctk.StringVar()
        self.cert_choice = ctk.StringVar()
        self.rows: List[FileRow] = []
        self.certs: List[CertInfo] = []
        self.q: "queue.Queue" = queue.Queue()
        self._busy = False
        self._driver_open = False
        self._last_out: Optional[str] = None
        self._log_lines: List[str] = []
        self._log_win = None
        self._log_box = None
        self._saved_pin: Optional[str] = store.load_pin()
        self._asked_save_pin = False
        self._token_lock = threading.Lock()     # one token session at a time (batch vs bridge)
        self._approval: Optional[ApprovalDialog] = None
        self._status_snapshot: dict = {}         # read by the bridge thread; written on the UI thread

        self._build()
        self.bridge = BridgeServer(on_request=lambda req: self.q.put(("bridge_req", req)),
                                   status=lambda: dict(self._status_snapshot))
        self.bridge_ok = self.bridge.start()
        self._refresh()
        self._poll()
        if self.module_var.get():
            self._log("Token driver: " + self.module_var.get())
        else:
            self._log("Couldn't find a token driver automatically — open Settings "
                      "and pick your token's DLL.")
            self._toggle_driver(True)
        if self.bridge_ok:
            self._log("One-click filing ready — Broto can ask this app for signatures (port %d)." % BRIDGE_PORT)
        else:
            self._log("One-click filing is OFF: " + (self.bridge.error or "could not start"))
        if store.has_saved_pin() and not self._saved_pin:
            store.forget_pin()   # saved under another Windows login / PC — useless here
        if self._saved_pin and self.module_var.get():
            self.root.after(400, self._connect)   # saved PIN → connect straight away

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
        ctk.CTkLabel(head, text="Sign with your USB token. Nothing leaves this computer.",
                     text_color=MUTED, font=_font(12), anchor="w").grid(row=1, column=1, sticky="nw")
        pills = ctk.CTkFrame(head, fg_color="transparent")
        pills.grid(row=0, column=2, rowspan=2, sticky="e")
        self.bridge_pill = ctk.CTkLabel(pills, text="", height=30, corner_radius=15, fg_color=CARD,
                                        font=_font(12, "bold"))
        self.bridge_pill.pack(side="left", padx=(0, 8))
        self.pill = ctk.CTkLabel(pills, text="", height=30, corner_radius=15, fg_color=CARD,
                                 font=_font(12, "bold"))
        self.pill.pack(side="left")
        secondary_button(head, "Activity log", self._open_log, width=110).grid(
            row=0, column=3, rowspan=2, sticky="e", padx=(10, 0))

        # Body --------------------------------------------------------
        body = ctk.CTkFrame(r, fg_color="transparent")
        body.grid(row=1, column=0, sticky="nsew", padx=24)
        body.grid_columnconfigure(0, weight=0, minsize=340)
        body.grid_columnconfigure(1, weight=1)
        body.grid_rowconfigure(0, weight=1)

        self._build_token_card(body)
        self._build_files_card(body)

        # Footer ------------------------------------------------------
        self._build_footer(r)

    def _build_token_card(self, parent) -> None:
        card = Card(parent)
        card.grid(row=0, column=0, sticky="nsew", padx=(0, 16), pady=(0, 16))
        card.grid_columnconfigure(0, weight=1)
        step_title(card, "1", "Your DSC token").grid(row=0, column=0, sticky="w", padx=18, pady=(16, 4))
        ctk.CTkLabel(card, text="Plug in the token and enter its PIN.", text_color=MUTED,
                     font=_font(12), anchor="w").grid(row=1, column=0, sticky="w", padx=18)

        pin_row = ctk.CTkFrame(card, fg_color="transparent")
        pin_row.grid(row=2, column=0, sticky="ew", padx=18, pady=(12, 0))
        pin_row.grid_columnconfigure(0, weight=1)
        self.pin_entry = ctk.CTkEntry(pin_row, show="•", height=40,
                                      corner_radius=10, placeholder_text="Token PIN",
                                      fg_color=FIELD, border_color=BORDER, text_color=TEXT,
                                      font=_font(14))
        self.saved_chip = ctk.CTkFrame(pin_row, fg_color=ROW, corner_radius=10, height=40)
        self.saved_chip.grid_columnconfigure(0, weight=1)
        ctk.CTkLabel(self.saved_chip, text="●  PIN saved", text_color=OK, font=_font(13, "bold"),
                     anchor="w").grid(row=0, column=0, sticky="w", padx=12, pady=6)
        ctk.CTkButton(self.saved_chip, text="Forget", width=60, height=28, corner_radius=8,
                      fg_color="transparent", hover_color=ROW_HOVER, text_color=MUTED, font=_font(12),
                      command=self._forget_pin).grid(row=0, column=1, padx=(0, 6))
        self._layout_pin_row()
        self.pin_entry.bind("<Return>", lambda _e: self._connect())
        self.pin_entry.bind("<KeyRelease>", lambda _e: self._refresh())
        self.connect_btn = ctk.CTkButton(pin_row, text="Connect", width=100, height=40,
                                         corner_radius=10, fg_color=(NAVY, LIME), hover_color=("#1B3160", LIME_HOVER),
                                         text_color=("#FFFFFF", NAVY), font=_font(13, "bold"),
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
        self.driver_toggle = ctk.CTkButton(card, text="▸ Settings", anchor="w", height=26,
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
        if store.autostart_supported():
            self.autostart_var = ctk.BooleanVar(value=store.autostart_enabled())
            ctk.CTkSwitch(self.driver_box, text="Open when Windows starts (for one-click filing)",
                          variable=self.autostart_var, command=self._toggle_autostart, text_color=TEXT,
                          font=_font(12), progress_color=(NAVY, LIME), switch_width=36,
                          switch_height=18).grid(row=2, column=0, columnspan=3, sticky="w", pady=(10, 0))

    def _build_files_card(self, parent) -> None:
        card = Card(parent)
        card.grid(row=0, column=1, sticky="nsew", pady=(0, 16))
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
        self.add_files_btn = secondary_button(btns, "+  Add files", self._add_files, width=104)
        self.add_files_btn.pack(side="left")
        self.add_folder_btn = secondary_button(btns, "Add folder", self._add_folder, width=96)
        self.add_folder_btn.pack(side="left", padx=(8, 0))
        self.clear_btn = secondary_button(btns, "Clear", self._clear, width=64)
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

    def _pin(self) -> str:
        return self._saved_pin or self.pin_entry.get().strip()

    def _layout_pin_row(self) -> None:
        if self._saved_pin:
            self.pin_entry.grid_forget()
            self.saved_chip.grid(row=0, column=0, sticky="ew")
        else:
            self.saved_chip.grid_forget()
            self.pin_entry.grid(row=0, column=0, sticky="ew")

    def _remember_pin(self, pin: str) -> None:
        try:
            store.save_pin(pin)
        except Exception as e:  # noqa: BLE001
            self._log("Couldn't save the PIN: %s" % e)
            return
        self._saved_pin = pin
        self.pin_entry.delete(0, "end")
        self._layout_pin_row()
        self._log("Token PIN saved on this computer (locked to your Windows login).")
        self._refresh()

    def _forget_pin(self, reason: str = "") -> None:
        store.forget_pin()
        self._saved_pin = None
        self._layout_pin_row()
        self._log(reason or "Saved PIN removed from this computer.")
        self._refresh()

    def _toggle_autostart(self) -> None:
        try:
            store.set_autostart(bool(self.autostart_var.get()))
            self._log("Open when Windows starts: %s" % ("on" if self.autostart_var.get() else "off"))
        except Exception as e:  # noqa: BLE001
            self._log("Couldn't change the start-up setting: %s" % e)

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
        if getattr(self, "bridge_ok", False):
            self.bridge_pill.configure(text="  ⚡  One-click filing on  ", text_color=OK)
        else:
            self.bridge_pill.configure(text="  One-click filing off  ", text_color=ERR)
        self._status_snapshot = {
            "version": APP_VERSION,
            "token_connected": bool(self.certs),
            "certificate": (cert.common_name or cert.display) if cert else None,
            "pin_saved": bool(self._saved_pin),
        }
        ready = bool(cert and n and self._pin()) and not self._busy
        if self._busy:
            self.sign_btn.configure(text="Signing…", state="disabled", fg_color=ROW_HOVER)
        else:
            self.sign_btn.configure(text=("Sign %d file%s" % (n, "" if n == 1 else "s")) if n else "Sign",
                                    state="normal" if ready else "disabled",
                                    fg_color=LIME if ready else ROW_HOVER)
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
        if c:
            self.settings = store.update_settings(cert_id=c.cert_id.hex() or None, cert_label=c.label or None,
                                                  slot_index=c.slot_index)
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
            self.driver_toggle.configure(text="▾ Settings")
            self.driver_box.grid(row=5, column=0, sticky="ew", padx=18, pady=(0, 16))
        else:
            self.driver_toggle.configure(text="▸ Settings")
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
            self._flash("Pick your token's driver first (Settings).", ERR)
            return
        self._busy = True
        self.connect_btn.configure(text="…")
        self._refresh()
        self._log("Reading certificates from the token…")
        pin = self._pin() or None

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
        pin = self._pin()
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
        with self._token_lock:
            self._sign_batch(module, cert_id, cert_label, slot_index, pin, files, out_dir)

    def _sign_batch(self, module, cert_id, cert_label, slot_index, pin, files, out_dir) -> None:
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
            self.q.put(("session_err", str(e) or repr(e), pin_error_kind(e), pin))
        finally:
            if signer:
                signer.close()
        self._log("Done — %d signed, %d failed. Saved to %s" % (ok, fail, out_dir))
        self.q.put(("done", ok, fail, out_dir, pin))

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
                want = self.settings.get("cert_id")
                pick = next((i for i, c in enumerate(self.certs) if want and c.cert_id.hex() == want), 0)
                self.cert_choice.set(labels[pick])
                self.settings = store.update_settings(module=self.module_var.get().strip())
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
            self._flash("Couldn't read the token — see Activity log.", ERR)
            self._refresh()
        elif kind == "file":
            _, i, state, detail = item
            if 0 <= i < len(self.rows):
                self.rows[i].set_state(state, detail)
        elif kind == "progress":
            self.progress.set(item[1])
        elif kind == "session_err":
            _, msg, pin_kind, pin = item
            if pin_kind == "wrong":
                if self._saved_pin and pin == self._saved_pin:
                    self._forget_pin("The token rejected the saved PIN, so it was removed. Type the PIN again.")
                self._flash("Wrong PIN. The token locks after a few wrong tries.", ERR)
            elif pin_kind == "locked":
                self._flash("The token is locked. Unlock it with your token's own tool.", ERR)
            else:
                self._flash("Couldn't open the token: " + msg[:80], ERR)
        elif kind == "bridge_req":
            self._on_bridge_request(item[1])
        elif kind == "bridge_done":
            self._bridge_done(*item[1:])
        elif kind == "bridge_err":
            self._bridge_err(*item[1:])
        elif kind == "done":
            _, ok, fail, out_dir, pin = item
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
            if ok:
                self._maybe_offer_save_pin(pin)

    # ---------------------------------------------------------- saved PIN
    def _maybe_offer_save_pin(self, pin: str) -> None:
        """Offer once per session, only after the PIN has just worked."""
        if (self._saved_pin or self._asked_save_pin or not pin or not store.pin_saving_supported()
                or store.load_settings().get("never_ask_pin")):
            return
        self._asked_save_pin = True
        SavePinDialog(self, pin)

    # ---------------------------------------------------------- one-click bridge
    def _on_bridge_request(self, req: SignRequest) -> None:
        if self._approval is not None and self._approval.winfo_exists():
            req.fail("busy", "The Broto Signer is already showing a request.")
            return
        s = req.summary
        self._log("Broto asks to sign %s (job %s, %s)." % (s["kind"], s.get("job_number"), req.filename))
        if self.root.state() == "iconic":
            self.root.deiconify()
        self._approval = ApprovalDialog(self, req)

    def _start_bridge_sign(self, req: SignRequest, pin: str, from_saved: bool, remember: bool) -> None:
        cert = self._selected_cert()
        module = self.module_var.get().strip()
        want = self.settings.get("cert_id")

        def work() -> None:
            try:
                if not module or not os.path.exists(module):
                    raise RuntimeError("Token driver not set — open the Broto Signer's Settings.")
                with self._token_lock:
                    use, listed = cert, None
                    if use is None:
                        listed = list_certificates(module, pin)
                        if not listed:
                            raise RuntimeError("No certificate found on the token. Is it plugged in?")
                        match = [c for c in listed if want and c.cert_id.hex() == want]
                        if match:
                            use = match[0]
                        elif len(listed) == 1:
                            use = listed[0]
                        else:
                            raise RuntimeError("This token has %d certificates — connect and pick one in the "
                                               "Broto Signer window, then try again." % len(listed))
                    signer = DscSigner(module, pin, cert_id=use.cert_id, cert_label=use.label,
                                       slot_index=use.slot_index)
                    try:
                        signed = signer.sign_icegate_json_bytes(req.content)
                    finally:
                        signer.close()
                self.q.put(("bridge_done", req, signed, pin, from_saved, remember, listed))
            except Exception as e:  # noqa: BLE001
                self.q.put(("bridge_err", req, pin_error_kind(e), str(e) or repr(e), from_saved))
        threading.Thread(target=work, daemon=True).start()

    def _bridge_done(self, req, signed, pin, from_saved, remember, listed) -> None:
        req.finish(signed)
        dlg, self._approval = self._approval, None
        if dlg is not None and dlg.winfo_exists():
            dlg.destroy()
        if listed and not self.certs:
            self._handle(("certs", listed))
        s = req.summary
        self._log("✓ Signed %s for job %s — handed back to Broto." % (s["kind"], s.get("job_number")))
        self._flash("✓  Signed %s (job %s) — Broto is filing it" % (s["kind"], s.get("job_number")), OK)
        if remember:
            self._remember_pin(pin)
        elif not from_saved:
            self._maybe_offer_save_pin(pin)

    def _bridge_err(self, req, pin_kind, msg, from_saved) -> None:
        dlg = self._approval
        alive = dlg is not None and dlg.winfo_exists()
        if pin_kind == "locked":
            req.fail("pin_locked", "The DSC token is locked.")
            if alive:
                dlg.destroy()
            self._approval = None
            self._flash("The token is locked. Unlock it with your token's own tool.", ERR)
            return
        if pin_kind == "wrong":
            if from_saved:
                self._forget_pin("The token rejected the saved PIN, so it was removed.")
                text = "The token rejected your saved PIN, so it was removed. Type the PIN."
            else:
                text = "Wrong PIN. Careful — the token locks after a few wrong tries."
            if alive:
                dlg.show_error(text, need_pin=True)
            else:
                req.fail("wrong_pin", text)
            return
        self._log("Signing for Broto failed: " + msg)
        if alive:
            dlg.show_error("Couldn't sign: " + msg[:200])
        else:
            req.fail("failed", msg[:300])

    def _flash(self, msg: str, color) -> None:
        self.status_lbl.configure(text=msg, text_color=color)

    def _log(self, msg: str) -> None:
        self.q.put(("log", msg))

    def _write(self, msg: str) -> None:
        line = datetime.now().strftime("%H:%M:%S  ") + msg
        self._log_lines.append(line)
        if self._log_box is not None:
            try:
                self._log_box.configure(state="normal")
                self._log_box.insert("end", line + "\n")
                self._log_box.see("end")
                self._log_box.configure(state="disabled")
            except Exception:  # noqa: BLE001 - window was closed
                self._log_box = None

    def _open_log(self) -> None:
        if self._log_win is not None and self._log_win.winfo_exists():
            self._log_win.focus()
            return
        win = ctk.CTkToplevel(self.root)
        win.title("Activity log — " + APP_TITLE)
        win.geometry("640x380")
        win.configure(fg_color=BG)
        win.transient(self.root)
        box = ctk.CTkTextbox(win, fg_color=CARD, text_color=TEXT, wrap="word", corner_radius=12,
                             border_width=1, border_color=BORDER,
                             font=ctk.CTkFont(family="Consolas" if sys.platform == "win32" else "Menlo",
                                              size=12))
        box.pack(fill="both", expand=True, padx=14, pady=14)
        box.insert("end", "\n".join(self._log_lines) + ("\n" if self._log_lines else ""))
        box.see("end")
        box.configure(state="disabled")
        self._log_win, self._log_box = win, box

def main() -> None:
    ctk.set_appearance_mode("system")      # follows Windows light/dark
    ctk.set_default_color_theme("blue")
    root = _Root()
    SignerApp(root)
    if "--minimized" in sys.argv:        # started with Windows — wait quietly for Broto
        root.after(300, root.iconify)
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
