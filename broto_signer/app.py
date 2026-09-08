"""
Broto DSC Signer — a small Windows desktop app to sign files with a Digital
Signature Certificate on a USB token.

Flow: pick your token's certificate -> add files -> enter the token PIN -> Sign.
PDFs get an embedded PAdES signature; .be/.sb (and other) flat files get the
ICEGATE append-format signature (<START-SIGNATURE>/<START-CERTIFICATE>/
<SIGNER-VERSION>). Everything happens on this machine; nothing is uploaded.

Run from source:  python app.py
Build a .exe:     see README.md
"""
from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText
from typing import List

from signer_core import DscSigner, discover_module, list_certificates, sign_one

APP_TITLE = "Broto DSC Signer"


class SignerApp:
    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        root.title(APP_TITLE)
        root.geometry("780x600")
        root.minsize(660, 500)

        self.module_var = tk.StringVar(value=discover_module() or "")
        self.pin_var = tk.StringVar()
        self.out_var = tk.StringVar()
        self.cert_var = tk.StringVar()
        self.files: List[str] = []
        self.certs: List = []
        self.log_q: "queue.Queue" = queue.Queue()
        self._signing = False

        self._build()
        self._poll_log()
        if not self.module_var.get():
            self._log("Could not auto-detect a token module. Set the path to your token's DLL, "
                      r"e.g. C:\Windows\System32\eps2003csp11v2.dll")
        else:
            self._log("Token module: " + self.module_var.get())

    # ---------------------------------------------------------------- UI
    def _build(self) -> None:
        pad = {"padx": 8, "pady": 4}

        f1 = ttk.Frame(self.root); f1.pack(fill="x", **pad)
        ttk.Label(f1, text="PKCS#11 module:").grid(row=0, column=0, sticky="w")
        ttk.Entry(f1, textvariable=self.module_var).grid(row=0, column=1, sticky="we", padx=4)
        ttk.Button(f1, text="Detect", command=self._detect).grid(row=0, column=2)
        f1.columnconfigure(1, weight=1)

        f2 = ttk.Frame(self.root); f2.pack(fill="x", **pad)
        ttk.Label(f2, text="Token PIN:").grid(row=0, column=0, sticky="w")
        ttk.Entry(f2, textvariable=self.pin_var, show="\u2022", width=22).grid(row=0, column=1, sticky="w", padx=4)
        ttk.Button(f2, text="Load certificates", command=self._load_certs).grid(row=0, column=2, padx=4)

        f3 = ttk.Frame(self.root); f3.pack(fill="x", **pad)
        ttk.Label(f3, text="Certificate:").grid(row=0, column=0, sticky="w")
        self.cert_combo = ttk.Combobox(f3, textvariable=self.cert_var, state="readonly")
        self.cert_combo.grid(row=0, column=1, sticky="we", padx=4)
        f3.columnconfigure(1, weight=1)

        ff = ttk.LabelFrame(self.root, text="Files to sign   (PDF → PAdES · .be/.sb → ICEGATE signature)")
        ff.pack(fill="both", expand=True, **pad)
        self.listbox = tk.Listbox(ff, selectmode="extended")
        self.listbox.pack(side="left", fill="both", expand=True, padx=(6, 0), pady=6)
        sb = ttk.Scrollbar(ff, command=self.listbox.yview); sb.pack(side="left", fill="y", pady=6)
        self.listbox.config(yscrollcommand=sb.set)
        col = ttk.Frame(ff); col.pack(side="left", fill="y", padx=6, pady=6)
        ttk.Button(col, text="Add files…", command=self._add_files).pack(fill="x", pady=2)
        ttk.Button(col, text="Add folder…", command=self._add_folder).pack(fill="x", pady=2)
        ttk.Button(col, text="Remove", command=self._remove).pack(fill="x", pady=2)
        ttk.Button(col, text="Clear", command=self._clear).pack(fill="x", pady=2)

        f4 = ttk.Frame(self.root); f4.pack(fill="x", **pad)
        ttk.Label(f4, text="Output folder:").grid(row=0, column=0, sticky="w")
        ttk.Entry(f4, textvariable=self.out_var).grid(row=0, column=1, sticky="we", padx=4)
        ttk.Button(f4, text="Browse", command=self._browse_out).grid(row=0, column=2)
        f4.columnconfigure(1, weight=1)

        self.sign_btn = ttk.Button(self.root, text="Sign", command=self._start_sign)
        self.sign_btn.pack(**pad)

        self.log = ScrolledText(self.root, height=10, state="disabled", wrap="word")
        self.log.pack(fill="both", expand=True, **pad)

    # ------------------------------------------------------------ actions
    def _pin(self):
        return self.pin_var.get().strip() or None

    def _detect(self) -> None:
        m = discover_module()
        if m:
            self.module_var.set(m); self._log("Detected module: " + m)
        else:
            self._log("No known token module found — enter the DLL path manually.")

    def _load_certs(self) -> None:
        mod = self.module_var.get().strip()
        if not mod or not os.path.exists(mod):
            messagebox.showerror(APP_TITLE, "Set a valid PKCS#11 module path first."); return
        self._log("Loading certificates…")
        try:
            self.certs = list_certificates(mod, self._pin())
        except Exception as e:  # noqa: BLE001 - surface the real error to the user
            self._log("ERROR listing certificates: " + repr(e))
            messagebox.showerror(APP_TITLE, "Could not read the token.\n\n" + str(e)); return
        if not self.certs:
            self._log("No certificates found. Is the token plugged in? Some tokens need the PIN first.")
            return
        self.cert_combo["values"] = [c.display for c in self.certs]
        self.cert_combo.current(0)
        self._log("Found %d certificate(s)." % len(self.certs))

    def _add_files(self) -> None:
        self._add(filedialog.askopenfilenames(
            title="Select files to sign",
            filetypes=[("Signable files", "*.pdf *.be *.sb"), ("PDF", "*.pdf"),
                       ("Flat files", "*.be *.sb"), ("All files", "*.*")]))

    def _add_folder(self) -> None:
        d = filedialog.askdirectory(title="Select a folder — its PDF/.be/.sb files are added")
        if not d:
            return
        exts = (".pdf", ".be", ".sb")
        self._add([os.path.join(d, f) for f in sorted(os.listdir(d))
                   if os.path.isfile(os.path.join(d, f)) and f.lower().endswith(exts)])

    def _add(self, paths) -> None:
        added = 0
        for p in paths:
            if p and p not in self.files:
                self.files.append(p); self.listbox.insert("end", p); added += 1
        if added and not self.out_var.get():
            self.out_var.set(os.path.join(os.path.dirname(self.files[0]), "signed"))

    def _remove(self) -> None:
        for i in reversed(self.listbox.curselection()):
            del self.files[i]; self.listbox.delete(i)

    def _clear(self) -> None:
        self.files.clear(); self.listbox.delete(0, "end")

    def _browse_out(self) -> None:
        d = filedialog.askdirectory(title="Output folder")
        if d:
            self.out_var.set(d)

    def _start_sign(self) -> None:
        if self._signing:
            return
        idx = self.cert_combo.current()
        if idx is None or idx < 0 or idx >= len(self.certs):
            messagebox.showerror(APP_TITLE, "Load and pick a certificate first."); return
        if not self.files:
            messagebox.showerror(APP_TITLE, "Add at least one file."); return
        pin = self.pin_var.get().strip()
        if not pin:
            messagebox.showerror(APP_TITLE, "Enter the token PIN."); return
        out_dir = self.out_var.get().strip() or os.path.join(os.path.dirname(self.files[0]), "signed")
        self.out_var.set(out_dir)
        self._signing = True
        self.sign_btn.config(state="disabled", text="Signing…")
        cert = self.certs[idx]
        args = (self.module_var.get().strip(), cert.cert_id, cert.label, cert.slot_index, pin, list(self.files), out_dir)
        threading.Thread(target=self._sign_worker, args=args, daemon=True).start()

    def _sign_worker(self, module, cert_id, cert_label, slot_index, pin, files, out_dir) -> None:
        ok = fail = 0
        signer = None
        try:
            self._log("Opening token session…")
            signer = DscSigner(module, pin, cert_id=cert_id, cert_label=cert_label, slot_index=slot_index)
            for p in files:
                try:
                    out = sign_one(signer, p, out_dir)
                    ok += 1; self._log("  \u2713 %s  \u2192  %s" % (os.path.basename(p), os.path.basename(out)))
                except Exception as e:  # noqa: BLE001 - per-file failure shouldn't abort the batch
                    fail += 1; self._log("  \u2717 %s  —  %s" % (os.path.basename(p), e))
        except Exception as e:  # noqa: BLE001 - session-level failure (wrong PIN, locked token, …)
            self._log("ERROR: " + repr(e))
        finally:
            if signer:
                signer.close()
        self._log("Done. %d signed, %d failed.  Output: %s" % (ok, fail, out_dir))
        self.log_q.put(("__DONE__", ok, fail))

    # -------------------------------------------------------------- logging
    def _poll_log(self) -> None:
        try:
            while True:
                item = self.log_q.get_nowait()
                if isinstance(item, tuple) and item and item[0] == "__DONE__":
                    self._signing = False
                    self.sign_btn.config(state="normal", text="Sign")
                    _, ok, fail = item
                    if fail == 0:
                        messagebox.showinfo(APP_TITLE, "Signed %d file(s)." % ok)
                    else:
                        messagebox.showwarning(APP_TITLE, "Signed %d, failed %d. See the log." % (ok, fail))
                else:
                    self._write(str(item))
        except queue.Empty:
            pass
        self.root.after(150, self._poll_log)

    def _log(self, msg: str) -> None:
        self.log_q.put(msg)

    def _write(self, msg: str) -> None:
        self.log.config(state="normal")
        self.log.insert("end", msg + "\n")
        self.log.see("end")
        self.log.config(state="disabled")


def main() -> None:
    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista")   # nicer on Windows; harmless elsewhere
    except Exception:
        pass
    SignerApp(root)
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        # Surface startup crashes even in a --windowed build: write a log the user
        # can send us, and try to show it in a dialog before exiting.
        import os
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

