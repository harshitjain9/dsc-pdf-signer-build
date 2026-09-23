# Broto DSC Signer

A small **Windows desktop app** that signs files with a Digital Signature
Certificate (DSC) on a USB token — the same kind of signing ICEGATE's *filesign*
utility does, but able to sign a **whole folder at once**.

Signs **PDFs** (invoices, packing lists, etc.) — each gets an embedded **PAdES**
signature — **`.be`/`.sb` flat files**, which get ICEGATE's append-format
signature (`<START-SIGNATURE>` / `<START-CERTIFICATE>` / `<SIGNER-VERSION>`) — and
**`.json` ICEGATE Open API payloads** (CACHI01/CACHE01), which get a `digSign`
object appended as the schema-form third top-level key
(`{headerField, master, digSign}`). All three use the same signed value
`SHA-1(SHA-256(content))`, matching real CHA tools (Royal Impex, Live Impex)
byte-for-byte.

Everything runs locally on the user's machine. **Nothing is uploaded.**

---

## Run from source (for development)
```bash
pip install -r requirements.txt
python app.py
```
Runs on macOS/Linux too (for UI work), but real signing needs a Windows machine
with the DSC token + its driver installed.

## Build the Windows `.exe`
On the Windows machine:
```bat
pip install -r requirements.txt
pip install pyinstaller
pyinstaller --onefile --windowed --name BrotoSigner ^
  --icon assets\broto.ico --add-data "assets;assets" ^
  --collect-all pyhanko ^
  --collect-all pyhanko_certvalidator ^
  --collect-all asn1crypto ^
  --collect-all pkcs11 ^
  --collect-all customtkinter ^
  --collect-all tkinterdnd2 ^
  app.py
```
The result is **`dist\BrotoSigner.exe`** — a single file you can copy to any
Windows machine. (First build may miss a hidden import; if it errors at launch,
send me the message and I'll add the right `--collect`/`--hidden-import`.)

## How to use
1. Plug in the DSC token.
2. Launch `BrotoSigner.exe`. It auto-detects the token driver; if it can't,
   **Settings** opens so you can pick the PKCS#11 DLL
   (e.g. `C:\Windows\System32\eps2003csp11v2.dll`).
3. Enter the **token PIN** → **Connect**. The certificate card shows the holder
   name, the issuing CA and the expiry date (amber inside 30 days, red once
   expired). Tokens with several certificates get a picker.
4. **Drag files in** (or a whole folder), or use **Add files / Add folder** →
   optionally **Change…** the output folder → **Sign N files**.
5. Each file row turns green (✓ with the signed file's name) or red (with the
   reason). **Open folder** jumps to the signed files; **Activity** keeps the log.

The UI is CustomTkinter and follows the Windows light/dark setting.

## One-click filing from Broto (`bridge.py`)
While the app is open it listens on **`http://127.0.0.1:47811`** — this PC only.
In Broto's **File on ICEGATE (API)** box, **Sign & file on ICEGATE** sends the
unsigned BE/SB JSON here; the app pops up **"Sign & file this Bill of Entry?"**
with the importer/exporter, IEC, job no., invoice/item counts, ICEGATE ID and
the certificate — all read from the payload itself. **Sign & file** returns the
signed JSON to the browser, which uploads it to Broto; Broto's server verifies
the signature and submits to ICEGATE. The app never talks to ICEGATE or Broto.

Guard rails: 127.0.0.1 only; Host header must be 127.0.0.1/localhost (blocks
DNS rebinding); only Broto's origin (`https://brotoai.com`, `www.`) may call it
(`BROTO_SIGNER_ORIGINS=http://localhost:3000` adds dev origins); only unsigned
CACHI01/CACHE01 filings are accepted (never a general signing oracle); every
request needs a click in the popup; one request at a time; 5-minute timeout.
The header pill shows **⚡ One-click filing on**. A second copy of the app
can't claim the port, so its pill says off.

**Settings → Open when Windows starts** adds a current-user Run entry that
launches the app minimised at login, so it's ready when Broto asks.

## Saved PIN (optional, Windows only)
After a PIN has **just worked** (a successful batch, or a one-click signature),
the app asks once: **Save PIN / Not now / Don't ask again**. The popup also has
a *Remember my PIN on this computer* tick box (off by default). Nothing is
saved without that yes. The PIN is encrypted with **Windows DPAPI**
(current-user scope, `secure_store.py`) in `%APPDATA%\BrotoSigner\settings.json`:
only the same Windows login on the same PC can decrypt it. Every signature
still needs the popup click. **Forget** (next to "PIN saved") removes it.
If the token ever rejects the saved PIN, it is deleted immediately and never
retried, because tokens lock after a few wrong PINs.

---

## Notes & known gotchas
- **Windows-first.** DSC tokens/drivers are effectively Windows-only.
- **32- vs 64-bit:** if loading the token DLL fails with *"not a valid Win32
  application"*, Python's bitness doesn't match the driver's. `System32` holds
  the 64-bit DLL, `SysWOW64` the 32-bit one — point the module path at the one
  matching your Python, or install matching-bitness Python.
- **PDF/A:** eSANCHIT wants PDF/A specifically. This tool signs PDFs as-is; a
  convert-to-PDF/A step can be added if we wire it to eSANCHIT later.
- **Not yet code-signed.** Windows SmartScreen may warn on an unsigned `.exe`;
  a real release should be built with an installer + code-signing certificate.
- Supersedes the earlier throwaway `dsc_spike/sign_spike.py` (same signing core,
  now with a GUI and batch signing).
