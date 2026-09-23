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
  --collect-all pyhanko ^
  --collect-all pyhanko_certvalidator ^
  --collect-all asn1crypto ^
  --collect-submodules pkcs11 ^
  app.py
```
The result is **`dist\BrotoSigner.exe`** — a single file you can copy to any
Windows machine. (First build may miss a hidden import; if it errors at launch,
send me the message and I'll add the right `--collect`/`--hidden-import`.)

## How to use
1. Plug in the DSC token.
2. Launch `BrotoSigner.exe`. It auto-detects the token driver; if not, set the
   PKCS#11 DLL path (e.g. `C:\Windows\System32\eps2003csp11v2.dll`).
3. Enter the **token PIN** → **Load certificates** → pick your certificate.
4. **Add files** (or **Add folder** for a whole batch) → set the **output
   folder** → **Sign**.
5. Signed files land in the output folder; the log shows one line per file.

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
