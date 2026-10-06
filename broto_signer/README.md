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
`SHA-1(SHA-256(content))`, matching real CHA tools byte-for-byte.

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

## Log in first (`account.py`)
The app opens on **Log in to Broto** — the same email and password as
brotoai.com (`POST /api/cha/auth/login`). Only a Broto user gets past it:
nothing else runs until then — no signing, no one-click bridge, no remote
signing. The login is Broto's normal 24-hour token, kept like the saved PIN
(Windows DPAPI, same Windows login on the same PC) and renewed
(`/api/cha/auth/refresh`) at start-up and every 4 hours, so an office PC that
stays on stays logged in. If Broto says no (user removed, token too old) the
app goes back to the login screen ("You were logged out. Log in again."); if
Broto just can't be reached, the token keeps working until it expires.
**Settings ▸ Logged in as … ▸ Log out** logs out (signing stops on that PC).
The login screen always shows, even when the app starts with Windows.

## Updates — "Relaunch to update" (`updater.py`)
After login and every 6 hours the app asks Broto for the newest published
version (`GET /api/cha/signer-devices/app-latest?current=<version>` — the
server reads `broto-signer/latest.json`, written next to the .exe by
`scripts/publish_broto_signer.py` / the build workflow: version, SHA-256,
size). If it is newer, the .exe downloads in the background to
`BrotoSigner.update.exe` beside the running one and is kept only if its size
and SHA-256 match. Then **Relaunch to update** appears next to **Sign**. The
click waits for any signing to finish, stops the bridge and remote signing,
renames `BrotoSigner.exe` → `BrotoSigner.old.exe` (Windows allows renaming a
running .exe), puts the new file at the same path (so the start-with-Windows
entry and shortcuts still work), starts it and quits; any failure puts the old
file back. The next start deletes `BrotoSigner.old.exe`. Settings, pairing and
the saved PIN are in `%APPDATA%` and are untouched. Needs PyInstaller ≥ 6.9
(`PYINSTALLER_RESET_ENVIRONMENT` gives the new copy a fresh start). Run from
source, the app only logs that a new version is out. **Every release must bump
`APP_VERSION`** — the check compares it with latest.json.

## How to use
1. Plug in the DSC token.
2. Launch `BrotoSigner.exe`. The default token driver is
   `C:\Windows\System32\SignatureP11.dll`; if another known driver is
   installed instead it is picked up automatically, and **Settings** lets you
   pick any PKCS#11 DLL (e.g. `C:\Windows\System32\eps2003csp11v2.dll`).
3. Enter the **token PIN** → **Connect**. The certificate card shows the holder
   name, the issuing CA and the expiry date (amber inside 30 days, red once
   expired).
   **More than one certificate?** Connect reads every certificate on the token
   AND on any other DSC token plugged in whose driver is installed (e.g. a
   ProxKey and an ePass at once), and a picker appears. Each entry is unique —
   same-name certificates get their expiry date (then serial) added, and
   encryption-only certificates are marked and listed last. The choice is
   remembered (by certificate thumbprint) and used for one-click signing and
   for remote jobs Broto doesn't name a certificate for, through that
   certificate's own driver. A typed PIN is sent only to the driver chosen in
   Settings; other tokens are read without logging in, since a PIN meant for
   one token counts as a wrong try on another.
   **The PIN is saved per token** (by the token's serial number): pick a
   certificate, type its token's PIN and tick *Remember* — each token keeps its
   own, and a saved PIN is only ever used on its own token. A PIN saved by an
   older version is filed under the token of the certificate picked at the
   first Connect.
4. **Drag files in** (or a whole folder), or use **Add files / Add folder** →
   optionally **Change…** the destination folder (default: the folder the
   files are in) → **Sign N files**.
5. Every run creates a **new folder inside the destination** —
   `Broto Signed 30-09-2026 14.05` (or `… (2)` if that name is taken) — and
   puts all its signed files there. Signed files **leave the list by
   themselves**; a file that failed stays, in red with the reason, so it can
   be fixed and signed again. **Open folder** jumps to the new folder;
   **Activity** keeps the log.

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

## Remote signing — pair this PC with Broto (`remote.py`)
One-click filing needs the browser on the *same* PC as the token. Remote
signing lifts that: the DSC token stays plugged into one always-on office PC,
and staff working anywhere can (next step) ask Broto to have **this** PC sign.
This release ships the trust link — pairing + a heartbeat — which is also what
Broto's **Settings ▸ DSC computers** list reads.

1. In Broto (an admin): **Settings ▸ DSC computers ▸ Add computer**. Broto shows
   a one-time code like `ABCD-EFGH`, valid for 10 minutes.
2. On this PC: **Settings ▸ Remote signing**, type the code, **Connect**. The
   header pill turns **☁ Remote signing on** and Broto's list shows this PC
   with the certificate holder, whether the token is plugged in, whether the
   PIN is saved, and online/offline (a check-in every 30 seconds).
3. **Disconnect** here, or **Remove** in Broto, ends it. A removed PC learns so
   on its next check-in and forgets its token.

**Signing for someone else.** When a colleague clicks **Sign & file on ICEGATE**
on a PC that has no Broto Signer, Broto emails a one-time code to the firm's
ICEGATE OTP mailbox; once they type it, this PC picks the job up on its next
check-in (every 2 seconds while a code is being typed, 5 seconds while someone
is filing, 30 seconds otherwise). It
checks the payload exactly as the popup does (an unsigned BE/SB filing, nothing
else), signs and hands the file back — Broto verifies the signature and that it
came from the right certificate, then files. **Which certificate:** every
ICEGATE ID has its own DSC. Broto names the certificate set for the job's
ICEGATE ID (its Filing Licence; set in Broto **Settings ▸ DSC computers**) and
this PC signs with exactly that one, using the PIN saved for **that
certificate's token** — never another token's PIN. With no certificate named
(a PC holding a single one), it signs with the certificate picked here.
No popup appears here; the header pill counts signatures ("☁ Remote signing on
· 3 signed") and the **Activity log** records each one with who asked. If the
PIN is not saved, the token is unplugged, or the token rejects the PIN, the
request fails with that reason on the requester's screen (a rejected saved PIN
is removed here and never retried).

The same lane signs a job's **supporting-document PDFs for eSANCHIT** (Sup Doc
▸ "No token here? Sign these PDFs on <this PC>"): each PDF arrives with the
fingerprint Broto announced, is checked to be a PDF under 25 MB that matches
it, gets a PAdES signature (an incremental update — the original bytes stay
intact), and Broto stores the signed copy on the job. No PDF/A conversion
happens here.

**A run of several files (v2.5.0, e.g. Sign & eSANCHIT).** While the code is
being typed, Broto asks this PC to check in every 2 seconds. Then the PC takes
the whole run in one call (`POST /jobs/claim`) and three things overlap: the
next two files download (`POST /jobs/{id}/content`), the token signs the
current one, and up to two signed files go back (`POST /jobs/{id}/result`).
The token still signs **one file at a time** — a token chip does one signature
at a time, and some drivers fail when asked for two — and it is logged in
**once for the run** (`RemoteSignSession` in `app.py`): before 2.5.0 every
file read all the certificates again and typed the PIN again. A token that
refuses its saved PIN is never tried again in that run; every file needing it
fails at once with the same reason. The Activity log shows each step's time
("got it in 0.8 s · signed in 1.1 s · sent back in 1.9 s") and one line per run;
the same timings go to Broto's logs. A Broto from before runs answers the claim
with 404, and the PC then takes files one at a time as before (still one
login per check-in).

And the **.be / .sb flat files** (the flat-file step ▸ "Sign .be on <this
PC>"): Broto generates the file through the download's own checks and hands it
over; this PC checks the ICEGATE HREC header (a BE or SB message, not already
signed, under 10 MB, matching fingerprint), appends the
`<START-SIGNATURE>` / `<START-CERTIFICATE>` / `<SIGNER-VERSION>` envelope exactly
as batch signing does, and Broto keeps the signed file on the job for the user
to download and upload on the ICEGATE portal.

What the app stores: the device token Broto issued (Windows: DPAPI-encrypted
like the PIN, same Windows login only), the firm + PC name, and which Broto
server it paired with. What it sends on every check-in: the PC's hostname,
app version, Windows version, token plugged in / PIN saved, and for each
certificate on the token the holder, issuer, serial, expiry, a SHA-256
thumbprint, whether it can sign, which token it is on (a short hash — never the
token's serial number) and whether that token's PIN is saved — never the PIN
and never any key material. The app still never talks to ICEGATE.

Development: `BROTO_API_BASE=http://localhost:8000` points pairing + check-ins
at a local backend (the Settings hint shows the server when it isn't
production). Off Windows the device token is kept in plain text in
`settings.json` — dev boxes only; real tokens live on Windows.

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
- **Read certificate details while the token session is open.** python-pkcs11
  reads each attribute live through the session; once the `with tok.open()`
  block closes, every read fails. v2.3.0 read them after the close, so every
  certificate showed as a blank "Certificate in slot 1", two blank ones looked
  identical (only one was listed), and the PC reported no thumbprints — which
  made Broto reject every remote signature. Fixed in v2.3.1 (`_read_certificates`).
- **pyHanko reads PDFs non-strict** (`open_pdf_for_signing`). Strict mode
  refused PDFs every viewer opens — e.g. DGFT licence PDFs saved by Acrobat,
  whose later revision frees a dead object with "next generation 0" ("a free
  xref with next generation 0 is only permitted in an initial revision",
  2026-09-30). Fixed in v2.4.0.
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
