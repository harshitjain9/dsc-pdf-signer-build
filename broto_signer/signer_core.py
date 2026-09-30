"""
broto_signer.signer_core — DSC signing over a PKCS#11 USB token (pyHanko).

No UI here. This module discovers the token's PKCS#11 module, lists the signing
certificates on it, and signs files:
  * PDF            -> embedded PAdES signature (a normal signed PDF)
  * .json          -> ICEGATE Open API filing signature: a digSign OBJECT appended
                      as a third top-level key (the CACHI01/CACHE01 schema form)
  * .be/.sb/other  -> ICEGATE 'Text file' signature: the original content plus
                      appended <START-SIGNATURE>/<START-CERTIFICATE>/<SIGNER-VERSION>
                      tags
  (JSON and flat file share the same signed value = SHA-1(SHA-256(content)).)

Windows-first — that's where DSC tokens and their drivers live — but the code is
cross-platform. Everything runs locally; nothing leaves the machine.
"""
from __future__ import annotations

import os
import platform
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, List, Optional

# The <SIGNER-VERSION> value stamped into signed flat files. ICEGATE appears to
# treat this as an audit/log tag (it is NOT part of the signed hash) — confirm on
# a real upload; change here if ICEGATE ever requires a specific value.
SIGNER_VERSION = b"V-BROTO_09.2026"

# The digSign.signerVersion for ICEGATE JSON (CACHI01/CACHE01) payloads. Real
# CHA tools vary the string ("V-ROYAL_09.01.2018" in one, "1.0" in another)
# and both are accepted, so ICEGATE does not appear to validate it — we use
# "1.0", the value that ships in the schema-form digSign object.
JSON_SIGNER_VERSION = b"1.0"


# The default token driver (ProxKey / mToken SignatureP11) — what the app
# offers when nothing was saved and auto-detect finds nothing.
DEFAULT_WINDOWS_MODULE = r"C:\Windows\System32\SignatureP11.dll"

# Common PKCS#11 module paths for the DSC tokens Indian CHAs use.
_WINDOWS_MODULES = [
    DEFAULT_WINDOWS_MODULE,                           # ProxKey / mToken — the default
    r"C:\Windows\System32\eps2003csp11v2.dll",       # ePass2003 (Watchdata)
    r"C:\Windows\System32\eps2003csp11.dll",
    r"C:\Windows\System32\wdpkcs.dll",               # Watchdata ProxKey
    r"C:\Windows\System32\eTPKCS11.dll",             # SafeNet / Aladdin eToken
    r"C:\Windows\System32\ShuttleCsp11_3003.dll",    # TrustKey / mToken CryptoID
    r"C:\Windows\System32\AKChiptokenInterface_3003.dll",
    r"C:\Windows\System32\opensc-pkcs11.dll",        # OpenSC (generic fallback)
]
_MAC_MODULES = [
    "/Library/OpenSC/lib/opensc-pkcs11.so",
    "/usr/local/lib/opensc-pkcs11.so",
    "/opt/homebrew/lib/opensc-pkcs11.so",
]
_LINUX_MODULES = [
    "/usr/lib/x86_64-linux-gnu/opensc-pkcs11.so",
    "/usr/lib/opensc-pkcs11.so",
    "/usr/lib64/opensc-pkcs11.so",
]


def _candidate_modules() -> List[str]:
    return {"Windows": _WINDOWS_MODULES, "Darwin": _MAC_MODULES}.get(platform.system(), _LINUX_MODULES)


def discover_modules() -> List[str]:
    """Every known PKCS#11 module present on this machine, default first."""
    return [p for p in _candidate_modules() if os.path.exists(p)]


def discover_module() -> Optional[str]:
    """Return the first known PKCS#11 module present on this machine, or None."""
    found = discover_modules()
    return found[0] if found else None


def default_module() -> str:
    """The driver path the app starts with when none is saved: the first one
    found on this PC, else (on Windows) SignatureP11.dll, else ""."""
    found = discover_module()
    if found:
        return found
    return DEFAULT_WINDOWS_MODULE if platform.system() == "Windows" else ""


@dataclass
class CertInfo:
    label: str            # real CKA_LABEL (may be "")
    subject: str
    cert_id: bytes = b""  # CKA_ID — the reliable selector when the label is empty
    slot_index: int = 0   # which token slot it lives in (multi-slot readers)
    common_name: str = ""             # holder name (subject CN)
    issuer: str = ""                  # issuing CA (issuer CN / O)
    not_after: Optional[datetime] = None   # expiry (UTC)
    serial: str = ""                  # certificate serial (hex) — what a CA / ICEGATE identifies it by
    thumbprint: str = ""              # sha256 of the DER, hex — what Broto pins a paired PC's DSC by
    can_sign: bool = True             # False = an encryption-only certificate (key usage has no signing bit)
    module: str = ""                  # the PKCS#11 driver it was read through ("" = the app's driver)
    token: str = ""                   # which token it is on (token_key) — the saved PIN is kept per token

    @property
    def display(self) -> str:
        name = self.common_name or self.subject
        if self.label and name and self.label != name:
            return "%s — %s" % (name, self.label)
        return name or self.label or "Certificate in slot %d" % (self.slot_index + 1)

    def report(self) -> dict:
        """What the signer tells Broto about this certificate when the PC is
        paired for remote signing (remote.py heartbeat). No key material, and
        the token only as a short hash (never its serial number); the app adds
        ``pin_saved`` for the token."""
        return {
            "holder": self.common_name or self.subject,
            "issuer": self.issuer,
            "serial": self.serial,
            "thumbprint": self.thumbprint,
            "not_after": self.not_after.isoformat() if self.not_after else "",
            "label": self.label,
            "token": token_ref(self.token),
            "can_sign": "1" if self.can_sign else "0",
        }


def token_key(tok, slot_index: int) -> str:
    """A stable name for a plugged-in token: its serial number (set by the maker,
    unchanged when it is plugged into another port), else its label and slot.
    The saved PIN is kept per token under this name."""
    serial = getattr(tok, "serial", b"") or b""
    if isinstance(serial, (bytes, bytearray)):
        serial = bytes(serial).decode("ascii", "replace")
    serial = str(serial).replace("\x00", "").strip()
    if serial:
        return "sn:" + serial
    label = str(getattr(tok, "label", "") or "").replace("\x00", "").strip()
    return "slot%d:%s" % (slot_index, label)


def token_ref(key: str) -> str:
    """What Broto is told about a token: a short hash of its key."""
    import hashlib
    return hashlib.sha256(key.encode("utf-8")).hexdigest()[:12] if key else ""


def _describe_cert(der: bytes) -> dict:
    """Best-effort holder / issuer / expiry / serial / thumbprint from a DER
    certificate. Each field is read on its own: Indian DSCs carry unusual
    subject attributes that can make one accessor fail while the others still
    work."""
    import hashlib

    from asn1crypto import x509
    out = _blank_info()
    try:
        out["thumbprint"] = hashlib.sha256(der).hexdigest()
    except Exception:
        pass
    try:
        cert = x509.Certificate.load(der)
    except Exception:
        return out
    try:
        out["serial"] = "%X" % cert.serial_number
    except Exception:
        pass
    try:
        out["subject"] = cert.subject.human_friendly
    except Exception:
        pass
    try:
        out["common_name"] = cert.subject.native.get("common_name") or ""
    except Exception:
        pass
    try:
        iss = cert.issuer.native
        out["issuer"] = iss.get("common_name") or iss.get("organization_name") or ""
    except Exception:
        pass
    try:
        out["not_after"] = cert.not_valid_after
    except Exception:
        pass
    try:
        usage = cert.key_usage_value
        if usage is not None:
            bits = set(usage.native)
            out["can_sign"] = bool(bits & {"digital_signature", "non_repudiation"})
    except Exception:
        pass
    return out


def _blank_info() -> dict:
    return {"subject": "", "common_name": "", "issuer": "", "not_after": None, "serial": "", "thumbprint": "",
            "can_sign": True}


def _read_certificates(session, slot_index: int, module: str) -> List[CertInfo]:
    """Every certificate on an OPEN session, with its details.

    The details MUST be read before the session closes: python-pkcs11 reads
    each attribute live through the session handle, so after the ``with``
    block has closed it every read fails. (Until v2.3.1 the reads ran after
    the close — every certificate came back blank as "Certificate in slot 1",
    and two blank certificates looked identical, so only one was listed.)"""
    from pkcs11 import Attribute, ObjectClass
    out: List[CertInfo] = []
    for cert in list(session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE})):
        label = ""
        try:
            label = cert[Attribute.LABEL] or ""
        except Exception:
            pass
        cert_id = b""
        try:
            cert_id = bytes(cert[Attribute.ID])
        except Exception:
            pass
        info = _blank_info()
        try:
            info = _describe_cert(bytes(cert[Attribute.VALUE]))
        except Exception:
            pass
        out.append(CertInfo(label=label, cert_id=cert_id, slot_index=slot_index, module=module, **info))
    return out


def list_certificates(module: str, pin: Optional[str] = None,
                      pins: Optional[Dict[str, str]] = None) -> List[CertInfo]:
    """Enumerate the certificates on every token this driver can see (each
    plugged-in token is a slot). Reads without logging in first — certificates
    are public on DSC tokens — and logs in only to a token that shows none, or
    none it could read, that way: with that token's OWN saved PIN (``pins``, by
    token_key), else with ``pin`` (the PIN just typed). Never another token's
    saved PIN."""
    import pkcs11

    lib = pkcs11.lib(module)
    out: List[CertInfo] = []
    seen = set()
    for slot_index, slot in enumerate(lib.get_slots(token_present=True)):
        tok = slot.get_token()
        key = token_key(tok, slot_index)
        token_pin = (pins or {}).get(key) or pin
        found: List[CertInfo] = []
        for use_pin in (None, token_pin):
            if use_pin is not None and any(c.thumbprint for c in found):
                break                                   # already read without the PIN
            try:
                with tok.open(user_pin=use_pin) as session:
                    got = _read_certificates(session, slot_index, module)
                if got and (not found or any(c.thumbprint for c in got)):
                    found = got
            except Exception:
                pass
            if token_pin is None:
                break
        for c in found:
            c.token = key
        for n, c in enumerate(found):
            # The same certificate in two slots is listed once; certificates
            # whose details could not be read are never merged with each other.
            key = c.thumbprint or (slot_index, n)
            if key in seen:
                continue
            seen.add(key)
            out.append(c)
    return out


def list_all_certificates(module: str, pin: Optional[str] = None,
                          pins: Optional[Dict[str, str]] = None) -> List[CertInfo]:
    """Certificates from the chosen driver AND every other known token driver
    on this PC, so a user with two DSC tokens of different makes (say a
    ProxKey and an ePass) sees both and can pick one.

    A typed PIN goes ONLY to the chosen driver: another make's token is read
    without logging in (or with its own saved PIN from ``pins``), because a PIN
    meant for one token counts as a wrong try on another — and tokens lock
    after a few. Signing certificates come first; a certificate seen through
    two drivers is listed once."""
    out: List[CertInfo] = []
    seen = set()

    def add(certs: List[CertInfo]) -> None:
        for c in certs:
            key = c.thumbprint or (c.module, c.slot_index, c.cert_id, c.label, c.subject)
            if key not in seen:
                seen.add(key)
                out.append(c)

    add(list_certificates(module, pin, pins))    # errors here are real — let them surface
    for other in discover_modules():
        if os.path.normcase(os.path.abspath(other)) == os.path.normcase(os.path.abspath(module)):
            continue
        try:
            add(list_certificates(other, None, pins))
        except Exception:
            pass                                 # a driver with no token of its own, or one that won't load
    out.sort(key=lambda c: not c.can_sign)       # stable: signing certificates first
    return out


def cert_choice_labels(certs: List[CertInfo]) -> List[str]:
    """One label per certificate for the picker — always unique, so picking
    the second of two same-name certificates (a renewed DSC, or the signing +
    encryption pair many Indian tokens carry) really selects the second."""
    def when(c: CertInfo) -> str:
        return c.not_after.strftime("%d %b %Y") if c.not_after else ""

    labels = []
    for c in certs:
        text = c.common_name or c.display
        if not c.can_sign:
            text += "  (encryption only)"
        labels.append(text)
    # Each pass counts from a snapshot, so every clashing label gets the extra part.
    snap = list(labels)                          # same name → add the expiry date
    labels = [("%s  ·  valid till %s" % (lab, when(c))) if snap.count(lab) > 1 and when(c) else lab
              for lab, c in zip(snap, certs)]
    snap = list(labels)                          # still the same → add the serial's tail
    labels = [("%s  ·  no. …%s" % (lab, c.serial[-6:])) if snap.count(lab) > 1 and c.serial else lab
              for lab, c in zip(snap, certs)]
    snap, seen = list(labels), {}                # last resort: number them
    for i, lab in enumerate(snap):
        if snap.count(lab) > 1:
            seen[lab] = seen.get(lab, 0) + 1
            labels[i] = "%s  (%d)" % (lab, seen[lab])
    return labels


class DscSigner:
    """Opens ONE PKCS#11 session (one PIN entry) and signs many files with one
    chosen certificate. Call close() when done."""

    def __init__(self, module: str, pin: str, cert_id: bytes = b"", cert_label: str = "",
                 slot_index: int = 0):
        import pkcs11
        from pkcs11 import Attribute, ObjectClass
        from pyhanko.sign.pkcs11 import PKCS11Signer
        slots = pkcs11.lib(module).get_slots(token_present=True)
        if not slots:
            raise RuntimeError("No token present — plug in the DSC and try again.")
        # Multi-slot readers (ProxKey / SignatureP11, etc.) expose several slots,
        # so open the exact slot the chosen certificate lives in rather than
        # letting pyHanko guess. Logging in here also lets us read the key.
        slot = slots[slot_index] if 0 <= slot_index < len(slots) else slots[0]
        self._session = slot.get_token().open(user_pin=pin)
        # If the cert listing couldn't read a selector (some tokens hide
        # attributes until login), resolve one now from the logged-in session.
        if not cert_id and not cert_label:
            try:
                found = list(self._session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}))
                if found:
                    try:
                        cert_id = bytes(found[0][Attribute.ID])
                    except Exception:
                        cert_id = b""
                    if not cert_id:
                        try:
                            cert_label = found[0][Attribute.LABEL] or ""
                        except Exception:
                            cert_label = ""
            except Exception:
                pass
        # Remember the resolved selectors so flat-file signing can find the same
        # private key + certificate on this session.
        self._cert_id = cert_id
        self._cert_label = cert_label
        # Select by CKA_ID when we have one (works even with an empty label; the
        # private key shares that ID on these tokens); else label; else the
        # token's single signing key.
        if cert_id:
            self._signer = PKCS11Signer(self._session, cert_id=cert_id, key_id=cert_id)
        elif cert_label:
            self._signer = PKCS11Signer(self._session, cert_label=cert_label)
        else:
            self._signer = PKCS11Signer(self._session)

    def sign_pdf(self, in_path: str, out_path: str) -> None:
        with open(in_path, "rb") as inf:
            signed = self.sign_pdf_bytes(inf.read())
        with open(out_path, "wb") as outf:
            outf.write(signed)

    def sign_pdf_bytes(self, content: bytes) -> bytes:
        """PAdES-sign a PDF held in memory (the remote lane hands PDFs over as
        bytes). pyHanko writes an incremental update, so the result starts with
        the original bytes — Broto relies on that to prove the document was not
        altered on the way."""
        import io

        from pyhanko.sign import signers
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        writer = IncrementalPdfFileWriter(io.BytesIO(content))
        out = signers.sign_pdf(
            writer, signers.PdfSignatureMetadata(field_name="BrotoSig"), signer=self._signer)
        return bytes(out.getbuffer())

    def _object_templates(self, klass):
        from pkcs11 import Attribute
        tmpls = []
        if self._cert_id:
            tmpls.append({Attribute.CLASS: klass, Attribute.ID: self._cert_id})
        if self._cert_label:
            tmpls.append({Attribute.CLASS: klass, Attribute.LABEL: self._cert_label})
        tmpls.append({Attribute.CLASS: klass})   # last resort: the only one on the token
        return tmpls

    def _private_key(self):
        from pkcs11 import ObjectClass
        for tmpl in self._object_templates(ObjectClass.PRIVATE_KEY):
            keys = list(self._session.get_objects(tmpl))
            if keys:
                return keys[0]
        raise RuntimeError("No private key found on the token.")

    def _certificate_der(self) -> bytes:
        from pkcs11 import Attribute, ObjectClass
        for tmpl in self._object_templates(ObjectClass.CERTIFICATE):
            certs = list(self._session.get_objects(tmpl))
            if certs:
                return bytes(certs[0][Attribute.VALUE])
        raise RuntimeError("No certificate found on the token.")

    def _double_hash_sign(self, core: bytes) -> bytes:
        """The ICEGATE signed value = SHA-1( SHA-256(core) ), RSA-PKCS#1 v1.5.

        Reproduced on the token by feeding the 32-byte SHA-256 digest to
        CKM_SHA1_RSA_PKCS (the token then SHA-1s that digest and signs the
        DigestInfo). Confirmed on real signed BE/SB flat files AND JSON payloads from
        two other CHA tools (Pantasign and Capricorn DSCs) — same math for both."""
        import hashlib
        from pkcs11 import Mechanism
        inner = hashlib.sha256(core).digest()
        return self._private_key().sign(inner, mechanism=Mechanism.SHA1_RSA_PKCS)

    def sign_flatfile(self, in_path: str, out_path: str) -> None:
        """File wrapper around :meth:`sign_flatfile_bytes`."""
        with open(in_path, "rb") as inf:
            content = inf.read()
        with open(out_path, "wb") as outf:
            outf.write(self.sign_flatfile_bytes(content))

    def sign_flatfile_bytes(self, content: bytes) -> bytes:
        """ICEGATE 'Text file' signature: original content + appended
        <START-SIGNATURE>/<START-CERTIFICATE>/<SIGNER-VERSION> tag lines. The signed
        value is SHA-1(SHA-256(content with trailing CR/LF stripped))."""
        import base64
        core = content.rstrip(b"\r\n")
        signature = self._double_hash_sign(core)
        cert_der = self._certificate_der()
        out = core + b"\n"
        out += b"<START-SIGNATURE>" + base64.b64encode(signature) + b"</START-SIGNATURE>\n"
        out += b"<START-CERTIFICATE>" + base64.b64encode(cert_der) + b"</START-CERTIFICATE>\n"
        out += b"<SIGNER-VERSION>" + SIGNER_VERSION + b"</SIGNER-VERSION>"
        return out

    def sign_icegate_json(self, in_path: str, out_path: str) -> None:
        """File wrapper around :meth:`sign_icegate_json_bytes`."""
        with open(in_path, "rb") as inf:
            content = inf.read()
        with open(out_path, "wb") as outf:
            outf.write(self.sign_icegate_json_bytes(content))

    def sign_icegate_json_bytes(self, content: bytes) -> bytes:
        """ICEGATE Open API JSON (CACHI01/CACHE01) signature — the digSign-OBJECT
        form the CACHE01/CACHI01 schema defines, as another CHA tool produces it
        (Capricorn DSC) on real, accepted filings.

        The signed value covers the JSON BODY bytes exactly (the compact
        ``{"headerField":...,"master":...}`` our serializer emits, trailing CR/LF
        stripped) with the SAME double hash as the flat file. digSign is then
        inserted as a proper third top-level key by replacing the body's final
        ``}`` with ``,"digSign":{...}}`` — yielding valid JSON
        ``{headerField, master, digSign}``. A verifier reconstructs the signed
        body as everything up to the ``,"digSign"`` marker plus ``}``.
        Also used by the one-click bridge (bridge.py), which signs in memory."""
        import base64
        body = content.rstrip(b"\r\n")
        if not body.endswith(b"}"):
            raise ValueError("JSON payload does not end with '}' — cannot append digSign.")
        signature = self._double_hash_sign(body)
        cert_der = self._certificate_der()
        digsign = (
            b'{"startSignature":"' + base64.b64encode(signature) + b'",'
            b'"startCertificate":"' + base64.b64encode(cert_der) + b'",'
            b'"signerVersion":"' + JSON_SIGNER_VERSION + b'"}'
        )
        # Replace the body's closing brace with the digSign key + a fresh close.
        return body[:-1] + b',"digSign":' + digsign + b"}"

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass


def pin_error_kind(exc: BaseException) -> Optional[str]:
    """'wrong' for an incorrect PIN, 'locked' for a locked token, else None.
    A saved PIN that comes back 'wrong' must be forgotten at once and never
    retried — tokens lock after a handful of bad attempts."""
    names = {type(e).__name__ for e in (exc, exc.__cause__, exc.__context__) if e is not None}
    text = " ".join(str(e) for e in (exc, exc.__cause__) if e is not None).upper()
    if names & {"PinLocked"} or "PIN_LOCKED" in text:
        return "locked"
    if names & {"PinIncorrect", "PinInvalid", "PinLenRange"} or "PIN_INCORRECT" in text:
        return "wrong"
    return None


def output_path_for(in_path: str, out_dir: str) -> str:
    base = os.path.basename(in_path)
    if base.lower().endswith(".pdf"):
        return os.path.join(out_dir, base[:-4] + ".signed.pdf")
    stem, ext = os.path.splitext(base)           # e.g. 162026.be -> 162026Signed.be
    return os.path.join(out_dir, stem + "Signed" + ext)


BATCH_FOLDER_PREFIX = "Broto Signed"


def make_batch_folder(dest: str, now: Optional[datetime] = None) -> str:
    """Create a NEW folder inside ``dest`` for one signing run and return it —
    "Broto Signed 30-09-2026 14.05", or "… (2)" if that name is taken — so
    every run's signed files sit together and never overwrite an earlier run."""
    now = now or datetime.now()
    base = "%s %s" % (BATCH_FOLDER_PREFIX, now.strftime("%d-%m-%Y %H.%M"))
    os.makedirs(dest, exist_ok=True)
    n = 1
    while True:
        path = os.path.join(dest, base if n == 1 else "%s (%d)" % (base, n))
        try:
            os.mkdir(path)
            return path
        except FileExistsError:
            n += 1


def sign_one(signer: DscSigner, in_path: str, out_dir: str) -> str:
    """Sign a single file into out_dir; returns the output path."""
    os.makedirs(out_dir, exist_ok=True)
    out_path = output_path_for(in_path, out_dir)
    if in_path.lower().endswith(".pdf"):
        signer.sign_pdf(in_path, out_path)
    elif in_path.lower().endswith(".json"):
        # ICEGATE Open API JSON filing → the digSign-object envelope (schema form).
        signer.sign_icegate_json(in_path, out_path)
    else:
        signer.sign_flatfile(in_path, out_path)
    return out_path
