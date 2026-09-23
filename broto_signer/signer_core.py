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
from typing import List, Optional

# The <SIGNER-VERSION> value stamped into signed flat files. ICEGATE appears to
# treat this as an audit/log tag (it is NOT part of the signed hash) — confirm on
# a real upload; change here if ICEGATE ever requires a specific value.
SIGNER_VERSION = b"V-BROTO_09.2026"

# The digSign.signerVersion for ICEGATE JSON (CACHI01/CACHE01) payloads. Real
# CHA tools vary the string (Royal Impex "V-ROYAL_09.01.2018", Live Impex "1.0")
# and both are accepted, so ICEGATE does not appear to validate it — we mirror
# Live Impex's "1.0", the value that ships in the schema-form digSign object.
JSON_SIGNER_VERSION = b"1.0"


# Common PKCS#11 module paths for the DSC tokens Indian CHAs use.
_WINDOWS_MODULES = [
    r"C:\Windows\System32\eps2003csp11v2.dll",       # ePass2003 (Watchdata) — most common
    r"C:\Windows\System32\eps2003csp11.dll",
    r"C:\Windows\System32\wdpkcs.dll",               # Watchdata ProxKey
    r"C:\Windows\System32\SignatureP11.dll",         # ProxKey / mToken (some builds)
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


def discover_module() -> Optional[str]:
    """Return the first known PKCS#11 module present on this machine, or None."""
    sysname = platform.system()
    candidates = {"Windows": _WINDOWS_MODULES, "Darwin": _MAC_MODULES}.get(sysname, _LINUX_MODULES)
    for path in candidates:
        if os.path.exists(path):
            return path
    return None


@dataclass
class CertInfo:
    label: str            # real CKA_LABEL (may be "")
    subject: str
    cert_id: bytes = b""  # CKA_ID — the reliable selector when the label is empty
    slot_index: int = 0   # which token slot it lives in (multi-slot readers)

    @property
    def display(self) -> str:
        if self.label and self.subject:
            return "%s — %s" % (self.label, self.subject)
        return self.label or self.subject or "(unlabeled certificate)"


def list_certificates(module: str, pin: Optional[str] = None) -> List[CertInfo]:
    """Enumerate signing certificates across the token's slots. Tries a public
    (no-login) session first; retries with the PIN if the token hides certs
    until authenticated."""
    import pkcs11
    from pkcs11 import Attribute, ObjectClass
    from asn1crypto import x509

    lib = pkcs11.lib(module)
    out: List[CertInfo] = []
    seen = set()
    for slot_index, slot in enumerate(lib.get_slots(token_present=True)):
        tok = slot.get_token()
        certs = []
        for use_pin in (None, pin):
            try:
                with tok.open(user_pin=use_pin) as session:
                    certs = list(session.get_objects({Attribute.CLASS: ObjectClass.CERTIFICATE}))
                if certs:
                    break
            except Exception:
                pass
            if pin is None:
                break
        for cert in certs:
            try:
                label = cert[Attribute.LABEL]
            except Exception:
                label = ""
            cert_id = b""
            try:
                cert_id = bytes(cert[Attribute.ID])
            except Exception:
                pass
            subject = ""
            try:
                subject = x509.Certificate.load(cert[Attribute.VALUE]).subject.human_friendly
            except Exception:
                pass
            key = (label, subject, cert_id)
            if key in seen:
                continue
            seen.add(key)
            out.append(CertInfo(label=label or "", subject=subject, cert_id=cert_id, slot_index=slot_index))
    return out


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
        from pyhanko.sign import signers
        from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
        with open(in_path, "rb") as inf:
            writer = IncrementalPdfFileWriter(inf)
            out = signers.sign_pdf(
                writer, signers.PdfSignatureMetadata(field_name="BrotoSig"), signer=self._signer)
        with open(out_path, "wb") as outf:
            outf.write(out.getbuffer())

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
        DigestInfo). Confirmed on real Royal Impex (Pantasign) and Live Impex
        (Capricorn) signed BE/SB flat files AND JSON payloads — same math for both."""
        import hashlib
        from pkcs11 import Mechanism
        inner = hashlib.sha256(core).digest()
        return self._private_key().sign(inner, mechanism=Mechanism.SHA1_RSA_PKCS)

    def sign_flatfile(self, in_path: str, out_path: str) -> None:
        """ICEGATE 'Text file' signature: original content + appended
        <START-SIGNATURE>/<START-CERTIFICATE>/<SIGNER-VERSION> tag lines. The signed
        value is SHA-1(SHA-256(content with trailing CR/LF stripped))."""
        import base64
        with open(in_path, "rb") as inf:
            content = inf.read()
        core = content.rstrip(b"\r\n")
        signature = self._double_hash_sign(core)
        cert_der = self._certificate_der()
        out = core + b"\n"
        out += b"<START-SIGNATURE>" + base64.b64encode(signature) + b"</START-SIGNATURE>\n"
        out += b"<START-CERTIFICATE>" + base64.b64encode(cert_der) + b"</START-CERTIFICATE>\n"
        out += b"<SIGNER-VERSION>" + SIGNER_VERSION + b"</SIGNER-VERSION>"
        with open(out_path, "wb") as outf:
            outf.write(out)

    def sign_icegate_json(self, in_path: str, out_path: str) -> None:
        """ICEGATE Open API JSON (CACHI01/CACHE01) signature — the digSign-OBJECT
        form the CACHE01/CACHI01 schema defines, as produced by Live Impex
        (Capricorn DSC) on real Aman Seatrans filings.

        The signed value covers the JSON BODY bytes exactly (the compact
        ``{"headerField":...,"master":...}`` our serializer emits, trailing CR/LF
        stripped) with the SAME double hash as the flat file. digSign is then
        inserted as a proper third top-level key by replacing the body's final
        ``}`` with ``,"digSign":{...}}`` — yielding valid JSON
        ``{headerField, master, digSign}``. A verifier reconstructs the signed
        body as everything up to the ``,"digSign"`` marker plus ``}``."""
        import base64
        with open(in_path, "rb") as inf:
            content = inf.read()
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
        out = body[:-1] + b',"digSign":' + digsign + b"}"
        with open(out_path, "wb") as outf:
            outf.write(out)

    def close(self) -> None:
        try:
            self._session.close()
        except Exception:
            pass


def output_path_for(in_path: str, out_dir: str) -> str:
    base = os.path.basename(in_path)
    if base.lower().endswith(".pdf"):
        return os.path.join(out_dir, base[:-4] + ".signed.pdf")
    stem, ext = os.path.splitext(base)           # e.g. 162026.be -> 162026Signed.be
    return os.path.join(out_dir, stem + "Signed" + ext)


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
