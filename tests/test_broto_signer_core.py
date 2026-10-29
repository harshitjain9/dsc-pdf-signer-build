"""Broto Signer core helpers (broto_signer/signer_core.py) that need no token:
the default driver path, listing certificates across several token drivers,
unique picker labels, and the new folder each signing run creates."""
import os
import sys
from datetime import datetime

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "broto_signer"))

import signer_core as core  # noqa: E402
from signer_core import CertInfo  # noqa: E402


# ------------------------------------------------------------ default driver
def test_signaturep11_is_the_default_windows_driver(monkeypatch):
    assert core.DEFAULT_WINDOWS_MODULE == r"C:\Windows\System32\SignatureP11.dll"
    assert core._WINDOWS_MODULES[0] == core.DEFAULT_WINDOWS_MODULE
    monkeypatch.setattr(core.platform, "system", lambda: "Windows")
    monkeypatch.setattr(core.os.path, "exists", lambda p: False)
    assert core.default_module() == core.DEFAULT_WINDOWS_MODULE   # nothing found → still offered


def test_default_module_prefers_a_driver_that_is_installed(monkeypatch):
    monkeypatch.setattr(core.platform, "system", lambda: "Windows")
    epass = r"C:\Windows\System32\eps2003csp11v2.dll"
    monkeypatch.setattr(core.os.path, "exists", lambda p: p == epass)
    assert core.default_module() == epass


def test_proxkey_driver_in_its_watchdata_folder_is_found_after_the_default(monkeypatch):
    """A PC with the WD ProxKey software but no SignatureP11.dll (2026-10-24): Watchdata's own
    driver in its version folder is found, newest version first, ahead of other makes."""
    monkeypatch.setattr(core.platform, "system", lambda: "Windows")
    v2 = r"C:\Windows\System32\Watchdata\PROXKey CSP India V2.0\wdpkcs.dll"
    v3 = r"C:\Windows\System32\Watchdata\PROXKey CSP India V3.0\wdpkcs.dll"
    epass = r"C:\Windows\System32\eps2003csp11v2.dll"
    monkeypatch.setattr(core.glob, "glob", lambda pattern: [v2, v3] if pattern == core._WATCHDATA_MODULES else [])
    monkeypatch.setattr(core.os.path, "exists", lambda p: p in (v2, v3, epass))
    assert core.discover_modules() == [v3, v2, epass]
    assert core.default_module() == v3
    monkeypatch.setattr(core.os.path, "exists", lambda p: p in (core.DEFAULT_WINDOWS_MODULE, v3, epass))
    assert core.discover_modules() == [core.DEFAULT_WINDOWS_MODULE, v3, epass]   # SignatureP11 stays first


def test_mtoken_cryptoid_driver_is_found_on_its_own_and_next_to_proxkey(monkeypatch):
    """A PC with an mToken plugged in (2026-10-26): the Signer knew only ProxKey's driver and
    showed "No certificates found". The mToken's own driver in System32 is now found — on its
    own it is the default, and next to SignatureP11.dll it is read too on every Connect."""
    monkeypatch.setattr(core.platform, "system", lambda: "Windows")
    mtoken = r"C:\Windows\System32\CryptoIDA_pkcs11.dll"
    monkeypatch.setattr(core.glob, "glob", lambda pattern: [])
    monkeypatch.setattr(core.os.path, "exists", lambda p: p == mtoken)
    assert core.discover_modules() == [mtoken]
    assert core.default_module() == mtoken
    monkeypatch.setattr(core.os.path, "exists", lambda p: p in (core.DEFAULT_WINDOWS_MODULE, mtoken))
    assert core.discover_modules() == [core.DEFAULT_WINDOWS_MODULE, mtoken]   # SignatureP11 stays first


def test_hyp2003_and_innait_drivers_are_found_on_their_own_and_next_to_proxkey(monkeypatch):
    """The other two tokens CCA allows for new DSCs since 21/09/2026: a PC with only the HyperPKI
    HYP2003 or the Precision InnaIT driver showed "No certificates found". Each driver in System32
    is now found — on its own it is the default, and next to SignatureP11.dll it is read too."""
    monkeypatch.setattr(core.platform, "system", lambda: "Windows")
    hyp2003 = r"C:\Windows\System32\HyperPKICsp11_2003.dll"
    innait = r"C:\Windows\System32\InnaITPKCS11Driver.dll"
    monkeypatch.setattr(core.glob, "glob", lambda pattern: [])
    for driver in (hyp2003, innait):
        monkeypatch.setattr(core.os.path, "exists", lambda p, d=driver: p == d)
        assert core.discover_modules() == [driver]
        assert core.default_module() == driver
    monkeypatch.setattr(core.os.path, "exists", lambda p: p in (core.DEFAULT_WINDOWS_MODULE, hyp2003, innait))
    assert core.discover_modules() == [core.DEFAULT_WINDOWS_MODULE, hyp2003, innait]   # SignatureP11 stays first
    assert not [p for p in core._WINDOWS_MODULES if "syswow64" in p.lower()]   # 32-bit copies never load


def test_a_driver_in_its_own_folder_loads_with_that_folder_on_path(monkeypatch):
    """python-pkcs11 loads a driver with a plain LoadLibraryW, which never looks in the driver's
    own folder for the DLLs it needs — so that folder goes on PATH first, once."""
    import types
    seen = []
    mod = types.ModuleType("pkcs11")
    mod.lib = lambda so: seen.append((so, os.environ["PATH"])) or "lib"
    monkeypatch.setitem(sys.modules, "pkcs11", mod)
    monkeypatch.setattr(core.platform, "system", lambda: "Windows")
    monkeypatch.setenv("PATH", "system32")
    folder = os.path.join("Watchdata", "PROXKey CSP India V3.0")
    driver = os.path.join(folder, "wdpkcs.dll")
    assert core._open_lib(driver) == "lib"
    assert core._open_lib(driver) == "lib"
    folder, driver = os.path.normcase(folder), os.path.normcase(driver)  # Windows loads it lower-cased (2.6.3)
    assert seen == [(driver, folder + os.pathsep + "system32")] * 2     # added once, not twice
    assert core._open_lib("SignatureP11.dll") == "lib"                   # no folder: PATH unchanged
    assert os.environ["PATH"] == folder + os.pathsep + "system32"


def test_one_driver_written_with_either_slash_is_loaded_once(monkeypatch):
    """A customer PC, 2026-10-26: the driver was loaded as C:\\Windows\\System32\\SignatureP11.dll at start,
    then Browse set C:/Windows/System32/SignatureP11.dll. python-pkcs11 keeps one driver per path
    text, so the DLL was started twice and every read after failed "already initialized"."""
    import ntpath
    import types
    seen = []
    mod = types.ModuleType("pkcs11")
    mod.lib = lambda so: seen.append(so) or "lib"
    monkeypatch.setitem(sys.modules, "pkcs11", mod)
    monkeypatch.setattr(core.platform, "system", lambda: "Windows")
    monkeypatch.setattr(core.os, "path", ntpath)
    monkeypatch.setenv("PATH", "")
    for spelling in (r"C:\Windows\System32\SignatureP11.dll", "C:/Windows/System32/SignatureP11.dll",
                     r"c:\windows\system32\SIGNATUREP11.DLL"):
        assert core._open_lib(spelling) == "lib"
    assert len(set(seen)) == 1


# ------------------------------------------------------------ several tokens
def _cert(name, thumb, module="", can_sign=True, serial="", not_after=None, slot=0):
    return CertInfo(label="", subject="CN=" + name, common_name=name, thumbprint=thumb, module=module,
                    can_sign=can_sign, serial=serial, not_after=not_after, slot_index=slot)


def test_list_all_certificates_reads_every_driver_but_sends_the_pin_only_to_the_chosen_one(monkeypatch):
    calls = []

    def fake_list(module, pin=None, pins=None):
        calls.append((module, pin, pins))
        if module == "C.dll":
            raise RuntimeError("driver will not load")
        return {
            "A.dll": [_cert("RAMESH", "t1", "A.dll", can_sign=False), _cert("RAMESH", "t2", "A.dll")],
            "B.dll": [_cert("SURESH", "t3", "B.dll"), _cert("RAMESH", "t2", "B.dll")],   # t2 seen twice
        }[module]

    monkeypatch.setattr(core, "list_certificates", fake_list)
    monkeypatch.setattr(core, "discover_modules", lambda: ["A.dll", "B.dll", "C.dll"])
    saved = {"sn:B1": "5555"}                                    # each token's own saved PIN may go anywhere
    out = core.list_all_certificates("A.dll", "1234", saved)
    assert calls == [("A.dll", "1234", saved), ("B.dll", None, saved), ("C.dll", None, saved)]
    assert [c.thumbprint for c in out] == ["t2", "t3", "t1"]     # signing first, duplicates once
    assert out[1].module == "B.dll"


def test_list_all_certificates_surfaces_an_error_from_the_chosen_driver(monkeypatch):
    def boom(module, pin=None, pins=None):
        raise RuntimeError("token not present")
    monkeypatch.setattr(core, "list_certificates", boom)
    monkeypatch.setattr(core, "discover_modules", lambda: [])
    try:
        core.list_all_certificates("A.dll", None)
    except RuntimeError as e:
        assert "token not present" in str(e)
    else:
        raise AssertionError("expected the chosen driver's error")


def test_picker_labels_are_unique_for_same_name_certificates():
    certs = [
        _cert("RAMESH KUMAR", "t1", not_after=datetime(2027, 3, 12)),
        _cert("RAMESH KUMAR", "t2", not_after=datetime(2025, 1, 5)),
        _cert("RAMESH KUMAR", "t3", can_sign=False, not_after=datetime(2027, 3, 12)),
        _cert("SURESH", "t4", serial="ABCDEF123456", not_after=datetime(2027, 1, 1)),
        _cert("SURESH", "t5", serial="ABCDEF654321", not_after=datetime(2027, 1, 1)),
        _cert("NO DATE", "t6"),
        _cert("NO DATE", "t7"),
    ]
    labels = core.cert_choice_labels(certs)
    assert len(set(labels)) == len(labels)
    assert labels[0] == "RAMESH KUMAR  ·  valid till 12 Mar 2027"
    assert labels[1] == "RAMESH KUMAR  ·  valid till 05 Jan 2025"
    assert labels[2] == "RAMESH KUMAR  (encryption only)"
    assert labels[3].endswith("no. …123456") and labels[4].endswith("no. …654321")
    assert labels[5] == "NO DATE  (1)" and labels[6] == "NO DATE  (2)"
    assert core.cert_choice_labels([_cert("ONLY ONE", "x")]) == ["ONLY ONE"]


# ------------------------------------------------------------ one folder per run
def test_each_signing_run_gets_a_new_folder(tmp_path):
    when = datetime(2026, 9, 30, 14, 5)
    first = core.make_batch_folder(str(tmp_path), when)
    second = core.make_batch_folder(str(tmp_path), when)
    assert os.path.basename(first) == "Broto Signed 30-09-2026 14.05"
    assert os.path.basename(second) == "Broto Signed 30-09-2026 14.05 (2)"
    assert os.path.isdir(first) and os.path.isdir(second)
    assert os.path.dirname(first) == str(tmp_path)


def test_batch_folder_creates_a_missing_destination(tmp_path):
    dest = tmp_path / "new" / "place"
    out = core.make_batch_folder(str(dest), datetime(2026, 1, 2, 3, 4))
    assert os.path.isdir(out) and os.path.dirname(out) == str(dest)


# ------------------------------------------------------------ reading the token
class _FakeObj:
    """A token object whose attributes read live through its session — like
    python-pkcs11, where every read fails once the session is closed."""

    def __init__(self, session, attrs):
        self.session, self.attrs = session, attrs

    def __getitem__(self, key):
        if self.session.closed:
            raise RuntimeError("CKR_SESSION_HANDLE_INVALID")
        return self.attrs[key]


class _FakeSession:
    def __init__(self, objects):
        self.objects, self.closed = objects, False

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.closed = True

    def get_objects(self, template):
        return iter([_FakeObj(self, a) for a in self.objects])


def _fake_pkcs11(monkeypatch, slots, serials=None, hidden=None):
    """Install a stand-in ``pkcs11`` module: ``slots`` = one list of cert DERs per plugged-in token.
    ``serials`` gives each token a serial number; ``hidden`` = {slot index: PIN} for a token that
    shows its certificates only after logging in with that PIN. Returns the PINs each token was
    opened with, per slot."""
    import types
    mod = types.ModuleType("pkcs11")
    mod.Attribute = types.SimpleNamespace(CLASS="class", LABEL="label", ID="id", VALUE="value")
    mod.ObjectClass = types.SimpleNamespace(CERTIFICATE="cert")
    opened = {i: [] for i in range(len(slots))}

    class _Token:
        def __init__(self, i, ders):
            self.i, self.ders = i, ders
            self.serial = ((serials or {}).get(i) or "").encode()
            self.label = "TOKEN %d" % i

        def open(self, user_pin=None):
            opened[self.i].append(user_pin)
            need = (hidden or {}).get(self.i)
            if need is not None and user_pin != need:
                if user_pin is not None:
                    raise RuntimeError("CKR_PIN_INCORRECT")
                return _FakeSession([])
            return _FakeSession([{"label": "", "id": b"\x01", "value": d} for d in self.ders])

    class _Slot:
        def __init__(self, i, ders):
            self.token = _Token(i, ders)

        def get_token(self):
            return self.token

    class _Lib:
        def __init__(self, path):
            pass

        def get_slots(self, token_present=True):
            return [_Slot(i, d) for i, d in enumerate(slots)]

    mod.lib = _Lib
    monkeypatch.setitem(sys.modules, "pkcs11", mod)
    return opened


def _der(cn, issuer, serial):
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, issuer)]))
            .public_key(key.public_key()).serial_number(serial)
            .not_valid_before(datetime(2025, 1, 1)).not_valid_after(datetime(2027, 11, 8))
            .sign(key, hashes.SHA256()))
    return cert.public_bytes(serialization.Encoding.DER)


def test_two_tokens_list_two_certificates_with_their_details(monkeypatch):
    """A PC with two DSC tokens (same key ID on both). v2.3.0 read the details
    after closing the session, so it listed ONE blank 'Certificate in slot 1'."""
    import pytest
    pytest.importorskip("asn1crypto")
    a = _der("HOLDER ONE", "Test Sub CA for Organisation DSC", 0x0A0B0C0D01)
    b = _der("HOLDER TWO", "Test Sub CA for Individual DSC", 0x0A0B0C0D02)
    _fake_pkcs11(monkeypatch, [[a], [b]])
    certs = core.list_certificates("SignatureP11.dll", None)
    assert [c.common_name for c in certs] == ["HOLDER ONE", "HOLDER TWO"]
    assert [c.issuer for c in certs] == ["Test Sub CA for Organisation DSC", "Test Sub CA for Individual DSC"]
    assert [c.serial for c in certs] == ["A0B0C0D01", "A0B0C0D02"]
    assert [c.slot_index for c in certs] == [0, 1]
    assert all(c.thumbprint and c.cert_id == b"\x01" for c in certs)   # Broto pins remote signing on the thumbprint


def test_same_certificate_in_two_slots_is_listed_once(monkeypatch):
    import pytest
    pytest.importorskip("asn1crypto")
    a = _der("RAMESH", "CA", 7)
    _fake_pkcs11(monkeypatch, [[a], [a]])
    assert len(core.list_certificates("x.dll", None)) == 1


def test_unreadable_certificates_are_never_merged(monkeypatch):
    _fake_pkcs11(monkeypatch, [[None, None]])       # the token refuses to hand over the certificate bytes
    certs = core.list_certificates("x.dll", None)
    assert len(certs) == 2 and not any(c.thumbprint for c in certs)


# ------------------------------------------------------------ PDFs pyHanko's strict mode refuses
def _pdf_with_freed_object_in_update() -> bytes:
    """A one-page PDF plus an incremental update that frees object 5 with a
    "next generation" of 0 — what Acrobat writes when it drops a dead object on
    save. pyHanko's strict reader refuses this in any revision after the first
    (the DGFT licence PDFs of 2026-09-30)."""
    objs = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
        b"<< /Length 0 >>\nstream\n\nendstream",
        b"<< /Unused true >>",
    ]
    out = bytearray(b"%PDF-1.7\n")
    offsets = []
    for i, body in enumerate(objs, start=1):
        offsets.append(len(out))
        out += b"%d 0 obj\n%s\nendobj\n" % (i, body)
    xref1 = len(out)
    out += b"xref\n0 %d\n0000000000 65535 f \n" % (len(objs) + 1)
    for off in offsets:
        out += b"%010d 00000 n \n" % off
    out += b"trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n" % (len(objs) + 1, xref1)
    xref2 = len(out)
    out += b"xref\n0 1\n0000000005 65535 f \n5 1\n0000000000 00000 f \n"
    out += b"trailer\n<< /Size %d /Root 1 0 R /Prev %d >>\nstartxref\n%d\n%%%%EOF\n" % (
        len(objs) + 1, xref1, xref2)
    return bytes(out)


def _test_signer():
    """A pyHanko SimpleSigner with a throwaway self-signed certificate."""
    import datetime as dt

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import pkcs12
    from cryptography.x509.oid import NameOID
    from pyhanko.sign import signers

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TEST HOLDER")])
    now = dt.datetime.now(dt.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=30)).sign(key, hashes.SHA256()))
    pfx = pkcs12.serialize_key_and_certificates(b"t", key, cert, None, serialization.NoEncryption())
    import tempfile
    with tempfile.NamedTemporaryFile(suffix=".pfx", delete=False) as fh:
        fh.write(pfx)
    try:
        return signers.SimpleSigner.load_pkcs12(fh.name)
    finally:
        os.unlink(fh.name)


def test_pdf_freed_in_a_later_revision_is_refused_by_strict_pyhanko():
    """Pins the root cause: strict mode is what threw the user's error."""
    import io

    import pytest
    pytest.importorskip("pyhanko")
    from pyhanko.pdf_utils.incremental_writer import IncrementalPdfFileWriter
    from pyhanko.pdf_utils.misc import PdfStrictReadError
    with pytest.raises(PdfStrictReadError, match="next generation 0"):
        IncrementalPdfFileWriter(io.BytesIO(_pdf_with_freed_object_in_update()))


def test_pdf_freed_in_a_later_revision_signs_and_keeps_its_original_bytes():
    import pytest
    pytest.importorskip("pyhanko")
    pytest.importorskip("cryptography")
    from pyhanko.sign import signers

    original = _pdf_with_freed_object_in_update()
    out = signers.sign_pdf(core.open_pdf_for_signing(original),
                           signers.PdfSignatureMetadata(field_name="BrotoSig"), signer=_test_signer())
    signed = bytes(out.getbuffer())
    assert signed.startswith(original)          # an incremental update — Broto checks this
    import io

    from pyhanko.pdf_utils.reader import PdfFileReader
    sigs = PdfFileReader(io.BytesIO(signed), strict=False).embedded_signatures
    assert [s.field_name for s in sigs] == ["BrotoSig"]


def test_sign_pdf_bytes_reads_pdfs_non_strict(monkeypatch):
    """DscSigner.sign_pdf_bytes goes through open_pdf_for_signing (no token needed)."""
    import pytest
    pytest.importorskip("pyhanko")
    pytest.importorskip("cryptography")
    signer = core.DscSigner.__new__(core.DscSigner)
    signer._signer = _test_signer()
    original = _pdf_with_freed_object_in_update()
    assert signer.sign_pdf_bytes(original).startswith(original)


# ------------------------------------------------------------ flat-file signature
def _token_key(monkeypatch, sha1_rsa: bool, rsa_pkcs: bool = True, rsa_x509: bool = False,
               refusal: str = "MechanismInvalid"):
    """A stand-in for the token's private key (real RSA maths) plus a stub pkcs11
    module. ``sha1_rsa`` / ``rsa_pkcs`` / ``rsa_x509`` say which mechanisms the token
    offers; ``refusal`` is the error it answers for the others."""
    import types

    import pytest
    pytest.importorskip("cryptography")
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    mod = types.ModuleType("pkcs11")
    mod.Mechanism = types.SimpleNamespace(SHA1_RSA_PKCS="SHA1_RSA_PKCS", RSA_PKCS="RSA_PKCS",
                                          RSA_X_509="RSA_X_509")
    for name in ("MechanismInvalid", "DataInvalid"):
        setattr(mod, name, type(name, (Exception,), {}))
    monkeypatch.setitem(sys.modules, "pkcs11", mod)
    priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    n, d, k = priv.public_key().public_numbers().n, priv.private_numbers().d, 256

    class Key:
        def __init__(self):
            self.used = []

        def sign(self, data, mechanism):
            self.used.append(mechanism)
            if mechanism == "SHA1_RSA_PKCS" and sha1_rsa:
                return priv.sign(data, padding.PKCS1v15(), hashes.SHA1())
            if mechanism == "RSA_PKCS" and rsa_pkcs:     # pad as PKCS#1 v1.5 type 1, raw RSA
                em = b"\x00\x01" + b"\xff" * (k - 3 - len(data)) + b"\x00" + data
                return pow(int.from_bytes(em, "big"), d, n).to_bytes(k, "big")
            if mechanism == "RSA_X_509" and rsa_x509:    # raw RSA on bytes padded by the caller
                assert len(data) == k
                return pow(int.from_bytes(data, "big"), d, n).to_bytes(k, "big")
            raise getattr(mod, refusal)()

    key = Key()
    key.key_length = 2048
    signer = core.DscSigner.__new__(core.DscSigner)
    signer._private_key = lambda: key
    signer._certificate_der = lambda: b"CERT"
    return signer, key, priv


def _signature_of(signed: bytes) -> bytes:
    import base64
    return base64.b64decode(signed.split(b"<START-SIGNATURE>")[1].split(b"</START-SIGNATURE>")[0])


def test_a_token_without_sha1_rsa_signs_flat_files_with_plain_rsa_and_the_same_bytes(monkeypatch):
    """A customer PC, 2026-10-26: an mToken CryptoID (FIPS 140-3) signed PDFs but every .be
    failed with "MechanismInvalid()" — its driver has no CKM_SHA1_RSA_PKCS. The Signer does
    the SHA-1 itself and signs with plain CKM_RSA_PKCS: byte-for-byte the signature
    CKM_SHA1_RSA_PKCS gives, and the token is asked for SHA-1 only once per session."""
    import hashlib

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    signer, key, priv = _token_key(monkeypatch, sha1_rsa=False)
    content = b"HREC\x1dZZ\x1dTESTCHA01\r\n"
    inner = hashlib.sha256(content.rstrip(b"\r\n")).digest()
    assert _signature_of(signer.sign_flatfile_bytes(content)) == priv.sign(inner, padding.PKCS1v15(), hashes.SHA1())
    signer.sign_flatfile_bytes(content)
    assert key.used == ["SHA1_RSA_PKCS", "RSA_PKCS", "RSA_PKCS"]


def test_a_token_with_sha1_rsa_still_signs_the_old_way(monkeypatch):
    signer, key, _ = _token_key(monkeypatch, sha1_rsa=True)
    signer.sign_flatfile_bytes(b"HREC\r\n")
    assert key.used == ["SHA1_RSA_PKCS"]


def test_a_token_answering_data_invalid_signs_flat_files_with_plain_rsa_and_the_same_bytes(monkeypatch):
    """A customer PC, 2026-10-29: an (n)Code DSC signed PDFs but every .sb failed with "DataInvalid()"
    — its driver refused CKM_SHA1_RSA_PKCS with that error, not MechanismInvalid, so the
    plain-RSA way was never tried. A day earlier the same token signed .sb files."""
    import hashlib

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    signer, key, priv = _token_key(monkeypatch, sha1_rsa=False, refusal="DataInvalid")
    content = b"HREC\x1dZZ\x1dTESTCHA01\r\n"
    inner = hashlib.sha256(content.rstrip(b"\r\n")).digest()
    assert _signature_of(signer.sign_flatfile_bytes(content)) == priv.sign(inner, padding.PKCS1v15(), hashes.SHA1())
    assert key.used == ["SHA1_RSA_PKCS", "RSA_PKCS"]


def test_a_token_with_only_raw_rsa_signs_flat_files_with_the_same_bytes(monkeypatch):
    import hashlib

    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric import padding
    signer, key, priv = _token_key(monkeypatch, sha1_rsa=False, rsa_pkcs=False, rsa_x509=True,
                                   refusal="DataInvalid")
    content = b"HREC\x1dZZ\x1dTESTCHA01\r\n"
    inner = hashlib.sha256(content.rstrip(b"\r\n")).digest()
    assert _signature_of(signer.sign_flatfile_bytes(content)) == priv.sign(inner, padding.PKCS1v15(), hashes.SHA1())
    signer.sign_flatfile_bytes(content)
    assert key.used == ["SHA1_RSA_PKCS", "RSA_PKCS", "RSA_X_509", "RSA_X_509"]


def test_a_token_with_neither_method_says_so_in_plain_words(monkeypatch):
    import pytest
    signer, _, _ = _token_key(monkeypatch, sha1_rsa=False, rsa_pkcs=False)
    with pytest.raises(RuntimeError, match="cannot sign .be, .sb or JSON files"):
        signer.sign_flatfile_bytes(b"HREC\r\n")


# ------------------------------------------------------------ one PIN per token
def test_each_certificate_knows_its_token_and_broto_gets_only_a_hash(monkeypatch):
    import pytest
    pytest.importorskip("asn1crypto")
    a = _der("HOLDER ONE", "Test CA", 11)
    b = _der("HOLDER TWO", "Test CA", 12)
    _fake_pkcs11(monkeypatch, [[a], [b]], serials={0: "SERIAL-A", 1: "SERIAL-B"})
    certs = core.list_certificates("SignatureP11.dll", None)
    assert [c.token for c in certs] == ["sn:SERIAL-A", "sn:SERIAL-B"]
    report = certs[0].report()
    assert report["token"] == core.token_ref("sn:SERIAL-A") and len(report["token"]) == 12
    assert "SERIAL-A" not in str(report) and report["can_sign"] == "1"


def test_a_token_without_a_serial_is_named_by_its_slot():
    import types
    assert core.token_key(types.SimpleNamespace(serial=b"   ", label="ePass2003"), 1) == "slot1:ePass2003"
    assert core.token_key(types.SimpleNamespace(serial=b"0A1B2C\x00\x00", label=""), 0) == "sn:0A1B2C"


def test_a_token_that_hides_its_certificates_gets_only_its_own_saved_pin(monkeypatch):
    """Two tokens, the first shows its certificate only after login. A PIN saved
    for the second token is never tried on the first — a wrong try counts
    towards locking it."""
    import pytest
    pytest.importorskip("asn1crypto")
    a = _der("HOLDER ONE", "Test CA", 11)
    b = _der("HOLDER TWO", "Test CA", 12)
    opened = _fake_pkcs11(monkeypatch, [[a], [b]], serials={0: "A", 1: "B"}, hidden={0: "1111"})

    certs = core.list_certificates("x.dll", None, pins={"sn:B": "2222"})
    assert [c.common_name for c in certs] == ["HOLDER TWO"]
    assert opened == {0: [None], 1: [None]}                 # nobody logged in to token A

    opened[0].clear(), opened[1].clear()
    certs = core.list_certificates("x.dll", None, pins={"sn:A": "1111", "sn:B": "2222"})
    assert [c.common_name for c in certs] == ["HOLDER ONE", "HOLDER TWO"]
    assert opened == {0: [None, "1111"], 1: [None]}         # A with its own PIN; B needed none


def test_a_typed_pin_still_opens_a_hiding_token_that_has_no_saved_pin(monkeypatch):
    import pytest
    pytest.importorskip("asn1crypto")
    a = _der("HOLDER ONE", "Test CA", 11)
    opened = _fake_pkcs11(monkeypatch, [[a]], serials={0: "A"}, hidden={0: "1111"})
    certs = core.list_certificates("x.dll", "1111")
    assert [c.common_name for c in certs] == ["HOLDER ONE"] and opened == {0: [None, "1111"]}


def test_present_token_keys_are_the_keys_the_certificates_carry(monkeypatch):
    """The heartbeat probe (2.6.1) names plugged-in tokens exactly as the certificate
    listing does — a serial when the token has one, else its slot + label — so
    "is the token of this certificate in?" is a plain set lookup. No session, no PIN."""
    a = _der("A", "CA", 1)
    opened = _fake_pkcs11(monkeypatch, [[a], [a]], serials={0: "SERIAL-A"})
    keys = core.present_token_keys("x.dll")
    assert keys == {"sn:SERIAL-A", "slot1:TOKEN 1"}
    assert opened == {0: [], 1: []}                       # the probe opens no token session
    assert {c.token for c in core.list_certificates("x.dll")} <= keys

    _fake_pkcs11(monkeypatch, [])
    assert core.present_token_keys("x.dll") == set()
