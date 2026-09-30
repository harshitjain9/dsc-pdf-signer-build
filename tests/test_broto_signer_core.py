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
