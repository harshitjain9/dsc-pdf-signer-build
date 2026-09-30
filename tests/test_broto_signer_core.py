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

    def fake_list(module, pin=None):
        calls.append((module, pin))
        if module == "C.dll":
            raise RuntimeError("driver will not load")
        return {
            "A.dll": [_cert("RAMESH", "t1", "A.dll", can_sign=False), _cert("RAMESH", "t2", "A.dll")],
            "B.dll": [_cert("SURESH", "t3", "B.dll"), _cert("RAMESH", "t2", "B.dll")],   # t2 seen twice
        }[module]

    monkeypatch.setattr(core, "list_certificates", fake_list)
    monkeypatch.setattr(core, "discover_modules", lambda: ["A.dll", "B.dll", "C.dll"])
    out = core.list_all_certificates("A.dll", "1234")
    assert calls == [("A.dll", "1234"), ("B.dll", None), ("C.dll", None)]
    assert [c.thumbprint for c in out] == ["t2", "t3", "t1"]     # signing first, duplicates once
    assert out[1].module == "B.dll"


def test_list_all_certificates_surfaces_an_error_from_the_chosen_driver(monkeypatch):
    def boom(module, pin=None):
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
