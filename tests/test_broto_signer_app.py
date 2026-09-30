"""Broto Signer screen state (broto_signer/app.py SignerApp._refresh).

Pins what the operator can click. The Sign button counts the files in the list,
never the remote signatures this PC has done for Broto, so a PC paired for
remote signing can still sign locally. No window is opened: the widgets are
stand-ins that remember their last options, and customtkinter / tkinter get
empty stand-ins while app.py imports where they are not installed (CI, macOS).
"""
import importlib.util
import os
import sys
import types
from datetime import datetime, timezone

import pytest

SIGNER_DIR = os.path.join(os.path.dirname(__file__), "..", "broto_signer")
sys.path.insert(0, SIGNER_DIR)


def _stand_in_class(name):
    if name.startswith("_"):
        raise AttributeError(name)
    return type(name, (), {"__init__": lambda self, *args, **kwargs: None})


def _load_signer_app():
    """Import broto_signer/app.py under its own name. The stand-ins are in
    sys.modules only while it imports: left there, they break code elsewhere in
    the test run that walks sys.modules (Playwright's PDF rendering hangs)."""
    stand_ins = {}
    try:
        import customtkinter  # noqa: F401
    except ImportError:
        ctk = types.ModuleType("customtkinter")
        ctk.__getattr__ = _stand_in_class
        stand_ins["customtkinter"] = ctk
    try:
        from tkinter import filedialog  # noqa: F401
    except ImportError:
        tk = types.ModuleType("tkinter")
        tk.filedialog = types.ModuleType("tkinter.filedialog")
        stand_ins.update({"tkinter": tk, "tkinter.filedialog": tk.filedialog})
    spec = importlib.util.spec_from_file_location("broto_signer_app", os.path.join(SIGNER_DIR, "app.py"))
    module = importlib.util.module_from_spec(spec)
    sys.modules.update(stand_ins)
    sys.modules["broto_signer_app"] = module
    try:
        spec.loader.exec_module(module)
    finally:
        for name in stand_ins:
            sys.modules.pop(name, None)
    return module


signer_app = _load_signer_app()

from signer_core import CertInfo  # noqa: E402

CERT = CertInfo(label="", subject="CN=TEST HOLDER", cert_id=b"\x01\x02", common_name="TEST HOLDER",
                issuer="Test Sub CA for Individual DSC", serial="0A1B2C3D", thumbprint="ab" * 32,
                not_after=datetime(2030, 1, 1, tzinfo=timezone.utc))


class _Widget:
    """A CTk widget stand-in that remembers the last value of each option."""

    def __init__(self, **options):
        self.options = dict(options)

    def configure(self, **options):
        self.options.update(options)

    def cget(self, key):
        return self.options.get(key, "")

    def grid(self, *args, **kwargs):
        pass

    def grid_forget(self):
        pass


class _Value:
    def __init__(self, value):
        self.value = value

    def get(self):
        return self.value


class _Remote:
    def __init__(self, **status):
        self._status = {"paired": False, "online": False, "last_error": None, "jobs_signed": 0}
        self._status.update(status)

    def status(self):
        return dict(self._status)


def _screen(files=1, pin="123456", busy=False, status_text="", **remote):
    """Run _refresh on a SignerApp built without a window and return it."""
    app = object.__new__(signer_app.SignerApp)
    app.rows = [types.SimpleNamespace(remove_btn=_Widget()) for _ in range(files)]
    app.certs = [CERT]
    app._cert_labels = [CERT.display]
    app.cert_choice = _Value(CERT.display)
    app._pins = {}
    app.pin_entry = _Value(pin)
    app._busy = busy
    app.remote = _Remote(**remote)
    app.module_var = _Value("SignatureP11.dll")
    app.settings = {}
    for name in ("count_lbl", "empty", "pill", "bridge_pill", "remote_pill", "sign_btn", "add_files_btn",
                 "add_folder_btn", "clear_btn", "connect_btn", "browse_out_btn"):
        setattr(app, name, _Widget())
    app.status_lbl = _Widget(text=status_text)
    app._refresh()
    return app


def test_a_pc_paired_for_remote_signing_can_still_sign_locally():
    """Paired and online with no remote signatures yet: the remote-signature
    count (0) replaced the file count, so Sign stayed greyed out and the screen
    said "Add the files you want to sign" with a file in the list."""
    screen = _screen(files=1, paired=True, online=True, jobs_signed=0,
                     status_text="Add the files you want to sign")
    assert screen.sign_btn.cget("state") == "normal"
    assert screen.sign_btn.cget("text") == "Sign 1 file"
    assert screen.status_lbl.cget("text") == ""


@pytest.mark.parametrize("remote", [
    {},
    {"paired": True, "online": True, "jobs_signed": 0},
    {"paired": True, "online": True, "jobs_signed": 3},
    {"paired": True, "last_error": "Could not reach Broto"},
    {"paired": True},
], ids=["not-paired", "online-none-signed", "online-3-signed", "cannot-reach-broto", "connecting"])
def test_the_sign_button_counts_files_in_every_remote_state(remote):
    screen = _screen(files=2, **remote)
    assert screen.sign_btn.cget("state") == "normal"
    assert screen.sign_btn.cget("text") == "Sign 2 files"
    assert screen.count_lbl.cget("text") == "2 files"


def test_no_files_keeps_sign_off_even_after_remote_signatures():
    screen = _screen(files=0, paired=True, online=True, jobs_signed=2)
    assert screen.sign_btn.cget("state") == "disabled"
    assert screen.sign_btn.cget("text") == "Sign"
    assert screen.status_lbl.cget("text") == "Add the files you want to sign"


def test_the_remote_pill_still_shows_the_remote_signature_count():
    screen = _screen(files=1, paired=True, online=True, jobs_signed=3)
    assert "Remote signing on" in screen.remote_pill.cget("text")
    assert "3 signed" in screen.remote_pill.cget("text")


def test_sign_needs_the_pin():
    screen = _screen(files=1, pin="", paired=True, online=True)
    assert screen.sign_btn.cget("state") == "disabled"
    assert screen.sign_btn.cget("text") == "Sign 1 file"


def test_sign_is_off_while_signing():
    screen = _screen(files=1, busy=True, paired=True, online=True)
    assert screen.sign_btn.cget("state") == "disabled"
    assert screen.sign_btn.cget("text") == "Signing…"


# ------------------------------------------------------------ remote jobs: the certificate Broto names
TP_ONE, TP_TWO = "11" * 32, "22" * 32
ONE = CertInfo(label="", subject="CN=HOLDER ONE", cert_id=b"\x01", common_name="HOLDER ONE", thumbprint=TP_ONE,
               slot_index=0, module="p11.dll", token="sn:A")
TWO = CertInfo(label="", subject="CN=HOLDER TWO", cert_id=b"\x01", common_name="HOLDER TWO", thumbprint=TP_TWO,
               slot_index=1, module="p11.dll", token="sn:B")


class _FakeSigner:
    opened = []

    def __init__(self, module, pin, cert_id=b"", cert_label="", slot_index=0):
        if pin == "bad":
            raise RuntimeError("CKR_PIN_INCORRECT")
        _FakeSigner.opened.append((module, pin, slot_index))

    def sign_flatfile_bytes(self, content):
        return content + b"<signed>"

    def close(self):
        pass


def _remote_app(monkeypatch, pins, picked=ONE):
    """A SignerApp with two certificates (two tokens) and the given saved PINs, as the
    heartbeat thread sees it — no window, fake token driver."""
    import queue
    import threading
    monkeypatch.setattr(signer_app, "list_certificates", lambda module, pin=None, pins=None: [ONE, TWO])
    monkeypatch.setattr(signer_app, "DscSigner", _FakeSigner)
    monkeypatch.setattr(signer_app.os.path, "exists", lambda p: p == "p11.dll")
    _FakeSigner.opened = []
    app = object.__new__(signer_app.SignerApp)
    app.q = queue.Queue()
    app._token_lock = threading.Lock()
    app._remote_ctx = {
        "module": "p11.dll", "cert_module": picked.module, "cert_id": picked.cert_id.hex(),
        "cert_thumbprint": picked.thumbprint, "picked_token": picked.token,
        "certs": [{"thumbprint": c.thumbprint, "module": c.module, "token": c.token} for c in (ONE, TWO)],
        "pins": dict(pins),
    }
    return app


def _flatfile_summary(cert_thumbprint="", cert_holder=""):
    return {"format": "flatfile", "cert_thumbprint": cert_thumbprint, "cert_holder": cert_holder}


def test_a_remote_job_signs_with_the_certificate_broto_names_and_that_tokens_pin(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111", "sn:B": "2222"}, picked=ONE)
    out = app._sign_for_remote(b"HREC", _flatfile_summary(TP_TWO, "HOLDER TWO"))
    assert out == b"HREC<signed>"
    assert _FakeSigner.opened == [("p11.dll", "2222", 1)]          # token B, with B's own PIN


def test_no_saved_pin_for_that_token_refuses_without_trying_another_tokens_pin(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111"}, picked=ONE)
    with pytest.raises(signer_app.SignError) as ei:
        app._sign_for_remote(b"HREC", _flatfile_summary(TP_TWO, "HOLDER TWO"))
    assert ei.value.code == "pin_not_saved" and "HOLDER TWO's certificate" in ei.value.message
    assert _FakeSigner.opened == []                                 # token B was never logged in to


def test_a_certificate_not_on_this_pc_is_refused(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111", "sn:B": "2222"})
    with pytest.raises(signer_app.SignError) as ei:
        app._sign_for_remote(b"HREC", _flatfile_summary("33" * 32, "HOLDER THREE"))
    assert ei.value.code == "cert_missing" and ei.value.message.startswith("HOLDER THREE's certificate isn't on")


def test_without_a_named_certificate_the_picked_one_signs_as_before(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111", "sn:B": "2222"}, picked=TWO)
    app._sign_for_remote(b"HREC", _flatfile_summary())
    assert _FakeSigner.opened == [("p11.dll", "2222", 1)]


def test_a_pin_saved_before_the_update_still_signs_with_the_picked_certificate(monkeypatch):
    app = _remote_app(monkeypatch, {"": "1111"}, picked=ONE)
    app._sign_for_remote(b"HREC", _flatfile_summary())
    assert _FakeSigner.opened == [("p11.dll", "1111", 0)]


def test_a_rejected_pin_is_forgotten_for_that_token_only(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111", "sn:B": "bad"})
    with pytest.raises(signer_app.SignError) as ei:
        app._sign_for_remote(b"HREC", _flatfile_summary(TP_TWO, "HOLDER TWO"))
    assert ei.value.code == "wrong_pin"
    assert app.q.get_nowait() == ("remote", "pin_rejected", "sn:B")


def test_broto_hears_which_certificates_have_their_tokens_pin_saved(monkeypatch):
    screen = _screen(files=0)
    screen.certs = [ONE, TWO]
    screen._cert_labels = ["HOLDER ONE", "HOLDER TWO"]
    screen.cert_choice = _Value("HOLDER ONE")
    screen._pins = {"sn:A": "1111"}
    screen._refresh()
    reported = {c["holder"]: c for c in screen._status_snapshot["certificates"]}
    assert reported["HOLDER ONE"]["pin_saved"] == "1" and reported["HOLDER TWO"]["pin_saved"] == "0"
    assert reported["HOLDER TWO"]["token"] and "sn:B" not in str(reported)
    assert screen._saved_pin == "1111"
    screen.cert_choice = _Value("HOLDER TWO")
    assert screen._saved_pin is None                                # B's token has no PIN saved
