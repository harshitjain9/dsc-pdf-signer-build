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
        tk.messagebox = types.ModuleType("tkinter.messagebox")
        stand_ins.update({"tkinter": tk, "tkinter.filedialog": tk.filedialog, "tkinter.messagebox": tk.messagebox})
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
    app.remotes = [_Remote(**remote)]
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


# ------------------------------------------------------------ Relaunch to update
class _Updater:
    def __init__(self):
        self.relaunched = False
        self.stopped = False

    def relaunch(self):
        self.relaunched = True

    def stop(self):
        self.stopped = True


def _update_screen(busy=False, locked=False):
    import threading

    app = object.__new__(signer_app.SignerApp)
    app._busy = busy
    app._approval = None
    app._token_lock = threading.Lock()
    if locked:
        app._token_lock.acquire()
    app._quitting = False
    app.updater = _Updater()
    app.remotes = [types.SimpleNamespace(stop=lambda: None)]
    app.bridge = types.SimpleNamespace(stop=lambda: None)
    app.status_lbl = _Widget()
    app.root = types.SimpleNamespace(destroyed=False)
    app.root.destroy = lambda: setattr(app.root, "destroyed", True)
    app._flash = lambda msg, color: app.status_lbl.configure(text=msg)
    return app


@pytest.mark.parametrize("busy, locked", [(True, False), (False, True)], ids=["batch-signing", "remote-signing"])
def test_relaunch_waits_while_signing(busy, locked):
    app = _update_screen(busy=busy, locked=locked)
    app._relaunch_to_update()
    assert not app.updater.relaunched and not app.root.destroyed
    assert "Wait for signing to finish" in app.status_lbl.cget("text")


def test_relaunch_stops_everything_then_swaps_and_quits():
    app = _update_screen()
    app._relaunch_to_update()
    assert app.updater.stopped and app.updater.relaunched and app.root.destroyed
    assert app._token_lock.locked()          # no signature can start while the new copy takes over


# ------------------------------------------------------------ Switch to 32-bit
class _Packable(_Widget):
    def __init__(self, **options):
        super().__init__(**options)
        self.packed = False

    def pack(self, *args, **kwargs):
        self.packed = True

    def pack_forget(self):
        self.packed = False


class _SwitchUpdater(_Updater):
    def __init__(self, can_switch=True):
        super().__init__()
        self.self_update = True
        self.can_switch = can_switch
        self.switched = False

    def switch_to_32bit(self):
        self.switched = self.can_switch
        return self.can_switch


def _token_error_screen(monkeypatch, offer):
    app = _update_screen()
    app.updater = _SwitchUpdater()
    app.module_var = _Value(r"C:\Windows\System32\SignatureP11.dll")
    app.connect_btn, app.cert_menu, app.switch_btn, app.update_btn = _Widget(), _Widget(), _Packable(), _Packable()
    app._show_cert = app._refresh = lambda: None
    app._log = lambda msg: None
    monkeypatch.setattr(signer_app, "needs_32bit_signer", lambda module, err: offer)
    app._handle(("certs_err", "OS exception while loading ...: A dynamic link library (DLL) initialization "
                              "routine failed."))
    return app


def test_a_driver_that_needs_the_32bit_signer_shows_the_switch_button(monkeypatch):
    app = _token_error_screen(monkeypatch, offer=True)
    assert app.switch_btn.packed
    assert "needs the 32-bit Broto Signer" in app.status_lbl.cget("text")


def test_any_other_token_error_shows_no_switch_button(monkeypatch):
    app = _token_error_screen(monkeypatch, offer=False)
    assert not app.switch_btn.packed
    assert "Couldn't read the token" in app.status_lbl.cget("text")


def test_the_switch_downloads_then_relaunches_into_the_32bit_signer(monkeypatch):
    app = _token_error_screen(monkeypatch, offer=True)
    app._switch_to_32bit()
    assert app.updater.switched and app.switch_btn.cget("state") == "disabled"
    app._on_update("ready", {"version": "2.6.7", "switch": True})
    assert app.updater.relaunched and app.root.destroyed
    assert not app.switch_btn.packed and app.update_btn.packed


def test_a_failed_switch_lets_the_operator_try_again(monkeypatch):
    app = _token_error_screen(monkeypatch, offer=True)
    app._switch_to_32bit()
    app._on_update("switch_failed", {"error": "Broto has no 32-bit Signer to give yet."})
    assert app.switch_btn.cget("state") == "normal" and not app.updater.relaunched
    assert "Couldn't get the 32-bit Broto Signer" in app.status_lbl.cget("text")


# ------------------------------------------------------------ remote jobs: the certificate Broto names
TP_ONE, TP_TWO = "11" * 32, "22" * 32
ONE = CertInfo(label="", subject="CN=HOLDER ONE", cert_id=b"\x01", common_name="HOLDER ONE", thumbprint=TP_ONE,
               slot_index=0, module="p11.dll", token="sn:A")
TWO = CertInfo(label="", subject="CN=HOLDER TWO", cert_id=b"\x01", common_name="HOLDER TWO", thumbprint=TP_TWO,
               slot_index=1, module="p11.dll", token="sn:B")


class _FakeSigner:
    opened = []
    attempts = []           # every login tried, refused ones included
    fail_next_sign = []     # exceptions the next signatures raise, in turn

    def __init__(self, module, pin, cert_id=b"", cert_label="", slot_index=0):
        _FakeSigner.attempts.append((module, pin, slot_index))
        if pin == "bad":
            raise RuntimeError("CKR_PIN_INCORRECT")
        _FakeSigner.opened.append((module, pin, slot_index))

    def sign_flatfile_bytes(self, content):
        if _FakeSigner.fail_next_sign:
            raise _FakeSigner.fail_next_sign.pop(0)
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
    _FakeSigner.opened, _FakeSigner.attempts, _FakeSigner.fail_next_sign = [], [], []
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


# ------------------------------------------------------------ a run of remote jobs: one token login
def test_a_run_logs_in_to_the_token_once_and_holds_it_until_the_end(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111", "sn:B": "2222"}, picked=ONE)
    session = app._remote_session()
    out = [session.sign(b"HREC%d" % i, _flatfile_summary(TP_TWO, "HOLDER TWO")) for i in range(3)]
    assert out == [b"HREC0<signed>", b"HREC1<signed>", b"HREC2<signed>"]
    assert _FakeSigner.opened == [("p11.dll", "2222", 1)]                    # one login for three files
    assert app._token_lock.locked()                                           # local signing waits for the run
    session.close()
    assert not app._token_lock.locked()


def test_a_run_with_two_certificates_opens_each_token_once(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111", "sn:B": "2222"})
    session = app._remote_session()
    for thumbprint in (TP_ONE, TP_TWO, TP_ONE, TP_TWO):
        assert session.sign(b"HREC", _flatfile_summary(thumbprint)) == b"HREC<signed>"
    session.close()
    assert _FakeSigner.opened == [("p11.dll", "1111", 0), ("p11.dll", "2222", 1)]


def test_a_refused_pin_is_tried_once_per_run_never_again(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111", "sn:B": "bad"})
    session = app._remote_session()
    codes = []
    for _ in range(3):
        with pytest.raises(signer_app.SignError) as ei:
            session.sign(b"HREC", _flatfile_summary(TP_TWO, "HOLDER TWO"))
        codes.append(ei.value.code)
    assert codes == ["wrong_pin"] * 3
    assert _FakeSigner.attempts == [("p11.dll", "bad", 1)]                   # one wrong try, not three
    assert app.q.get_nowait() == ("remote", "pin_rejected", "sn:B") and app.q.empty()
    assert session.sign(b"HREC", _flatfile_summary(TP_ONE)) == b"HREC<signed>"   # the other token still signs
    session.close()
    assert not app._token_lock.locked()


def test_a_failure_inside_the_token_session_opens_a_fresh_one_for_the_next_file(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111", "sn:B": "2222"})
    _FakeSigner.fail_next_sign = [RuntimeError("CKR_DEVICE_ERROR")]
    session = app._remote_session()
    with pytest.raises(signer_app.SignError) as ei:
        session.sign(b"HREC", _flatfile_summary(TP_ONE))
    assert ei.value.code == "failed" and "CKR_DEVICE_ERROR" in ei.value.message
    assert session.sign(b"HREC", _flatfile_summary(TP_ONE)) == b"HREC<signed>"
    session.close()
    assert _FakeSigner.opened == [("p11.dll", "1111", 0), ("p11.dll", "1111", 0)]


def test_the_certificates_are_read_once_per_run(monkeypatch):
    app = _remote_app(monkeypatch, {"sn:A": "1111", "sn:B": "2222"})
    reads = []
    monkeypatch.setattr(signer_app, "list_certificates",
                        lambda module, pin=None, pins=None: reads.append(module) or [ONE, TWO])
    session = app._remote_session()
    for _ in range(3):
        session.sign(b"HREC", _flatfile_summary(TP_ONE))
    session.close()
    assert reads == ["p11.dll"]


def test_the_activity_log_says_how_long_each_step_took():
    assert (signer_app._timing_note({"fetch_ms": 812, "sign_ms": 1100, "send_ms": 1949})
            == " (got it in 0.8 s · signed in 1.1 s · sent back in 1.9 s)")
    assert signer_app._timing_note({}) == "" and signer_app._timing_note(None) == ""


# ------------------------------------------------------------ two firms on one PC (2.6)
class _Shown(_Widget):
    """A widget stand-in that knows whether it is on screen."""

    def __init__(self, **options):
        super().__init__(**options)
        self.shown = False

    def grid(self, *args, **kwargs):
        self.shown = True

    def grid_forget(self):
        self.shown = False


class _Link:
    def __init__(self, slot, firm=None, online=True, last_error=None, jobs_signed=0):
        self.slot, self.firm_name, self.device_name = slot, firm, "OFFICE-PC"
        self.paired = firm is not None
        self._st = {"paired": self.paired, "online": self.paired and online, "last_error": last_error,
                    "jobs_signed": jobs_signed, "firm_name": firm, "device_name": "OFFICE-PC"}

    def status(self):
        return dict(self._st)


def _remote_box(*firms):
    app = object.__new__(signer_app.SignerApp)
    app.remotes = [_Link(slot, firm) for slot, firm in enumerate(firms)]
    app._adding_firm = False
    app.pair_entry, app.pair_btn, app.add_firm_btn = _Shown(), _Shown(), _Shown()
    app.pair_entry.focus_set = lambda: None
    app.remote_lbls = [_Shown() for _ in firms]
    app.unpair_btns = [_Shown() for _ in firms]
    app._layout_remote()
    return app


def test_a_pc_with_no_firm_shows_the_code_box_as_before():
    app = _remote_box(None, None)
    assert app.pair_entry.shown and app.pair_btn.shown and not app.add_firm_btn.shown
    assert not any(w.shown for w in app.remote_lbls + app.unpair_btns)


def test_a_pc_with_one_firm_shows_it_and_offers_another():
    app = _remote_box("Firm A", None)
    assert app.remote_lbls[0].shown and app.unpair_btns[0].shown
    assert "Connected to Firm A as OFFICE-PC" in app.remote_lbls[0].cget("text")
    assert not app.pair_entry.shown and app.add_firm_btn.shown
    app._add_firm()
    assert app.pair_entry.shown and app.pair_btn.shown and not app.add_firm_btn.shown
    assert app._free_remote() is app.remotes[1]


def test_a_pc_with_two_firms_shows_both_and_no_code_box():
    app = _remote_box("Firm A", "Firm B")
    assert all(w.shown for w in app.remote_lbls + app.unpair_btns)
    assert not app.pair_entry.shown and not app.add_firm_btn.shown and app._free_remote() is None


def test_firm_1_disconnected_keeps_firm_2_and_fills_slot_1_next():
    app = _remote_box(None, "Firm B")
    assert app.remote_lbls[1].shown and not app.remote_lbls[0].shown and app.add_firm_btn.shown
    assert app._free_remote() is app.remotes[0]


def _pill(*links):
    app = _screen()
    app.remotes = list(links)
    app._refresh()
    return app.remote_pill.cget("text")


def test_the_pill_adds_up_both_firms():
    assert "Remote signing on" in _pill(_Link(0, "A", jobs_signed=2), _Link(1, "B", jobs_signed=3))
    assert "5 signed" in _pill(_Link(0, "A", jobs_signed=2), _Link(1, "B", jobs_signed=3))
    assert "can't reach Broto" in _pill(_Link(0, "A"), _Link(1, "B", online=False, last_error="down"))
    assert "connecting" in _pill(_Link(0, "A"), _Link(1, "B", online=False))
    assert "Remote signing off" in _pill(_Link(0, None), _Link(1, None))


def test_one_firm_pill_reads_exactly_as_before():
    assert _pill(_Link(0, "A", jobs_signed=3), _Link(1, None)) == "  ☁  Remote signing on  ·  3 signed  "
    assert _pill(_Link(0, "A"), _Link(1, None)) == "  ☁  Remote signing on  "


def test_the_activity_log_names_the_firm_only_when_there_are_two():
    app = _remote_box("Firm A", None)
    assert app._for_firm(0) == "" and app._for_firm(None) == ""
    app = _remote_box("Firm A", "Firm B")
    assert app._for_firm(1) == " for Firm B"


# ---------------------------------------------------------------------------
# 2.6.1: "token plugged in" on every check-in comes from the driver, not from Connect
# ---------------------------------------------------------------------------
def _probe_app(monkeypatch, present, *, tokens=(("x.dll", "sn:A"),), busy=False, locked=False, broken=False):
    import threading

    app = object.__new__(signer_app.SignerApp)
    app._busy = busy
    app._approval = None
    app._token_lock = threading.Lock()
    if locked:
        app._token_lock.acquire()
    app._status_snapshot = {"token_connected": True, "pin_saved": True, "certificates": [], "tokens": list(tokens)}
    calls = []

    def fake_probe(module):
        calls.append(module)
        if broken:
            raise RuntimeError("driver gone")
        return set(present)

    monkeypatch.setattr(signer_app, "present_token_keys", fake_probe)
    return app, calls


def test_check_in_says_the_token_is_out_once_it_is_pulled(monkeypatch):
    app, calls = _probe_app(monkeypatch, present=set())
    assert app._tokens_present(app._status_snapshot["tokens"]) is False
    assert app._remote_report()["token_connected"] is False
    assert calls == ["x.dll", "x.dll"]
    assert not app._token_lock.locked()           # released after the probe


def test_check_in_says_the_token_is_in_while_it_is(monkeypatch):
    app, _ = _probe_app(monkeypatch, present={"sn:A", "sn:OTHER"})
    assert app._remote_report()["token_connected"] is True


def test_no_probe_while_a_signature_runs_or_before_connect(monkeypatch):
    # The token lock is held by a signature: not probed, the snapshot's value stands.
    app, calls = _probe_app(monkeypatch, present=set(), locked=True)
    assert app._tokens_present(app._status_snapshot["tokens"]) is None
    assert app._remote_report()["token_connected"] is True and calls == []
    # Busy (a local batch) — same.
    app, calls = _probe_app(monkeypatch, present=set(), busy=True)
    assert app._remote_report()["token_connected"] is True and calls == []
    # Nothing connected yet: nothing to look for.
    app, calls = _probe_app(monkeypatch, present=set(), tokens=())
    app._status_snapshot["token_connected"] = False
    assert app._remote_report()["token_connected"] is False and calls == []


def test_a_driver_that_will_not_answer_leaves_the_last_value(monkeypatch):
    app, _ = _probe_app(monkeypatch, present=set(), broken=True)
    assert app._tokens_present(app._status_snapshot["tokens"]) is None
    assert app._remote_report()["token_connected"] is True
    assert not app._token_lock.locked()
