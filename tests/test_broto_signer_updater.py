"""Broto Signer "Relaunch to update" (broto_signer/updater.py).

Pins: only a newer published version is fetched; only a file that matches the
published size + SHA-256 is kept; the swap keeps the same .exe path, starts the
new copy, and puts the old file back on any failure; leftovers are cleaned up.
No Tk, no network (fake opener), no real .exe (temp files stand in).
"""
import hashlib
import io
import json
import os
import sys
import urllib.error

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "broto_signer"))

import updater  # noqa: E402

BASE = "https://api.example"
NEW_EXE = b"MZ new build " * 100


def _info(data=NEW_EXE, version="9.0.0", **over):
    out = {"version": version, "update": True, "sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
           "url": "https://storage.example/broto-signer/BrotoSigner.exe?token=x"}
    out.update(over)
    return out


class _Resp:
    def __init__(self, raw, status=200):
        self.status = status
        self._buf = io.BytesIO(raw)

    def read(self, n=-1):
        return self._buf.read(n)

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _opener(routes, seen=None):
    """routes: url prefix -> bytes / dict (JSON) / Exception."""
    def opener(req, timeout=None):
        if seen is not None:
            seen.append(req)
        for prefix, answer in routes.items():
            if req.full_url.startswith(prefix):
                if isinstance(answer, BaseException):
                    raise answer
                return _Resp(json.dumps(answer).encode() if isinstance(answer, dict) else answer)
        raise AssertionError("unexpected " + req.full_url)
    return opener


@pytest.fixture
def exe(tmp_path):
    p = tmp_path / "BrotoSigner.exe"
    p.write_bytes(b"MZ old build")
    return str(p)


def _updater(exe, routes, events, seen=None, current="2.4.0", token="tok"):
    return updater.Updater(current, BASE, token_fn=lambda: token, exe=exe, self_update=True,
                           notify=lambda ev, info: events.append((ev, info)), opener=_opener(routes, seen))


def test_version_compare_is_numeric():
    assert updater.is_newer("2.10.0", "2.9.9")
    assert updater.is_newer("2.4.1", "2.4")
    assert not updater.is_newer("2.4.0", "2.4.0")
    assert not updater.is_newer("2.3.9", "2.4.0")
    assert not updater.is_newer("latest", "2.4.0")


def test_newer_version_is_downloaded_checked_and_offered(exe):
    events, seen = [], []
    up = _updater(exe, {BASE: _info(), "https://storage.example/": NEW_EXE}, events, seen)
    assert up.check_once() is True
    assert seen[0].full_url == BASE + "/api/cha/signer-devices/app-latest?current=2.4.0"
    assert seen[0].get_header("Authorization") == "Bearer tok"
    assert [e for e, _ in events] == ["ready"]
    with open(updater.staged_path(exe), "rb") as fh:
        assert fh.read() == NEW_EXE
    assert not os.path.exists(updater.staged_path(exe) + ".part")


def test_no_update_means_no_download(exe):
    events = []
    up = _updater(exe, {BASE: {"version": "2.4.0", "update": False}}, events)
    assert up.check_once() is True
    assert events == [] and not os.path.exists(updater.staged_path(exe))


def test_server_saying_update_for_an_older_version_is_ignored(exe):
    events = []
    up = _updater(exe, {BASE: _info(version="2.3.3")}, events)
    assert up.check_once() is True and events == []


@pytest.mark.parametrize("served", [NEW_EXE[:-1], NEW_EXE + b"x", b"MZ tampered" * 118])
def test_a_file_that_does_not_match_is_thrown_away(exe, served):
    events = []
    up = _updater(exe, {BASE: _info(), "https://storage.example/": served}, events)
    assert up.check_once() is False                       # try again sooner
    assert events == [] and up.ready is None
    assert not os.path.exists(updater.staged_path(exe))
    assert not os.path.exists(updater.staged_path(exe) + ".part")


def test_plain_http_download_link_is_refused(exe):
    events = []
    up = _updater(exe, {BASE: _info(url="http://storage.example/x")}, events)
    assert up.check_once() is False and events == []


def test_not_logged_in_means_no_check(exe):
    events, seen = [], []
    up = _updater(exe, {}, events, seen, token=None)
    assert up.check_once() is True and seen == []


def test_check_failure_retries_sooner(exe):
    events = []
    up = _updater(exe, {BASE: urllib.error.URLError("offline")}, events)
    assert up.check_once() is False and events == []


def test_run_from_source_only_says_a_new_version_is_out(exe):
    events = []
    up = updater.Updater("2.4.0", BASE, token_fn=lambda: "tok", exe=exe, self_update=False,
                         notify=lambda ev, info: events.append((ev, info)), opener=_opener({BASE: _info()}))
    up.check_once()
    up.check_once()
    assert [e for e, _ in events] == ["available"]         # said once, nothing downloaded
    assert not os.path.exists(updater.staged_path(exe))


def test_a_32bit_signer_updates_from_the_32bit_build(exe, monkeypatch):
    """The 32-bit Signer (a PC whose 64-bit token driver will not start) asks for its
    own build — never the 64-bit one, which would bring the broken driver back."""
    monkeypatch.setattr(updater, "is_32bit", lambda: True)
    events, seen = [], []
    up = _updater(exe, {BASE: _info(), "https://storage.example/": NEW_EXE}, events, seen, current="2.6.7")
    assert up.check_once() is True
    assert seen[0].full_url == BASE + "/api/cha/signer-devices/app-latest?current=2.6.7&arch=x86"
    assert [e for e, _ in events] == ["ready"] and not events[0][1].get("switch")


def test_a_64bit_signer_still_asks_exactly_as_before(exe):
    seen = []
    _updater(exe, {BASE: {"version": "2.4.0", "update": False}}, [], seen).check_once()
    assert seen[0].full_url == BASE + "/api/cha/signer-devices/app-latest?current=2.4.0"


def test_switch_to_32bit_fetches_it_even_at_the_same_version_and_says_switch(exe):
    events, seen = [], []
    up = _updater(exe, {BASE: _info(version="2.6.7"), "https://storage.example/": NEW_EXE}, events, seen,
                  current="2.6.7")
    assert up.switch_to_32bit() is True
    assert up.check_once() is True
    assert seen[0].full_url == BASE + "/api/cha/signer-devices/app-latest?arch=x86"
    assert [e for e, _ in events] == ["ready"] and events[0][1]["switch"] is True
    with open(updater.staged_path(exe), "rb") as fh:
        assert fh.read() == NEW_EXE


def test_switch_with_no_32bit_build_published_says_so_and_goes_back(exe):
    events = []
    up = _updater(exe, {BASE: {"version": None, "update": False}}, events)
    up.switch_to_32bit()
    up.check_once()
    assert [e for e, _ in events] == ["switch_failed"] and up.arch == "x64" and up.ready is None


def test_switch_whose_download_fails_says_so_and_goes_back(exe):
    events = []
    up = _updater(exe, {BASE: _info(), "https://storage.example/": b"MZ something else"}, events)
    up.switch_to_32bit()
    assert up.check_once() is False
    assert [e for e, _ in events] == ["switch_failed"] and up.arch == "x64"


def test_switch_is_refused_when_already_32bit_or_run_from_source(exe, monkeypatch):
    up = updater.Updater("2.6.7", BASE, token_fn=lambda: "tok", exe=exe, self_update=False, notify=lambda *a: None)
    assert up.switch_to_32bit() is False
    monkeypatch.setattr(updater, "is_32bit", lambda: True)
    assert _updater(exe, {}, []).switch_to_32bit() is False


def test_only_a_32bit_python_counts_as_32bit(monkeypatch):
    monkeypatch.setattr(sys, "maxsize", 2 ** 31 - 1)
    assert updater.is_32bit()
    monkeypatch.setattr(sys, "maxsize", 2 ** 63 - 1)
    assert not updater.is_32bit()


def test_relaunch_swaps_in_place_and_starts_the_same_path(exe):
    events, started = [], []
    up = _updater(exe, {BASE: _info(), "https://storage.example/": NEW_EXE}, events)
    up.check_once()
    up.relaunch(start=started.append)
    with open(exe, "rb") as fh:
        assert fh.read() == NEW_EXE                          # same path → autostart + shortcuts still work
    with open(updater.old_path(exe), "rb") as fh:
        assert fh.read() == b"MZ old build"
    assert not os.path.exists(updater.staged_path(exe))
    assert started == [updater.relaunch_command(exe)]


def test_relaunch_failure_puts_the_old_file_back(exe):
    events = []
    up = _updater(exe, {BASE: _info(), "https://storage.example/": NEW_EXE}, events)
    up.check_once()

    def cannot_start(_cmd):
        raise OSError("blocked")

    with pytest.raises(OSError):
        up.relaunch(start=cannot_start)
    with open(exe, "rb") as fh:
        assert fh.read() == b"MZ old build"
    with open(updater.staged_path(exe), "rb") as fh:
        assert fh.read() == NEW_EXE                          # kept for the next try
    assert not os.path.exists(updater.old_path(exe))


def test_relaunch_refuses_a_changed_download(exe):
    events = []
    up = _updater(exe, {BASE: _info(), "https://storage.example/": NEW_EXE}, events)
    up.check_once()
    with open(updater.staged_path(exe), "wb") as fh:
        fh.write(b"MZ swapped")
    with pytest.raises(OSError):
        up.relaunch(start=lambda _c: None)
    with open(exe, "rb") as fh:
        assert fh.read() == b"MZ old build"


def test_an_earlier_download_is_reused(exe):
    with open(updater.staged_path(exe), "wb") as fh:
        fh.write(NEW_EXE)
    events = []
    up = _updater(exe, {BASE: _info(), "https://storage.example/": AssertionError("must not download")}, events)
    assert up.check_once() is True and [e for e, _ in events] == ["ready"]


def test_cleanup_removes_leftovers(exe):
    for path in (updater.old_path(exe), updater.staged_path(exe) + ".part"):
        with open(path, "wb") as fh:
            fh.write(b"x")
    updater.cleanup(exe)
    assert not os.path.exists(updater.old_path(exe))
    assert not os.path.exists(updater.staged_path(exe) + ".part")
    assert os.path.exists(exe)


def test_the_new_copy_starts_fresh(monkeypatch):
    monkeypatch.setattr(sys, "_MEIPASS", "/tmp/_MEI123", raising=False)
    monkeypatch.setenv("TCL_LIBRARY", "/tmp/_MEI123/tcl")
    monkeypatch.setenv("_PYI_ARCHIVE_FILE", "x")
    monkeypatch.setenv("KEEP_ME", "1")
    env = updater._child_env()
    assert env["PYINSTALLER_RESET_ENVIRONMENT"] == "1"
    assert "TCL_LIBRARY" not in env and "_PYI_ARCHIVE_FILE" not in env
    assert env["KEEP_ME"] == "1"
