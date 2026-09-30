"""Broto Signer remote pairing (broto_signer/remote.py + the device-token store).

Pins the signer side of remote signing: what the PC reports about itself, how
Broto's answers map to outcomes (paired / revoked / offline), that the device
token is stored and forgotten at the right moments, and that the client never
mistakes a network blip for a revocation. Standard library only — no token,
no Tk, no network (the HTTP layer is a fake opener / fake client).
"""
import io
import json
import os
import sys
import threading
import urllib.error

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "broto_signer"))

import bridge  # noqa: E402
import remote  # noqa: E402
import secure_store  # noqa: E402

SNAPSHOT = {
    "version": "2.2.0",
    "token_connected": True,
    "pin_saved": True,
    "certificates": [{"holder": "RAJESH KUMAR", "issuer": "eMudhra", "serial": "0A", "thumbprint": "ab" * 32,
                      "not_after": "2027-12-31T00:00:00", "label": "DSC"}],
}


@pytest.fixture(autouse=True)
def _isolated_settings(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.delenv("BROTO_API_BASE", raising=False)
    yield


# ------------------------------------------------------------ report
def test_device_report_is_bounded_and_reads_the_snapshot():
    rep = remote.device_report(SNAPSHOT, "2.2.0")
    assert rep["signer_version"] == "2.2.0" and rep["token_connected"] is True and rep["pin_saved"] is True
    assert rep["name"] and rep["platform"] is not None
    assert rep["certificates"][0]["holder"] == "RAJESH KUMAR"
    many = dict(SNAPSHOT, certificates=[{"holder": "H%d" % i} for i in range(30)] + ["junk"])
    assert len(remote.device_report(many, "x")["certificates"]) == remote.MAX_CERTIFICATES
    empty = remote.device_report({}, "")
    assert empty["certificates"] == [] and empty["token_connected"] is False


def test_default_api_base_precedence(monkeypatch):
    assert remote.default_api_base() == remote.DEFAULT_API_BASE
    secure_store.update_settings(remote_api_base="https://staging.example/")
    assert remote.default_api_base() == "https://staging.example"
    monkeypatch.setenv("BROTO_API_BASE", "http://localhost:8000/")
    assert remote.default_api_base() == "http://localhost:8000"


# ------------------------------------------------------------ HTTP client
class _Resp:
    def __init__(self, status, body):
        self.status = status
        self._raw = json.dumps(body).encode()

    def read(self):
        return self._raw

    def __enter__(self):
        return self

    def __exit__(self, *_a):
        return False


def _http_error(status, body):
    return urllib.error.HTTPError("https://x", status, "err", {}, io.BytesIO(json.dumps(body).encode()))


def test_client_sends_json_with_bearer_and_parses_success():
    seen = []

    def opener(req, timeout=None):
        seen.append(req)
        return _Resp(200, {"ok": True, "status": "active"})

    c = remote.RemoteClient("https://api.example/", token="tok", opener=opener)
    assert c.heartbeat({"name": "PC"}) == {"ok": True, "status": "active"}
    req = seen[0]
    assert req.full_url == "https://api.example/api/cha/signer-devices/heartbeat"
    assert req.get_header("Authorization") == "Bearer tok"
    assert json.loads(req.data.decode()) == {"name": "PC"}
    c.pair("ABCD-EFGH", {"name": "PC"})
    assert json.loads(seen[1].data.decode()) == {"name": "PC", "code": "ABCD-EFGH"}
    assert seen[1].get_header("Authorization") is None      # pairing carries no token yet


@pytest.mark.parametrize("status, body, code, needle", [
    (401, {"detail": {"code": "revoked", "message": "This computer was removed from Broto."}}, "revoked", "removed"),
    (404, {"detail": {"code": "invalid_code", "message": "That code isn't valid any more."}}, "invalid_code", "valid"),
    (404, {"detail": "Not Found"}, "http_404", "Not Found"),
    (500, {}, "http_500", "HTTP 500"),
])
def test_client_maps_http_errors_to_remote_errors(status, body, code, needle):
    def opener(req, timeout=None):
        raise _http_error(status, body)

    c = remote.RemoteClient("https://api.example", token="t", opener=opener)
    with pytest.raises(remote.RemoteError) as ei:
        c.heartbeat({})
    assert ei.value.code == code and needle in ei.value.message and ei.value.status == status


def test_client_reports_network_trouble_as_network():
    def opener(req, timeout=None):
        raise urllib.error.URLError("no route to host")

    c = remote.RemoteClient("https://api.example", opener=opener)
    with pytest.raises(remote.RemoteError) as ei:
        c.pair("X", {})
    assert ei.value.code == "network" and "no route to host" in ei.value.message


# ------------------------------------------------------------ link (fake client)
def _fake_client_cls(script):
    """A RemoteClient stand-in. ``script`` maps method -> list of results; a
    result that is an Exception is raised. Records every call."""
    calls = []

    class Fake:
        def __init__(self, base_url, token=None, **_kw):
            self.base_url, self.token = base_url, token

        def _next(self, method, body):
            calls.append((method, self.base_url, self.token, body))
            outcomes = script.get(method) or []
            out = outcomes.pop(0) if outcomes else {"ok": True}
            if isinstance(out, Exception):
                raise out
            return out

        def pair(self, code, report):
            return self._next("pair", dict(report, code=code))

        def heartbeat(self, report):
            return self._next("heartbeat", report)

        def unpair(self):
            return self._next("unpair", {})

        def next_job(self):
            return self._next("next_job", {})

        def post_result(self, job_id, signed=None, code=None, message=None):
            body = {"job_id": job_id, "ok": signed is not None, "signed": signed, "code": code, "message": message}
            return self._next("post_result", body)

    Fake.calls = calls
    return Fake


def _link(script, events):
    cls = _fake_client_cls(script)
    link = remote.RemoteLink(report_fn=lambda: remote.device_report(SNAPSHOT, "2.2.0"),
                             notify=lambda ev, p: events.append((ev, p)), client_cls=cls)
    return link, cls


def test_pair_stores_token_and_identity_and_notifies():
    events = []
    link, cls = _link({"pair": [{"ok": True, "device_token": "secret-token", "device_id": "d1",
                                 "firm_name": "Firm A", "device_name": "OFFICE-PC", "heartbeat_interval_s": 45}]},
                      events)
    assert not link.paired
    out = link.pair(" abcd-efgh ")
    assert out["device_id"] == "d1"
    assert link.paired and link.firm_name == "Firm A" and link.device_name == "OFFICE-PC"
    assert link.interval_s == 45
    assert secure_store.load_remote_token() == "secret-token"
    st = secure_store.load_settings()
    assert st["remote_device_id"] == "d1" and st["remote_firm_name"] == "Firm A"
    assert st["remote_api_base"] == remote.DEFAULT_API_BASE
    assert events[0][0] == "paired" and events[0][1]["firm_name"] == "Firm A"
    method, base, token, body = cls.calls[0]
    assert method == "pair" and token is None and body["code"] == "abcd-efgh"
    assert body["certificates"][0]["holder"] == "RAJESH KUMAR"
    # A fresh RemoteLink picks the pairing straight back up from the store.
    again = remote.RemoteLink(report_fn=dict, notify=lambda *_a: None, client_cls=cls)
    assert again.paired and again.firm_name == "Firm A" and again.device_id == "d1"


def test_pair_failure_stores_nothing():
    events = []
    link, _ = _link({"pair": [remote.RemoteError("invalid_code", "That code isn't valid any more.", 404)]}, events)
    with pytest.raises(remote.RemoteError):
        link.pair("ZZZZ-ZZZZ")
    assert not link.paired and secure_store.load_remote_token() is None and events == []
    link2, _ = _link({"pair": [{"ok": True}]}, events)     # no token in the answer
    with pytest.raises(remote.RemoteError) as ei:
        link2.pair("ABCD-EFGH")
    assert ei.value.code == "bad_response" and not link2.paired


def test_pair_async_reports_failure_through_notify():
    events = []
    done = threading.Event()
    link, _ = _link({"pair": [remote.RemoteError("network", "Couldn't reach Broto (timed out).")]}, [])
    link.notify = lambda ev, p: (events.append((ev, p)), done.set())
    link.pair_async("ABCD-EFGH")
    assert done.wait(5)
    assert events == [("pair_failed", "Couldn't reach Broto (timed out).")]


def _paired_link(script, events):
    secure_store.save_remote_token("tok-1")
    secure_store.update_settings(remote_device_id="d1", remote_firm_name="Firm A", remote_device_name="OFFICE-PC")
    return _link(script, events)


def test_heartbeat_marks_online_once_and_absorbs_server_hints():
    events = []
    link, cls = _paired_link({"heartbeat": [
        {"ok": True, "status": "active", "heartbeat_interval_s": 20, "device_name": "Front desk PC"},
        {"ok": True, "status": "active"},
    ]}, events)
    assert link.paired and not link.online
    link._beat()
    assert link.online and link.interval_s == 20 and link.device_name == "Front desk PC"
    link._beat()
    assert [e for e, _ in events] == ["online"]          # not repeated while healthy
    assert cls.calls[0][2] == "tok-1" and cls.calls[0][3]["pin_saved"] is True


def test_revoked_heartbeat_forgets_the_token():
    events = []
    link, _ = _paired_link({"heartbeat": [remote.RemoteError("revoked", "This computer was removed from Broto.", 401)]},
                           events)
    link._beat()
    assert not link.paired and secure_store.load_remote_token() is None
    assert secure_store.load_settings().get("remote_device_id") is None
    assert events == [("revoked", "This computer was removed from Broto.")]
    link._beat()                                          # nothing to do without a token
    assert events == [("revoked", "This computer was removed from Broto.")]


def test_unknown_device_also_forgets_the_token():
    events = []
    link, _ = _paired_link({"heartbeat": [remote.RemoteError("unknown_device", "Not paired.", 401)]}, events)
    link._beat()
    assert not link.paired and events[0][0] == "revoked"


def test_network_trouble_is_offline_not_revoked_and_recovers():
    events = []
    link, _ = _paired_link({"heartbeat": [
        {"ok": True},
        remote.RemoteError("network", "Couldn't reach Broto (timeout)."),
        remote.RemoteError("network", "Couldn't reach Broto (timeout)."),
        remote.RemoteError("http_502", "Broto answered HTTP 502.", 502),
        {"ok": True},
    ]}, events)
    link._beat()
    assert link.online
    link._beat()
    assert link.online and [e for e, _ in events] == ["online"]      # one blip is not offline yet
    link._beat()
    assert not link.online and events[-1] == ("offline", "Couldn't reach Broto (timeout).")
    link._beat()
    assert [e for e, _ in events] == ["online", "offline"]            # offline is not repeated
    link._beat()
    assert link.online and [e for e, _ in events] == ["online", "offline", "online"]
    assert link.paired and secure_store.load_remote_token() == "tok-1"   # never forgotten over network trouble


def test_disconnect_tells_broto_best_effort_and_forgets():
    events = []
    link, cls = _paired_link({"unpair": [remote.RemoteError("network", "down")]}, events)
    link.disconnect()
    assert cls.calls[0][0] == "unpair" and cls.calls[0][2] == "tok-1"
    assert not link.paired and secure_store.load_remote_token() is None
    assert events == [("disconnected", None)]


def test_thread_beats_on_demand():
    events = []
    beat = threading.Event()
    link, cls = _paired_link({"heartbeat": [{"ok": True}] * 5}, events)
    link.interval_s = 600
    link.notify = lambda ev, p: (events.append((ev, p)), beat.set())
    link.start()
    try:
        assert beat.wait(5)                     # the first pass beats at once
        assert cls.calls and cls.calls[0][0] == "heartbeat"
    finally:
        link.stop()


# ------------------------------------------------------------ signing jobs (drain)
import base64  # noqa: E402

BE_JOB_DOC = {
    "headerField": {"senderID": "SUNWAYCHA", "receiverID": "INNSA1", "indicator": "P", "messageID": "CACHI01",
                    "sequenceOrControlNumber": 1, "jobNumber": 386, "jobDate": "20260924", "messageType": "F"},
    "master": {"beModel": [{"iecCode": "0512345678", "nameOfImporter": "ACME IMPORTS PVT LTD"}],
               "invoiceModel": [{}], "itemsModel": [{}, {}]},
}


def _job(doc=BE_JOB_DOC, job_id="r1", **extra):
    content = json.dumps(doc, separators=(",", ":")).encode()
    return dict({"id": job_id, "filing_id": "f1", "doc_type": "BE", "filename": "3862026.json",
                 "content_b64": base64.b64encode(content).decode(), "requested_by": "ops@firm.com"}, **extra)


def _drain_link(script, events, sign_fn):
    cls = _fake_client_cls(script)
    secure_store.save_remote_token("tok-1")
    link = remote.RemoteLink(report_fn=lambda: remote.device_report(SNAPSHOT, "2.2.0"),
                             notify=lambda ev, p: events.append((ev, p)), sign_fn=sign_fn, client_cls=cls)
    return link, cls


def test_heartbeat_with_jobs_waiting_signs_and_returns_each_job():
    events, seen = [], []

    def sign_fn(content, summary):
        seen.append((content, summary))
        return b"SIGNED:" + content[:10]

    link, cls = _drain_link({
        "heartbeat": [{"ok": True, "jobs_waiting": 2}, {"ok": True, "jobs_waiting": 0}],
        "next_job": [{"job": _job(job_id="r1")}, {"job": _job(job_id="r2")}, {"job": None}],
    }, events, sign_fn)
    link._beat()
    assert [s["kind"] for _, s in seen] == ["Bill of Entry", "Bill of Entry"]
    assert seen[0][1]["party"] == "ACME IMPORTS PVT LTD" and seen[0][1]["job_number"] == 386
    results = [c for c in cls.calls if c[0] == "post_result"]
    assert [r[3]["job_id"] for r in results] == ["r1", "r2"]
    assert all(r[3]["ok"] and r[3]["signed"].startswith(b"SIGNED:") for r in results)
    assert [e for e, _ in events] == ["online", "job_signed", "job_signed"]
    assert events[1][1]["job"]["requested_by"] == "ops@firm.com"
    assert link.jobs_signed == 2 and link.status()["jobs_signed"] == 2
    link._beat()                                                  # nothing waiting → no next_job call
    assert len([c for c in cls.calls if c[0] == "next_job"]) == 3


def test_drain_refuses_anything_but_an_unsigned_filing():
    events, seen = [], []
    link, cls = _drain_link({
        "heartbeat": [{"ok": True, "jobs_waiting": 1}],
        "next_job": [{"job": _job(doc={"hello": "world"}, job_id="bad")}, {"job": None}],
    }, events, lambda c, s: seen.append(c) or b"x")
    link._beat()
    assert seen == []                                             # sign_fn never ran
    res = [c for c in cls.calls if c[0] == "post_result"][0][3]
    assert res["ok"] is False and res["code"] == "rejected_payload" and "ICEGATE filing" in res["message"]
    assert events[-1][0] == "job_failed" and events[-1][1]["code"] == "rejected_payload"
    assert link.jobs_signed == 0


def test_drain_reports_sign_errors_with_their_code():
    events = []

    def sign_fn(content, summary):
        raise remote.SignError("pin_not_saved", "No saved PIN on this PC.")

    link, cls = _drain_link({
        "heartbeat": [{"ok": True, "jobs_waiting": 1}],
        "next_job": [{"job": _job()}, {"job": None}],
    }, events, sign_fn)
    link._beat()
    res = [c for c in cls.calls if c[0] == "post_result"][0][3]
    assert res == {"job_id": "r1", "ok": False, "signed": None, "code": "pin_not_saved", "message": "No saved PIN on this PC."}
    assert events[-1] == ("job_failed", {"job": _job(), "summary": events[-1][1]["summary"],
                                         "code": "pin_not_saved", "message": "No saved PIN on this PC."})


def test_drain_without_sign_fn_and_unexpected_errors():
    events = []
    link, cls = _drain_link({
        "heartbeat": [{"ok": True, "jobs_waiting": 1}],
        "next_job": [{"job": _job()}, {"job": None}],
    }, events, None)
    link._beat()
    assert [c for c in cls.calls if c[0] == "post_result"][0][3]["code"] == "no_signer"

    events2 = []
    link2, cls2 = _drain_link({
        "heartbeat": [{"ok": True, "jobs_waiting": 1}],
        "next_job": [{"job": _job()}, {"job": None}],
    }, events2, lambda c, s: (_ for _ in ()).throw(RuntimeError("token yanked")))
    link2._beat()
    res = [c for c in cls2.calls if c[0] == "post_result"][0][3]
    assert res["code"] == "failed" and "token yanked" in res["message"]


def test_describe_job_guards_documents_and_filings():
    import hashlib
    pdf = b"%PDF-1.7\nhello\n%%EOF\n"
    ok = remote.describe_job({"kind": "document", "filename": "inv.pdf", "doc_type": "invoice", "job_seq": "386",
                              "sha256": hashlib.sha256(pdf).hexdigest()}, pdf)
    assert ok["format"] == "pdf" and ok["filename"] == "inv.pdf" and ok["job_number"] == "386" and ok["size"] == len(pdf)
    with pytest.raises(bridge.PayloadRejected, match="Not a PDF"):
        remote.describe_job({"kind": "document"}, b"not a pdf")
    with pytest.raises(bridge.PayloadRejected, match="fingerprint"):
        remote.describe_job({"kind": "document", "sha256": "00" * 32}, pdf)
    with pytest.raises(bridge.PayloadRejected, match="Unknown job kind"):
        remote.describe_job({"kind": "anything"}, pdf)
    filing = remote.describe_job({"kind": "filing"}, json.dumps(BE_JOB_DOC).encode())
    assert filing["format"] == "json" and filing["kind"] == "Bill of Entry"
    assert remote.describe_job({}, json.dumps(BE_JOB_DOC).encode())["format"] == "json"   # default kind


def test_drain_signs_a_pdf_document_with_the_pdf_signature():
    import hashlib
    events, seen = [], []
    pdf = b"%PDF-1.7\ninvoice\n%%EOF\n"
    job = {"kind": "document", "id": "d1", "filename": "inv.pdf", "doc_type": "invoice", "job_seq": "386",
           "sha256": hashlib.sha256(pdf).hexdigest(), "content_b64": base64.b64encode(pdf).decode(),
           "requested_by": "ops@firm.com"}

    def sign_fn(content, summary):
        seen.append(summary)
        assert summary["format"] == "pdf" and content == pdf
        return content + b"\n<signature>"

    link, cls = _drain_link({"heartbeat": [{"ok": True, "jobs_waiting": 1}],
                             "next_job": [{"job": job}, {"job": None}]}, events, sign_fn)
    link._beat()
    assert len(seen) == 1
    res = [c for c in cls.calls if c[0] == "post_result"][0][3]
    assert res["ok"] and res["signed"] == pdf + b"\n<signature>"
    assert events[-1][0] == "job_signed" and events[-1][1]["summary"]["kind"] == "PDF document"


HREC = (b"HREC\x1dZZ\x1dINMUN1\x1dZZ\x1dICEGATE\x1dICES1_5\x1dP\x1d\x1dCACHI01\x1d9839487260415\x1d20260415\x1d185409\n"
        b"<TABLE>BE\nF\x1dINMUN1\x1d9839487\n<END-BE>\nTREC\x1d9839487260415\n")


def test_describe_flatfile_reads_the_hrec_envelope_and_refuses_the_rest():
    s = remote.describe_flatfile(HREC)
    assert s["format"] == "flatfile" and s["kind"] == "Bill of Entry flat file"
    assert s["sender_id"] == "INMUN1" and s["receiver_id"] == "ICEGATE" and s["test_mode"] is False
    sb = remote.describe_flatfile(HREC.replace(b"CACHI01", b"CACHE01").replace(b"\x1dP\x1d", b"\x1dT\x1d"))
    assert sb["kind"] == "Shipping Bill flat file" and sb["test_mode"] is True
    with pytest.raises(bridge.PayloadRejected, match="no HREC header"):
        remote.describe_flatfile(b"hello world")
    with pytest.raises(bridge.PayloadRejected, match="Unsupported flat file type"):
        remote.describe_flatfile(HREC.replace(b"CACHI01", b"CUCHI01"))
    with pytest.raises(bridge.PayloadRejected, match="already signed"):
        remote.describe_flatfile(HREC + b"<START-SIGNATURE>x</START-SIGNATURE>")
    import hashlib
    job = {"kind": "flatfile", "filename": "9839487.be", "job_seq": "9839487", "sha256": hashlib.sha256(HREC).hexdigest()}
    d = remote.describe_job(job, HREC)
    assert d["filename"] == "9839487.be" and d["job_number"] == "9839487"
    with pytest.raises(bridge.PayloadRejected, match="fingerprint"):
        remote.describe_job(dict(job, sha256="00" * 32), HREC)


def test_drain_signs_a_flat_file_with_the_tag_envelope_signature():
    import hashlib
    events, seen = [], []
    job = {"kind": "flatfile", "id": "f1", "filename": "9839487.be", "doc_type": "BE", "job_seq": "9839487",
           "sha256": hashlib.sha256(HREC).hexdigest(), "content_b64": base64.b64encode(HREC).decode()}

    def sign_fn(content, summary):
        seen.append(summary)
        assert summary["format"] == "flatfile" and content == HREC
        return content.rstrip(b"\r\n") + b"\n<START-SIGNATURE>sig</START-SIGNATURE>"

    link, cls = _drain_link({"heartbeat": [{"ok": True, "jobs_waiting": 1}],
                             "next_job": [{"job": job}, {"job": None}]}, events, sign_fn)
    link._beat()
    assert len(seen) == 1 and seen[0]["kind"] == "Bill of Entry flat file"
    res = [c for c in cls.calls if c[0] == "post_result"][0][3]
    assert res["ok"] and res["signed"].endswith(b"</START-SIGNATURE>")


def test_drain_survives_broto_dropping_mid_way():
    events = []
    link, cls = _drain_link({
        "heartbeat": [{"ok": True, "jobs_waiting": 1}],
        "next_job": [{"job": _job()}],
        "post_result": [remote.RemoteError("network", "Couldn't reach Broto (timeout).")],
    }, events, lambda c, s: b"signed")
    link._beat()                                                  # must not raise
    assert events[-1][0] == "job_failed" and events[-1][1]["code"] == "network"
    assert link.paired and link.last_error == "Couldn't reach Broto (timeout)."


# ------------------------------------------------------------ token store
@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows behaviour")
def test_remote_token_plain_text_off_windows():
    assert secure_store.remote_token_protected() is False
    assert secure_store.load_remote_token() is None and not secure_store.has_remote_token()
    secure_store.save_remote_token("abc")
    assert secure_store.load_remote_token() == "abc" and secure_store.has_remote_token()
    assert secure_store.load_settings()["remote_token_plain"] == "abc"
    secure_store.forget_remote_token()
    assert secure_store.load_remote_token() is None and not secure_store.has_remote_token()


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_remote_token_dpapi_round_trip(tmp_path):
    secure_store.save_remote_token("abc-token")
    raw = json.loads((tmp_path / "BrotoSigner" / "settings.json").read_text())
    assert "remote_token_plain" not in raw and "abc-token" not in raw["remote_token_dpapi"]
    assert secure_store.load_remote_token() == "abc-token"
    # The PIN blob and the token blob use different entropy — one can't read the other.
    secure_store.save_pin("1234")
    assert secure_store.load_pin() == "1234" and secure_store.load_remote_token() == "abc-token"
    secure_store.forget_remote_token()
    assert secure_store.load_remote_token() is None


# ------------------------------------------------------------ certificate report
def test_certificate_report_carries_serial_and_thumbprint():
    import hashlib
    from datetime import datetime, timezone

    pytest.importorskip("asn1crypto")
    cryptography = pytest.importorskip("cryptography")
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    import signer_core

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "RAJESH KUMAR"),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Personal")])
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "eMudhra Sub CA for Class 3 Individual 2022")])
    der = (x509.CertificateBuilder().subject_name(name).issuer_name(issuer).public_key(key.public_key())
           .serial_number(0x0A1B2C).not_valid_before(datetime(2026, 1, 1, tzinfo=timezone.utc))
           .not_valid_after(datetime(2027, 12, 31, tzinfo=timezone.utc))
           .sign(key, hashes.SHA256()).public_bytes(serialization.Encoding.DER))
    assert cryptography  # keep the importorskip binding used

    info = signer_core._describe_cert(der)
    assert info["common_name"] == "RAJESH KUMAR"
    assert info["issuer"].startswith("eMudhra")
    assert info["serial"] == "A1B2C"
    assert info["thumbprint"] == hashlib.sha256(der).hexdigest()

    cert = signer_core.CertInfo(label="DSC", cert_id=b"\x01", slot_index=0, **info)
    rep = cert.report()
    assert rep == {
        "holder": "RAJESH KUMAR",
        "issuer": info["issuer"],
        "serial": "A1B2C",
        "thumbprint": info["thumbprint"],
        "not_after": info["not_after"].isoformat(),
        "label": "DSC",
        "token": "",
        "can_sign": "1",
    }
    # never key material, and the token only as a short hash
    assert set(rep) <= {"holder", "issuer", "serial", "thumbprint", "not_after", "label", "token", "can_sign"}


# ------------------------------------------------------------ the certificate of the job's ICEGATE ID
def test_drain_hands_the_certificate_broto_names_to_the_signer():
    import hashlib
    events, seen = [], []
    job = {"kind": "flatfile", "id": "f2", "filename": "9839487.be", "doc_type": "BE", "job_seq": "9839487",
           "sha256": hashlib.sha256(HREC).hexdigest(), "content_b64": base64.b64encode(HREC).decode(),
           "cert_thumbprint": "AB" * 32, "cert_holder": "HOLDER TWO"}

    def sign_fn(content, summary):
        seen.append(summary)
        return content.rstrip(b"\r\n") + b"\n<START-SIGNATURE>sig</START-SIGNATURE>"

    link, _cls = _drain_link({"heartbeat": [{"ok": True, "jobs_waiting": 1}],
                              "next_job": [{"job": job}, {"job": None}]}, events, sign_fn)
    link._beat()
    assert seen[0]["cert_thumbprint"] == "ab" * 32 and seen[0]["cert_holder"] == "HOLDER TWO"


def test_a_job_without_a_named_certificate_leaves_the_choice_to_the_pc():
    events, seen = [], []
    link, _cls = _drain_link({"heartbeat": [{"ok": True, "jobs_waiting": 1}],
                              "next_job": [{"job": _job()}, {"job": None}]}, events,
                             lambda c, s: seen.append(s) or b"signed")
    link._beat()
    assert seen[0]["cert_thumbprint"] == "" and seen[0]["cert_holder"] == ""


# ------------------------------------------------------------ one saved PIN per token
@pytest.fixture()
def fake_dpapi(monkeypatch):
    """Stand-in for Windows DPAPI so the per-token PIN store runs on any OS."""
    monkeypatch.setattr(secure_store, "pin_saving_supported", lambda: True)
    monkeypatch.setattr(secure_store, "_protect", lambda data, *a, **k: b"enc:" + data)
    monkeypatch.setattr(secure_store, "_unprotect", lambda data, *a, **k: data[len(b"enc:"):])


def test_pins_are_saved_per_token(fake_dpapi):
    secure_store.save_pin("1111", "sn:A")
    secure_store.save_pin("2222", "sn:B")
    assert secure_store.load_pins() == {"sn:A": "1111", "sn:B": "2222"}
    raw = json.dumps(secure_store.load_settings())
    assert "1111" not in raw and "2222" not in raw                       # stored encrypted only
    secure_store.forget_pin("sn:A")
    assert secure_store.load_pins() == {"sn:B": "2222"} and secure_store.has_saved_pin()
    secure_store.forget_pin()                                            # every saved PIN
    assert secure_store.load_pins() == {} and not secure_store.has_saved_pin()


def test_a_pin_saved_before_the_update_is_filed_under_its_token(fake_dpapi):
    secure_store.save_pin("1111")                                        # how 2.3.3 saved it
    assert secure_store.load_pins() == {"": "1111"} and secure_store.load_pin() == "1111"
    assert secure_store.bind_legacy_pin("sn:A") is True
    assert secure_store.load_pins() == {"sn:A": "1111"} and secure_store.load_pin() is None
    assert secure_store.bind_legacy_pin("sn:B") is False                 # nothing left to file
