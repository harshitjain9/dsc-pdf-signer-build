"""Broto Signer one-click bridge (broto_signer/bridge.py) + settings store.

The bridge is what lets Broto's web app ask the desktop signer for a signature.
These tests pin its guard rails: only Broto's origin, only this PC's host name,
only unsigned ICEGATE BE/SB filings, nothing signed without the app's decision,
one request at a time. Standard library only — no token, no Tk.
"""
import base64
import http.client
import json
import os
import socket
import sys
import threading
import time

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "broto_signer"))

import bridge  # noqa: E402
import secure_store  # noqa: E402

ORIGIN = "https://brotoai.com"

BE = {
    "headerField": {"senderID": "SUNWAYCHA", "receiverID": "INNSA1", "indicator": "T",
                    "messageID": "CACHI01", "sequenceOrControlNumber": 1,
                    "jobNumber": 4382026, "jobDate": "20260922", "messageType": "F"},
    "master": {"beModel": [{"iecCode": "0512345678", "nameOfImporter": "ACME IMPORTS PVT LTD"}],
               "invoiceModel": [{}, {}], "itemsModel": [{}, {}, {}]},
}
SB = {
    "headerField": {"senderID": "SUNWAYCHA", "messageID": "CACHE01", "jobNumber": 9, "jobDate": "22092026"},
    "master": {"sbModel": [{"importerExporterCode": "AAACA1234B", "impExpName": "ACME EXPORTS"}],
               "invoiceModel": [{}], "itemModel": [{}]},
}


def _bytes(doc):
    return json.dumps(doc, separators=(",", ":")).encode()


# ------------------------------------------------------------ describe_payload
def test_describe_be_reads_everything_from_the_payload():
    s = bridge.describe_payload(_bytes(BE))
    assert s["kind"] == "Bill of Entry"
    assert s["party"] == "ACME IMPORTS PVT LTD" and s["iec"] == "0512345678"
    assert s["job_number"] == 4382026 and s["job_date"] == "20260922"
    assert s["invoices"] == 2 and s["items"] == 3
    assert s["test_mode"] is True and s["sender_id"] == "SUNWAYCHA"


def test_describe_sb():
    s = bridge.describe_payload(_bytes(SB))
    assert s["kind"] == "Shipping Bill" and s["party"] == "ACME EXPORTS"
    assert s["iec"] == "AAACA1234B" and s["items"] == 1 and s["test_mode"] is False


@pytest.mark.parametrize("payload, needle", [
    (b"not json", "Not valid JSON"),
    (_bytes({"hello": 1}), "Not an ICEGATE filing"),
    (_bytes(dict(BE, digSign={"startSignature": "x"})), "already signed"),
    (_bytes({"headerField": {"messageID": "CUCHI01"}, "master": {}}), "Unsupported filing type"),
    (_bytes({"headerField": [], "master": {}}), "must be objects"),
])
def test_describe_rejects_anything_but_an_unsigned_filing(payload, needle):
    with pytest.raises(bridge.PayloadRejected, match=needle):
        bridge.describe_payload(payload)


# ------------------------------------------------------------ HTTP server
def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class _Harness:
    def __init__(self, decide=None, timeout=5.0):
        self.requests = []
        self.decide = decide
        self.port = _free_port()

        def on_request(req):
            self.requests.append(req)
            if self.decide:
                threading.Thread(target=self.decide, args=(req,), daemon=True).start()

        self.server = bridge.BridgeServer(on_request=on_request,
                                          status=lambda: {"version": "9.9.9", "token_connected": True},
                                          port=self.port, decision_timeout=timeout)
        assert self.server.start()

    def call(self, method, path, body=None, origin=ORIGIN, host=None):
        conn = http.client.HTTPConnection("127.0.0.1", self.port, timeout=10)
        headers = {"Host": host or "127.0.0.1:%d" % self.port}
        if origin:
            headers["Origin"] = origin
        data = None
        if body is not None:
            data = json.dumps(body).encode()
            headers["Content-Type"] = "application/json"
        conn.request(method, path, body=data, headers=headers)
        r = conn.getresponse()
        raw = r.read()
        out = json.loads(raw) if raw else None
        hdrs = dict(r.getheaders())
        conn.close()
        return r.status, out, hdrs

    def sign(self, doc=BE, **kw):
        return self.call("POST", "/sign", {"filename": "4382026.json", "action": "sign_and_file",
                                           "content_b64": base64.b64encode(_bytes(doc)).decode()}, **kw)

    def close(self):
        self.server.stop()


@pytest.fixture
def harness():
    made = []

    def make(**kw):
        h = _Harness(**kw)
        made.append(h)
        return h
    yield make
    for h in made:
        h.close()


def test_preflight_allows_broto_and_private_network(harness):
    h = harness()
    code, _, hdrs = h.call("OPTIONS", "/sign")
    assert code == 204
    assert hdrs["Access-Control-Allow-Origin"] == ORIGIN
    assert hdrs["Access-Control-Allow-Private-Network"] == "true"


def test_preflight_refuses_other_sites(harness):
    h = harness()
    code, _, hdrs = h.call("OPTIONS", "/sign", origin="https://evil.example")
    assert code == 403 and "Access-Control-Allow-Origin" not in hdrs


def test_status(harness):
    h = harness()
    code, body, hdrs = h.call("GET", "/status")
    assert code == 200 and body["app"] == "broto-signer" and body["version"] == "9.9.9"
    assert hdrs["Access-Control-Allow-Origin"] == ORIGIN


def test_dns_rebinding_host_is_refused(harness):
    h = harness()
    code, body, _ = h.call("GET", "/status", host="attacker.example:%d" % h.port)
    assert code == 403 and body["code"] == "bad_host"


def test_sign_from_other_site_never_reaches_the_app(harness):
    h = harness()
    code, body, _ = h.sign(origin="https://evil.example")
    assert code == 403 and body["code"] == "bad_origin"
    code, body, _ = h.sign(origin=None)
    assert code == 403
    assert h.requests == []


def test_non_filing_payload_is_refused_before_the_app_sees_it(harness):
    h = harness()
    code, body, _ = h.call("POST", "/sign", {"filename": "x.json",
                                             "content_b64": base64.b64encode(b'{"a":1}').decode()})
    assert code == 400 and body["code"] == "rejected_payload"
    assert h.requests == []


def test_approved_request_returns_the_signed_bytes(harness):
    h = harness(decide=lambda req: req.finish(req.content + b"SIGNED"))
    code, body, _ = h.sign()
    assert code == 200 and body["ok"] is True
    assert body["filename"] == "4382026Signed.json"
    assert base64.b64decode(body["signed_b64"]) == _bytes(BE) + b"SIGNED"
    req = h.requests[0]
    assert req.action == "sign_and_file" and req.summary["kind"] == "Bill of Entry"
    assert req.origin == ORIGIN


def test_declined_request(harness):
    h = harness(decide=lambda req: req.fail("cancelled", "Cancelled in the Broto Signer."))
    code, body, _ = h.sign()
    assert code == 200 and body == {"ok": False, "code": "cancelled",
                                     "message": "Cancelled in the Broto Signer."}


def test_no_decision_times_out(harness):
    h = harness(timeout=0.3)
    code, body, _ = h.sign()
    assert code == 504 and body["code"] == "timeout"
    assert h.requests[0].done   # the app sees it closed and dismisses its popup


def test_one_request_at_a_time(harness):
    release = threading.Event()
    h = harness(decide=lambda req: (release.wait(5), req.finish(b"ok")))
    first = {}
    t = threading.Thread(target=lambda: first.update(r=h.sign()))
    t.start()
    for _ in range(50):
        if h.requests:
            break
        time.sleep(0.05)
    code, body, _ = h.sign()
    assert code == 409 and body["code"] == "busy"
    release.set()
    t.join(5)
    assert first["r"][0] == 200


def test_second_server_on_same_port_fails_cleanly(harness):
    h = harness()
    other = bridge.BridgeServer(on_request=lambda r: None, status=dict, port=h.port)
    assert other.start() is False and "busy" in other.error


def test_dev_origin_via_env(harness, monkeypatch):
    monkeypatch.setenv("BROTO_SIGNER_ORIGINS", "http://localhost:3000/")
    h = harness()
    code, _, hdrs = h.call("OPTIONS", "/sign", origin="http://localhost:3000")
    assert code == 204 and hdrs["Access-Control-Allow-Origin"] == "http://localhost:3000"


# ------------------------------------------------------------ settings store
def test_settings_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    monkeypatch.setenv("HOME", str(tmp_path))
    assert secure_store.load_settings() == {}
    secure_store.update_settings(module="C:/x.dll", cert_id="ab12")
    secure_store.update_settings(cert_id=None, slot_index=1)
    assert secure_store.load_settings() == {"module": "C:/x.dll", "slot_index": 1}


@pytest.mark.skipif(sys.platform == "win32", reason="non-Windows behaviour")
def test_pin_saving_is_windows_only(tmp_path, monkeypatch):
    monkeypatch.setenv("HOME", str(tmp_path))
    assert secure_store.pin_saving_supported() is False
    with pytest.raises(OSError):
        secure_store.save_pin("1234")
    assert secure_store.load_pin() is None and secure_store.has_saved_pin() is False


@pytest.mark.skipif(sys.platform != "win32", reason="DPAPI is Windows-only")
def test_pin_dpapi_round_trip(tmp_path, monkeypatch):
    monkeypatch.setenv("APPDATA", str(tmp_path))
    secure_store.save_pin("12345678")
    raw = json.loads((tmp_path / "BrotoSigner" / "settings.json").read_text())["pin_dpapi"]
    assert "12345678" not in raw and b"12345678" not in base64.b64decode(raw)
    assert secure_store.load_pin() == "12345678"
    secure_store.forget_pin()
    assert secure_store.load_pin() is None
