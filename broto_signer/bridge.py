"""
broto_signer.bridge — one-click signing for Broto's "File on ICEGATE (API)".

While the signer app is open it listens on http://127.0.0.1:47811 (this PC
only). Broto's web app, running in the user's browser on the same PC, sends it
the unsigned ICEGATE JSON; the signer shows a confirmation popup (what will be
signed, which certificate, PIN if not saved); on "Sign" it returns the signed
JSON to the browser, which uploads it to Broto — Broto's server then submits to
ICEGATE. The signer itself never talks to ICEGATE or to Broto's server.

Guard rails (all enforced here, none trusted to the caller):
  * binds to 127.0.0.1 only — unreachable from the network;
  * the Host header must be 127.0.0.1/localhost (blocks DNS-rebinding pages);
  * signing requests must come from an allow-listed Origin (Broto's site);
  * only ICEGATE BE/SB filing JSON is accepted ({headerField, master}, CACHI01
    or CACHE01, not already signed) — it is never a general signing oracle;
  * every request needs the user's click in the popup; one at a time.

No UI and no token code here — the app wires ``on_request`` to its popup and
calls ``SignRequest.finish`` / ``fail``. Standard library only.
"""
from __future__ import annotations

import base64
import json
import os
import socket
import sys
import threading
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any, Callable, Dict, Optional

BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 47811
PROTOCOL_VERSION = 1

DEFAULT_ORIGINS = ("https://brotoai.com", "https://www.brotoai.com")
MAX_BODY_BYTES = 25 * 1024 * 1024
DECISION_TIMEOUT_S = 300           # how long a request waits for the user's click

_MESSAGE_KINDS = {"CACHI01": "Bill of Entry", "CACHE01": "Shipping Bill"}


def allowed_origins() -> set:
    """Broto's site, plus any extras from BROTO_SIGNER_ORIGINS (comma-separated;
    for local development, e.g. http://localhost:3000)."""
    extra = os.environ.get("BROTO_SIGNER_ORIGINS", "")
    return set(DEFAULT_ORIGINS) | {o.strip().rstrip("/") for o in extra.split(",") if o.strip()}


class PayloadRejected(ValueError):
    """The request is not an unsigned ICEGATE BE/SB filing JSON."""


def _first(master: Dict[str, Any], key: str) -> Dict[str, Any]:
    rows = master.get(key)
    if isinstance(rows, list) and rows and isinstance(rows[0], dict):
        return rows[0]
    return {}


def describe_payload(content: bytes) -> Dict[str, Any]:
    """Validate an unsigned ICEGATE filing and summarise it for the confirmation
    popup. Every shown value is read from the payload itself, never from the
    caller's labels, so the user sees exactly what their DSC will sign."""
    try:
        doc = json.loads(content.decode("utf-8"))
    except Exception:
        raise PayloadRejected("Not valid JSON.")
    if not isinstance(doc, dict) or set(doc.keys()) != {"headerField", "master"}:
        if isinstance(doc, dict) and "digSign" in doc:
            raise PayloadRejected("This filing is already signed.")
        raise PayloadRejected("Not an ICEGATE filing (expected headerField + master).")
    head, master = doc["headerField"], doc["master"]
    if not isinstance(head, dict) or not isinstance(master, dict):
        raise PayloadRejected("Not an ICEGATE filing (headerField/master must be objects).")
    msg = str(head.get("messageID") or "")
    if msg not in _MESSAGE_KINDS:
        raise PayloadRejected("Unsupported filing type %r (only BE CACHI01 / SB CACHE01)." % msg)
    if msg == "CACHI01":
        main = _first(master, "beModel")
        party, iec = main.get("nameOfImporter"), main.get("iecCode")
        items = len(master.get("itemsModel") or [])
    else:
        main = _first(master, "sbModel")
        party, iec = main.get("impExpName"), main.get("importerExporterCode")
        items = len(master.get("itemModel") or [])
    return {
        "kind": _MESSAGE_KINDS[msg],
        "message_id": msg,
        "party": str(party or "").strip(),
        "iec": str(iec or "").strip(),
        "job_number": head.get("jobNumber"),
        "job_date": str(head.get("jobDate") or ""),
        "sender_id": str(head.get("senderID") or ""),
        "test_mode": str(head.get("indicator") or "P").upper() == "T",
        "invoices": len(master.get("invoiceModel") or []),
        "items": items,
    }


class SignRequest:
    """One pending signing request, handed from the HTTP thread to the UI."""

    def __init__(self, origin: str, filename: str, content: bytes, summary: Dict[str, Any],
                 action: str) -> None:
        self.id = uuid.uuid4().hex
        self.origin = origin
        self.filename = filename
        self.content = content
        self.summary = summary
        self.action = action              # "sign" | "sign_and_file" (wording only)
        self._done = threading.Event()
        self.signed: Optional[bytes] = None
        self.error_code: Optional[str] = None
        self.error_message: Optional[str] = None

    def finish(self, signed: bytes) -> None:
        if not self._done.is_set():
            self.signed = signed
            self._done.set()

    def fail(self, code: str, message: str) -> None:
        if not self._done.is_set():
            self.error_code, self.error_message = code, message
            self._done.set()

    @property
    def done(self) -> bool:
        return self._done.is_set()

    def wait(self, timeout: float) -> bool:
        return self._done.wait(timeout)


class _ExclusiveServer(ThreadingHTTPServer):
    """On Windows SO_REUSEADDR lets a second process bind the same port, so ask
    for the port exclusively instead (a second copy of the app then fails to
    start its bridge rather than silently sharing it)."""
    allow_reuse_address = sys.platform != "win32"
    daemon_threads = True

    def server_bind(self) -> None:
        if sys.platform == "win32" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
        super().server_bind()


class BridgeServer:
    def __init__(self, on_request: Callable[[SignRequest], None],
                 status: Callable[[], Dict[str, Any]], port: int = BRIDGE_PORT,
                 decision_timeout: float = DECISION_TIMEOUT_S) -> None:
        self.on_request = on_request
        self.status = status
        self.port = port
        self.decision_timeout = decision_timeout
        self._httpd: Optional[_ExclusiveServer] = None
        self._busy = threading.Lock()
        self.error: Optional[str] = None

    def start(self) -> bool:
        bridge = self

        class Handler(_Handler):
            server_bridge = bridge

        try:
            self._httpd = _ExclusiveServer((BRIDGE_HOST, self.port), Handler)
        except OSError as e:
            self.error = "Port %d is busy (is another Broto Signer open?): %s" % (self.port, e)
            return False
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()
        return True

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd.server_close()
            self._httpd = None


class _Handler(BaseHTTPRequestHandler):
    server_bridge: BridgeServer
    server_version = "BrotoSigner"

    def log_message(self, *_a) -> None:  # keep the console quiet
        pass

    # ------------------------------------------------------------ helpers
    def _origin(self) -> str:
        return (self.headers.get("Origin") or "").rstrip("/")

    def _host_ok(self) -> bool:
        host = (self.headers.get("Host") or "").lower()
        return host in {"127.0.0.1:%d" % self.server_bridge.port, "localhost:%d" % self.server_bridge.port}

    def _send(self, code: int, body: Dict[str, Any]) -> None:
        data = json.dumps(body).encode("utf-8")
        self.send_response(code)
        origin = self._origin()
        if origin and origin in allowed_origins():
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Vary", "Origin")
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _guard(self, require_origin: bool) -> bool:
        if not self._host_ok():
            self._send(403, {"ok": False, "code": "bad_host", "message": "Forbidden host."})
            return False
        origin = self._origin()
        if origin and origin not in allowed_origins():
            self._send(403, {"ok": False, "code": "bad_origin", "message": "This website may not use the Broto Signer."})
            return False
        if require_origin and not origin:
            self._send(403, {"ok": False, "code": "bad_origin", "message": "Missing Origin."})
            return False
        return True

    # ------------------------------------------------------------ verbs
    def do_OPTIONS(self) -> None:  # noqa: N802 - CORS / Private-Network preflight
        origin = self._origin()
        if not self._host_ok() or origin not in allowed_origins():
            self.send_response(403)
            self.send_header("Content-Length", "0")
            self.end_headers()
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", origin)
        self.send_header("Vary", "Origin")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.send_header("Access-Control-Allow-Private-Network", "true")
        self.send_header("Access-Control-Max-Age", "600")
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?")[0] != "/status":
            self._send(404, {"ok": False, "code": "not_found"})
            return
        if not self._guard(require_origin=False):
            return
        try:
            st = dict(self.server_bridge.status())
        except Exception:  # noqa: BLE001
            st = {}
        st.update({"ok": True, "app": "broto-signer", "protocol": PROTOCOL_VERSION})
        self._send(200, st)

    def do_POST(self) -> None:  # noqa: N802
        if self.path.split("?")[0] != "/sign":
            self._send(404, {"ok": False, "code": "not_found"})
            return
        if not self._guard(require_origin=True):
            return
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError:
            length = 0
        if length <= 0 or length > MAX_BODY_BYTES:
            self._send(413 if length > MAX_BODY_BYTES else 400,
                       {"ok": False, "code": "bad_request", "message": "Empty or oversized request."})
            return
        try:
            body = json.loads(self.rfile.read(length).decode("utf-8"))
            content = base64.b64decode(body["content_b64"], validate=True)
            filename = os.path.basename(str(body.get("filename") or "filing.json"))[:120]
            action = "sign_and_file" if body.get("action") == "sign_and_file" else "sign"
        except Exception:
            self._send(400, {"ok": False, "code": "bad_request", "message": "Malformed request."})
            return
        try:
            summary = describe_payload(content)
        except PayloadRejected as e:
            self._send(400, {"ok": False, "code": "rejected_payload", "message": str(e)})
            return

        bridge = self.server_bridge
        if not bridge._busy.acquire(blocking=False):
            self._send(409, {"ok": False, "code": "busy",
                             "message": "The Broto Signer is already waiting on another request."})
            return
        try:
            req = SignRequest(self._origin(), filename, content, summary, action)
            bridge.on_request(req)
            if not req.wait(bridge.decision_timeout):
                req.fail("timeout", "No response in the Broto Signer — the request timed out.")
        finally:
            bridge._busy.release()

        if req.signed is not None:
            stem = os.path.splitext(filename)[0]
            self._send(200, {"ok": True, "filename": stem + "Signed.json",
                             "signed_b64": base64.b64encode(req.signed).decode("ascii")})
        else:
            code = req.error_code or "failed"
            status = 200 if code == "cancelled" else (504 if code == "timeout" else 500)
            self._send(status, {"ok": False, "code": code, "message": req.error_message or "Signing failed."})
