"""
broto_signer.remote — pair this Signer with a Broto firm for remote signing.

The DSC token stays plugged into this PC. Once paired, staff working elsewhere
can (in the next step) ask Broto to have THIS PC sign a filing. This module is
the trust link only: pairing, the device token, and a heartbeat that tells
Broto the PC is on, the token is plugged in and which certificate it holds.

How pairing works (server side: cha_api/signer_devices.py):
  1. A Broto admin opens Settings ▸ DSC computers ▸ Add computer and gets a
     one-time code (10-minute life).
  2. Whoever sits at this PC types it into the Signer's Settings ▸ Remote
     signing. We POST it to Broto with a self-report (hostname, version, token
     plugged in, PIN saved, certificates) and get back a device token.
  3. The token is stored with the saved PIN's protection (Windows DPAPI —
     same Windows login, same PC; plain text only on non-Windows dev boxes) and
     sent as a bearer on every heartbeat. Broto keeps only its hash.
  4. Every HEARTBEAT_INTERVAL_S we report again. A 401 ``revoked`` /
     ``unknown_device`` means Broto no longer trusts this PC: we forget the
     token and tell the user. Network trouble is reported as "offline" and
     retried forever — the PC may simply have lost its connection.

Standard library only (urllib honours the system proxy). No UI here: the app
supplies ``report_fn`` (a snapshot of its state, safe to read off-thread) and
``notify(event, payload)`` (called from worker threads — route it through the
app's queue).
"""
from __future__ import annotations

import base64
import json
import os
import platform
import socket
import threading
import time
import urllib.error
import urllib.request
from typing import Any, Callable, Dict, Optional

import bridge
import secure_store as store

DEFAULT_API_BASE = "https://api.brotoai.com"
API_PATH = "/api/cha/signer-devices"
HEARTBEAT_INTERVAL_S = 30
OFFLINE_AFTER_FAILURES = 2      # consecutive failed heartbeats before we call it "offline"
TIMEOUT_S = 15
MAX_CERTIFICATES = 10
MAX_JOBS_PER_DRAIN = 10         # signing jobs taken in one go before the next heartbeat

# Events handed to ``notify`` (payload in brackets):
#   paired (status dict) · pair_failed (message) · online (status dict) ·
#   offline (message) · revoked (message) · disconnected (None) ·
#   job_signed ({job, summary}) · job_failed ({job, summary, code, message})


class RemoteError(Exception):
    """A failed call to Broto with a stable ``code`` (``network`` when we never
    got an answer, else the server's code such as ``invalid_code`` / ``revoked``)."""

    def __init__(self, code: str, message: str, status: int = 0) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status = status


class SignError(Exception):
    """The app's ``sign_fn`` could not sign: a stable ``code`` Broto shows the
    requester (``pin_not_saved``, ``token_missing``, ``wrong_pin``, ``pin_locked``,
    ``driver_missing``, ``failed``) plus a plain message."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def default_api_base() -> str:
    """Broto's API. ``BROTO_API_BASE`` (dev: http://localhost:8000) beats the
    base remembered at pairing time, which beats production."""
    return (os.environ.get("BROTO_API_BASE") or store.load_settings().get("remote_api_base")
            or DEFAULT_API_BASE).rstrip("/")


def _hostname() -> str:
    try:
        return socket.gethostname() or platform.node() or "this PC"
    except Exception:  # noqa: BLE001
        return "this PC"


def _platform() -> str:
    try:
        return ("%s %s" % (platform.system(), platform.release())).strip()
    except Exception:  # noqa: BLE001
        return ""


MAX_PDF_BYTES = 25 * 1024 * 1024
MAX_FLATFILE_BYTES = 10 * 1024 * 1024
_FLATFILE_KINDS = {"CACHI01": "Bill of Entry flat file", "CACHE01": "Shipping Bill flat file"}


def describe_flatfile(content: bytes) -> Dict[str, Any]:
    """Validate an ICES 1.5 flat file (.be / .sb) by its HREC envelope — the
    header record ``HREC ^] ZZ ^] <sender> ^] ZZ ^] <receiver> ^] ICES1_5 ^] T|P
    ^] ^] <messageID> ^] <seq> ^] <date> ^] <time>`` — and refuse anything that
    is already signed. Never a general text-signing oracle."""
    if len(content) > MAX_FLATFILE_BYTES:
        raise bridge.PayloadRejected("Flat file is over 10 MB.")
    if b"<START-SIGNATURE>" in content:
        raise bridge.PayloadRejected("This flat file is already signed.")
    first = content.split(b"\n", 1)[0].rstrip(b"\r")
    fields = first.split(b"\x1d")
    if len(fields) < 9 or fields[0] != b"HREC":
        raise bridge.PayloadRejected("Not an ICEGATE flat file (no HREC header).")
    message = fields[8].decode("ascii", "replace").strip()
    if message not in _FLATFILE_KINDS:
        raise bridge.PayloadRejected("Unsupported flat file type %r (only BE CACHI01 / SB CACHE01)." % message)
    return {
        "format": "flatfile",
        "kind": _FLATFILE_KINDS[message],
        "message_id": message,
        "sender_id": fields[2].decode("ascii", "replace").strip(),
        "receiver_id": fields[4].decode("ascii", "replace").strip() if len(fields) > 4 else "",
        "test_mode": fields[6].decode("ascii", "replace").strip().upper() == "T" if len(fields) > 6 else False,
        "size": len(content),
    }


def describe_job(job: Dict[str, Any], content: bytes) -> Dict[str, Any]:
    """What a remote job is, checked against the bytes themselves (never the
    server's labels alone). ``format`` tells ``sign_fn`` which signature to
    apply:
      * ``json`` — an unsigned ICEGATE BE/SB filing (``bridge.describe_payload``,
        the same guard rail as the local popup);
      * ``flatfile`` — an unsigned ICES .be/.sb flat file (HREC envelope,
        ``describe_flatfile``), signed with the ICEGATE tag envelope;
      * ``pdf`` — one of the job's own supporting documents: must be a PDF, under
        MAX_PDF_BYTES, and hash to the sha256 Broto announced for it.
    Anything else raises ``bridge.PayloadRejected``."""
    kind = str(job.get("kind") or "filing")
    if kind == "flatfile":
        want = str(job.get("sha256") or "").lower()
        if want:
            import hashlib
            if hashlib.sha256(content).hexdigest() != want:
                raise bridge.PayloadRejected("The flat file's fingerprint doesn't match what Broto announced.")
        summary = describe_flatfile(content)
        summary["filename"] = str(job.get("filename") or "")
        summary["job_number"] = job.get("job_seq") or job.get("job_id")
        return summary
    if kind == "document":
        if not content.startswith(b"%PDF"):
            raise bridge.PayloadRejected("Not a PDF file.")
        if len(content) > MAX_PDF_BYTES:
            raise bridge.PayloadRejected("PDF is over 25 MB.")
        want = str(job.get("sha256") or "").lower()
        if want:
            import hashlib
            if hashlib.sha256(content).hexdigest() != want:
                raise bridge.PayloadRejected("The PDF's fingerprint doesn't match what Broto announced.")
        return {
            "format": "pdf",
            "kind": "PDF document",
            "filename": str(job.get("filename") or "document.pdf"),
            "doc_type": str(job.get("doc_type") or ""),
            "job_number": job.get("job_seq") or job.get("job_id"),
            "size": len(content),
        }
    if kind != "filing":
        raise bridge.PayloadRejected("Unknown job kind %r." % kind)
    summary = bridge.describe_payload(content)
    summary["format"] = "json"
    return summary


def device_report(snapshot: Dict[str, Any], version: str) -> Dict[str, Any]:
    """The self-report sent on pair + every heartbeat, built from the app's
    UI-thread snapshot (``token_connected``, ``pin_saved``, ``certificates``)."""
    certs = snapshot.get("certificates") or []
    return {
        "name": _hostname()[:80],
        "signer_version": str(version or "")[:40],
        "platform": _platform()[:80],
        "token_connected": bool(snapshot.get("token_connected")),
        "pin_saved": bool(snapshot.get("pin_saved")),
        "certificates": [dict(c) for c in certs if isinstance(c, dict)][:MAX_CERTIFICATES],
    }


# ------------------------------------------------------------------ HTTP client
class RemoteClient:
    """Thin JSON-over-HTTPS client. ``opener`` is ``urllib.request.urlopen``
    unless a test injects a fake."""

    def __init__(self, base_url: str, token: Optional[str] = None, timeout: float = TIMEOUT_S,
                 opener: Optional[Callable[..., Any]] = None) -> None:
        self.base_url = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self._open = opener or urllib.request.urlopen

    def _call(self, path: str, body: Dict[str, Any], *, bearer: Optional[str] = None) -> Dict[str, Any]:
        data = json.dumps(body).encode("utf-8")
        req = urllib.request.Request(
            self.base_url + API_PATH + path, data=data, method="POST",
            headers={"Content-Type": "application/json", "Accept": "application/json",
                     "User-Agent": "BrotoSigner"})
        if bearer:
            req.add_header("Authorization", "Bearer " + bearer)
        try:
            with self._open(req, timeout=self.timeout) as resp:
                raw = resp.read()
                status = int(getattr(resp, "status", 200) or 200)
        except urllib.error.HTTPError as e:
            try:
                raw = e.read()
            except Exception:  # noqa: BLE001
                raw = b""
            status = e.code
        except (urllib.error.URLError, OSError, socket.timeout) as e:
            reason = getattr(e, "reason", None) or e
            raise RemoteError("network", "Couldn't reach Broto (%s)." % (str(reason)[:120] or "no answer"))
        try:
            out = json.loads(raw.decode("utf-8")) if raw else {}
        except ValueError:
            out = {}
        if not isinstance(out, dict):
            out = {}
        if status >= 400:
            detail = out.get("detail")
            code = msg = None
            if isinstance(detail, dict):
                code, msg = detail.get("code"), detail.get("message")
            elif isinstance(detail, str):
                msg = detail
            raise RemoteError(str(code or "http_%d" % status), str(msg or "Broto answered HTTP %d." % status), status)
        return out

    def pair(self, code: str, report: Dict[str, Any]) -> Dict[str, Any]:
        return self._call("/pair", dict(report, code=code))

    def heartbeat(self, report: Dict[str, Any]) -> Dict[str, Any]:
        return self._call("/heartbeat", report, bearer=self.token)

    def unpair(self) -> Dict[str, Any]:
        return self._call("/unpair", {}, bearer=self.token)

    def next_job(self) -> Dict[str, Any]:
        """Claim the oldest queued signing job → ``{"job": {...} | None}``."""
        return self._call("/jobs/next", {}, bearer=self.token)

    def post_result(self, job_id: str, *, signed: Optional[bytes] = None, code: Optional[str] = None,
                    message: Optional[str] = None) -> Dict[str, Any]:
        if signed is not None:
            body: Dict[str, Any] = {"ok": True, "signed_b64": base64.b64encode(signed).decode("ascii")}
        else:
            body = {"ok": False, "code": code or "failed", "message": (message or "")[:1000]}
        return self._call("/jobs/%s/result" % job_id, body, bearer=self.token)


# ------------------------------------------------------------------ the link
class RemoteLink:
    """Pairing state + the heartbeat thread."""

    def __init__(self, report_fn: Callable[[], Dict[str, Any]],
                 notify: Callable[[str, Any], None], *,
                 sign_fn: Optional[Callable[[bytes, Dict[str, Any]], bytes]] = None,
                 client_cls: Callable[..., Any] = RemoteClient,
                 interval_s: float = HEARTBEAT_INTERVAL_S) -> None:
        self.report_fn = report_fn
        self.notify = notify
        # sign_fn(content, summary) -> signed bytes, or raise SignError. Runs on
        # the heartbeat thread; the app must not touch Tk inside it.
        self.sign_fn = sign_fn
        self.jobs_signed = 0
        self._client_cls = client_cls
        self.interval_s = float(interval_s)
        self.api_base = default_api_base()
        self.token: Optional[str] = store.load_remote_token()
        s = store.load_settings()
        self.device_id: Optional[str] = s.get("remote_device_id") or None
        self.firm_name: Optional[str] = s.get("remote_firm_name") or None
        self.device_name: Optional[str] = s.get("remote_device_name") or None
        self.last_ok: Optional[float] = None
        self.last_error: Optional[str] = None
        self._failures = 0
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None

    # ----------------------------------------------------------- state
    @property
    def paired(self) -> bool:
        return bool(self.token)

    @property
    def online(self) -> bool:
        return self.paired and self.last_ok is not None and self._failures < OFFLINE_AFTER_FAILURES

    def status(self) -> Dict[str, Any]:
        return {
            "paired": self.paired,
            "online": self.online,
            "firm_name": self.firm_name,
            "device_name": self.device_name,
            "device_id": self.device_id,
            "api_base": self.api_base,
            "last_ok": self.last_ok,
            "last_error": self.last_error,
            "jobs_signed": self.jobs_signed,
        }

    # ----------------------------------------------------------- thread
    def start(self) -> None:
        if self._thread is not None:
            return
        self._thread = threading.Thread(target=self._loop, name="broto-remote", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def beat_now(self) -> None:
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            if self.token:
                try:
                    self._beat()
                except Exception:  # noqa: BLE001 - the loop must survive anything
                    pass
            self._wake.wait(self.interval_s)
            self._wake.clear()

    def _beat(self) -> None:
        token = self.token
        if not token:
            return
        client = self._client_cls(self.api_base, token)
        try:
            out = client.heartbeat(self.report_fn())
        except RemoteError as e:
            if e.code in ("revoked", "unknown_device"):
                self._forget()
                self.notify("revoked", e.message)
                return
            self._fail(e.message)
            return
        except Exception as e:  # noqa: BLE001
            self._fail(str(e) or repr(e))
            return
        was_down = self.last_ok is None or self._failures >= OFFLINE_AFTER_FAILURES
        self.last_ok = time.time()
        self._failures = 0
        self.last_error = None
        self._absorb(out)
        if was_down:
            self.notify("online", self.status())
        try:
            waiting = int(out.get("jobs_waiting") or 0)
        except (TypeError, ValueError):
            waiting = 0
        if waiting > 0 and self.token:
            self._drain(client)

    # ----------------------------------------------------------- signing jobs
    def _drain(self, client: Any) -> None:
        """Take queued signing jobs one at a time until Broto has none left (or
        MAX_JOBS_PER_DRAIN). Each job: same payload guard rail as the local
        popup → sign_fn with the saved PIN → hand the result back."""
        for _ in range(MAX_JOBS_PER_DRAIN):
            try:
                out = client.next_job()
            except RemoteError as e:
                self.last_error = e.message
                return
            job = out.get("job") if isinstance(out, dict) else None
            if not isinstance(job, dict) or not job.get("id"):
                return
            self._handle_job(client, job)

    def _handle_job(self, client: Any, job: Dict[str, Any]) -> None:
        job_id = str(job.get("id") or "")
        summary: Optional[Dict[str, Any]] = None
        try:
            content = base64.b64decode(str(job.get("content_b64") or ""), validate=True)
            summary = describe_job(job, content)             # the guard rail: filing JSON or a job's PDF, nothing else
            # The certificate of the job's ICEGATE ID (Broto sends it once an admin has
            # tied certificates to IDs) — sign_fn signs with exactly that one.
            summary["cert_thumbprint"] = str(job.get("cert_thumbprint") or "").lower()
            summary["cert_holder"] = str(job.get("cert_holder") or "")
            if self.sign_fn is None:
                raise SignError("no_signer", "Remote signing isn't available in this build of the Broto Signer.")
            signed = self.sign_fn(content, summary)
            if not isinstance(signed, (bytes, bytearray)) or not signed:
                raise SignError("failed", "The signer returned nothing.")
            client.post_result(job_id, signed=bytes(signed))
            self.jobs_signed += 1
            self.notify("job_signed", {"job": job, "summary": summary})
        except bridge.PayloadRejected as e:
            self._report_failure(client, job, summary, "rejected_payload", str(e))
        except SignError as e:
            self._report_failure(client, job, summary, e.code, e.message)
        except RemoteError as e:                               # handing the result back failed
            self.last_error = e.message
            self.notify("job_failed", {"job": job, "summary": summary, "code": e.code, "message": e.message})
        except Exception as e:  # noqa: BLE001
            self._report_failure(client, job, summary, "failed", str(e) or repr(e))

    def _report_failure(self, client: Any, job: Dict[str, Any], summary: Optional[Dict[str, Any]],
                        code: str, message: str) -> None:
        try:
            client.post_result(str(job.get("id") or ""), code=code, message=message)
        except Exception:  # noqa: BLE001 - Broto will time the claim out on its own
            pass
        self.notify("job_failed", {"job": job, "summary": summary, "code": code, "message": message})

    def _fail(self, message: str) -> None:
        self._failures += 1
        self.last_error = message
        if self._failures == OFFLINE_AFTER_FAILURES:
            self.notify("offline", message)

    def _absorb(self, out: Dict[str, Any]) -> None:
        iv = out.get("heartbeat_interval_s")
        if isinstance(iv, (int, float)) and 5 <= iv <= 600:
            self.interval_s = float(iv)
        if out.get("firm_name"):
            self.firm_name = str(out["firm_name"])
        if out.get("device_name"):
            self.device_name = str(out["device_name"])

    # ----------------------------------------------------------- pairing
    def pair(self, code: str, api_base: Optional[str] = None) -> Dict[str, Any]:
        """Redeem a pairing code (blocking — the app calls it on a thread).
        Raises RemoteError; on success the token is stored and a heartbeat is
        triggered right away."""
        base = (api_base or self.api_base).rstrip("/")
        out = self._client_cls(base).pair(code.strip(), self.report_fn())
        token = out.get("device_token")
        if not isinstance(token, str) or not token:
            raise RemoteError("bad_response", "Broto didn't return a device token — try again.")
        with self._lock:
            store.save_remote_token(token)
            store.update_settings(remote_api_base=base,
                                  remote_device_id=out.get("device_id") or None,
                                  remote_firm_name=out.get("firm_name") or None,
                                  remote_device_name=out.get("device_name") or None)
            self.api_base = base
            self.token = token
            self.device_id = out.get("device_id") or None
            self.firm_name = out.get("firm_name") or None
            self.device_name = out.get("device_name") or None
            self.last_ok = time.time()
            self._failures = 0
            self.last_error = None
            self._absorb(out)
        self.notify("paired", self.status())
        self.beat_now()
        return out

    def pair_async(self, code: str, api_base: Optional[str] = None) -> None:
        def work() -> None:
            try:
                self.pair(code, api_base)
            except RemoteError as e:
                self.notify("pair_failed", e.message)
            except Exception as e:  # noqa: BLE001
                self.notify("pair_failed", str(e) or repr(e))
        threading.Thread(target=work, name="broto-remote-pair", daemon=True).start()

    def disconnect(self) -> None:
        """Forget the pairing here and (best effort) tell Broto."""
        token = self.token
        if token:
            try:
                self._client_cls(self.api_base, token).unpair()
            except Exception:  # noqa: BLE001 - forgetting locally is what matters
                pass
        self._forget()
        self.notify("disconnected", None)

    def disconnect_async(self) -> None:
        threading.Thread(target=self.disconnect, name="broto-remote-unpair", daemon=True).start()

    def _forget(self) -> None:
        with self._lock:
            store.forget_remote_token()
            store.update_settings(remote_device_id=None, remote_firm_name=None, remote_device_name=None)
            self.token = None
            self.device_id = None
            self.firm_name = None
            self.device_name = None
            self.last_ok = None
            self._failures = 0
