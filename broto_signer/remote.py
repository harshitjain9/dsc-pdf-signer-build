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

Signing a run (Broto's "Sign & eSANCHIT", several files at once): the
heartbeat says jobs are waiting, we take the whole run in one call, and then
three things overlap — the next files download from Broto, the token signs
the current one, and signed files go back to Broto. The token itself signs
one file at a time and is logged in once for the run (a token chip does one
signature at a time, and every extra login is another chance to lock it).

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
from collections import deque
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List, Optional, Tuple

import bridge
import secure_store as store

DEFAULT_API_BASE = "https://api.brotoai.com"
API_PATH = "/api/cha/signer-devices"
HEARTBEAT_INTERVAL_S = 30
MIN_HEARTBEAT_S = 2             # the fastest pace Broto may ask for (while someone types the one-time code)
OFFLINE_AFTER_FAILURES = 2      # consecutive failed heartbeats before we call it "offline"
TIMEOUT_S = 15
MAX_CERTIFICATES = 10
MAX_JOBS_PER_DRAIN = 10         # signing jobs taken in one go before the next heartbeat
FETCH_LANES = 2                 # files downloading from Broto at the same time while the token signs
POST_LANES = 2                  # signed files going back to Broto at the same time (each holds a Broto DB slot)
READ_AHEAD = 2                  # downloaded files waiting for the token, at most

# Events handed to ``notify`` (payload in brackets):
#   paired (status dict) · pair_failed (message) · online (status dict) ·
#   offline (message) · revoked (message) · disconnected (None) ·
#   job_signed ({job, summary, timings}) · job_failed ({job, summary, code, message}) ·
#   run_done ({signed, failed, seconds}) — after a run of several jobs


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

    def claim_jobs(self, max_jobs: int = MAX_JOBS_PER_DRAIN) -> Dict[str, Any]:
        """Take up to ``max_jobs`` queued jobs at once → ``{"jobs": [{"id", "kind"}, …]}``.
        A Broto from before runs answers 404 (then we take them one at a time)."""
        return self._call("/jobs/claim", {"max": int(max_jobs)}, bearer=self.token)

    def job_content(self, job_id: str) -> Dict[str, Any]:
        """The exact bytes of one claimed job → ``{"job": {...} | None}`` (``None``:
        the file was deleted or changed, and Broto has failed that job itself)."""
        return self._call("/jobs/%s/content" % job_id, {}, bearer=self.token)

    def post_result(self, job_id: str, *, signed: Optional[bytes] = None, code: Optional[str] = None,
                    message: Optional[str] = None, timings: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        if signed is not None:
            body: Dict[str, Any] = {"ok": True, "signed_b64": base64.b64encode(signed).decode("ascii")}
        else:
            body = {"ok": False, "code": code or "failed", "message": (message or "")[:1000]}
        if timings:
            body["timings"] = {k: int(v) for k, v in timings.items() if isinstance(v, (int, float))}
        return self._call("/jobs/%s/result" % job_id, body, bearer=self.token)


class _OneCallSession:
    """A signing session made from a plain ``sign_fn`` (one token login per
    call) — what RemoteLink uses when the app gives no ``session_fn``."""

    def __init__(self, sign_fn: Optional[Callable[[bytes, Dict[str, Any]], bytes]]) -> None:
        self.sign_fn = sign_fn

    def sign(self, content: bytes, summary: Dict[str, Any]) -> bytes:
        if self.sign_fn is None:
            raise SignError("no_signer", "Remote signing isn't available in this build of the Broto Signer.")
        return self.sign_fn(content, summary)

    def close(self) -> None:
        pass


# ------------------------------------------------------------------ the link
class RemoteLink:
    """Pairing state + the heartbeat thread."""

    def __init__(self, report_fn: Callable[[], Dict[str, Any]],
                 notify: Callable[[str, Any], None], *,
                 sign_fn: Optional[Callable[[bytes, Dict[str, Any]], bytes]] = None,
                 session_fn: Optional[Callable[[], Any]] = None,
                 client_cls: Callable[..., Any] = RemoteClient,
                 interval_s: float = HEARTBEAT_INTERVAL_S) -> None:
        self.report_fn = report_fn
        self.notify = notify
        # sign_fn(content, summary) -> signed bytes, or raise SignError. Runs on
        # the heartbeat thread; the app must not touch Tk inside it.
        self.sign_fn = sign_fn
        # session_fn() -> an object with sign(content, summary) and close(): ONE
        # token login for every job of a run. Without it, sign_fn per job.
        self.session_fn = session_fn
        self.fetch_lanes = FETCH_LANES
        self.post_lanes = POST_LANES
        self.jobs_signed = 0
        self._count_lock = threading.Lock()
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
    def _open_session(self) -> Any:
        if self.session_fn is not None:
            return self.session_fn()
        return _OneCallSession(self.sign_fn)

    def _drain(self, client: Any) -> None:
        """Take the queued signing jobs: the whole run in one call and signed as
        a pipeline (``_run_batch``), or — from a Broto that predates runs — one
        at a time (``_drain_one_by_one``)."""
        try:
            out = client.claim_jobs(MAX_JOBS_PER_DRAIN)
        except RemoteError as e:
            if e.status in (404, 405):
                self._drain_one_by_one(client)
            else:
                self.last_error = e.message
            return
        jobs = out.get("jobs") if isinstance(out, dict) else None
        metas = [j for j in (jobs or []) if isinstance(j, dict) and j.get("id")]
        if metas:
            self._run_batch(client, metas)

    def _drain_one_by_one(self, client: Any) -> None:
        """Take queued signing jobs one at a time until Broto has none left (or
        MAX_JOBS_PER_DRAIN). Each job: same payload guard rail as the local
        popup → sign with the saved PIN → hand the result back. One token login
        serves the whole drain."""
        session = self._open_session()
        try:
            for _ in range(MAX_JOBS_PER_DRAIN):
                try:
                    out = client.next_job()
                except RemoteError as e:
                    self.last_error = e.message
                    return
                job = out.get("job") if isinstance(out, dict) else None
                if not isinstance(job, dict) or not job.get("id"):
                    return
                summary, signed, failure, _sign_s = self._sign_job(job, session)
                self._finish_job(client, job, summary, signed, failure, None)
        finally:
            session.close()

    def _run_batch(self, client: Any, metas: List[Dict[str, Any]]) -> None:
        """Sign a claimed run as a pipeline: up to ``fetch_lanes`` files download
        from Broto while the token signs, and each signed file goes back on one
        of ``post_lanes`` while the token moves on to the next. The token signs
        one file at a time, in claim order, logged in once for the whole run."""
        started = time.monotonic()
        fetch_pool = ThreadPoolExecutor(max_workers=max(1, self.fetch_lanes), thread_name_prefix="broto-fetch")
        post_pool = ThreadPoolExecutor(max_workers=max(1, self.post_lanes), thread_name_prefix="broto-send")
        todo = deque(metas)
        ahead: "deque[Tuple[Dict[str, Any], Any]]" = deque()   # downloads started, in claim order
        sent: List[Any] = []
        session = self._open_session()

        def top_up() -> None:
            while todo and len(ahead) < max(1, self.fetch_lanes, READ_AHEAD):
                meta = todo.popleft()
                ahead.append((meta, fetch_pool.submit(self._fetch_job, client, meta)))

        try:
            top_up()
            while ahead:
                meta, pending = ahead.popleft()
                top_up()                                   # the next downloads run while this one signs
                job, fetch_s, error = pending.result()
                if job is None:
                    if error is not None:                  # couldn't get the file from Broto
                        sent.append(post_pool.submit(self._report_failure, client, meta, None, error.code,
                                                     error.message))
                    continue                               # else Broto failed that job itself (file gone / changed)
                summary, signed, failure, sign_s = self._sign_job(job, session)
                timings = {"fetch_ms": int(fetch_s * 1000), "sign_ms": int(sign_s * 1000)}
                sent.append(post_pool.submit(self._finish_job, client, job, summary, signed, failure, timings))
        finally:
            session.close()                                # the token is free before the last files finish sending
            fetch_pool.shutdown(wait=True)
            post_pool.shutdown(wait=True)
        outcomes = [f.result() for f in sent if f.done() and not f.cancelled() and f.exception() is None]
        ok = sum(1 for o in outcomes if o is True)
        if len(metas) > 1:
            self.notify("run_done", {"signed": ok, "failed": len(metas) - ok,
                                     "seconds": round(time.monotonic() - started, 1)})

    def _fetch_job(self, client: Any, meta: Dict[str, Any]) -> Tuple[Optional[Dict[str, Any]], float,
                                                                      Optional[RemoteError]]:
        """Download one claimed job (a fetch lane): ``(job, seconds, None)``;
        ``(None, seconds, None)`` when Broto failed the job itself (the file was
        deleted or changed); ``(None, seconds, error)`` when we couldn't get it."""
        started = time.monotonic()
        error: Optional[RemoteError] = None
        for _attempt in range(2):                          # one retry, for a network blip only
            try:
                out = client.job_content(str(meta.get("id") or ""))
            except RemoteError as e:
                error = e
                if e.code != "network":
                    break
                continue
            except Exception as e:  # noqa: BLE001 - one bad answer must not stop the rest of the run
                error = RemoteError("failed", str(e) or repr(e))
                break
            job = out.get("job") if isinstance(out, dict) else None
            return (job if isinstance(job, dict) and job.get("id") else None), time.monotonic() - started, None
        return None, time.monotonic() - started, error

    def _sign_job(self, job: Dict[str, Any], session: Any) -> Tuple[Optional[Dict[str, Any]], Optional[bytes],
                                                                    Optional[Tuple[str, str]], float]:
        """Check one job's bytes and sign them on the token. Returns ``(summary,
        signed, failure, seconds)``: ``failure`` = ``(code, message)`` Broto
        shows the person who asked; ``seconds`` = the time spent signing."""
        summary: Optional[Dict[str, Any]] = None
        started = time.monotonic()
        try:
            content = base64.b64decode(str(job.get("content_b64") or ""), validate=True)
            summary = describe_job(job, content)             # the guard rail: filing JSON or a job's PDF, nothing else
            # The certificate of the job's ICEGATE ID (Broto sends it once an admin has
            # tied certificates to IDs) — the session signs with exactly that one.
            summary["cert_thumbprint"] = str(job.get("cert_thumbprint") or "").lower()
            summary["cert_holder"] = str(job.get("cert_holder") or "")
            started = time.monotonic()
            signed = session.sign(content, summary)
            if not isinstance(signed, (bytes, bytearray)) or not signed:
                raise SignError("failed", "The signer returned nothing.")
            return summary, bytes(signed), None, time.monotonic() - started
        except bridge.PayloadRejected as e:
            return summary, None, ("rejected_payload", str(e)), 0.0
        except SignError as e:
            return summary, None, (e.code, e.message), time.monotonic() - started
        except Exception as e:  # noqa: BLE001
            return summary, None, ("failed", str(e) or repr(e)), time.monotonic() - started

    def _finish_job(self, client: Any, job: Dict[str, Any], summary: Optional[Dict[str, Any]],
                    signed: Optional[bytes], failure: Optional[Tuple[str, str]],
                    timings: Optional[Dict[str, int]]) -> bool:
        """Hand one job's outcome back to Broto and tell the app (a send lane in
        a run). True when Broto took the signed file."""
        if failure is not None or signed is None:
            code, message = failure or ("failed", "The signer returned nothing.")
            self._report_failure(client, job, summary, code, message)
            return False
        sent_at = time.monotonic()
        extra = {"timings": timings} if timings else {}
        try:
            out = client.post_result(str(job.get("id") or ""), signed=signed, **extra)
        except RemoteError as e:                           # handing the result back failed
            self.last_error = e.message
            self.notify("job_failed", {"job": job, "summary": summary, "code": e.code, "message": e.message})
            return False
        except Exception as e:  # noqa: BLE001
            self._report_failure(client, job, summary, "failed", str(e) or repr(e))
            return False
        status = out.get("status") if isinstance(out, dict) else None
        if status and status != "signed":                  # Broto checked the file and refused it
            self.notify("job_failed", {"job": job, "summary": summary,
                                       "code": out.get("error_code") or "failed",
                                       "message": out.get("error_message") or "Broto did not keep the signed file."})
            return False
        with self._count_lock:
            self.jobs_signed += 1
        done = dict(timings or {}, send_ms=int((time.monotonic() - sent_at) * 1000)) if timings else {}
        self.notify("job_signed", {"job": job, "summary": summary, "timings": done})
        return True

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
        if isinstance(iv, (int, float)) and MIN_HEARTBEAT_S <= iv <= 600:
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
