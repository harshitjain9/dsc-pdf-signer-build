"""
broto_signer.account — the Broto login that unlocks the Signer.

Only Broto users may use the app: it opens on a login screen (the same email +
password as brotoai.com, via ``POST /api/cha/auth/login``) and nothing else —
signing, the one-click bridge, remote signing — starts until that succeeds.

The session is Broto's normal 24-hour token. It is kept like the saved PIN
(Windows DPAPI, current-user scope — only the same Windows login on the same
PC can read it; plain text in settings.json only on non-Windows dev boxes) and
swapped for a fresh one (``POST /api/cha/auth/refresh``) at start-up and every
REFRESH_INTERVAL_S, so an office PC that stays on stays logged in. Broto
answering 401 (user removed, password changed, token too old) logs the app
out. When Broto can't be reached, a token that has not expired yet keeps
working — the PC may simply have lost its connection.

Standard library only (urllib honours the system proxy). No UI here.
"""
from __future__ import annotations

import base64
import json
import socket
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable, Dict, Optional

import secure_store as store

AUTH_PATH = "/api/cha/auth"
TIMEOUT_S = 20
REFRESH_INTERVAL_S = 4 * 3600      # well inside the token's 24 hours


class ApiError(Exception):
    """A failed call to Broto: ``status`` 0 means no answer (network)."""

    def __init__(self, status: int, message: str) -> None:
        super().__init__(message)
        self.status = status
        self.message = message


def call_json(base_url: str, path: str, *, method: str = "GET", body: Optional[Dict[str, Any]] = None,
              bearer: Optional[str] = None, query: Optional[Dict[str, str]] = None,
              opener: Optional[Callable[..., Any]] = None, timeout: float = TIMEOUT_S) -> Dict[str, Any]:
    """One JSON request to Broto's API. Raises ApiError."""
    url = base_url.rstrip("/") + path
    if query:
        url += "?" + urllib.parse.urlencode(query)
    data = json.dumps(body).encode("utf-8") if body is not None else None
    req = urllib.request.Request(url, data=data, method=method,
                                 headers={"Accept": "application/json", "User-Agent": "BrotoSigner"})
    if data is not None:
        req.add_header("Content-Type", "application/json")
    if bearer:
        req.add_header("Authorization", "Bearer " + bearer)
    try:
        with (opener or urllib.request.urlopen)(req, timeout=timeout) as resp:
            raw = resp.read()
            status = int(getattr(resp, "status", 200) or 200)
    except urllib.error.HTTPError as e:
        try:
            raw = e.read()
        except Exception:  # noqa: BLE001
            raw = b""
        status = e.code
    except (urllib.error.URLError, OSError, socket.timeout) as e:
        raise ApiError(0, "Can't reach Broto (%s)." % (str(getattr(e, "reason", None) or e)[:120] or "no answer"))
    try:
        out = json.loads(raw.decode("utf-8")) if raw else {}
    except ValueError:
        out = {}
    if not isinstance(out, dict):
        out = {}
    if status >= 400:
        detail = out.get("detail")
        if isinstance(detail, dict):
            detail = detail.get("message")
        raise ApiError(status, str(detail or "Broto answered HTTP %d." % status))
    return out


def token_expiry(token: str) -> float:
    """The ``exp`` inside a Broto token (seconds since 1970), 0 when unreadable.
    Read without checking the signature — only used to decide whether a token
    is still worth using while Broto can't be reached."""
    try:
        payload = token.split(".")[0]
        data = json.loads(base64.urlsafe_b64decode(payload + "=" * (-len(payload) % 4)))
        return float(data.get("exp") or 0)
    except Exception:  # noqa: BLE001
        return 0.0


def login_error_message(err: ApiError) -> str:
    """What the login screen shows. Plain words, with the step to fix it."""
    if err.status == 0:
        return "Can't reach Broto. Check the internet on this computer and try again."
    if err.status == 401:
        return "Wrong email or password. Use the same ones you use on brotoai.com."
    if err.status == 429:
        return "Too many tries. Wait one minute, then try again."
    if err.status == 422:
        return "Type your email and password."
    return "Broto could not log you in right now. Try again in a few minutes."


class Account:
    """The logged-in Broto user (or nobody)."""

    def __init__(self, api_base: str, opener: Optional[Callable[..., Any]] = None,
                 now: Callable[[], float] = time.time) -> None:
        self.api_base = api_base.rstrip("/")
        self._open = opener
        self._now = now
        s = store.load_settings()
        self.token: Optional[str] = store.load_session_token()
        self.email: str = s.get("session_email") or ""
        self.name: str = s.get("session_name") or ""
        self.firm_name: str = s.get("session_firm") or ""
        if self.token and (s.get("session_api_base") or self.api_base).rstrip("/") != self.api_base:
            self._clear()                  # logged in to another Broto server (dev vs production)

    # ----------------------------------------------------------- state
    @property
    def logged_in(self) -> bool:
        return bool(self.token) and token_expiry(self.token or "") > self._now()

    def label(self) -> str:
        who = self.name or self.email
        return "%s (%s)" % (who, self.firm_name) if self.firm_name else who

    # ----------------------------------------------------------- calls
    def login(self, email: str, password: str) -> None:
        """Blocking — call on a thread. Raises ApiError; use login_error_message."""
        out = call_json(self.api_base, AUTH_PATH + "/login", method="POST",
                        body={"email": email.strip(), "password": password}, opener=self._open)
        self._keep(out)

    def refresh(self) -> str:
        """Swap the token for a fresh one → ``ok`` / ``logged_out`` (Broto said
        no: the app must show the login screen) / ``offline`` (no answer; the
        current token stays until it expires)."""
        if not self.token:
            return "logged_out"
        try:
            out = call_json(self.api_base, AUTH_PATH + "/refresh", method="POST", body={},
                            bearer=self.token, opener=self._open)
        except ApiError as e:
            if e.status in (401, 403):
                self.logout()
                return "logged_out"
            return "offline" if self.logged_in else "logged_out"
        try:
            self._keep(out)
        except ApiError:
            return "offline" if self.logged_in else "logged_out"
        return "ok"

    def logout(self) -> None:
        self._clear()

    # ----------------------------------------------------------- storage
    def _keep(self, out: Dict[str, Any]) -> None:
        token = out.get("access_token")
        if not isinstance(token, str) or not token:
            raise ApiError(500, "Broto didn't send a login token.")
        user = out.get("user") if isinstance(out.get("user"), dict) else {}
        self.token = token
        self.email = str(user.get("email") or self.email or "")
        self.name = str(user.get("name") or "")
        self.firm_name = str(user.get("firm_name") or "")
        store.save_session_token(token)
        store.update_settings(session_email=self.email or None, session_name=self.name or None,
                              session_firm=self.firm_name or None, session_api_base=self.api_base)

    def _clear(self) -> None:
        self.token = None
        store.forget_session_token()
        store.update_settings(session_name=None, session_firm=None, session_api_base=None)
        # session_email stays so the login screen can fill it in next time.
