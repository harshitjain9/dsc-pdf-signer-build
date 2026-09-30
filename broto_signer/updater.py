"""
broto_signer.updater — "Relaunch to update".

Every CHECK_INTERVAL_S (and right after login) the app asks Broto for the
newest published Signer (``GET /api/cha/signer-devices/app-latest?current=``).
When there is a newer one, the .exe is downloaded in the background next to
the running one as ``BrotoSigner.update.exe`` and checked against the size and
SHA-256 Broto published (scripts/publish_broto_signer.py writes both). Only a
file that matches is kept; then the header shows **Relaunch to update**.

The click swaps the files and starts the new one:
  1. ``BrotoSigner.exe`` → ``BrotoSigner.old.exe`` (Windows lets a running
     .exe be renamed, never overwritten);
  2. ``BrotoSigner.update.exe`` → ``BrotoSigner.exe`` — the same path, so the
     "Open when Windows starts" entry and desktop shortcuts keep working;
  3. start it and quit. Any failure puts the old file back.
The next start deletes ``BrotoSigner.old.exe``. Settings, pairing and the
saved PIN live in %APPDATA% and are untouched.

Only a packaged Windows build updates itself; run from source it just logs
that a new version is out. Standard library only.
"""
from __future__ import annotations

import hashlib
import os
import subprocess
import sys
import threading
import urllib.request
from typing import Any, Callable, Dict, List, Optional, Tuple

from account import ApiError, call_json

LATEST_PATH = "/api/cha/signer-devices/app-latest"
CHECK_INTERVAL_S = 6 * 3600
RETRY_S = 20 * 60                 # after a failed download / a file that didn't match
DOWNLOAD_TIMEOUT_S = 120
MAX_SIZE = 300 * 1024 * 1024
_CHUNK = 256 * 1024


def version_tuple(v: str) -> Tuple[int, ...]:
    try:
        return tuple(int(p) for p in str(v).strip().split("."))
    except ValueError:
        return ()


def is_newer(candidate: str, current: str) -> bool:
    a, b = version_tuple(candidate), version_tuple(current)
    return bool(a) and a > b


def can_self_update() -> bool:
    """A packaged (PyInstaller) Windows .exe — the only thing we can swap."""
    return sys.platform == "win32" and bool(getattr(sys, "frozen", False))


def _sibling(exe: str, suffix: str) -> str:
    base, _ext = os.path.splitext(exe)
    return base + suffix


def staged_path(exe: str) -> str:
    return _sibling(exe, ".update.exe")


def old_path(exe: str) -> str:
    return _sibling(exe, ".old.exe")


def sha256_of(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for block in iter(lambda: fh.read(_CHUNK), b""):
            h.update(block)
    return h.hexdigest()


def cleanup(exe: str) -> None:
    """Delete what an earlier update left behind (best effort: the old process
    may still be closing — the next start tries again)."""
    for path in (old_path(exe), staged_path(exe) + ".part"):
        try:
            if os.path.exists(path):
                os.remove(path)
        except OSError:
            pass


def download(info: Dict[str, Any], dest: str, opener: Optional[Callable[..., Any]] = None) -> None:
    """Fetch ``info["url"]`` into ``dest`` only if it is exactly the published
    file (size + SHA-256). A file that doesn't match is deleted; raises
    ValueError / OSError."""
    size, want = int(info.get("size") or 0), str(info.get("sha256") or "").lower()
    url = str(info.get("url") or "")
    if not url.startswith("https://") and not os.environ.get("BROTO_API_BASE"):
        raise ValueError("Update link is not https.")
    if not (0 < size <= MAX_SIZE) or len(want) != 64:
        raise ValueError("Broto sent an incomplete update record.")
    if os.path.exists(dest) and os.path.getsize(dest) == size and sha256_of(dest) == want:
        return                                        # downloaded on an earlier run
    part = dest + ".part"
    h, got = hashlib.sha256(), 0
    req = urllib.request.Request(url, headers={"User-Agent": "BrotoSigner"})
    try:
        with (opener or urllib.request.urlopen)(req, timeout=DOWNLOAD_TIMEOUT_S) as resp, open(part, "wb") as out:
            while True:
                block = resp.read(_CHUNK)
                if not block:
                    break
                got += len(block)
                if got > size:
                    raise ValueError("The update is bigger than Broto said.")
                h.update(block)
                out.write(block)
        if got != size or h.hexdigest() != want:
            raise ValueError("The downloaded update doesn't match what Broto published.")
        os.replace(part, dest)
    except BaseException:
        try:
            os.remove(part)
        except OSError:
            pass
        raise


def _child_env() -> Dict[str, str]:
    """The environment for the new copy: a fresh PyInstaller start
    (PYINSTALLER_RESET_ENVIRONMENT, PyInstaller ≥ 6.9) and nothing pointing
    into this copy's unpack folder, which is deleted when it quits."""
    env = dict(os.environ)
    mei = getattr(sys, "_MEIPASS", None)
    if mei:
        env = {k: v for k, v in env.items() if mei not in v}
    for k in list(env):
        if k.startswith("_PYI_") or k == "_MEIPASS2":
            env.pop(k, None)
    env["PYINSTALLER_RESET_ENVIRONMENT"] = "1"
    return env


def relaunch_command(exe: str, args: Optional[List[str]] = None) -> List[str]:
    if getattr(sys, "frozen", False):
        return [exe] + list(args or [])
    return [sys.executable, os.path.abspath(sys.argv[0])] + list(args or [])


def spawn(cmd: List[str]) -> None:
    """Start ``cmd`` on its own, so it outlives this process."""
    kw: Dict[str, Any] = {"env": _child_env(), "close_fds": True, "cwd": os.path.dirname(cmd[0]) or None}
    if sys.platform == "win32":
        kw["creationflags"] = 0x00000008 | 0x00000200     # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
    else:
        kw["start_new_session"] = True
    subprocess.Popen(cmd, **kw)


def swap_and_start(exe: str, staged: str, start: Callable[[List[str]], None] = spawn) -> None:
    """Put ``staged`` in place of ``exe`` and start it. Any failure puts the
    old file back and raises OSError (the caller shows it)."""
    old = old_path(exe)
    if os.path.exists(old):
        os.remove(old)
    os.replace(exe, old)
    try:
        os.replace(staged, exe)
    except OSError:
        os.replace(old, exe)
        raise
    try:
        start(relaunch_command(exe))
    except Exception as e:  # noqa: BLE001
        os.replace(exe, staged)
        os.replace(old, exe)
        raise OSError(str(e) or repr(e))


class Updater:
    """Background check + download. ``notify(event, info)`` is called from the
    worker thread with ``available`` (newer version out, this copy can't update
    itself) or ``ready`` (downloaded and checked — show Relaunch to update)."""

    def __init__(self, current: str, api_base: str, token_fn: Callable[[], Optional[str]],
                 notify: Callable[[str, Dict[str, Any]], None], exe: Optional[str] = None,
                 self_update: Optional[bool] = None, opener: Optional[Callable[..., Any]] = None,
                 interval_s: float = CHECK_INTERVAL_S) -> None:
        self.current = current
        self.api_base = api_base.rstrip("/")
        self.token_fn = token_fn
        self.notify = notify
        self.exe = exe or sys.executable
        self.self_update = can_self_update() if self_update is None else self_update
        self._open = opener
        self.interval_s = interval_s
        self.ready: Optional[Dict[str, Any]] = None
        self.last_error: Optional[str] = None
        self._told: Optional[str] = None
        self._stop = threading.Event()
        self._wake = threading.Event()
        self._thread: Optional[threading.Thread] = None

    @property
    def staged(self) -> str:
        return staged_path(self.exe)

    def start(self) -> None:
        if self.self_update:
            cleanup(self.exe)
        if self._thread is None:
            self._thread = threading.Thread(target=self._loop, name="broto-updater", daemon=True)
            self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()

    def check_now(self) -> None:
        self._wake.set()

    def _loop(self) -> None:
        while not self._stop.is_set():
            wait = self.interval_s
            try:
                if not self.check_once():
                    wait = RETRY_S
            except Exception as e:  # noqa: BLE001 - the loop must survive anything
                self.last_error = str(e) or repr(e)
                wait = RETRY_S
            self._wake.wait(wait)
            self._wake.clear()

    def check_once(self) -> bool:
        """One check (+ download). False = try again sooner (RETRY_S)."""
        if self.ready is not None:
            return True
        token = self.token_fn()
        if not token:
            return True
        try:
            info = call_json(self.api_base, LATEST_PATH, bearer=token, query={"current": self.current},
                             opener=self._open)
        except ApiError as e:
            self.last_error = e.message
            return False
        version = str(info.get("version") or "")
        if not info.get("update") or not is_newer(version, self.current):
            return True
        if not self.self_update:
            if self._told != version:
                self._told = version
                self.notify("available", info)
            return True
        try:
            download(info, self.staged, opener=self._open)
        except (ValueError, OSError) as e:
            self.last_error = str(e)
            return False
        self.ready = info
        self.notify("ready", info)
        return True

    def relaunch(self, start: Callable[[List[str]], None] = spawn) -> None:
        """Swap in the downloaded copy and start it (the caller then quits).
        Raises OSError with the reason when this folder can't be written."""
        if self.ready is None:
            raise OSError("No update is ready.")
        if not os.path.exists(self.staged) or sha256_of(self.staged) != self.ready.get("sha256"):
            self.ready = None
            raise OSError("The downloaded update is missing or changed.")
        swap_and_start(self.exe, self.staged, start)
