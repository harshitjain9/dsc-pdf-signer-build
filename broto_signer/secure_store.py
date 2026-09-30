"""
broto_signer.secure_store — the signer's small settings file + the saved token PINs
(one per token).

Settings (driver path, which certificate, start-with-Windows) are plain JSON in
%APPDATA%\\BrotoSigner\\settings.json. The PIN is stored ONLY if the user says
yes, and only encrypted with Windows DPAPI (CryptProtectData, current-user
scope): the blob can be decrypted by the same Windows account on the same
machine and nothing else — no key of ours is involved, nothing leaves the PC.
On other platforms PIN saving is simply unavailable.

Standard library only (ctypes), so the bridge/tests can import it anywhere.
"""
from __future__ import annotations

import base64
import json
import os
import sys
from typing import Any, Dict, Optional

_APP_DIR_NAME = "BrotoSigner"
_PIN_ENTROPY = b"BrotoSigner/token-pin/v1"
_REMOTE_ENTROPY = b"BrotoSigner/remote-token/v1"


def settings_dir() -> str:
    base = os.environ.get("APPDATA") if sys.platform == "win32" else None
    base = base or os.path.join(os.path.expanduser("~"), ".config")
    return os.path.join(base, _APP_DIR_NAME)


def settings_path() -> str:
    return os.path.join(settings_dir(), "settings.json")


def load_settings() -> Dict[str, Any]:
    try:
        with open(settings_path(), "r", encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001 - missing/corrupt file = defaults
        return {}


def save_settings(data: Dict[str, Any]) -> None:
    os.makedirs(settings_dir(), exist_ok=True)
    tmp = settings_path() + ".tmp"
    with open(tmp, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, settings_path())


def update_settings(**changes: Any) -> Dict[str, Any]:
    data = load_settings()
    for k, v in changes.items():
        if v is None:
            data.pop(k, None)
        else:
            data[k] = v
    save_settings(data)
    return data


# ------------------------------------------------------------------ DPAPI
def pin_saving_supported() -> bool:
    return sys.platform == "win32"


if sys.platform == "win32":
    import ctypes
    from ctypes import wintypes

    class _Blob(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    _crypt32 = ctypes.windll.crypt32
    _kernel32 = ctypes.windll.kernel32
    _CRYPTPROTECT_UI_FORBIDDEN = 0x01

    def _in_blob(data: bytes):
        buf = ctypes.create_string_buffer(data, len(data))
        return _Blob(len(data), ctypes.cast(buf, ctypes.POINTER(ctypes.c_char))), buf

    def _protect(data: bytes, entropy: bytes = _PIN_ENTROPY, description: str = "Broto Signer PIN") -> bytes:
        inb, _k1 = _in_blob(data)
        ent, _k2 = _in_blob(entropy)
        out = _Blob()
        if not _crypt32.CryptProtectData(ctypes.byref(inb), description, ctypes.byref(ent),
                                         None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise OSError("CryptProtectData failed (%d)" % ctypes.GetLastError())
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)

    def _unprotect(data: bytes, entropy: bytes = _PIN_ENTROPY) -> bytes:
        inb, _k1 = _in_blob(data)
        ent, _k2 = _in_blob(entropy)
        out = _Blob()
        if not _crypt32.CryptUnprotectData(ctypes.byref(inb), None, ctypes.byref(ent),
                                           None, None, _CRYPTPROTECT_UI_FORBIDDEN, ctypes.byref(out)):
            raise OSError("CryptUnprotectData failed (%d)" % ctypes.GetLastError())
        try:
            return ctypes.string_at(out.pbData, out.cbData)
        finally:
            _kernel32.LocalFree(out.pbData)
else:
    def _protect(data: bytes, entropy: bytes = _PIN_ENTROPY, description: str = "") -> bytes:
        raise OSError("PIN saving is only available on Windows.")

    def _unprotect(data: bytes, entropy: bytes = _PIN_ENTROPY) -> bytes:
        raise OSError("PIN saving is only available on Windows.")


# One PIN per token. A PC can hold several DSC tokens (one per ICEGATE ID), each
# with its own PIN. A PIN is saved under the token it belongs to (its serial
# number — signer_core.token_key) and only ever offered to that token: a PIN
# typed into the wrong token counts as a wrong try, and tokens lock after a few.
# A PIN an older Signer saved has no token (``pin_dpapi``, key ""); the app binds it
# to the token of the certificate it was used with the first time it reads them.
def save_pin(pin: str, token: str = "") -> None:
    blob = base64.b64encode(_protect(pin.encode("utf-8"))).decode("ascii")
    if not token:
        update_settings(pin_dpapi=blob)
        return
    pins = dict(load_settings().get("pins_dpapi") or {})
    pins[token] = blob
    update_settings(pins_dpapi=pins)


def load_pins() -> Dict[str, str]:
    """Every saved PIN this Windows login can read, by token ("" = saved by an
    older Signer, token not known yet). A blob another login / PC saved is skipped."""
    if not pin_saving_supported():
        return {}
    data = load_settings()
    raw = dict(data.get("pins_dpapi") or {})
    if data.get("pin_dpapi"):
        raw[""] = data["pin_dpapi"]
    out: Dict[str, str] = {}
    for token, b64 in raw.items():
        try:
            out[str(token)] = _unprotect(base64.b64decode(b64)).decode("utf-8")
        except Exception:  # noqa: BLE001 - other user / other PC / corrupt → not saved
            continue
    return out


def load_pin() -> Optional[str]:
    """The PIN an older Signer saved (no token)."""
    raw = load_settings().get("pin_dpapi")
    if not raw or not pin_saving_supported():
        return None
    try:
        return _unprotect(base64.b64decode(raw)).decode("utf-8")
    except Exception:  # noqa: BLE001 - other user / other PC / corrupt → treat as not saved
        return None


def has_saved_pin() -> bool:
    data = load_settings()
    return bool(data.get("pin_dpapi") or data.get("pins_dpapi"))


def forget_pin(token: Optional[str] = None) -> None:
    """Forget one token's saved PIN ("" = the one an older Signer saved), or every
    saved PIN when ``token`` is None."""
    if token is None:
        update_settings(pin_dpapi=None, pins_dpapi=None)
        return
    if not token:
        update_settings(pin_dpapi=None)
        return
    pins = dict(load_settings().get("pins_dpapi") or {})
    pins.pop(token, None)
    update_settings(pins_dpapi=pins or None)


def bind_legacy_pin(token: str) -> bool:
    """File the PIN an older Signer saved (no token) under ``token``. True if moved."""
    data = load_settings()
    legacy = data.get("pin_dpapi")
    if not legacy or not token:
        return False
    pins = dict(data.get("pins_dpapi") or {})
    pins.setdefault(token, legacy)
    update_settings(pins_dpapi=pins, pin_dpapi=None)
    return True


# ------------------------------------------------------------ remote-signing device token
# The bearer token Broto issues when this PC is paired for remote signing
# (remote.py). On Windows it gets the PIN's protection: DPAPI, current-user
# scope — only the same Windows login on the same PC can read it back. On other
# platforms (development only; real tokens live on Windows) it is kept in plain
# text in settings.json, under a key that says so.
def remote_token_protected() -> bool:
    return sys.platform == "win32"


def save_remote_token(token: str) -> None:
    if remote_token_protected():
        blob = _protect(token.encode("utf-8"), _REMOTE_ENTROPY, "Broto Signer remote token")
        update_settings(remote_token_dpapi=base64.b64encode(blob).decode("ascii"), remote_token_plain=None)
    else:
        update_settings(remote_token_plain=token, remote_token_dpapi=None)


def load_remote_token() -> Optional[str]:
    data = load_settings()
    raw = data.get("remote_token_dpapi")
    if raw:
        if not remote_token_protected():
            return None
        try:
            return _unprotect(base64.b64decode(raw), _REMOTE_ENTROPY).decode("utf-8")
        except Exception:  # noqa: BLE001 - other user / other PC / corrupt → not paired
            return None
    plain = data.get("remote_token_plain")
    return str(plain) if plain else None


def has_remote_token() -> bool:
    data = load_settings()
    return bool(data.get("remote_token_dpapi") or data.get("remote_token_plain"))


def forget_remote_token() -> None:
    update_settings(remote_token_dpapi=None, remote_token_plain=None)


# ------------------------------------------------------------ Broto login (account.py)
# The logged-in user's Broto token. Same protection as the remote token: DPAPI
# on Windows (same Windows login, same PC), plain text only on dev boxes.
_SESSION_ENTROPY = b"BrotoSigner/user-session/v1"


def save_session_token(token: str) -> None:
    if remote_token_protected():
        blob = _protect(token.encode("utf-8"), _SESSION_ENTROPY, "Broto Signer login")
        update_settings(session_token_dpapi=base64.b64encode(blob).decode("ascii"), session_token_plain=None)
    else:
        update_settings(session_token_plain=token, session_token_dpapi=None)


def load_session_token() -> Optional[str]:
    data = load_settings()
    raw = data.get("session_token_dpapi")
    if raw:
        if not remote_token_protected():
            return None
        try:
            return _unprotect(base64.b64decode(raw), _SESSION_ENTROPY).decode("utf-8")
        except Exception:  # noqa: BLE001 - other user / other PC / corrupt → logged out
            return None
    plain = data.get("session_token_plain")
    return str(plain) if plain else None


def forget_session_token() -> None:
    update_settings(session_token_dpapi=None, session_token_plain=None)


# ------------------------------------------------------------ start with Windows
_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_RUN_NAME = "BrotoSigner"


def autostart_supported() -> bool:
    return sys.platform == "win32" and getattr(sys, "frozen", False)


def autostart_enabled() -> bool:
    if sys.platform != "win32":
        return False
    import winreg
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as k:
            winreg.QueryValueEx(k, _RUN_NAME)
        return True
    except OSError:
        return False


def set_autostart(enabled: bool) -> None:
    """Current-user Run entry that opens the signer minimised at login, so it is
    ready when Broto asks for a signature."""
    import winreg
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY, 0, winreg.KEY_SET_VALUE) as k:
        if enabled:
            winreg.SetValueEx(k, _RUN_NAME, 0, winreg.REG_SZ, '"%s" --minimized' % sys.executable)
        else:
            try:
                winreg.DeleteValue(k, _RUN_NAME)
            except OSError:
                pass
