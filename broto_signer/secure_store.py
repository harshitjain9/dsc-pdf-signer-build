"""
broto_signer.secure_store — the signer's small settings file + the saved token PIN.

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


def save_pin(pin: str) -> None:
    blob = _protect(pin.encode("utf-8"))
    update_settings(pin_dpapi=base64.b64encode(blob).decode("ascii"))


def load_pin() -> Optional[str]:
    raw = load_settings().get("pin_dpapi")
    if not raw or not pin_saving_supported():
        return None
    try:
        return _unprotect(base64.b64decode(raw)).decode("utf-8")
    except Exception:  # noqa: BLE001 - other user / other PC / corrupt → treat as not saved
        return None


def has_saved_pin() -> bool:
    return bool(load_settings().get("pin_dpapi"))


def forget_pin() -> None:
    update_settings(pin_dpapi=None)


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
