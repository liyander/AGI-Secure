"""Store the NVIDIA credential for the current Windows user with DPAPI."""

from __future__ import annotations

import ctypes
import os
from ctypes import wintypes
from pathlib import Path


KEY_PATH = Path(__file__).resolve().parent.parent / "data" / "nvidia_key.dpapi"


class CredentialError(Exception):
    pass


class _DataBlob(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_ubyte))]


def _crypt(data: bytes, protect: bool) -> bytes:
    if os.name != "nt":
        raise CredentialError("Saved keys require Windows DPAPI; use NVIDIA_API_KEY on this system.")
    buffer = (ctypes.c_ubyte * len(data)).from_buffer_copy(data)
    source = _DataBlob(len(data), buffer)
    destination = _DataBlob()
    crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    operation = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    operation.argtypes = [ctypes.POINTER(_DataBlob), ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, ctypes.c_void_p, wintypes.DWORD, ctypes.POINTER(_DataBlob)]
    operation.restype = wintypes.BOOL
    kernel32.LocalFree.argtypes = [ctypes.c_void_p]
    kernel32.LocalFree.restype = ctypes.c_void_p
    # UI_FORBIDDEN avoids a desktop prompt when the server runs in the background.
    if not operation(ctypes.byref(source), None, None, None, None, 0x1, ctypes.byref(destination)):
        raise CredentialError("Windows could not unlock the saved key for this user.")
    try:
        return ctypes.string_at(destination.pbData, destination.cbData)
    finally:
        kernel32.LocalFree(destination.pbData)


def save_nvidia_key(key: str) -> None:
    key = key.strip()
    if not key or len(key) > 2048 or any(char.isspace() for char in key):
        raise CredentialError("Enter a valid API key without spaces.")
    encrypted = _crypt(key.encode("utf-8"), True)
    KEY_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary = KEY_PATH.with_suffix(".tmp")
    temporary.write_bytes(encrypted)
    os.replace(temporary, KEY_PATH)


def get_nvidia_key() -> str:
    if KEY_PATH.exists():
        try:
            return _crypt(KEY_PATH.read_bytes(), False).decode("utf-8")
        except (UnicodeDecodeError, OSError) as exc:
            raise CredentialError("The saved key could not be read.") from exc
    return os.getenv("NVIDIA_API_KEY", "")


def key_status() -> dict:
    if KEY_PATH.exists():
        get_nvidia_key()
        return {"configured": True, "source": "saved"}
    if os.getenv("NVIDIA_API_KEY"):
        return {"configured": True, "source": "environment"}
    return {"configured": False, "source": "none"}


def delete_nvidia_key() -> None:
    KEY_PATH.unlink(missing_ok=True)
