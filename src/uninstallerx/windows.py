from __future__ import annotations

import ctypes
import os
import stat
from ctypes import wintypes
from pathlib import Path


def normalized_path(path: str | Path) -> str:
    """Normalize spelling without following a junction or symlink."""
    return os.path.normcase(os.path.abspath(os.fspath(path)))


def is_within(path: str | Path, root: str | Path) -> bool:
    candidate = normalized_path(path)
    parent = normalized_path(root)
    try:
        return os.path.commonpath((candidate, parent)) == parent
    except ValueError:
        return False


def has_reparse_component(path: str | Path, stop_at: str | Path) -> bool:
    """Reject links/junctions from the trusted root down to the target."""
    if not is_within(path, stop_at):
        return True
    current = Path(stop_at)
    relative = Path(normalized_path(path)).relative_to(Path(normalized_path(stop_at)))
    for part in ((), *[(p,) for p in relative.parts]):
        if part:
            current = current / part[0]
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or bool(getattr(info, "st_file_attributes", 0) & getattr(stat, "FILE_ATTRIBUTE_REPARSE_POINT", 0)):
            return True
    return False


def system_directory() -> Path:
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    buffer = ctypes.create_unicode_buffer(32768)
    size = kernel.GetSystemDirectoryW(buffer, len(buffer))
    if not 0 < size < len(buffer):
        raise ctypes.WinError(ctypes.get_last_error())
    return Path(buffer.value)


def require_interactive_account() -> None:
    """Keep an elevated removal session bound to the desktop user's SID."""
    user = ctypes.WinDLL("user32", use_last_error=True)
    kernel = ctypes.WinDLL("kernel32", use_last_error=True)
    advapi = ctypes.WinDLL("advapi32", use_last_error=True)
    user.GetShellWindow.restype = wintypes.HWND
    user.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    kernel.GetCurrentProcess.restype = wintypes.HANDLE
    kernel.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    advapi.OpenProcessToken.argtypes = [wintypes.HANDLE, wintypes.DWORD, ctypes.POINTER(wintypes.HANDLE)]
    advapi.GetTokenInformation.argtypes = [wintypes.HANDLE, ctypes.c_int, wintypes.LPVOID, wintypes.DWORD,
                                           ctypes.POINTER(wintypes.DWORD)]
    advapi.EqualSid.argtypes = [wintypes.LPVOID, wintypes.LPVOID]

    def token_user(process: int) -> ctypes.Array:
        token = wintypes.HANDLE()
        if not advapi.OpenProcessToken(process, 0x0008, ctypes.byref(token)):  # TOKEN_QUERY
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            size = wintypes.DWORD()
            advapi.GetTokenInformation(token, 1, None, 0, ctypes.byref(size))  # TokenUser
            if not 0 < size.value <= 65536:
                raise ctypes.WinError(ctypes.get_last_error())
            buffer = ctypes.create_string_buffer(size.value)
            if not advapi.GetTokenInformation(token, 1, buffer, size, ctypes.byref(size)):
                raise ctypes.WinError(ctypes.get_last_error())
            return buffer
        finally:
            kernel.CloseHandle(token)

    window = user.GetShellWindow()
    pid = wintypes.DWORD()
    if not window or not user.GetWindowThreadProcessId(window, ctypes.byref(pid)):
        raise PermissionError("Could not verify the signed-in Windows desktop account.")
    process = kernel.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not process:
        raise ctypes.WinError(ctypes.get_last_error())
    try:
        desktop = token_user(process)
        current = token_user(kernel.GetCurrentProcess())
        if not advapi.EqualSid(ctypes.cast(desktop, ctypes.POINTER(wintypes.LPVOID))[0],
                               ctypes.cast(current, ctypes.POINTER(wintypes.LPVOID))[0]):
            raise PermissionError("UninstallerX is running as a different account than the signed-in Windows user.")
    finally:
        kernel.CloseHandle(process)


def registry_target(key: str, value_name: str) -> str:
    return f"HKCU\\{key}::{value_name}"


def split_registry_target(target: str) -> tuple[str, str]:
    if not target.upper().startswith("HKCU\\") or "::" not in target:
        raise ValueError("Expected HKCU\\<key>::<value_name>")
    key, name = target[5:].rsplit("::", 1)
    if not key or not name or ".." in key.split("\\"):
        raise ValueError("Invalid registry target")
    return key, name
