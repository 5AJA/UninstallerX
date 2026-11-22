from __future__ import annotations

import ctypes
import hashlib
import os
import winreg
from ctypes import wintypes
from pathlib import Path

from .types import AppRecord
from .windows import has_reparse_component, is_within, normalized_path


UNINSTALL_ROOT = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"


def _validate_app_name(display_name: str) -> None:
    if not display_name.strip() or display_name in {".", ".."} or any(character in display_name for character in "\\/:"):
        raise ValueError("Invalid app display name")


def split_windows_command(command: str) -> tuple[str, ...]:
    """Parse a Windows uninstall command without invoking a shell."""
    if not command or "\x00" in command:
        raise ValueError("Invalid UninstallString")
    argc = ctypes.c_int()
    parser = ctypes.windll.shell32.CommandLineToArgvW
    parser.argtypes = [wintypes.LPCWSTR, ctypes.POINTER(ctypes.c_int)]
    parser.restype = ctypes.POINTER(wintypes.LPWSTR)
    argv = parser(command, ctypes.byref(argc))
    if not argv:
        raise ValueError("Could not parse UninstallString")
    try:
        args = tuple(argv[index] for index in range(argc.value))
    finally:
        local_free = ctypes.windll.kernel32.LocalFree
        local_free.argtypes = [wintypes.HLOCAL]
        local_free.restype = wintypes.HLOCAL
        local_free(ctypes.cast(argv, wintypes.HLOCAL))
    if not args:
        raise ValueError("Empty UninstallString")
    return args


def _read_values(key: str) -> dict[str, object]:
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_READ) as handle:
        values: dict[str, object] = {}
        index = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(handle, index)
            except OSError:
                break
            values[name] = value
            index += 1
    return values


def _uninstaller_file(command: tuple[str, ...]) -> Path:
    executable = Path(command[0])
    if not executable.is_absolute() or not executable.is_file():
        raise ValueError("UninstallString must name an existing absolute executable")
    if executable.name.casefold() in {"cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe"}:
        raise ValueError("Shell-hosted uninstall commands are unsupported")
    if executable.name.casefold().startswith("python") and len(command) > 1 and Path(command[1]).suffix.casefold() == ".py":
        script = Path(command[1])
        if not script.is_absolute() or not script.is_file():
            raise ValueError("Python uninstaller script is missing")
        return script
    return executable


def discover_hkcu_installed_app(
    display_name: str,
    *,
    scope_root: Path,
    registry_scope_key: str,
) -> AppRecord:
    """Resolve an exact named installed app from the live HKCU uninstall registry.

    The caller supplies only broad disposable file and registry boundaries.
    App locations come from the observed uninstall record, not fixture labels.
    """
    _validate_app_name(display_name)
    scope_root = scope_root.resolve()
    matches: list[tuple[str, dict[str, object]]] = []
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, UNINSTALL_ROOT, 0, winreg.KEY_READ) as root:
        index = 0
        while True:
            try:
                subkey = winreg.EnumKey(root, index)
            except OSError:
                break
            index += 1
            key = UNINSTALL_ROOT + "\\" + subkey
            values = _read_values(key)
            if str(values.get("DisplayName", "")).casefold() == display_name.casefold():
                matches.append((key, values))
    if len(matches) != 1:
        raise ValueError(f"Expected one exact HKCU app match, found {len(matches)}")
    install_key, values = matches[0]
    required = ("InstallLocation", "AppDataLocation", "SettingsKey", "UninstallString")
    if any(not isinstance(values.get(name), str) or not values[name] for name in required):
        raise ValueError("Installed app record lacks required locations or uninstall command")
    settings_key = str(values["SettingsKey"])
    expected_settings_key = registry_scope_key.rstrip("\\") + "\\Apps\\" + display_name
    if not registry_scope_key or settings_key.casefold() != expected_settings_key.casefold():
        raise ValueError("Installed app settings key is outside the caller scope")
    install_root = Path(str(values["InstallLocation"]))
    appdata_root = Path(str(values["AppDataLocation"]))
    if not install_root.is_absolute() or not appdata_root.is_absolute():
        raise ValueError("Installed app roots must be absolute")
    if not all(is_within(path, scope_root) for path in (install_root, appdata_root)):
        raise ValueError("Installed app roots are outside the caller scope")
    if any(normalized_path(path) == normalized_path(scope_root) for path in (install_root, appdata_root)):
        raise ValueError("Installed app roots must be below the caller scope")
    if is_within(install_root, appdata_root) or is_within(appdata_root, install_root):
        raise ValueError("Installed app roots overlap")
    if any(has_reparse_component(path, scope_root) for path in (install_root, appdata_root)):
        raise ValueError("Installed app root contains a reparse point")
    command = split_windows_command(str(values["UninstallString"]))
    uninstall_path = _uninstaller_file(command)
    if not is_within(uninstall_path, scope_root) or has_reparse_component(uninstall_path, scope_root):
        raise ValueError("Uninstaller is outside the caller scope")
    primary = Path(str(values.get("DisplayIcon", "")))
    primary_executable = primary if primary.is_absolute() and is_within(primary, install_root) else None
    return AppRecord(
        app_id=display_name,
        kind="installed",
        fixture_root=scope_root,
        install_root=install_root,
        appdata_root=appdata_root,
        settings_key=settings_key,
        install_record_key=install_key,
        uninstall_path=uninstall_path,
        uninstall_command=command,
        uninstall_sha256=hashlib.sha256(uninstall_path.read_bytes()).hexdigest(),
        primary_executable=primary_executable,
    )


def discover_portable_fixture_app(display_name: str, *, scope_root: Path, registry_scope_key: str) -> AppRecord:
    """Resolve a portable app using the declared synthetic sandbox layout."""
    _validate_app_name(display_name)
    if not registry_scope_key:
        raise ValueError("Registry scope is required")
    scope_root = scope_root.resolve()
    install_root = scope_root / "portable" / display_name
    appdata_root = scope_root / "appdata" / display_name
    settings_key = registry_scope_key.rstrip("\\") + "\\Apps\\" + display_name
    if not install_root.is_dir() or not appdata_root.is_dir():
        raise ValueError("Portable app folders are missing")
    if any(has_reparse_component(path, scope_root) for path in (install_root, appdata_root)):
        raise ValueError("Portable app root contains a reparse point")
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, settings_key, 0, winreg.KEY_READ):
        pass
    return AppRecord(
        app_id=display_name,
        kind="portable",
        fixture_root=scope_root,
        install_root=install_root,
        appdata_root=appdata_root,
        settings_key=settings_key,
        install_record_key=None,
    )
