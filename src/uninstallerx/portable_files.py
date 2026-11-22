from __future__ import annotations

import ctypes
import hashlib
import msvcrt
import os
import stat
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

from .windows import normalized_path


@dataclass(frozen=True)
class PortableFile:
    path: Path
    identity: tuple[int, int, int, int]
    digest: str


@dataclass(frozen=True)
class PortableDirectory:
    path: Path
    identity: tuple[int, int]


_kernel = ctypes.WinDLL("kernel32", use_last_error=True)
_kernel.CreateFileW.argtypes = [
    wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD, ctypes.c_void_p,
    wintypes.DWORD, wintypes.DWORD, wintypes.HANDLE,
]
_kernel.CreateFileW.restype = wintypes.HANDLE
_kernel.GetFinalPathNameByHandleW.argtypes = [wintypes.HANDLE, wintypes.LPWSTR, wintypes.DWORD, wintypes.DWORD]
_kernel.GetFinalPathNameByHandleW.restype = wintypes.DWORD
_kernel.SetFileInformationByHandle.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
_kernel.SetFileInformationByHandle.restype = wintypes.BOOL
_kernel.CloseHandle.argtypes = [wintypes.HANDLE]
_kernel.CloseHandle.restype = wintypes.BOOL

INVALID_HANDLE = ctypes.c_void_p(-1).value
GENERIC_READ = 0x80000000
DELETE_ACCESS = 0x00010000
FILE_READ_ATTRIBUTES = 0x00000080
FILE_WRITE_ATTRIBUTES = 0x00000100
FILE_SHARE_READ_WRITE = 0x00000003
OPEN_EXISTING = 3
OPEN_REPARSE_POINT = 0x00200000
BACKUP_SEMANTICS = 0x02000000
FILE_DISPOSITION_INFO = 4
FILE_DISPOSITION_INFO_EX = 21
FILE_RENAME_INFO = 3
DELETE_WITH_POSIX_SEMANTICS = 0x00000003
IGNORE_READONLY = 0x00000010
UNSUPPORTED_DISPOSITION_ERRORS = {1, 50, 87, 120}
EXTENDED_PATH = "\\\\?\\"


class _RenameInfo(ctypes.Structure):
    _fields_ = [("flags", wintypes.DWORD), ("directory", wintypes.HANDLE),
                ("name_length", wintypes.DWORD), ("name", wintypes.WCHAR * 1)]


def _plain(info: os.stat_result) -> bool:
    return not (info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT)


def _fingerprint(path: Path, stream: BinaryIO) -> PortableFile:
    info = os.fstat(stream.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not _plain(info):
        raise ValueError("The path is not a single, regular file.")
    digest = hashlib.file_digest(stream, "sha256").hexdigest()
    identity = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    after = os.fstat(stream.fileno())
    if identity != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns) or after.st_nlink != 1:
        raise ValueError("The file changed while it was being verified.")
    return PortableFile(path, identity, digest)


def fingerprint(path: Path) -> PortableFile:
    info = path.lstat()
    if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not _plain(info):
        raise ValueError("The path is not a single, regular file.")
    with path.open("rb") as stream:
        found = _fingerprint(path, stream)
    if found.identity != (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns):
        raise ValueError("The file was replaced before it could be verified.")
    return found


def directory_identity(path: Path) -> PortableDirectory:
    info = path.lstat()
    if not stat.S_ISDIR(info.st_mode) or not _plain(info):
        raise ValueError("The folder is not a regular local directory.")
    return PortableDirectory(path, (info.st_dev, info.st_ino))


def _operation_error(operation: str, code: int | None = None) -> OSError:
    error = ctypes.WinError(ctypes.get_last_error() if code is None else code)
    error.operation = operation
    return error


@contextmanager
def _open_verified_for_delete(target: PortableFile | PortableDirectory, *, write_attributes: bool = False,
                              pin_parent: bool = False) -> Iterator[int]:
    path = target.path
    directory = isinstance(target, PortableDirectory)
    # Directory readers that share deletion do not interfere with removing an empty folder.
    # Keep files exclusive while reading their approved content hash.
    handle = _kernel.CreateFileW(
        EXTENDED_PATH + str(path), (0 if pin_parent else DELETE_ACCESS) | (FILE_READ_ATTRIBUTES if directory else GENERIC_READ)
        | (FILE_WRITE_ATTRIBUTES if write_attributes else 0),
        FILE_SHARE_READ_WRITE if directory else 0, None, OPEN_EXISTING,
        OPEN_REPARSE_POINT | BACKUP_SEMANTICS, None,
    )
    if handle == INVALID_HANDLE:
        raise _operation_error("CreateFileW")
    try:
        final = ctypes.create_unicode_buffer(32768)
        length = _kernel.GetFinalPathNameByHandleW(handle, final, len(final), 0)
        if not length:
            raise _operation_error("GetFinalPathNameByHandleW")
        if length >= len(final) or not final.value.startswith(EXTENDED_PATH) or (
            normalized_path(final.value.removeprefix(EXTENDED_PATH)) != normalized_path(path)
        ):
            raise ValueError("The approved path was redirected before deletion.")
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except (OSError, ValueError):
        _kernel.CloseHandle(handle)
        raise
    try:
        if directory:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or not _plain(info) or (info.st_dev, info.st_ino) != target.identity:
                raise ValueError("The approved folder changed before deletion.")
        else:
            with os.fdopen(fd, "rb", closefd=False) as stream:
                if _fingerprint(path, stream) != target:
                    raise ValueError("The approved file changed before deletion.")
        yield handle
    finally:
        os.close(fd)


def check_delete_access(target: PortableFile | PortableDirectory) -> None:
    readonly = bool(target.path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
    with _open_verified_for_delete(target, write_attributes=readonly):
        pass


def _mark_for_deletion(handle: int, directory: bool, readonly: bool) -> None:
    if directory or readonly:
        flags = wintypes.DWORD((DELETE_WITH_POSIX_SEMANTICS if directory else 1) | (IGNORE_READONLY if readonly else 0))
        if _kernel.SetFileInformationByHandle(handle, FILE_DISPOSITION_INFO_EX, ctypes.byref(flags), ctypes.sizeof(flags)):
            return
        error = ctypes.get_last_error()
        if readonly or error not in UNSUPPORTED_DISPOSITION_ERRORS:
            raise _operation_error("SetFileInformationByHandle(FileDispositionInfoEx)", error)
    delete = ctypes.c_ubyte(1)
    if not _kernel.SetFileInformationByHandle(handle, FILE_DISPOSITION_INFO, ctypes.byref(delete), ctypes.sizeof(delete)):
        raise _operation_error("SetFileInformationByHandle(FileDispositionInfo)")


def delete_verified(target: PortableFile | PortableDirectory) -> None:
    """Delete the exact object verified through the open handle, not a second path lookup."""
    directory = isinstance(target, PortableDirectory)
    readonly = bool(target.path.lstat().st_file_attributes & stat.FILE_ATTRIBUTE_READONLY)
    with _open_verified_for_delete(target, write_attributes=readonly) as handle:
        _mark_for_deletion(handle, directory, readonly)
    try:
        target.path.lstat()
    except FileNotFoundError:
        return
    except OSError as exc:
        exc.operation = "lstat after deletion"
        raise
    error = OSError("The approved path still exists after Windows accepted the deletion request.")
    error.operation = "lstat after deletion"
    raise error


def _rename_handle(handle: int, destination: str) -> None:
    name = destination.encode("utf-16-le")
    buffer = ctypes.create_string_buffer(_RenameInfo.name.offset + len(name) + 2)
    info = _RenameInfo.from_buffer(buffer)
    info.name_length = len(name)
    ctypes.memmove(ctypes.addressof(buffer) + _RenameInfo.name.offset, name, len(name))
    if not _kernel.SetFileInformationByHandle(handle, FILE_RENAME_INFO, buffer, ctypes.sizeof(buffer)):
        raise _operation_error("SetFileInformationByHandle(FileRenameInfo)")


def rename_sibling_verified(target: PortableDirectory, destination: Path,
                            check_contents: Callable[[], None] | None = None) -> None:
    if target.path.parent != destination.parent or not destination.name or destination.name in {".", ".."}:
        raise ValueError("A staged folder must stay in its original parent directory.")
    with _open_verified_for_delete(directory_identity(destination.parent), pin_parent=True):
        with _open_verified_for_delete(target) as handle:
            if check_contents is not None:
                check_contents()
            _rename_handle(handle, EXTENDED_PATH + str(destination))


def move_verified(target: PortableFile | PortableDirectory, destination: Path,
                  check_contents: Callable[[], None] | None = None) -> None:
    """Move the verified object through its original handle."""
    with _open_verified_for_delete(directory_identity(destination.parent)):
        with _open_verified_for_delete(target) as handle:
            if check_contents is not None:
                check_contents()
            _rename_handle(handle, EXTENDED_PATH + str(destination))
