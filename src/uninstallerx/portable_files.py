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
FILE_SHARE_READ_WRITE = 0x00000003
OPEN_EXISTING = 3
OPEN_REPARSE_POINT = 0x00200000
BACKUP_SEMANTICS = 0x02000000
FILE_RENAME_INFO = 3
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
def _open_verified_for_delete(target: PortableFile | PortableDirectory, *, pin_parent: bool = False) -> Iterator[int]:
    path = target.path
    directory = isinstance(target, PortableDirectory)
    # The handle carries the DELETE access right for the rename. A pinned parent only holds its place.
    # Keep files exclusive while reading their approved content hash.
    handle = _kernel.CreateFileW(
        EXTENDED_PATH + str(path), (0 if pin_parent else DELETE_ACCESS) | (FILE_READ_ATTRIBUTES if directory else GENERIC_READ),
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
            raise ValueError("The approved path was redirected before the move.")
        fd = msvcrt.open_osfhandle(handle, os.O_RDONLY | os.O_BINARY)
    except (OSError, ValueError):
        _kernel.CloseHandle(handle)
        raise
    try:
        if directory:
            info = os.fstat(fd)
            if not stat.S_ISDIR(info.st_mode) or not _plain(info) or (info.st_dev, info.st_ino) != target.identity:
                raise ValueError("The approved folder changed before the move.")
        else:
            with os.fdopen(fd, "rb", closefd=False) as stream:
                if _fingerprint(path, stream) != target:
                    raise ValueError("The approved file changed before the move.")
        yield handle
    finally:
        os.close(fd)


def check_delete_access(target: PortableFile | PortableDirectory) -> None:
    with _open_verified_for_delete(target):
        pass


def _rename_handle(handle: int, destination: str) -> None:
    name = destination.encode("utf-16-le")
    buffer = ctypes.create_string_buffer(_RenameInfo.name.offset + len(name) + 2)
    info = _RenameInfo.from_buffer(buffer)
    info.name_length = len(name)
    ctypes.memmove(ctypes.addressof(buffer) + _RenameInfo.name.offset, name, len(name))
    if not _kernel.SetFileInformationByHandle(handle, FILE_RENAME_INFO, buffer, ctypes.sizeof(buffer)):
        raise _operation_error("SetFileInformationByHandle(FileRenameInfo)")


def move_verified(target: PortableFile | PortableDirectory, destination: Path,
                  check_contents: Callable[[], None] | None = None) -> None:
    """Move the verified object through its original handle."""
    with _open_verified_for_delete(directory_identity(destination.parent), pin_parent=True):
        with _open_verified_for_delete(target) as handle:
            if check_contents is not None:
                check_contents()
            _rename_handle(handle, EXTENDED_PATH + str(destination))
