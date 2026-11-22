from __future__ import annotations

import codecs
import ctypes
import hashlib
import json
import os
import re
import stat
import struct
import zlib
from collections import deque
from collections.abc import Callable
from dataclasses import dataclass
from itertools import islice
from pathlib import Path
from threading import Event
from typing import BinaryIO
from zipfile import BadZipFile, ZipFile, ZIP_DEFLATED, ZIP_STORED

from .packaged_apps import powershell
from .portable_files import PortableDirectory, PortableFile, directory_identity, fingerprint
from .windows import has_reparse_component, is_within, normalized_path


MAX_PACKAGE_ENTRIES = 4096
RECOVERY_FOLDER = ".uninstallerx-recovery"
MAX_PACKAGE_BYTES = 2 * 1024 ** 3
MAX_ARCHIVES = 80
PORTABLE_SCAN_ENTRIES = 6000
MAX_ZIP_DIRECTORY_BYTES = 16 * 1024 ** 2
ZIP_END_RECORD = struct.Struct("<4s4H2IH")


@dataclass(frozen=True)
class PortableArchive:
    file: PortableFile
    search_root: Path


@dataclass(frozen=True)
class PortablePackage:
    folder: Path
    directories: tuple[PortableDirectory, ...]
    archive: PortableArchive | None
    evidence: str


@dataclass(frozen=True)
class PortableDistribution:
    files: tuple[PortableFile, ...]
    package: PortablePackage
    archive_files: tuple[PortableFile, ...] = ()


@dataclass(frozen=True)
class PortableApp:
    name: str
    executable: Path
    search_root: Path
    files: tuple[PortableFile, ...]
    package: PortablePackage | None = None
    grouped_files: bool = False


@dataclass(frozen=True)
class PortableCandidate:
    name: str
    product: str
    executable: Path
    search_root: Path


def _bounded_zip_directory(stream: BinaryIO, size: int) -> bool:
    # Check the classic ZIP trailer before ZipFile allocates its central directory buffer.
    stream.seek(max(0, size - 65535 - ZIP_END_RECORD.size - 20))
    trailer = stream.read(65535 + ZIP_END_RECORD.size + 20)
    pos = trailer.rfind(b"PK\x05\x06")
    if pos < 0 or pos + ZIP_END_RECORD.size > len(trailer) or (pos >= 20 and trailer[pos - 20:pos - 16] == b"PK\x06\x07"):
        return False
    _, disk, start_disk, disk_entries, entries, directory_bytes, _, comment_bytes = ZIP_END_RECORD.unpack_from(trailer, pos)
    return (disk == start_disk == 0 and disk_entries == entries and 0 < entries <= MAX_PACKAGE_ENTRIES
            and directory_bytes <= MAX_ZIP_DIRECTORY_BYTES and pos + ZIP_END_RECORD.size + comment_bytes == len(trailer))


def _name(text: str) -> str:
    text = re.sub(r"(?:[\s_-]*portable|[\s_-]+(?:x64|x86))$", "", text.strip(), flags=re.I)
    return "".join(re.findall(r"[\w+]+", text.casefold())).replace("_", "")


def _local_path(path: Path) -> bool:
    return (path.is_absolute() and bool(re.fullmatch(r"[a-zA-Z]:", path.drive))
            and ".." not in path.parts and ":" not in str(path)[2:]
            and not has_reparse_component(path, path.anchor))


def _below(path: Path, root: Path) -> bool:
    return normalized_path(path) != normalized_path(root) and is_within(path, root)


def _protected(path: Path, *, recovery: bool = False, browsing: bool = False) -> bool:
    protected = [Path(os.environ[key]) for key in ("SystemRoot", "ProgramFiles", "ProgramFiles(x86)", "ProgramData",
                                                  "ProgramW6432") if os.environ.get(key)]
    protected_names = {"$recycle.bin", "system volume information", "windowsapps", ".git"}
    if not recovery:
        protected_names.add(RECOVERY_FOLDER)
    return (any(is_within(path, root) or (not browsing and is_within(root, path)) for root in protected)
            or any(part.casefold() in protected_names for part in path.parts))


def _local_drives() -> list[Path]:
    kernel = ctypes.windll.kernel32
    drives = kernel.GetLogicalDrives
    drives.argtypes = []
    drives.restype = ctypes.c_uint
    drive_type = kernel.GetDriveTypeW
    drive_type.argtypes = [ctypes.c_wchar_p]
    drive_type.restype = ctypes.c_uint
    mask = drives()
    roots = [f"{letter}:\\" for index, letter in enumerate("ABCDEFGHIJKLMNOPQRSTUVWXYZ") if mask & (1 << index)]
    return [Path(root) for root in roots if drive_type(root) in (2, 3)]


def _searchable_folder(path: Path) -> bool:
    return _local_path(path) and not _protected(path, browsing=True) and path.is_dir()


def search_areas(extra: tuple[Path, ...], *, include_drives: bool = False,
                 on_error: Callable[[Path, OSError], None] | None = None) -> list[Path]:
    candidates = [path.absolute() for path in extra]
    if profile := os.environ.get("USERPROFILE"):
        candidates.extend([Path(profile) / "Desktop", Path(profile) / "Downloads"])
    if local := os.environ.get("LOCALAPPDATA"):
        candidates.append(Path(local) / "Programs")
    if include_drives:
        candidates.extend(_local_drives())
    roots = []
    for path in dict.fromkeys(candidates):
        try:
            if _searchable_folder(path):
                roots.append(path)
        except OSError as exc:
            if on_error is None:
                raise
            on_error(path, exc)
    return roots


def portable_search_area(location: Path) -> tuple[Path, Path | None]:
    if _searchable_folder(location):
        return location, None
    if (location.suffix.casefold() == ".exe" and _local_path(location) and not _protected(location)
            and location.is_file()):
        return location.parent, location
    raise ValueError("The location must be an accessible local portable-app folder or executable.")


def _peek_binary(path: Path, on_error: Callable[[Path, OSError], None] | None = None) -> bool:
    try:
        with path.open("rb") as stream:
            header = stream.read(64)
            if len(header) != 64 or not header.startswith(b"MZ"):
                return False
            pointer = int.from_bytes(header[60:64], "little")
            if not 64 <= pointer <= 65536:
                return False
            stream.seek(pointer)
            return stream.read(4) == b"PE\0\0"
    except OSError as exc:
        if on_error is not None:
            on_error(path, exc)
        return False


def safe_portable_path(path: Path, root: Path) -> bool:
    return _local_path(path) and not _protected(path) and _below(path, root)


def verify_file(file: PortableFile, app: PortableApp) -> bool:
    return safe_portable_path(file.path, app.search_root) and fingerprint(file.path) == file


def package_tree(folder: Path, closing: Event, *,
                 recovery: bool = False) -> tuple[tuple[PortableFile, ...], tuple[PortableDirectory, ...]]:
    """Record only regular files and directories. Refuse trees containing redirects or special files."""
    if not _local_path(folder) or _protected(folder, recovery=recovery):
        raise ValueError("The package folder is outside the portable app policy.")
    pending = [folder]
    files: list[PortableFile] = []
    directories: list[PortableDirectory] = [directory_identity(folder)]
    size = 0
    while pending:
        directory = pending.pop()
        with os.scandir(directory) as entries:
            for entry in entries:
                if closing.is_set() or len(files) + len(directories) >= MAX_PACKAGE_ENTRIES:
                    raise ValueError("The package tree could not be fully inspected.")
                path = Path(entry.path)
                if not _local_path(path) or _protected(path, recovery=recovery) or not _below(path, folder):
                    raise ValueError("The package tree contains a protected or redirected path.")
                info = entry.stat(follow_symlinks=False)
                if stat.S_ISDIR(info.st_mode):
                    directories.append(directory_identity(path))
                    pending.append(path)
                else:
                    size += info.st_size
                    if size > MAX_PACKAGE_BYTES:
                        raise ValueError("The package is too large to verify.")
                    files.append(fingerprint(path))
    return (tuple(sorted(files, key=lambda item: normalized_path(item.path))),
            tuple(sorted(directories, key=lambda item: (-len(item.path.parts), normalized_path(item.path)))))


def _archive_candidates(candidate: PortableCandidate, roots: tuple[Path, ...], closing: Event) -> list[tuple[Path, Path]]:
    allowed = list(dict.fromkeys((candidate.search_root, *roots)))
    candidates: dict[str, tuple[Path, Path]] = {}
    for root in allowed:
        nearby = candidate.executable.parent.parent
        pending = deque([(root, 0)])
        if root == candidate.search_root and _below(nearby, root):
            pending.appendleft((nearby, 0))
        seen: set[Path] = set()
        visited = 0
        while pending and visited < 6000 and not closing.is_set():
            directory, depth = pending.popleft()
            if directory in seen or not _local_path(directory) or _protected(directory):
                continue
            seen.add(directory)
            try:
                with os.scandir(directory) as entries:
                    for entry in entries:
                        visited += 1
                        if visited > 6000 or closing.is_set():
                            break
                        path = Path(entry.path)
                        if depth < 4 and entry.is_dir(follow_symlinks=False):
                            pending.append((path, depth + 1))
                        elif path.suffix.casefold() == ".zip" and safe_portable_path(path, root):
                            candidates.setdefault(normalized_path(path), (path, root))
            except (FileNotFoundError, PermissionError):
                continue

    def relevance(item: tuple[Path, Path]) -> tuple[bool, bool, str]:
        path, _ = item
        names = {_name(candidate.product), _name(candidate.executable.stem)} - {""}
        return (not any(name in _name(path.stem) for name in names),
                path.parent != candidate.executable.parent.parent, normalized_path(path))

    return sorted(candidates.values(), key=relevance)[:MAX_ARCHIVES]


def _match_archive(
    archive_path: Path, root: Path, executable: Path, folders: tuple[Path, ...], closing: Event,
) -> tuple[Path, tuple[PortableFile, ...], PortableArchive] | None:
    if not safe_portable_path(archive_path, root):
        return None
    before = archive_path.lstat()
    if before.st_size > MAX_PACKAGE_BYTES or not stat.S_ISREG(before.st_mode):
        return None
    with archive_path.open("rb") as stream:
        if not _bounded_zip_directory(stream, before.st_size):
            return None
        return _match_archive_members(stream, archive_path, before, root, executable, folders, closing)


def _match_archive_members(
    source: BinaryIO, archive_path: Path, before: os.stat_result, root: Path, executable: Path,
    folders: tuple[Path, ...], closing: Event,
) -> tuple[Path, tuple[PortableFile, ...], PortableArchive] | None:
    with ZipFile(source) as archive:
        entries = archive.infolist()
        if len(entries) > MAX_PACKAGE_ENTRIES or sum(entry.file_size for entry in entries) > MAX_PACKAGE_BYTES:
            return None
        members = {}
        for entry in entries:
            parts = entry.filename.removesuffix("/").split("/")
            if (any(not part or part in {".", ".."} or part.rstrip(" .") != part
                    or re.search(r'[<>:"\\|?*\x00-\x1f]', part) for part in parts)
                    or "\x00" in entry.orig_filename or stat.S_ISLNK(entry.external_attr >> 16) or entry.flag_bits & 1
                    or entry.compress_type not in {ZIP_STORED, ZIP_DEFLATED}):
                return None
            if not entry.is_dir():
                key = tuple(part.casefold() for part in parts)
                if key in members:
                    return None
                members[key] = (parts, entry)
        if closing.is_set():
            return None
        for folder in folders:
            relative = tuple(part.casefold() for part in executable.relative_to(folder).parts)
            for name in members:
                if name[-len(relative):] != relative:
                    continue
                prefix = name[:-len(relative)]
                if any(key[:len(prefix)] != prefix or len(key) == len(prefix) for key in members):
                    continue
                files = []
                for parts, entry in members.values():
                    path = folder.joinpath(*parts[len(prefix):])
                    if closing.is_set() or not safe_portable_path(path, folder) or not path.is_file():
                        break
                    if path.lstat().st_size != entry.file_size:
                        break
                    file = fingerprint(path)
                    with archive.open(entry) as stream:
                        if hashlib.file_digest(stream, "sha256").hexdigest() != file.digest:
                            break
                    files.append(file)
                else:
                    zip_file = fingerprint(archive_path)
                    if zip_file.identity != (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns):
                        return None
                    return (folder, tuple(sorted(files, key=lambda item: normalized_path(item.path))),
                            PortableArchive(zip_file, root))
    return None


def observe_portable_distributions(
    candidate: PortableCandidate, roots: tuple[Path, ...], closing: Event,
) -> tuple[PortableDistribution, ...]:
    executable, root = candidate.executable, candidate.search_root
    folders = tuple(path for path in executable.parents if path != Path(path.anchor) and is_within(path, root) and _local_path(path))
    shared = [*search_areas(())]
    if profile := os.environ.get("USERPROFILE"):
        shared.append(Path(profile))
    trees: dict[Path, tuple[tuple[PortableFile, ...], tuple[PortableDirectory, ...]]] = {}

    def observe_folder(folder: Path) -> tuple[tuple[PortableFile, ...], tuple[PortableDirectory, ...]]:
        if folder in trees:
            return trees[folder]
        trees[folder] = ((), ())
        if not any(is_within(path, folder) for path in shared):
            try:
                files, directories = package_tree(folder, closing)
                if any(file.path == executable for file in files):
                    trees[folder] = files, directories
            except (OSError, ValueError):
                pass
        return trees[folder]

    observations = []
    for path, source_root in _archive_candidates(candidate, roots, closing):
        if closing.is_set():
            return ()
        try:
            match = _match_archive(path, source_root, executable, folders, closing)
        except (BadZipFile, EOFError, OSError, ValueError, zlib.error):
            continue
        if match is None:
            continue
        folder, archive_files, archive = match
        current, directories = observe_folder(folder)
        files = tuple(file for file in current if file != archive.file) if directories else archive_files
        if directories and not set(archive_files) <= set(files):
            continue
        evidence = "The listed application files match ZIP members by SHA-256."
        if directories and files == archive_files:
            evidence = "The complete folder contents match the distribution ZIP by SHA-256."
        elif directories:
            evidence = "ZIP members match, and the folder contains additional files. Review the additional files before choosing the whole folder."
        observed = PortablePackage(folder, directories, archive, evidence)
        observations.append(PortableDistribution(files, observed, archive_files))
        if len(observations) >= 4:
            break
    covered_folders = {item.package.folder for item in observations}
    dedicated_names = {_name(candidate.product), _name(executable.stem)} - {""}
    for folder in folders:
        named_for_app = _name(folder.name) in dedicated_names
        if closing.is_set() or folder in covered_folders or (folder != executable.parent and not named_for_app):
            continue
        # A matched outer distribution already shows the folder containing this executable.
        if any(is_within(folder, item.package.folder) and item.package.directories for item in observations):
            continue
        files, directories = observe_folder(folder)
        if directories:
            evidence = ("The folder name matches the application. Review the whole folder's contents."
                        if named_for_app else "The executable is in this folder. Use the other files and documentation to decide whether the whole folder belongs to the app.")
            observations.append(PortableDistribution(files, PortablePackage(folder, directories, None, evidence)))
    return tuple(observations)


def _products(paths: list[Path]) -> dict[Path, str]:
    if not paths:
        return {}
    values = powershell(r"""
        $metadata = @(foreach ($path in (ConvertFrom-Json -InputObject $env:UNINSTALLERX_PORTABLE_PATHS)) {
            $file = Get-Item -LiteralPath $path -ErrorAction SilentlyContinue
            if ($file) { @{ path = $file.FullName; product = [string]$file.VersionInfo.ProductName } }
        })
        ConvertTo-Json -InputObject $metadata -Compress
    """, environment={"UNINSTALLERX_PORTABLE_PATHS": json.dumps([str(path) for path in paths])})
    return {Path(item["path"]): item["product"].strip() for item in json.loads(values)}


def portable_query_key(value: str) -> str:
    return "".join(char for char in value.casefold() if char.isalnum())


def read_portable_executables(
    area: Path, registered: set[Path], closing: Event, *, query: str | None = None,
    pending: deque[tuple[Path, int]], exact_file: Path | None = None, folders: list[Path] | None = None,
    on_error: Callable[[Path, OSError], None] | None = None,
    continue_scanning: Callable[[], bool] | None = None,
    covered_roots: set[Path] | None = None,
) -> list[PortableCandidate]:
    if not _searchable_folder(area):
        raise ValueError("The search folder is outside the portable app policy.")
    term = portable_query_key(query) if isinstance(query, str) else ""
    if folders is None and exact_file is None and (not term or len(query) > 80):
        raise ValueError("Choose a literal file or folder search term of up to 80 characters.")
    if exact_file is not None:
        if (not safe_portable_path(exact_file, area) or exact_file in registered
                or any(parent in registered for parent in exact_file.parents) or not _peek_binary(exact_file, on_error)):
            return []
        found = [exact_file]
    else:
        found = []
        visited = 0
        interrupted = False
        while pending and not interrupted and not closing.is_set():
            if visited >= PORTABLE_SCAN_ENTRIES:
                break
            if continue_scanning is not None and not continue_scanning():
                break
            directory, offset = pending.popleft()
            subdirs = []
            try:
                if covered_roots and (directory in covered_roots or any(parent in covered_roots for parent in directory.parents)):
                    continue
                if (not _local_path(directory) or _protected(directory, browsing=True)
                        or directory in registered or any(parent in registered for parent in directory.parents)):
                    continue
                with os.scandir(directory) as entries:
                    for index, entry in enumerate(islice(entries, offset, None), offset):
                        if closing.is_set():
                            break
                        if (visited >= PORTABLE_SCAN_ENTRIES or len(found) == 12
                                or (folders is not None and len(folders) == 12)):
                            pending.appendleft((directory, index))
                            break
                        if continue_scanning is not None and visited % 256 == 0 and not continue_scanning():
                            pending.appendleft((directory, index))
                            interrupted = True
                            break
                        visited += 1
                        path = Path(entry.path)
                        try:
                            if entry.is_dir(follow_symlinks=False):
                                if folders is None:
                                    subdirs.append((path, 0))
                                elif _searchable_folder(path):
                                    folders.append(path)
                            elif (path.suffix.casefold() == ".exe" and path not in registered
                                  and (not term or term in portable_query_key(path.name) or term in portable_query_key(path.parent.name))
                                  and safe_portable_path(path, area) and _peek_binary(path, on_error)):
                                found.append(path)
                        except OSError as exc:
                            if on_error is not None:
                                on_error(path, exc)
                            elif not isinstance(exc, (FileNotFoundError, PermissionError)):
                                raise
            except OSError as exc:
                if on_error is not None:
                    on_error(directory, exc)
                elif not isinstance(exc, (FileNotFoundError, PermissionError)):
                    raise
            if folders is None:
                priority = {row for row in subdirs if term in portable_query_key(row[0].name)}
                pending.extendleft(row for row in reversed(subdirs) if row in priority)
                pending.extend(row for row in subdirs if row not in priority)
            if len(found) == 12 or (folders is not None and len(folders) == 12):
                break
    products = _products(found) if not closing.is_set() else {}
    return [PortableCandidate(products[path] or path.stem, products[path], path, area) for path in found if path in products]


def inspect_portable(candidate: PortableCandidate) -> PortableApp:
    executable, root, product = candidate.executable, candidate.search_root, candidate.product
    if not (_local_path(executable) and not _protected(executable) and _below(executable, root) and _peek_binary(executable)):
        raise ValueError("The observed executable is no longer a supported portable file.")
    files = [fingerprint(executable)]
    # In a dedicated product folder, corroborate sibling DLLs by their PE product metadata.
    if product and _name(executable.parent.name) in {_name(product), _name(executable.stem)}:
        with os.scandir(executable.parent) as entries:
            libraries = [
                Path(entry.path) for entry in islice(entries, 100)
                if Path(entry.path).suffix.casefold() == ".dll" and _local_path(Path(entry.path))
                and _peek_binary(Path(entry.path))
            ][:20]
        for path, name in _products(libraries).items():
            if _name(name) == _name(product):
                try:
                    files.append(fingerprint(path))
                except (OSError, ValueError):
                    continue
    return PortableApp(candidate.name, executable, root, tuple(files))


def portable_file_inventory(
    app: PortableApp, distributions: tuple[PortableDistribution, ...], closing: Event,
) -> dict[Path, tuple[int, int, int, int]]:
    observed = {file.path: file.identity for file in app.files}
    for distribution in distributions:
        observed.update((file.path, file.identity) for file in distribution.files)
    folder = app.executable.parent
    if any(distribution.package.folder == folder and distribution.package.directories for distribution in distributions):
        return observed
    if _protected(folder) or not is_within(folder, app.search_root) or not _local_path(folder):
        return observed
    try:
        with os.scandir(folder) as entries:
            for entry in entries:
                if closing.is_set():
                    break
                path = Path(entry.path)
                if path in observed or not entry.is_file(follow_symlinks=False):
                    continue
                try:
                    info = path.lstat()
                except OSError:
                    continue
                if stat.S_ISREG(info.st_mode) and info.st_nlink == 1 and not info.st_file_attributes & stat.FILE_ATTRIBUTE_REPARSE_POINT:
                    observed[path] = (info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns)
    except (FileNotFoundError, PermissionError):
        pass
    return observed


PORTABLE_TEXT_READ_BYTES = 1536


def read_portable_text(path: Path, scope: Path, identity: tuple[int, int, int, int], offset: int) -> dict:
    if not safe_portable_path(path, scope):
        raise PermissionError("The observed file is outside the local search area or was redirected.")
    size = identity[2]
    if type(offset) is not int or offset < 0 or (offset and offset >= size):
        raise ValueError("Use offset zero or a next_offset reported for the observed file.")
    with path.open("rb") as stream:
        before = os.fstat(stream.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_nlink != 1
                or (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns) != identity):
            raise ValueError("The observed file changed before it could be read.")
        prefix = stream.read(3)
        stream.seek(offset)
        data = stream.read(PORTABLE_TEXT_READ_BYTES)
        after = os.fstat(stream.fileno())
        if (after.st_size, after.st_mtime_ns) != identity[2:]:
            raise ValueError("The observed file changed during reading.")
    result = {"path": str(path), "offset": offset, "next_offset": None, "text_excerpt": ""}
    if not data:
        return {**result, "status": "empty"}
    encoding = "utf-8-sig" if offset == 0 else "utf-8"
    if prefix.startswith(codecs.BOM_UTF16_LE):
        encoding = "utf-16" if offset == 0 else "utf-16-le"
    elif prefix.startswith(codecs.BOM_UTF16_BE):
        encoding = "utf-16" if offset == 0 else "utf-16-be"
    decoder = codecs.getincrementaldecoder(encoding)()
    end = offset + len(data)
    try:
        excerpt = decoder.decode(data, final=end >= size)
    except UnicodeError:
        return {**result, "status": "not_text"}
    if any(not char.isprintable() and char not in "\r\n\t" for char in excerpt):
        return {**result, "status": "not_text"}
    next_offset = end - len(decoder.getstate()[0]) if end < size else None
    return {**result, "status": "read", "next_offset": next_offset, "text_excerpt": excerpt}
