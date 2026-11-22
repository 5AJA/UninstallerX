from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import secrets
import stat
import tempfile
import winreg
from collections.abc import Callable
from dataclasses import asdict
from pathlib import Path
from threading import Event

from .audit import AuditLog
from .portable_apps import package_tree
from .portable_files import PortableDirectory, PortableFile, directory_identity, move_verified
from .registry_settings import Setting, _actual_path, eligible_value, exact_user_key
from .windows import has_reparse_component, is_within, normalized_path


JOB_ID = re.compile(r"windows-[0-9a-f]{12}")
Review = Callable[[str, list[tuple[str, str]], str], bool]


def _safe(path: Path) -> bool:
    return (path.is_absolute() and re.fullmatch(r"[A-Za-z]:", path.drive) is not None
            and ".." not in path.parts and ":" not in str(path)[2:]
            and not has_reparse_component(path, path.anchor))


def _child(path: Path, scope: Path) -> bool:
    return is_within(path, scope) and normalized_path(path) != normalized_path(scope)


def _file_snapshot(path: Path) -> dict:
    if not _safe(path):
        raise PermissionError("The file path is redirected or outside a local drive.")
    before = path.lstat()
    if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
        raise ValueError("Recovery supports only regular files without extra links.")
    with path.open("rb") as stream:
        snapshot = os.fstat(stream.fileno())
        if (snapshot.st_dev, snapshot.st_ino) != (before.st_dev, before.st_ino):
            raise PermissionError("The file changed while its backup was checked.")
        digest = hashlib.file_digest(stream, "sha256").hexdigest()
        after = os.fstat(stream.fileno())
    if (snapshot.st_size, snapshot.st_mtime_ns) != (after.st_size, after.st_mtime_ns):
        raise PermissionError("The file changed during its backup check.")
    return {"size": snapshot.st_size, "modified_ns": snapshot.st_mtime_ns,
            "created_ns": getattr(snapshot, "st_birthtime_ns", snapshot.st_ctime_ns),
            "attributes": snapshot.st_file_attributes, "sha256": digest}


def _canonical(payload: dict) -> bytes:
    return json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")


def folder_manifest(folder: Path, files: tuple[PortableFile, ...], directories: tuple[PortableDirectory, ...]) -> str:
    return hashlib.sha256(_canonical({
        "files": [(str(item.path.relative_to(folder)), item.identity, item.digest) for item in files],
        "folders": [(str(item.path.relative_to(folder)), item.identity) for item in directories],
    })).hexdigest()


class RecoveryJournal:
    def __init__(self, repo_root: Path, job_id: str) -> None:
        if not JOB_ID.fullmatch(job_id):
            raise ValueError("Enter a valid Windows removal job ID.")
        self.repo_root = repo_root
        self.job_id = job_id
        self.path = repo_root / ".local" / "recovery" / f"{job_id}.json"
        self.key_path = repo_root / ".local" / "runtime" / "recovery-key.bin"

    def _key(self, *, create: bool) -> bytes:
        if not _safe(self.key_path):
            raise PermissionError("The recovery key location is redirected.")
        if create:
            self.key_path.parent.mkdir(parents=True, exist_ok=True)
            try:
                with self.key_path.open("xb") as stream:
                    stream.write(secrets.token_bytes(32))
                    stream.flush()
                    os.fsync(stream.fileno())
            except FileExistsError:
                pass
        key = self.key_path.read_bytes()
        if len(key) != 32:
            raise ValueError("The local recovery key is invalid.")
        return key

    def load(self) -> list[dict]:
        if not _safe(self.path):
            raise PermissionError("The recovery journal location is redirected.")
        if not self.path.is_file():
            return []
        if self.path.stat().st_size > 4 * 1024 ** 2:
            raise ValueError("The recovery journal exceeds its maximum size.")
        envelope = json.loads(self.path.read_bytes())
        if not isinstance(envelope, dict) or not isinstance(envelope.get("signature"), str) or not isinstance(envelope.get("payload"), dict):
            raise ValueError("The recovery journal has an invalid format.")
        payload = envelope["payload"]
        expected = hmac.new(self._key(create=False), _canonical(payload), hashlib.sha256).hexdigest()
        signature = envelope["signature"]
        if payload.get("job_id") != self.job_id or not re.fullmatch(r"[0-9a-f]{64}", signature) or not hmac.compare_digest(expected, signature):
            raise PermissionError("Recovery journal authentication failed.")
        return payload["entries"]

    def _append(self, item: dict) -> None:
        entries = self.load()
        payload = {"job_id": self.job_id, "entries": [*entries, item]}
        signature = hmac.new(self._key(create=True), _canonical(payload), hashlib.sha256).hexdigest()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=self.path.parent, delete=False) as temp:
            staging = Path(temp.name)
            try:
                temp.write(_canonical({"payload": payload, "signature": signature}))
                temp.flush()
                os.fsync(temp.fileno())
            except OSError:
                temp.close()
                staging.unlink(missing_ok=True)
                raise
        try:
            os.replace(staging, self.path)
        finally:
            staging.unlink(missing_ok=True)

    def record_file(self, source: Path, backup: Path, scope: Path) -> None:
        if not _safe(scope) or not _child(source, scope) or not self._allowed_backup(backup, scope):
            raise PermissionError("The file is outside the approved recovery boundaries.")
        self._append({"operation": "file", "source": str(source), "backup": str(backup),
                      "scope": str(scope), "snapshot": _file_snapshot(source)})

    def record_folder(self, source: Path, backup: Path, scope: Path, manifest: str) -> None:
        if not _safe(source) or not _safe(scope) or not _child(source, scope) or not self._allowed_backup(backup, scope):
            raise PermissionError("The folder is outside the approved recovery boundaries.")
        self._append({"operation": "folder", "source": str(source), "backup": str(backup),
                      "scope": str(scope), "manifest": manifest})

    def record_setting(self, setting: Setting, opened_key: winreg.HKEYType) -> None:
        self._append({"operation": "setting", "setting": asdict(setting), "native_key": _actual_path(opened_key)})

    def _allowed_backup(self, backup: Path, scope: Path) -> bool:
        allowed = (self.repo_root / ".local" / "quarantine" / self.job_id,
                   scope / ".uninstallerx-recovery" / self.job_id)
        return _safe(backup) and any(backup.parent == root for root in allowed)

    def _restore_file(self, entry: dict) -> None:
        source, backup, scope = (Path(entry[key]) for key in ("source", "backup", "scope"))
        if not _safe(source) or not _safe(scope) or not _child(source, scope) or not self._allowed_backup(backup, scope):
            raise PermissionError("The original or recovery path is no longer valid.")
        if source.exists():
            raise FileExistsError("A file already occupies the original path.")
        if not source.parent.is_dir():
            raise FileNotFoundError("The original parent folder no longer exists.")
        if _file_snapshot(backup) != entry["snapshot"]:
            raise PermissionError("The stored file or its metadata no longer matches the approved backup.")
        if not _safe(source) or not _safe(backup):
            raise PermissionError("A recovery path changed.")
        os.rename(backup, source)

    def _restore_folder(self, entry: dict, closing: Event) -> None:
        source, backup, scope = (Path(entry[key]) for key in ("source", "backup", "scope"))
        if not _safe(source) or not _safe(scope) or not _child(source, scope) or not self._allowed_backup(backup, scope):
            raise PermissionError("The original or recovery path is no longer valid.")

        def check_contents() -> None:
            if folder_manifest(backup, *package_tree(backup, closing, recovery=True)) != entry["manifest"]:
                raise PermissionError("The stored folder no longer matches the approved backup.")

        move_verified(directory_identity(backup), source, check_contents)

    def _restore_setting(self, entry: dict) -> None:
        setting = Setting(**entry["setting"])
        if not eligible_value(setting.name, setting.kind, setting.data):
            raise PermissionError("The stored value is outside the app settings policy.")
        with exact_user_key(setting.key, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as key:
            if _actual_path(key).casefold() != entry["native_key"].casefold():
                raise PermissionError("The registry backup belongs to a different user or key.")
            try:
                winreg.QueryValueEx(key, setting.name)
            except FileNotFoundError:
                winreg.SetValueEx(key, setting.name, 0, setting.kind, setting.data)
            else:
                raise FileExistsError("A value already occupies the original registry location.")

    def restore(self, review: Review, closing: Event) -> dict:
        entries = self.load()
        if not entries:
            raise ValueError("This job has no authenticated recovery records.")
        rows = [(f"Restore {entry['operation']}", entry["source"]) if entry["operation"] in {"file", "folder"} else
                ("Restore setting", Setting(**entry["setting"]).target) for entry in entries]
        if closing.is_set() or not review(
            "Restore the listed targets?", rows,
            "Backups return to their original locations. Existing files and registry values are preserved.",
        ) or closing.is_set():
            return {"restored": 0, "skipped": 0, "declined": True}
        audit = AuditLog(self.repo_root / ".local" / "audit" / f"{self.job_id}-restore.jsonl")
        restored = 0
        for entry, (_, target) in zip(entries, rows):
            if closing.is_set():
                break
            try:
                audit.append("restore_approved", target=target)
                if entry["operation"] == "file":
                    self._restore_file(entry)
                elif entry["operation"] == "folder":
                    self._restore_folder(entry, closing)
                else:
                    self._restore_setting(entry)
                restored += 1
                audit.append("restored", target=target)
            except (OSError, ValueError) as exc:
                audit.append("restore_skipped", target=target, reason=str(exc))
        return {"restored": restored, "skipped": len(entries) - restored, "declined": False, "audit_path": str(audit.path)}
