from __future__ import annotations

import hashlib
import os
import subprocess
import winreg
from pathlib import Path
from typing import Any

from .gate import SecurityGate
from .types import Candidate, GateDecision, Observation
from .windows import is_within, split_registry_target


class ControlledExecutor:
    def __init__(self, gate: SecurityGate, quarantine_root: Path) -> None:
        self.gate = gate
        self.quarantine_root = quarantine_root

    def apply(
        self,
        candidate: Candidate,
        original: GateDecision,
        observations: list[Observation],
        *,
        approved: bool,
        job_id: str,
    ) -> dict[str, Any]:
        fresh = self.gate.evaluate(candidate, observations)
        if fresh.decision != original.decision or fresh.reason != original.reason or fresh.exact_target != original.exact_target:
            raise PermissionError("gate_result_changed_before_execution")
        if fresh.decision == "deny":
            raise PermissionError(fresh.reason)
        if fresh.decision == "approval_required" and not approved:
            raise PermissionError("exact_target_approval_missing")

        if candidate.operation == "run_uninstaller":
            command = self.gate.record.uninstall_command
            if not command:
                raise PermissionError("trusted_uninstaller_missing")
            try:
                process = subprocess.run(
                    command,
                    cwd=self.gate.record.fixture_root,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    timeout=30,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                return {"operation": candidate.operation, "target": fresh.exact_target, "status": "timed_out"}
            return {
                "operation": candidate.operation,
                "target": fresh.exact_target,
                "exit_code": process.returncode,
                "status": "completed" if process.returncode == 0 else "execution_failed",
            }

        if candidate.operation == "quarantine_file":
            source = Path(fresh.exact_target)
            if not is_within(source, self.gate.record.fixture_root):
                raise PermissionError("outside_fixture")
            job_root = self.quarantine_root / job_id
            job_root.mkdir(parents=True, exist_ok=True)
            suffix = hashlib.sha256(str(source).encode("utf-8")).hexdigest()[:16]
            destination = job_root / f"{suffix}-{source.name}"
            if destination.exists():
                raise FileExistsError(destination)
            before = source.stat()
            os.replace(source, destination)
            return {
                "operation": candidate.operation,
                "target": str(source),
                "quarantine_path": str(destination),
                "size": before.st_size,
                "modified_ns": before.st_mtime_ns,
                "status": "completed",
            }

        if candidate.operation == "delete_registry_value":
            key, name = split_registry_target(fresh.exact_target)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE) as handle:
                value, value_type = winreg.QueryValueEx(handle, name)
                winreg.DeleteValue(handle, name)
            return {
                "operation": candidate.operation,
                "target": fresh.exact_target,
                "old_value": value,
                "old_type": value_type,
                "status": "completed",
            }
        raise PermissionError("unsupported_operation")


def restore_quarantined(outcome: dict[str, Any], fixture_root: Path, quarantine_root: Path) -> None:
    if outcome.get("operation") != "quarantine_file":
        raise ValueError("Only quarantined files can be restored")
    source = Path(outcome["quarantine_path"])
    destination = Path(outcome["target"])
    if not is_within(source, quarantine_root) or not is_within(destination, fixture_root):
        raise PermissionError("Restore path outside trusted roots")
    if destination.exists() or not source.is_file():
        raise FileExistsError("Restore source missing or destination occupied")
    destination.parent.mkdir(parents=True, exist_ok=True)
    os.replace(source, destination)
