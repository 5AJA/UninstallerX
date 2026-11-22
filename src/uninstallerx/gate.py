from __future__ import annotations

import hashlib
import os
import re
import stat
import subprocess
import winreg
from pathlib import Path

from .read_tools import observation_supports_file, observation_supports_registry_value
from .types import AppRecord, Candidate, GateDecision, Observation
from .windows import has_reparse_component, is_within, normalized_path, split_registry_target


class SecurityGate:
    def __init__(self, record: AppRecord) -> None:
        self.record = record

    def evaluate(self, candidate: Candidate, observations: list[Observation]) -> GateDecision:
        def result(decision: str, reason: str, target: str | None = None) -> GateDecision:
            return GateDecision(decision, reason, target or candidate.exact_target, candidate)  # type: ignore[arg-type]

        if candidate.app_id != self.record.app_id:
            return result("deny", "app_identity_mismatch")
        if not candidate.evidence_refs:
            return result("deny", "evidence_missing")
        refs = {obs.ref: obs for obs in observations}
        if any(ref not in refs for ref in candidate.evidence_refs):
            return result("deny", "evidence_reference_invalid")
        supporting = [refs[ref] for ref in candidate.evidence_refs]

        if candidate.operation == "run_uninstaller":
            command = self.record.uninstall_command
            script = self.record.uninstall_path
            install_key = self.record.install_record_key
            if self.record.kind != "installed" or not command or not script or not install_key or not self.record.uninstall_sha256:
                return result("deny", "trusted_uninstaller_missing")
            if normalized_path(candidate.exact_target) != normalized_path(script):
                return result("deny", "uninstaller_target_mismatch")
            if not is_within(script, self.record.fixture_root) or has_reparse_component(script, self.record.fixture_root):
                return result("deny", "uninstaller_path_untrusted")
            for argument in command[1:]:
                argument_path = Path(argument)
                if re.fullmatch(r"(?:--?|/)[A-Za-z][A-Za-z0-9{}_-]*", argument):
                    continue
                if not argument_path.is_absolute():
                    argument_path = self.record.fixture_root / argument_path
                if not (
                    normalized_path(argument_path) == normalized_path(script)
                    or is_within(argument_path, self.record.install_root)
                    or is_within(argument_path, self.record.appdata_root)
                ):
                    return result("deny", "uninstaller_argument_outside_app_roots")
            expected_command = subprocess.list2cmdline(command)
            if not any(
                obs.tool == "list_registry_values"
                and obs.target.casefold() == ("HKCU\\" + install_key).casefold()
                and any(value["name"].casefold() == "uninstallstring" and value["value"] == expected_command for value in obs.result["values"])
                for obs in supporting
            ):
                return result("deny", "uninstaller_record_evidence_missing")
            try:
                info = os.lstat(script)
                digest = hashlib.sha256(script.read_bytes()).hexdigest()
            except FileNotFoundError:
                return result("deny", "uninstaller_missing")
            if not stat.S_ISREG(info.st_mode) or digest != self.record.uninstall_sha256:
                return result("deny", "uninstaller_changed")
            return result("approval_required", "vendor_uninstaller_requires_approval", str(script))

        if candidate.operation == "quarantine_file":
            path = Path(candidate.exact_target)
            if not path.is_absolute():
                return result("deny", "absolute_path_required")
            if not is_within(path, self.record.fixture_root):
                return result("deny", "outside_fixture")
            if has_reparse_component(path, self.record.fixture_root):
                return result("deny", "reparse_point_in_path")
            in_install = is_within(path, self.record.install_root)
            in_appdata = is_within(path, self.record.appdata_root)
            if not (in_install or in_appdata):
                return result("deny", "ownership_not_proven")
            if path.parent not in (self.record.install_root, self.record.appdata_root):
                return result("deny", "nested_file_ownership_unproven")
            if not any(observation_supports_file(obs, str(path)) for obs in supporting):
                return result("deny", "independent_file_evidence_missing")
            try:
                info = os.lstat(path)
            except FileNotFoundError:
                return result("deny", "file_missing")
            if not stat.S_ISREG(info.st_mode):
                return result("deny", "not_a_regular_file")
            if in_appdata:
                return result("approval_required", "appdata_residual_requires_approval", str(path))
            if self.record.uninstall_command and path.suffix.casefold() == ".exe":
                return result("approval_required", "direct_executable_removal_requires_approval", str(path))
            return result("allow", "policy_root_and_read_evidence", str(path))

        if candidate.operation == "delete_registry_value":
            try:
                key, name = split_registry_target(candidate.exact_target)
            except ValueError:
                return result("deny", "invalid_registry_target")
            if key.casefold() != self.record.settings_key.casefold():
                return result("deny", "registry_ownership_not_proven")
            if not any(observation_supports_registry_value(obs, key, name) for obs in supporting):
                return result("deny", "independent_registry_evidence_missing")
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_READ) as handle:
                    winreg.QueryValueEx(handle, name)
            except FileNotFoundError:
                return result("deny", "registry_value_missing")
            return result("allow", "policy_registry_key_and_read_evidence")

        return result("deny", "unsupported_operation")
