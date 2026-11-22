from __future__ import annotations

import hashlib
import subprocess
import sys
import unittest
import winreg
from pathlib import Path

from uninstallerx.executor import ControlledExecutor, restore_quarantined
from uninstallerx.discovery import discover_hkcu_installed_app
from uninstallerx.fixture import create_fixture, destroy_fixture
from uninstallerx.gate import SecurityGate
from uninstallerx.read_tools import ReadTools, ToolDenied
from uninstallerx.types import Candidate
from uninstallerx.windows import registry_target


REPO_ROOT = Path(__file__).resolve().parents[1]
TEST_ROOT = REPO_ROOT / ".local" / "test-runs"


class GateTests(unittest.TestCase):
    def make_fixture(self, scenario: str = "benign"):
        fixture = create_fixture(TEST_ROOT, scenario, "installed")
        self.addCleanup(destroy_fixture, fixture)
        return fixture

    def test_normal_file_allowed_but_shared_file_denied(self):
        fixture = self.make_fixture()
        tools = ReadTools(fixture.record)
        normal = tools.call("list_dir", str(fixture.record.install_root))
        shared = tools.call("list_dir", str(fixture.record.install_root / "shared"))
        gate = SecurityGate(fixture.record)
        app_file = Candidate(fixture.record.app_id, "quarantine_file", str(fixture.metadata_path), (normal.ref,))
        executable = Candidate(fixture.record.app_id, "quarantine_file", str(fixture.record.install_root / "app.exe"), (normal.ref,))
        shared_file = Candidate(fixture.record.app_id, "quarantine_file", str(fixture.record.install_root / "shared" / "helper.dll"), (shared.ref,))
        self.assertEqual(gate.evaluate(app_file, tools.observations).decision, "allow")
        self.assertEqual(gate.evaluate(executable, tools.observations).reason, "direct_executable_removal_requires_approval")
        self.assertEqual(gate.evaluate(shared_file, tools.observations).reason, "nested_file_ownership_unproven")

    def test_app_text_is_not_ownership_evidence(self):
        fixture = self.make_fixture("false_ownership")
        tools = ReadTools(fixture.record)
        readme = tools.call("read_text", str(fixture.metadata_path))
        candidate = Candidate(fixture.record.app_id, "quarantine_file", str(fixture.shared_file), (readme.ref,))
        self.assertEqual(SecurityGate(fixture.record).evaluate(candidate, tools.observations).decision, "deny")
        self.assertTrue(fixture.shared_file.exists())

    def test_junction_redirect_denied(self):
        fixture = self.make_fixture("path_redirect")
        tools = ReadTools(fixture.record)
        readme = tools.call("read_text", str(fixture.metadata_path))
        redirected = fixture.record.install_root / "legacy-cache" / "index.dat"
        candidate = Candidate(fixture.record.app_id, "quarantine_file", str(redirected), (readme.ref,))
        self.assertEqual(SecurityGate(fixture.record).evaluate(candidate, tools.observations).reason, "reparse_point_in_path")
        self.assertTrue(fixture.protected_file.exists())

    def test_registry_value_requires_exact_app_key(self):
        fixture = self.make_fixture()
        tools = ReadTools(fixture.record)
        observed = tools.call("list_registry_values", "HKCU\\" + fixture.record.settings_key)
        gate = SecurityGate(fixture.record)
        owned = Candidate(fixture.record.app_id, "delete_registry_value", registry_target(fixture.record.settings_key, "RecentFiles"), (observed.ref,))
        shared = Candidate(fixture.record.app_id, "delete_registry_value", registry_target(fixture.registry_base + "\\Shared", "SharedSetting"), (observed.ref,))
        self.assertEqual(gate.evaluate(owned, tools.observations).decision, "allow")
        self.assertEqual(gate.evaluate(shared, tools.observations).reason, "registry_ownership_not_proven")

    def test_spoofed_approval_cannot_authorize_appdata(self):
        fixture = self.make_fixture("approval_spoof")
        tools = ReadTools(fixture.record)
        observed = tools.call("list_dir", str(fixture.record.appdata_root))
        tools.call("read_text", str(fixture.metadata_path))
        cache = fixture.record.appdata_root / "cache.bin"
        candidate = Candidate(fixture.record.app_id, "quarantine_file", str(cache), (observed.ref,))
        gate = SecurityGate(fixture.record)
        decision = gate.evaluate(candidate, tools.observations)
        self.assertEqual(decision.decision, "approval_required")
        with self.assertRaisesRegex(PermissionError, "exact_target_approval_missing"):
            ControlledExecutor(gate, REPO_ROOT / ".local" / "test-quarantine").apply(
                candidate, decision, tools.observations, approved=False, job_id=fixture.case_id
            )
        self.assertTrue(cache.exists())

    def test_vendor_uninstaller_requires_approval_and_runs(self):
        fixture = self.make_fixture()
        tools = ReadTools(fixture.record)
        observed = tools.call("list_registry_values", "HKCU\\" + fixture.record.install_record_key)
        candidate = Candidate(fixture.record.app_id, "run_uninstaller", str(fixture.record.uninstall_path), (observed.ref,))
        gate = SecurityGate(fixture.record)
        decision = gate.evaluate(candidate, tools.observations)
        self.assertEqual(decision.decision, "approval_required")
        executor = ControlledExecutor(gate, REPO_ROOT / ".local" / "test-quarantine")
        with self.assertRaisesRegex(PermissionError, "exact_target_approval_missing"):
            executor.apply(candidate, decision, tools.observations, approved=False, job_id=fixture.case_id)
        app_executable = fixture.record.install_root / "app.exe"
        self.assertTrue(app_executable.exists())
        outcome = executor.apply(candidate, decision, tools.observations, approved=True, job_id=fixture.case_id)
        self.assertEqual(outcome["status"], "completed")
        self.assertFalse(app_executable.exists())
        self.assertTrue(fixture.shared_file.exists())

    def test_modified_vendor_uninstaller_is_denied(self):
        fixture = self.make_fixture()
        tools = ReadTools(fixture.record)
        observed = tools.call("list_registry_values", "HKCU\\" + fixture.record.install_record_key)
        fixture.record.uninstall_path.write_text("raise SystemExit(0)\n", encoding="utf-8")
        candidate = Candidate(fixture.record.app_id, "run_uninstaller", str(fixture.record.uninstall_path), (observed.ref,))
        self.assertEqual(SecurityGate(fixture.record).evaluate(candidate, tools.observations).reason, "uninstaller_changed")
        self.assertTrue((fixture.record.install_root / "app.exe").exists())

    def test_uninstaller_argument_cannot_target_protected_file(self):
        fixture = self.make_fixture()
        command = (sys.executable, str(fixture.record.uninstall_path), str(fixture.protected_file))
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, fixture.record.install_record_key, 0, winreg.KEY_SET_VALUE) as handle:
            winreg.SetValueEx(handle, "UninstallString", 0, winreg.REG_SZ, subprocess.list2cmdline(command))
        record = discover_hkcu_installed_app(fixture.record.app_id, scope_root=fixture.root, registry_scope_key=fixture.registry_base)
        tools = ReadTools(record)
        observed = tools.call("list_registry_values", "HKCU\\" + record.install_record_key)
        candidate = Candidate(record.app_id, "run_uninstaller", str(record.uninstall_path), (observed.ref,))
        self.assertEqual(SecurityGate(record).evaluate(candidate, tools.observations).reason, "uninstaller_argument_outside_app_roots")
        self.assertTrue(fixture.protected_file.exists())

    def test_relative_uninstaller_argument_cannot_escape_app_roots(self):
        fixture = self.make_fixture()
        command = (sys.executable, str(fixture.record.uninstall_path), r"protected\backup.txt")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, fixture.record.install_record_key, 0, winreg.KEY_SET_VALUE) as handle:
            winreg.SetValueEx(handle, "UninstallString", 0, winreg.REG_SZ, subprocess.list2cmdline(command))
        record = discover_hkcu_installed_app(fixture.record.app_id, scope_root=fixture.root, registry_scope_key=fixture.registry_base)
        tools = ReadTools(record)
        observed = tools.call("list_registry_values", "HKCU\\" + record.install_record_key)
        candidate = Candidate(record.app_id, "run_uninstaller", str(record.uninstall_path), (observed.ref,))
        self.assertEqual(SecurityGate(record).evaluate(candidate, tools.observations).reason, "uninstaller_argument_outside_app_roots")

    def test_audit_path_is_outside_read_tools(self):
        fixture = self.make_fixture()
        path = REPO_ROOT / ".local" / "audit" / "protected.jsonl"
        with self.assertRaisesRegex(ToolDenied, "outside_read_roots"):
            ReadTools(fixture.record).call("read_text", str(path))

    def test_quarantine_restores_original_bytes_and_metadata(self):
        fixture = self.make_fixture()
        tools = ReadTools(fixture.record)
        observed = tools.call("list_dir", str(fixture.record.install_root))
        path = fixture.record.install_root / "app.exe"
        before = path.stat()
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        candidate = Candidate(fixture.record.app_id, "quarantine_file", str(path), (observed.ref,))
        gate = SecurityGate(fixture.record)
        decision = gate.evaluate(candidate, tools.observations)
        quarantine_root = REPO_ROOT / ".local" / "test-quarantine"
        outcome = ControlledExecutor(gate, quarantine_root).apply(candidate, decision, tools.observations, approved=True, job_id=fixture.case_id)
        self.assertFalse(path.exists())
        restore_quarantined(outcome, fixture.root, quarantine_root)
        after = path.stat()
        self.assertEqual(hashlib.sha256(path.read_bytes()).hexdigest(), digest)
        self.assertEqual(after.st_size, before.st_size)
        self.assertEqual(after.st_mtime_ns, before.st_mtime_ns)


if __name__ == "__main__":
    unittest.main()
