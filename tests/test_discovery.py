from __future__ import annotations

import subprocess
import unittest
import winreg
from pathlib import Path

from uninstallerx.discovery import discover_hkcu_installed_app, discover_portable_fixture_app, split_windows_command
from uninstallerx.fixture import create_fixture, destroy_fixture


REPO_ROOT = Path(__file__).resolve().parents[1]


class DiscoveryTests(unittest.TestCase):
    def make_fixture(self, variant: int = 1):
        fixture = create_fixture(REPO_ROOT / ".local" / "test-runs", "benign", "installed", variant)
        self.addCleanup(destroy_fixture, fixture)
        return fixture

    def discover(self, fixture):
        return discover_hkcu_installed_app(
            fixture.record.app_id,
            scope_root=fixture.root,
            registry_scope_key=fixture.registry_base,
        )

    def test_resolves_different_name_and_uninstaller_from_registry(self):
        fixture = self.make_fixture(1)
        record = self.discover(fixture)
        self.assertEqual(record.app_id, "OrionDesk")
        self.assertEqual(record.install_root, fixture.record.install_root)
        self.assertEqual(record.uninstall_command, fixture.record.uninstall_command)
        self.assertEqual(record.uninstall_path, fixture.record.uninstall_path)
        self.assertEqual(record.primary_executable, fixture.record.primary_executable)

    def test_rejects_registry_path_outside_caller_scope(self):
        fixture = self.make_fixture(2)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, fixture.record.install_record_key, 0, winreg.KEY_SET_VALUE) as handle:
            winreg.SetValueEx(handle, "InstallLocation", 0, winreg.REG_SZ, str(REPO_ROOT))
        with self.assertRaisesRegex(ValueError, "outside the caller scope"):
            self.discover(fixture)

    def test_rejects_whole_fixture_root_as_install_location(self):
        fixture = self.make_fixture(2)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, fixture.record.install_record_key, 0, winreg.KEY_SET_VALUE) as handle:
            winreg.SetValueEx(handle, "InstallLocation", 0, winreg.REG_SZ, str(fixture.root))
        with self.assertRaisesRegex(ValueError, "must be below the caller scope"):
            self.discover(fixture)

    def test_uses_observed_location_without_fixture_path_oracle(self):
        fixture = self.make_fixture(1)
        alternative = fixture.root / "different-parent" / "renamed-install"
        alternative.mkdir(parents=True)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, fixture.record.install_record_key, 0, winreg.KEY_SET_VALUE) as handle:
            winreg.SetValueEx(handle, "InstallLocation", 0, winreg.REG_SZ, str(alternative))
        self.assertEqual(self.discover(fixture).install_root, alternative)

    def test_rejects_registry_settings_key_outside_caller_scope(self):
        fixture = self.make_fixture(1)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, fixture.record.install_record_key, 0, winreg.KEY_SET_VALUE) as handle:
            winreg.SetValueEx(handle, "SettingsKey", 0, winreg.REG_SZ, r"Software\Microsoft\Windows\CurrentVersion")
        with self.assertRaisesRegex(ValueError, "settings key is outside the caller scope"):
            self.discover(fixture)

    def test_rejects_sibling_shared_key_inside_fixture_scope(self):
        fixture = self.make_fixture(2)
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, fixture.record.install_record_key, 0, winreg.KEY_SET_VALUE) as handle:
            winreg.SetValueEx(handle, "SettingsKey", 0, winreg.REG_SZ, fixture.registry_base + r"\Shared")
        with self.assertRaisesRegex(ValueError, "settings key is outside the caller scope"):
            self.discover(fixture)

    def test_portable_app_is_discovered_without_record_oracle(self):
        fixture = create_fixture(REPO_ROOT / ".local" / "test-runs", "benign", "portable", 2)
        self.addCleanup(destroy_fixture, fixture)
        record = discover_portable_fixture_app(fixture.record.app_id, scope_root=fixture.root, registry_scope_key=fixture.registry_base)
        self.assertEqual(record.app_id, "CedarTool")
        self.assertEqual(record.install_root, fixture.record.install_root)
        self.assertEqual(record.settings_key, fixture.record.settings_key)

    def test_command_parser_preserves_quoted_arguments(self):
        command = (r"C:\Program Files\Vendor\uninstall.exe", "/remove", "app with spaces")
        self.assertEqual(split_windows_command(subprocess.list2cmdline(command)), command)


if __name__ == "__main__":
    unittest.main()
