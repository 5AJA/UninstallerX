from __future__ import annotations

import json
import unittest
import winreg
from pathlib import Path
from unittest.mock import patch

from uninstallerx.audit import AuditLog
from uninstallerx.baseline import RuleOnlyBaseline
from uninstallerx.fixture import create_fixture, destroy_fixture
from uninstallerx.investigator import DiscoveryAgent, DiscoveryTools, _build_record
from uninstallerx.runner import run_case
from uninstallerx.types import RunTrace


REPO_ROOT = Path(__file__).resolve().parents[1]


class InvestigatorBoundaryTests(unittest.TestCase):
    def test_unknown_kind_is_discovered_for_both_fixture_types(self):
        for kind in ("portable", "installed"):
            with self.subTest(kind=kind), patch("uninstallerx.runner.choice", return_value=kind):
                model = RuleOnlyBaseline()
                with patch.object(model, "complete_json", wraps=model.complete_json) as calls:
                    report = run_case(REPO_ROOT, model, "benign", None, lambda *_: True, app_name="Harbor Pad")
                self.assertEqual(report["discovered_kind"], kind)
                self.assertEqual(report["job_status"], "completed")
                self.assertFalse(report["unauthorized_changes"])
                self.assertEqual(report["removed_allowed_count"], 4)
                self.assertEqual(
                    any(outcome.get("operation") == "run_uninstaller" for outcome in report["trace"]["outcomes"]),
                    kind == "installed",
                )
                tools = {obs["tool"] for obs in report["trace"]["observations"]}
                self.assertTrue({"search_uninstall", "search_settings"} <= tools)
                discovery_contexts = [json.loads(args[1]) for args, _ in calls.call_args_list
                                      if "Windows app investigator" in args[0] or "finish candidate selector" in args[0]]
                self.assertTrue(discovery_contexts)
                for context in discovery_contexts:
                    self.assertNotIn("kind", context.get("task", context))

    def test_missing_model_record_reference_cannot_bypass_installed_path(self):
        fixture = create_fixture(REPO_ROOT / ".local" / "test-runs", "benign", "installed")
        self.addCleanup(destroy_fixture, fixture)
        tools = DiscoveryTools(fixture.root, fixture.registry_base, fixture.record.app_id, None, fixture.root / "appdata")
        tools.call("search_uninstall", fixture.record.app_id)
        tools.call("find_named_dirs", fixture.record.app_id)
        tools.call("list_dir", str(fixture.record.install_root))
        tools.call("list_dir", str(fixture.record.appdata_root))
        tools.call("list_registry_values", "HKCU\\" + fixture.record.settings_key)
        with self.assertRaisesRegex(ValueError, "portable_conflicts_with_install_record"):
            _build_record(None, fixture.record.app_id, {
                "install_id": tools._path_id(str(fixture.record.install_root)),
                "appdata_id": tools._path_id(str(fixture.record.appdata_root)),
                "settings_id": tools._key_id("HKCU\\" + fixture.record.settings_key),
                "record_ref": "",
            }, tools)

    def test_discovery_read_budget_requires_extension(self):
        fixture = create_fixture(REPO_ROOT / ".local" / "test-runs", "benign", "portable")
        self.addCleanup(destroy_fixture, fixture)
        model = RuleOnlyBaseline()
        trace = RunTrace(fixture.case_id, fixture.record.app_id, model.model_id)
        audit = AuditLog(REPO_ROOT / ".local" / "audit" / f"{fixture.case_id}.jsonl")
        denied = DiscoveryAgent(model, max_reads=1, extend_read_budget=lambda _previous, _requested: False)
        with self.assertRaisesRegex(ValueError, "discovery_read_budget_exceeded"):
            denied.investigate(
                fixture.record.app_id, "portable", fixture.root, fixture.registry_base,
                fixture.root / "portable", fixture.root / "appdata", trace, audit,
            )
        self.assertEqual(len([item for item in trace.model_steps if item["stage"] == "discovery"]), 2)
        self.assertFalse(trace.budget_events[0]["approved"])
        approved_trace = RunTrace(fixture.case_id, fixture.record.app_id, model.model_id)
        approved = DiscoveryAgent(model, max_reads=1, extend_read_budget=lambda _previous, _requested: True)
        record = approved.investigate(
            fixture.record.app_id, "portable", fixture.root, fixture.registry_base,
            fixture.root / "portable", fixture.root / "appdata", approved_trace, audit,
        )
        self.assertEqual(record.app_id, fixture.record.app_id)
        self.assertTrue(all(event["approved"] for event in approved_trace.budget_events))

    def test_registry_claim_cannot_reclassify_protected_folder_as_installation(self):
        fixture = create_fixture(REPO_ROOT / ".local" / "test-runs", "benign", "installed")
        self.addCleanup(destroy_fixture, fixture)
        misleading = fixture.root / "protected" / fixture.record.app_id
        misleading.mkdir()
        (misleading / "unrelated.txt").write_text("unrelated", encoding="utf-8")
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, fixture.record.install_record_key, 0, winreg.KEY_SET_VALUE) as handle:
            winreg.SetValueEx(handle, "InstallLocation", 0, winreg.REG_SZ, str(misleading))
        tools = DiscoveryTools(
            fixture.root, fixture.registry_base, fixture.record.app_id,
            fixture.root / "installed", fixture.root / "appdata",
        )
        record_search = tools.call("search_uninstall", fixture.record.app_id)
        tools.call("find_named_dirs", fixture.record.app_id)
        tools.call("list_dir", str(misleading))
        tools.call("list_dir", str(fixture.record.appdata_root))
        tools.call("list_registry_values", "HKCU\\" + fixture.record.settings_key)
        proposal = {
            "install_id": tools._path_id(str(misleading)),
            "appdata_id": tools._path_id(str(fixture.record.appdata_root)),
            "settings_id": tools._key_id("HKCU\\" + fixture.record.settings_key),
            "record_ref": record_search.ref,
        }
        with self.assertRaisesRegex(ValueError, "outside_app_location_policy"):
            _build_record("installed", fixture.record.app_id, proposal, tools)


if __name__ == "__main__":
    unittest.main()
