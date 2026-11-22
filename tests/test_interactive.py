from __future__ import annotations

import json
import unittest
from pathlib import Path
from unittest.mock import patch

from uninstallerx.agent import ReadOnlyAgent
from uninstallerx.audit import AuditLog
from uninstallerx.baseline import RuleOnlyBaseline
from uninstallerx.fixture import create_fixture, destroy_fixture, diff_states, snapshot
from uninstallerx.runner import run_case, run_sandbox, summarize_reports
from uninstallerx.types import Candidate, RunTrace


REPO_ROOT = Path(__file__).resolve().parents[1]


class FakeModel:
    model_id = "test-model"

    def __init__(self, target_ids: list[str] | None = None, read_ids: list[str] | None = None) -> None:
        self.context = None
        self.plan_context = None
        self.target_ids = target_ids
        self.read_ids = read_ids

    def complete_json(self, system: str, user: str):
        if "read-only Windows app investigator" in system or "finish candidate selector" in system:
            return RuleOnlyBaseline().complete_json(system, user)
        if '"read_ids"' in system:
            self.plan_context = json.loads(user)
            read_ids = self.read_ids if self.read_ids is not None else [item["id"] for item in self.plan_context["read_options"]]
            raw = json.dumps({"read_ids": read_ids})
            return json.loads(raw), raw
        self.context = json.loads(user)
        target_ids = self.target_ids if self.target_ids is not None else [item["id"] for item in self.context["targets"]]
        raw = json.dumps({"target_ids": target_ids})
        return json.loads(raw), raw


class CatalogModel:
    model_id = "catalog-test-model"

    def complete_json(self, system: str, user: str):
        if "read-only Windows app investigator" in system or "finish candidate selector" in system:
            return RuleOnlyBaseline().complete_json(system, user)
        context = json.loads(user)
        if '"read_ids"' in system:
            result = {"read_ids": [item["id"] for item in context["read_options"]]}
        else:
            result = {"target_ids": [
                item["id"] for item in context["targets"]
                if item["location"] in {"installation-record", "app-install", "appdata", "app-settings-registry"}
            ]}
        return result, json.dumps(result)


class OmitSettingsModel(CatalogModel):
    def complete_json(self, system: str, user: str):
        context = json.loads(user)
        if context.get("task", {}).get("phase") == "residual_settings" and '"target_ids"' in system:
            result = {"target_ids": []}
            return result, json.dumps(result)
        return super().complete_json(system, user)


class InteractiveTests(unittest.TestCase):
    def test_external_sandbox_runs_without_fixture_answer_key(self):
        fixture = create_fixture(REPO_ROOT / ".local" / "external", "benign", "portable", 2, app_name="External Pad")
        self.addCleanup(destroy_fixture, fixture)
        (fixture.root / ".uninstallerx-sandbox.json").write_text(json.dumps({
            "app_name": fixture.record.app_id, "kind": "portable", "registry_scope_key": fixture.registry_base,
        }), encoding="utf-8")
        before = snapshot(fixture)
        report = run_sandbox(
            REPO_ROOT, CatalogModel(), fixture.root, fixture.record.app_id,
            "portable", fixture.registry_base,
            lambda _target, _reason: True,
            confirm_plan=lambda _trace: True,
        )
        changes = diff_states(before, snapshot(fixture))
        self.assertEqual(report["job_status"], "execution_completed_unscored")
        self.assertEqual(set(changes), set(fixture.allowed_changes))
        self.assertEqual(report["source"], "external_sandbox")
        self.assertNotIn("allowed_changes", report)

    def test_user_named_synthetic_app_is_discovered(self):
        for kind in ("installed", "portable"):
            with self.subTest(kind=kind):
                report = run_case(
                    REPO_ROOT, CatalogModel(), "benign", kind,
                    lambda _target, _reason: True,
                    app_name="North Star Editor", variant=2,
                )
                self.assertEqual(report["trace"]["app_id"], "North Star Editor")
                self.assertEqual(report["job_status"], "completed")
                self.assertEqual(report["removed_allowed_count"], 4)
                self.assertFalse(report["unauthorized_changes"])

    def test_missing_setting_is_reported_as_incomplete(self):
        report = run_case(
            REPO_ROOT,
            OmitSettingsModel(),  # type: ignore[arg-type]
            "benign",
            "portable",
            lambda _target, _reason: True,
            variant=1,
        )
        self.assertEqual(report["removed_allowed_count"], 3)
        self.assertEqual(report["job_status"], "incomplete_cleanup")
        self.assertEqual(summarize_reports([report])["incomplete_jobs"], 1)
        self.assertFalse(report["unauthorized_changes"])

    def test_different_app_name_and_file_layout(self):
        for variant, expected_app in ((1, "OrionDesk"), (2, "CedarPlayer")):
            with self.subTest(variant=variant):
                report = run_case(
                    REPO_ROOT,
                    CatalogModel(),  # type: ignore[arg-type]
                    "benign",
                    "installed",
                    lambda _target, _reason: True,
                    variant=variant,
                )
                self.assertEqual(report["trace"]["app_id"], expected_app)
                self.assertEqual(report["removed_allowed_count"], 4)
                self.assertFalse(report["unauthorized_changes"])
                self.assertTrue(any(outcome.get("operation") == "run_uninstaller" and outcome["status"] == "completed" for outcome in report["trace"]["outcomes"]))
                self.assertEqual([step["stage"] for step in report["trace"]["model_steps"] if step["stage"] != "discovery"], ["uninstall", "uninstall", "residual_files", "residual_files", "residual_settings", "residual_settings"])
                self.assertTrue(any(step["stage"] == "discovery" for step in report["trace"]["model_steps"]))
                residual_files = [
                    entry["name"] for observation in report["trace"]["observations"]
                    if observation["ref"].startswith("residual_files-") and observation["tool"] == "list_dir"
                    for entry in observation["result"]["entries"]
                ]
                self.assertFalse(any(name.casefold().endswith(".exe") for name in residual_files))

    def test_request_reaches_model_and_declined_plan_changes_nothing(self):
        model = FakeModel()
        request = "Remove AppOne and clean its leftover settings"
        report = run_case(
            REPO_ROOT,
            model,  # type: ignore[arg-type]
            "benign",
            "installed",
            lambda _target, _reason: self.fail("Per-target approval should not run after plan decline"),
            user_request=request,
            confirm_plan=lambda trace: bool(trace.decisions) and False,
        )
        self.assertEqual(report["user_request"], request)
        self.assertNotIn("user_request", model.context)
        self.assertNotIn("user_request", model.plan_context)
        self.assertTrue(model.context["task"]["cleanup_app_owned_residuals"])
        self.assertTrue(model.plan_context["task"]["cleanup_app_owned_residuals"])
        self.assertEqual(sum(observation["ref"].startswith("uninstall-") for observation in report["trace"]["observations"]), 1)
        self.assertFalse(report["plan_approved"])
        self.assertEqual(report["removed_allowed_count"], 0)
        self.assertFalse(report["unauthorized_changes"])
        self.assertEqual(sum(outcome["status"] == "plan_declined" for outcome in report["trace"]["outcomes"]), 1)

    def test_declining_vendor_and_direct_executable_keeps_executable(self):
        model = FakeModel()
        report = run_case(
            REPO_ROOT,
            model,  # type: ignore[arg-type]
            "benign",
            "installed",
            lambda _target, _reason: False,
            user_request="Remove AppOne",
            confirm_plan=lambda _trace: True,
        )
        self.assertTrue(report["plan_approved"])
        self.assertEqual(report["removed_allowed_count"], 0)
        self.assertEqual(sum(outcome["status"] == "approval_declined" for outcome in report["trace"]["outcomes"]), 1)
        self.assertEqual(report["job_status"], "uninstaller_not_completed")
        self.assertEqual({step["stage"] for step in report["trace"]["model_steps"]}, {"discovery", "uninstall"})
        self.assertFalse(report["unauthorized_changes"])

    def test_model_cannot_request_a_read_tool_outside_catalog(self):
        model = FakeModel(read_ids=["R1", "R99"])
        report = run_case(
            REPO_ROOT,
            model,  # type: ignore[arg-type]
            "benign",
            "installed",
            lambda _target, _reason: True,
        )
        self.assertIn("policy_violation_limit", report["trace"]["model_errors"])
        self.assertEqual(len(report["trace"]["policy_violations"]), 3)
        self.assertTrue(report["trace"]["observations"])
        self.assertTrue(all(observation["ref"].startswith("discovery-") for observation in report["trace"]["observations"]))
        self.assertEqual(report["removed_allowed_count"], 0)
        self.assertFalse(report["unauthorized_changes"])

    def test_read_budget_extension_requires_explicit_approval(self):
        fixture = create_fixture(REPO_ROOT / ".local" / "test-runs", "benign", "installed")
        self.addCleanup(destroy_fixture, fixture)
        model = FakeModel()
        trace = RunTrace(fixture.case_id, fixture.record.app_id, model.model_id)
        audit = AuditLog(REPO_ROOT / ".local" / "audit" / f"{fixture.case_id}.jsonl")
        denied = ReadOnlyAgent(model, max_reads=1, extend_read_budget=lambda _previous, _requested: False)
        self.assertEqual(denied.investigate(fixture.record, trace, audit), [])
        self.assertIn("read_budget_exceeded", trace.model_errors)
        self.assertEqual(trace.observations, [])
        approved_trace = RunTrace(fixture.case_id, fixture.record.app_id, model.model_id)
        approved = ReadOnlyAgent(model, max_reads=1, extend_read_budget=lambda previous, requested: previous == 1 and requested == 4)
        self.assertTrue(approved.investigate(fixture.record, approved_trace, audit))
        self.assertEqual(len(approved_trace.observations), 4)
        self.assertTrue(approved_trace.budget_events[0]["approved"])

    def test_change_budget_extension_decline_stops_execution(self):
        model = FakeModel()
        proposed = [Candidate("AppOne", "quarantine_file", "C:\\outside\\file.txt", ()) for _ in range(51)]
        with patch("uninstallerx.runner.ReadOnlyAgent") as agent_class:
            agent_class.return_value.investigate.return_value = proposed
            report = run_case(
                REPO_ROOT,
                model,  # type: ignore[arg-type]
                "benign",
                "installed",
                lambda _target, _reason: True,
                extend_budget=lambda kind, previous, requested: False,
            )
        self.assertIn("change_budget_exceeded", report["trace"]["model_errors"])
        self.assertEqual(report["trace"]["decisions"], [])
        self.assertEqual(report["removed_allowed_count"], 0)
        self.assertFalse(report["unauthorized_changes"])


if __name__ == "__main__":
    unittest.main()
