from __future__ import annotations

import ctypes
import io
import json
import os
import shutil
import stat
import subprocess
import sys
import time
import unittest
import winreg
from collections import deque
from contextlib import nullcontext
from dataclasses import replace
from pathlib import Path
from tempfile import TemporaryDirectory
from threading import Event
from unittest.mock import Mock, patch
from uuid import uuid4
from zipfile import ZipFile

from uninstallerx.audit import AuditLog
from uninstallerx.live_reasoning import InvestigationError, ToolSession
from uninstallerx.model_provider import LocalGranite, ModelContextError, ModelOutputLimitError
from uninstallerx.recovery import RecoveryJournal
from uninstallerx.registry_settings import Setting, investigate_settings
from uninstallerx.real_apps import (
    Installation,
    BinaryInfo,
    LiveDiscovery,
    ResidualDiscovery,
    RemovalPlan,
    RemovalProposal,
    installed_apps,
    prepare_uninstall,
    run_real,
    scan_caches,
)
from uninstallerx.vendor_process import VendorRun
from uninstallerx.windows import system_directory
from uninstallerx.packaged_apps import PackageApp
from uninstallerx.portable_apps import PortableApp, read_portable_executables
from uninstallerx.portable_files import BACKUP_SEMANTICS, INVALID_HANDLE, OPEN_EXISTING, _kernel, delete_verified, fingerprint, rename_sibling_verified


class RealAppTests(unittest.TestCase):
    def setUp(self):
        self.tmp = TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.enterContext(patch.dict(os.environ, {"USERPROFILE": str(self.root / "TestProfile"),
                                                 "LOCALAPPDATA": str(self.root / "TestLocalData"),
                                                 "APPDATA": str(self.root / "TestRoamingData"),
                                                 "TEMP": str(self.root / "TestTemp"),
                                                 "TMP": str(self.root / "TestTemp")}))
        self.enterContext(patch("uninstallerx.portable_apps._local_drives", return_value=[]))
        self.enterContext(patch("uninstallerx.real_apps.packaged_apps", return_value=[]))
        self.app = Installation(winreg.HKEY_LOCAL_MACHINE, winreg.KEY_WOW64_32KEY, "arbor", {
            "DisplayName": "Arbor Editor",
            "Publisher": "Arbor Tools",
        })

    def model(self, *steps, scripted_discovery=False, review_residuals=None):
        script = iter(steps)

        def call(system, user, *, schema=None):
            context = json.loads(user) if user.startswith("{") else {}
            if "proposed_targets" in context:
                # Filesystem tests use a scripted model verdict. Review tests can supply their own verdict.
                targets = context["proposed_targets"]
                if review_residuals is not None:
                    answer = review_residuals(context)
                elif "assessments" in schema["properties"]:
                    answer = {"assessments": {ref: {"producer": "verified_app", "purpose": "generated_disposable_output",
                                                     "evidence": item["text_excerpt"][:160]}
                                              for ref, item in targets.items()}}
                else:
                    answer = {"confirmed_ids": list(targets)}
            elif not scripted_discovery and context.get("copies_added_to_plan"):
                actions = context["available_actions"]
                action = next(key for key in actions if key in {"desktop", "packages", "portable_folders", "finish"}
                              or key.startswith(("scan_", "skip_")))
                answer = {"action": action}
            else:
                answer = next(script)
                answer = answer(context) if callable(answer) else {"action": answer} if isinstance(answer, str) else answer
            selected = context.get("available_actions", {}).get(answer.get("action"), {})
            if selected.get("query") == "Supply a literal query" and "query" not in answer:
                answer = {**answer, "query": context["lookup_names"][0]}
            return answer, json.dumps(answer)

        model = Mock()
        model.complete_json.side_effect = call
        return model

    def read_document(self, name):
        def from_inventory(context):
            key = next(key for key, file in context["readable_files"].items() if Path(file["path"]).name == name)
            return {"action": "read_text", "file_id": key, "offset": 0}
        return from_inventory

    def test_name_translation_selects_an_observed_entry(self):
        plan = RemovalPlan(self.app, ("C:\\Program Files\\Arbor Editor\\uninstall.exe",), "digest",
                           "Arbor Editor", "Arbor Tools", None, None, "verified")
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
            patch("uninstallerx.real_apps.packaged_apps", return_value=[]),
            patch("uninstallerx.real_apps.search_areas", return_value=[]),
            patch("uninstallerx.real_apps._registered_target", return_value=plan.command),
            patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
            patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
        ):
            model = self.model({"names": ["Arbor Editor"]}, "desktop", "inspect_c1", "propose_c1", "list_search_locations", "stop")
            report = run_real(self.root, model, "아버 편집기", apply=False, closing=Event(), review=Mock(), progress=Mock())
            self.assertEqual(report["app_name"], "Arbor Editor")
            self.assertEqual(report["status"], "preview")
            model = self.model({"names": ["Missing Editor"]}, "desktop", "packages", "portable_folders", "stop")
            report = run_real(self.root, model, "없는 편집기", apply=False, closing=Event(), review=Mock(), progress=Mock())
            self.assertEqual(report["status"], "not_found")

    def test_cache_scan_does_not_select_profile_data_or_links(self):
        root = self.root / "AppData" / "Arbor Editor"
        profile = root / "User Data" / "Default"
        cache = profile / "Cache" / "Cache_Data"
        cache.mkdir(parents=True)
        (profile / "Bookmarks").write_text("keep")
        (profile / "Local Storage" / "Cache").mkdir(parents=True)
        (profile / "Local Storage" / "Cache" / "keep.db").write_text("keep")
        (cache / "temporary").write_text("cache")
        os.link(profile / "Bookmarks", cache / "linked")
        files, limited = scan_caches([root], Event())
        self.assertEqual([item.path for item in files], [cache / "temporary"])
        self.assertFalse(limited)

    def test_preview_does_not_execute_even_when_removal_plan_is_available(self):
        plan = RemovalPlan(self.app, ("C:\\Program Files\\Arbor Editor\\uninstall.exe",), "digest",
                           "Arbor Editor", "Arbor Tools", None, None, "verified")
        review = Mock()
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
            patch("uninstallerx.real_apps.packaged_apps", return_value=[]) as packages,
            patch("uninstallerx.real_apps._registered_target", return_value=plan.command),
            patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
            patch("uninstallerx.real_apps.run_vendor") as execute,
            patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
        ):
            model = self.model("desktop", "inspect_c1", "propose_c1", "list_search_locations", "stop")
            result = run_real(self.root, model, self.app.name, apply=False, closing=Event(), review=review, progress=Mock())
        self.assertEqual(result["status"], "preview")
        self.assertEqual(result["residual_deleted_count"], 0)
        execute.assert_not_called()
        review.assert_not_called()
        packages.assert_called_once_with()

    def test_observed_plan_is_not_used_when_model_abstains(self):
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
            patch("uninstallerx.real_apps._registered_target", return_value=("C:\\app\\uninstall.exe",)),
            patch("uninstallerx.real_apps.prepare_uninstall") as verify,
        ):
            model = self.model("desktop", "inspect_c1", "stop")
            review = Mock()
            report = run_real(self.root, model, self.app.name, apply=True, closing=Event(), review=review, progress=Mock())
        self.assertEqual(report["status"], "not_found")
        self.assertNotIn("command", report)
        verify.assert_not_called()
        review.assert_not_called()

    def test_rejects_unobserved_removal_proposal_before_gate(self):
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
            patch("uninstallerx.real_apps._registered_target", return_value=("C:\\app\\uninstall.exe",)),
            patch("uninstallerx.real_apps.prepare_uninstall") as verify,
        ):
            model = self.model("desktop", "inspect_c1", "propose_c99", "propose_c99", "propose_c99")
            review = Mock()
            report = run_real(self.root, model, self.app.name, apply=True, closing=Event(), review=review, progress=Mock())
        self.assertEqual(report["status"], "blocked")
        verify.assert_not_called()
        review.assert_not_called()

    def test_model_can_propose_the_second_observed_installation(self):
        another = Installation(self.app.hive, self.app.view, "arbor-other", {
            **self.app.values, "DisplayVersion": "2.0",
        })
        command = ("C:\\Arbor 2\\uninstall.exe",)
        plan = RemovalPlan(another, command, "digest", another.name, another.publisher, None, None, "verified")
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app, another]),
            patch("uninstallerx.real_apps._registered_target", return_value=command) as observed,
            patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan) as verify,
            patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
        ):
            model = self.model("desktop", "inspect_c2", "propose_c2", "list_search_locations", "stop")
            report = run_real(self.root, model, self.app.name, apply=False, closing=Event(), review=Mock(), progress=Mock())
        self.assertEqual(report["status"], "preview")
        self.assertEqual(report["model_candidate_id"], "c2")
        observed.assert_called_once_with(another)
        verify.assert_called_once_with(another)

    def test_app_data_is_rechecked_after_confirmed_uninstaller(self):
        app_root = self.root / "Arbor Editor"
        primary = app_root / "arbor.exe"
        cache_root = self.root / "AppData" / "Arbor Editor"
        cache_dir = cache_root / "cache"
        cache_dir.mkdir(parents=True)
        profile = cache_root / "Profile.db"
        profile.write_text("user data")
        cache = cache_dir / "after-uninstall.bin"
        other_cache = cache_dir / "preserve.bin"
        plan = RemovalPlan(self.app, (str(app_root / "uninstall.exe"),), "digest",
                           "Arbor Editor", "Arbor Tools", app_root, primary, "verified")
        clock = 0.0

        def approve_after_reading(*_):
            nonlocal clock
            clock += 601
            return True

        review = Mock(side_effect=approve_after_reading)

        def execute(command, **kwargs):
            nonlocal clock
            self.assertEqual(kwargs["cwd"], Path(os.environ["SystemRoot"]) / "System32")
            clock += 601
            cache.write_text("residual")
            other_cache.write_text("not proposed")
            return VendorRun(0)

        def select_observed_file(context):
            files = context["observed_files"]
            selected = next(ref for ref, info in files.items() if info["name"] == cache.name)
            return {"action": "propose", "target_ids": [selected]}

        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
            patch("uninstallerx.real_apps.packaged_apps", return_value=[]),
            patch("uninstallerx.real_apps._registered_target", return_value=plan.command),
            patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
            patch("uninstallerx.real_apps._read_installation", side_effect=[self.app, None]),
            patch("uninstallerx.real_apps.residual_search_roots", return_value=[cache_root]),
            patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
            patch("uninstallerx.real_apps.run_vendor", side_effect=execute),
            patch("uninstallerx.live_reasoning.time.monotonic", side_effect=lambda: clock),
        ):
            model = self.model("desktop", "inspect_c1", "propose_c1", "list_search_locations", "list_d1", "read_d2",
                               select_observed_file, "read_d1", "stop")
            result = run_real(self.root, model, self.app.name, apply=True, closing=Event(), review=review, progress=Mock())
        self.assertEqual(result["status"], "removed")
        self.assertEqual(result["residual_deleted_count"], 1)
        self.assertEqual(review.call_count, 2)
        self.assertEqual(review.call_args.args[1][0][1], str(cache))
        self.assertFalse(cache.exists())
        self.assertEqual(other_cache.read_text(), "not proposed")
        self.assertEqual(profile.read_text(), "user data")
        self.assertEqual(profile.read_text(), "user data")
        self.assertFalse((self.root / ".local" / "quarantine").exists())
        self.assertFalse(result["recovery_available"])
        events = [json.loads(line) for line in Path(result["audit_path"]).read_text(encoding="utf-8").splitlines()]
        phase = [event["event"] for event in events if event.get("phase") == "residuals"]
        self.assertLess(phase.index("model_read_requested"), phase.index("read_observation"))
        self.assertLess(phase.index("read_observation"), phase.index("model_proposal"))
        self.assertLess(phase.index("model_proposal"), phase.index("gate_decision"))

    def test_preview_reports_blocked_when_no_proposed_copy_can_be_prepared(self):
        other = replace(self.app, key="other")
        model = self.model("inventory", "propose_c1", "propose_c2", scripted_discovery=True)
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app, other]),
            patch("uninstallerx.real_apps.search_areas", return_value=[]),
            patch("uninstallerx.real_apps._registered_target", return_value=(str(self.root / "remove.exe"),)),
            patch("uninstallerx.real_apps.prepare_uninstall", side_effect=ValueError("A valid removal command is unavailable.")),
        ):
            report = run_real(self.root, model, self.app.name, apply=False, closing=Event(), review=Mock(), progress=Mock())
        self.assertEqual(report["status"], "blocked")
        self.assertEqual([copy["status"] for copy in report["copies"]], ["blocked", "blocked"])

    def test_verify_installation_after_vendor_exit_before_investigating_leftovers(self):
        cases = (
            (19, False, False, "removed"),
            (73, False, False, "removed"),
            (73, True, False, "uninstaller_failed"),
            (73, False, True, "uninstaller_failed"),
            (0, True, True, "uninstaller_unverified"),
            (3010, False, False, "restart_required"),
        )
        for exit_code, keep_entry, keep_primary, status in cases:
            with self.subTest(exit_code=exit_code, keep_entry=keep_entry, keep_primary=keep_primary):
                folder = self.root / f"app-{exit_code}-{keep_entry}-{keep_primary}"
                folder.mkdir()
                primary = folder / "arbor.exe"
                primary.touch()
                command = (str(folder / "uninstall.exe"),)
                plan = RemovalPlan(self.app, command, "digest", self.app.name, self.app.publisher, folder,
                                   primary, "verified")
                entry = self.app

                def execute(args, **kwargs):
                    nonlocal entry
                    if not keep_entry:
                        entry = None
                    if not keep_primary:
                        primary.unlink()
                    return VendorRun(exit_code)

                closing = Event()
                review = Mock(return_value=True)
                model = self.model("desktop", "inspect_c1", "propose_c1")
                with (
                    patch.object(closing, "wait", return_value=False),
                    patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
                    patch("uninstallerx.real_apps._registered_target", return_value=command),
                    patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
                    patch("uninstallerx.real_apps._read_installation", side_effect=lambda *_: entry),
                    patch("uninstallerx.real_apps.run_vendor", side_effect=execute),
                    patch.object(ResidualDiscovery, "run", return_value=([], [], False)) as residuals,
                    patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
                ):
                    result = run_real(self.root, model, self.app.name, apply=True,
                                      closing=closing, review=review, progress=Mock())
                self.assertEqual(result["exit_code"], exit_code)
                self.assertEqual(result["status"], status)
                if status == "removed":
                    residuals.assert_called_once_with()
                else:
                    residuals.assert_not_called()

    def test_vendor_process_tree_finishes_before_actual_leftover_cleanup(self):
        for launch in ("direct", "grandchild", "no-op"):
            with self.subTest(launch=launch):
                root = self.root / f"Paket {launch}"
                root.mkdir()
                primary = root / "viewer.exe"
                registration = root / "registered"
                primary.touch()
                registration.touch()
                data = root / "Temp"
                data.mkdir()
                leftover = data / "viewer-trace.log"
                preserved = data / "other-data.txt"
                preserved.write_text("untouched")
                worker = (
                    "import pathlib,sys,time; time.sleep(float(sys.argv[1])); "
                    "pathlib.Path(sys.argv[2]).unlink(); pathlib.Path(sys.argv[3]).unlink(); "
                    "pathlib.Path(sys.argv[4]).write_text('created by the last vendor process')"
                )
                command = (sys.executable, "-c", worker, "0", str(primary), str(registration), str(leftover))
                if launch == "grandchild":
                    worker_command = (*command[:3], "6.8", *command[4:])
                    spawn = "import subprocess,sys; subprocess.Popen(sys.argv[1:])"
                    command = (sys.executable, "-c", spawn, sys.executable, "-c", spawn, *worker_command)
                elif launch == "no-op":
                    command = (sys.executable, "-c", "pass")
                plan = RemovalPlan(self.app, command, "digest", self.app.name, self.app.publisher, root,
                                   primary, "verified fixture")
                review = Mock(return_value=True)

                def choose_leftover(context):
                    ref = next(ref for ref, item in context["observed_files"].items() if item["name"] == leftover.name)
                    self.assertFalse(primary.exists())
                    self.assertFalse(registration.exists())
                    return {"action": "propose", "target_ids": [ref]}

                model = self.model("inventory", "propose_c1", "list_search_locations", "read_d1", choose_leftover,
                                   scripted_discovery=True)
                with (
                    patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
                    patch("uninstallerx.real_apps.search_areas", return_value=[]),
                    patch("uninstallerx.real_apps._registered_target", return_value=command),
                    patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
                    patch("uninstallerx.real_apps._read_installation",
                          side_effect=lambda *_: self.app if registration.exists() else None),
                    patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
                    patch("uninstallerx.real_apps.residual_search_roots", return_value=[data]),
                ):
                    result = run_real(self.root, model, self.app.name, apply=True, closing=Event(), review=review, progress=Mock())
                self.assertTrue(preserved.is_file())
                events = [json.loads(line) for line in Path(result["audit_path"]).read_text(encoding="utf-8").splitlines()]
                names = [event["event"] for event in events]
                self.assertLess(names.index("uninstaller_launcher_exited"), names.index("uninstaller_verification"))
                if launch == "no-op":
                    self.assertEqual(result["status"], "uninstaller_unverified")
                    self.assertTrue(primary.is_file() and registration.is_file())
                    self.assertFalse(result["primary_removed"] or result["registration_removed"])
                    self.assertFalse(any(event.get("phase") == "residuals" for event in events))
                    review.assert_called_once()
                else:
                    self.assertEqual(result["status"], "removed", result)
                    self.assertEqual(result["residual_deleted_count"], 1)
                    self.assertFalse(leftover.exists())
                    self.assertEqual(review.call_count, 2)
                    self.assertLess(names.index("uninstaller_exited"), names.index("residual_delete_approved"))
                if launch == "grandchild":
                    self.assertIn("uninstaller_waiting_for_children", names)
                    total = next(event["total_processes"] for event in events if event["event"] == "uninstaller_exited")
                    self.assertGreaterEqual(total, 3)

    def test_msi_checks_product_state_before_investigating_leftovers(self):
        product_code = "{" + str(uuid4()).upper() + "}"
        app = Installation(self.app.hive, self.app.view, product_code,
                           {**self.app.values, "WindowsInstaller": 1})
        command = (str(system_directory() / "msiexec.exe"),
                   "/x", product_code, "/norestart")
        plan = RemovalPlan(app, command, "digest", app.name, "", None, None, "verified")
        for state, status in ((-1, "removed"), (2, "uninstaller_failed"), (-2, "uninstaller_failed")):
            with self.subTest(state=state):
                closing = Event()
                with (
                    patch.object(closing, "wait", return_value=False),
                    patch("uninstallerx.real_apps.installed_apps", return_value=[app]),
                    patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
                    patch("uninstallerx.real_apps._read_installation", side_effect=[app, *[None] * 12]),
                    patch("uninstallerx.real_apps.run_vendor", return_value=VendorRun(73)),
                    patch("uninstallerx.real_apps._msi_state", return_value=state),
                    patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
                    patch.object(ResidualDiscovery, "run", return_value=([], [], False)) as residuals,
                ):
                    model = self.model("desktop", "inspect_c1", "propose_c1")
                    result = run_real(self.root, model, app.name, apply=True, closing=closing,
                                      review=Mock(return_value=True), progress=Mock())
                self.assertEqual(result["status"], status)
                self.assertEqual(residuals.call_count, int(state == -1))

    def test_discovery_constrains_a_single_action_and_refreshes_choices_after_reading(self):
        plan = RemovalPlan(self.app, ("C:\\Arbor\\uninstall.exe",), "digest", self.app.name,
                           self.app.publisher, None, None, "verified")
        search_root = self.root / "local-search"
        search_root.mkdir()
        model = self.model("desktop", "inspect_c1", "propose_c1", "packages", "portable_folders",
                           {"action": "scan_p1", "query": "Arbor"}, "finish", scripted_discovery=True)
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
            patch("uninstallerx.real_apps._registered_target", return_value=plan.command),
            patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
            patch("uninstallerx.real_apps.search_areas", return_value=[search_root]),
            patch.object(ResidualDiscovery, "run", return_value=([], [], False)),
            patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
        ):
            report = run_real(self.root, model, self.app.name, apply=False, closing=Event(),
                              review=Mock(), progress=Mock())
        self.assertEqual(report["status"], "preview")
        self.assertFalse(report["search_incomplete"])
        choices = []
        for call in model.complete_json.call_args_list:
            menu = json.loads(call.args[1])["available_actions"]
            schema = call.kwargs["schema"]
            self.assertEqual(schema["required"], ["action"])
            self.assertEqual(schema["properties"]["action"]["enum"], list(menu))
            self.assertEqual("query" in schema["properties"], any(key.startswith(("scan_", "rescan_")) for key in menu))
            choices.append(list(menu))
        self.assertIn(["portable_folders"], choices)
        self.assertEqual(choices[-1], ["finish", "rescan_p1"])

    def test_optional_review_of_current_proposals_does_not_approve_removal(self):
        command = (str(self.root / "vendor" / "Uninstall.exe"),)
        plan = RemovalPlan(self.app, command, "digest", self.app.name, self.app.publisher,
                           self.root / "vendor", self.root / "vendor" / "editor.exe", "verified")

        for request_review in (False, True):
            with self.subTest(request_review=request_review):
                requested = Event()
                events = []

                def review_available(available):
                    events.append(available)
                    if available and request_review:
                        requested.set()

                def review(*args):
                    events.append("removal review")
                    return False

                extra = () if request_review else ("packages", "portable_folders")
                model = self.model("desktop", "inspect_c1", "propose_c1", *extra, scripted_discovery=True)
                with (patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
                      patch("uninstallerx.real_apps._registered_target", return_value=command),
                      patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
                      patch("uninstallerx.real_apps.search_areas", return_value=[]),
                      patch("uninstallerx.real_apps.run_vendor") as execute):
                    report = run_real(self.root, model, self.app.name, apply=True, closing=Event(), review=review,
                                      progress=Mock(), review_requested=requested, review_available=review_available)
                execute.assert_not_called()
                self.assertEqual(events, [True, False, "removal review"])
                self.assertEqual(report["search_incomplete"], request_review)
                self.assertEqual(report.get("search_stopped", False), request_review)
                self.assertEqual(report["status"], "declined")

    def test_filesystem_search_reads_past_empty_pages_and_can_pause_for_review(self):
        root = self.root / "portable"
        folder = root.joinpath(*(f"level-{i}" for i in range(8)))
        folder.mkdir(parents=True)
        executable = folder / "Arbor.exe"
        shutil.copyfile(sys.executable, executable)
        queue = deque([(root, 0)])
        with patch("uninstallerx.portable_apps.PORTABLE_SCAN_ENTRIES", 4):
            self.assertEqual(read_portable_executables(root, set(), Event(), query="Arbor", pending=queue), [])
            self.assertTrue(queue)
            paused = read_portable_executables(root, set(), Event(), query="Arbor", pending=queue,
                                                continue_scanning=lambda: False)
            self.assertEqual(paused, [])
            self.assertTrue(queue)
            rest = read_portable_executables(root, set(), Event(), query="Arbor", pending=queue,
                                              continue_scanning=lambda: True)
            self.assertEqual(rest, [])
            self.assertTrue(queue, "An empty page must yield control and retain its cursor.")
            rest = read_portable_executables(root, set(), Event(), query="Arbor", pending=queue,
                                              continue_scanning=lambda: True)
        self.assertEqual([item.executable for item in rest], [executable])
        self.assertFalse(queue)

    def test_grouped_inventory_collects_evidence_and_leaves_the_proposal_to_the_model(self):
        command = (str(self.root / "chosen" / "uninstall.exe"),)
        other = replace(self.app, key="other")
        plan = RemovalPlan(self.app, command, "digest", self.app.name, self.app.publisher, None, None, "verified")

        def choose(context):
            self.assertEqual(set(context["inspected"]), {"c1", "c2"})
            self.assertEqual(context["copies_added_to_plan"], [])
            return {"action": "propose_c2"}

        model = self.model("inventory", choose, "skip_c1", scripted_discovery=True)
        audit = AuditLog(self.root / "grouped.jsonl")
        session = ToolSession(model, Event(), audit)
        with (patch("uninstallerx.real_apps.installed_apps", return_value=[other, self.app]),
              patch("uninstallerx.real_apps._registered_target", return_value=plan.command),
              patch("uninstallerx.real_apps.packaged_apps", return_value=[]) as packages,
              patch("uninstallerx.real_apps.search_areas", return_value=[])):
            found = LiveDiscovery(self.app.name, session, (), Mock()).run()
        self.assertEqual([proposal.app for proposal in found], [self.app])
        packages.assert_called_once()
        self.assertEqual(model.complete_json.call_count, 3)

    def test_model_retries_windows_lookup_after_its_first_name_misses(self):
        request = "Remove the Arbor writing app"
        command = (str(self.root / "Arbor" / "uninstall.exe"),)

        def retry(context):
            self.assertEqual(context["user_request"], request)
            self.assertEqual(context["inspected"], {})
            self.assertIn("query_windows", context["available_actions"])
            self.assertEqual(context["searched_windows_names"], ["Arbor Writing App"])
            return {"action": "query_windows", "query": "Arbor Writing App"}

        def propose(context):
            self.assertIn("c1", context["inspected"])
            self.assertNotIn("query_windows", context["available_actions"])
            return {"action": "propose_c1"}

        model = self.model("inventory", retry, {"query": "Arbor"}, "inspect_c1", propose, scripted_discovery=True)
        with (patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]) as desktop,
              patch("uninstallerx.real_apps._registered_target", return_value=command),
              patch("uninstallerx.real_apps.search_areas", return_value=[])):
            discovery = LiveDiscovery("Arbor Writing App", ToolSession(model, Event(), AuditLog(self.root / "retry.jsonl")),
                                      (), Mock(), user_request=request, lookup_names=("Arbor Writing App",))
            self.assertEqual([item.app for item in discovery.run()], [self.app])
        desktop.assert_called_once()
        self.assertEqual(model.complete_json.call_args_list[2].args[1], request)

    def test_model_can_browse_actual_windows_names_without_a_matching_query(self):
        notes = replace(self.app, key="notes", values={**self.app.values, "DisplayName": "Notes App"})
        command = (str(self.root / "Notes" / "uninstall.exe"),)

        def choose(context):
            self.assertEqual(context["inspected"], {})
            self.assertEqual(context["copies_added_to_plan"], [])
            return {"action": next(key for key, option in context["available_actions"].items()
                                   if key.startswith("inspect_windows_") and option["name"] == notes.name)}

        model = self.model("inventory", "browse_windows", choose, "propose_c1", "finish",
                           scripted_discovery=True)
        with (patch("uninstallerx.real_apps.installed_apps", return_value=[notes, self.app]),
              patch("uninstallerx.real_apps._registered_target", return_value=command),
              patch("uninstallerx.real_apps.search_areas", return_value=[])):
            discovery = LiveDiscovery("Notebook Tool", ToolSession(model, Event(), AuditLog(self.root / "browse.jsonl")),
                                      (), Mock(), user_request="Remove my app for taking notes", lookup_names=())
            self.assertEqual([item.app for item in discovery.run()], [notes])
            self.assertEqual(list(discovery.candidates.values()), [notes])

    def test_search_locations_reuses_a_covered_subtree_and_matches_both_copies(self):
        root = self.root / "workspace"
        child = root / "downloads"
        child.mkdir(parents=True)
        expected = {child / "Arbor-A.exe", root / "Arbor-B.exe"}
        for file in expected:
            shutil.copyfile(sys.executable, file)
        scanned = []
        actual_scandir = os.scandir

        def scandir(path):
            scanned.append(Path(path))
            return actual_scandir(path)

        def inspect(context):
            self.assertEqual({item["file"] for item in context["available_actions"].values() if "file" in item},
                             {path.name for path in expected})
            return {"action": "skip_c1", "reason": "uncertain"}

        model = self.model("inventory", {"action": "search_locations", "locations": ["scan_p1", "scan_p999"], "query": "Arbor"},
                           {"action": "search_locations", "locations": ["scan_p1", "scan_p2"], "query": "Arbor"},
                           inspect, "skip_c2", "stop", scripted_discovery=True)
        session = ToolSession(model, Event(), AuditLog(self.root / "scan.jsonl"))
        with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
              patch("uninstallerx.real_apps.search_areas", return_value=[child, root]),
              patch("uninstallerx.portable_apps.os.scandir", side_effect=scandir)):
            discovery = LiveDiscovery(self.app.name, session, (), Mock())
            self.assertEqual(discovery.run(), [])
        self.assertEqual({item.executable for item in discovery.candidates.values()}, expected)
        self.assertEqual(scanned, [child, root])
        self.assertEqual(session.violations, 1)
        self.assertFalse(discovery.search_incomplete)

    def test_context_overflow_pages_actions_with_the_original_user_request(self):
        request = "Remove Arbor, keep the project data."
        actions = {f"read_{index}": {"tool": "Read a directory", "path": "a" * 1_000} for index in range(9)}

        def choose(prompt, payload, *, schema):
            context = json.loads(payload)
            menu = context["available_actions"]
            self.assertEqual(context["user_request"], request)
            self.assertEqual(schema["properties"]["action"]["enum"], list(menu))
            if "action_menu_page" not in context:
                raise ModelContextError("request too large")
            action = "menu_next" if context["action_menu_page"] == 1 else "read_8"
            return {"action": action}, json.dumps({"action": action})

        model = Mock()
        model.complete_json.side_effect = choose
        session = ToolSession(model, Event(), AuditLog(self.root / "menu.jsonl"))
        self.assertEqual(session.ask("residuals", "Choose an action", {"user_request": request}, actions)["action"], "read_8")
        self.assertEqual(session.violations, 0)

    def test_win32_recognizes_signed_app_without_an_icon(self):
        root = self.root / "app-folder"
        root.mkdir()
        primary, uninstaller = root / "ArborEditor.exe", root / "Uninstall.exe"
        primary.touch()
        uninstaller.touch()
        values = {**self.app.values, "InstallLocation": str(root), "UninstallString": f'"{uninstaller}" /S'}
        app = replace(self.app, values=values)
        with (patch("uninstallerx.real_apps._app_location", return_value=True),
              patch("uninstallerx.real_apps._binary_info", return_value=BinaryInfo("Arbor Tools", "Arbor Editor"))):
            plan = prepare_uninstall(app)
            self.assertEqual(plan.primary, primary)
            self.assertEqual(plan.command, (str(uninstaller), "/S"))
        with (patch("uninstallerx.real_apps._app_location", return_value=True),
              patch("uninstallerx.real_apps._binary_info", side_effect=lambda path: BinaryInfo(
                  "Arbor Tools", "Inno Setup" if path == uninstaller else "Arbor Editor", "CN=Arbor Tools"))):
            self.assertEqual(prepare_uninstall(app).primary, primary)
        with (patch("uninstallerx.real_apps._app_location", return_value=True),
              patch("uninstallerx.real_apps._binary_info", side_effect=lambda path: BinaryInfo(
                  "Arbor Tools", "Inno Setup" if path == uninstaller else "Arbor Editor", str(path)))):
            with self.assertRaisesRegex(ValueError, "one independently signed"):
                prepare_uninstall(app)

    def test_win32_passes_approved_vendor_arguments_and_blocks_changed_arguments(self):
        folder = self.root / "Arbor Editor"
        folder.mkdir()
        primary = folder / "ArborEditor.exe"
        uninstaller = folder / "Maintenance Wizard.exe"
        uninstaller.touch()
        command = (str(uninstaller), "/mode:remove", "--product=Arbor Editor", "--preserve-local-settings", "")
        command_line = subprocess.list2cmdline(command)
        app = replace(self.app, values={**self.app.values, "InstallLocation": str(folder),
                                        "DisplayIcon": str(primary), "UninstallString": command_line})

        for outcome in ("removed", "blocked", "uninstaller_unverified"):
            with self.subTest(outcome=outcome):
                primary.touch()
                live = app

                def approve(title, rows, note):
                    nonlocal live
                    self.assertEqual(dict(rows)["Uninstaller"], str(uninstaller))
                    self.assertNotIn("--preserve-local-settings", str((title, rows, note)))
                    if outcome == "blocked":
                        live = replace(app, values={**app.values, "UninstallString": command_line + " --extra"})
                    return True

                def execute(received, **kwargs):
                    nonlocal live
                    self.assertEqual(received, command)
                    if outcome == "uninstaller_unverified":
                        return VendorRun(None, state="timed_out", total_processes=1, active_processes=1)
                    live = None
                    primary.unlink()
                    return VendorRun(0)

                with (patch("uninstallerx.real_apps.installed_apps", return_value=[app]),
                      patch("uninstallerx.real_apps.search_areas", return_value=[]),
                      patch("uninstallerx.real_apps._app_location", return_value=True),
                      patch("uninstallerx.real_apps._binary_info", return_value=BinaryInfo(app.publisher, app.name)),
                      patch("uninstallerx.real_apps._read_installation", side_effect=lambda *_: live),
                      patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
                      patch("uninstallerx.real_apps.run_vendor", side_effect=execute) as process,
                      patch.object(ResidualDiscovery, "run", return_value=([], [], False))):
                    model = self.model("inventory", "propose_c1", scripted_discovery=True)
                    report = run_real(self.root, model, app.name, apply=True, closing=Event(), review=approve, progress=Mock())
                self.assertEqual(report.get("command"), command_line, report)
                self.assertEqual(report["display_target"], str(uninstaller))
                self.assertEqual(report["status"], outcome)
                if outcome == "blocked":
                    process.assert_not_called()
                else:
                    process.assert_called_once()
                self.assertEqual(primary.is_file(), outcome != "removed")
                self.assertNotIn("--preserve-local-settings", report["message"])
                if outcome == "uninstaller_unverified":
                    audit = Path(report["audit_path"]).read_text(encoding="utf-8")
                    self.assertIn("uninstaller_timed_out", audit)
                    self.assertIn("--preserve-local-settings", audit)

    def test_installation_path_scope_and_batch_approval_before_removal(self):
        folders = [self.root / name for name in ("first-install", "second-install")]
        registered = []
        commands = {}
        for directory in folders:
            directory.mkdir()
            primary, uninstaller = directory / "Arbor.exe", directory / "Uninstall.exe"
            primary.touch()
            command = (str(uninstaller), "--vendor-option", directory.name)
            commands[directory.name] = command
            registered.append(replace(self.app, key=directory.name, values={**self.app.values,
                                      "InstallLocation": str(directory), "DisplayIcon": str(primary),
                                      "UninstallString": subprocess.list2cmdline(command)}))
        plans = {app.key: RemovalPlan(app, commands[app.key], "digest", app.name,
                                      app.publisher, directory, directory / "Arbor.exe", "verified")
                 for app, directory in zip(registered, folders)}
        live = {value.key: value for value in registered}
        events = []

        def review_copies(options):
            self.assertEqual(set(options), {"c1", "c2"})
            self.assertEqual({dict(rows)["Uninstaller"] for _, rows in options.values()},
                             {command[0] for command in commands.values()})
            self.assertTrue(all(title == self.app.name for title, _ in options.values()))
            self.assertNotIn("--vendor-option", str(options))
            events.append("batch approval")
            return set(options)

        def execute(command, **kwargs):
            key, plan = next((key, plan) for key, plan in plans.items() if plan.command == command)
            events.append(key)
            del live[key]
            plan.primary.unlink()
            return VendorRun(0)

        with (patch("uninstallerx.real_apps.installed_apps", return_value=registered),
              patch("uninstallerx.real_apps.prepare_uninstall", side_effect=lambda app: plans[app.key]),
              patch("uninstallerx.real_apps.search_areas", return_value=[]),
              patch("uninstallerx.real_apps._read_installation", side_effect=lambda *parts: live.get(parts[-1])),
              patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
              patch("uninstallerx.real_apps.run_vendor", side_effect=execute),
              patch.object(ResidualDiscovery, "run", return_value=([], [], False))):
            locate = self.model("desktop", "packages", "scan_p1", "inspect_c1", "propose_c1", scripted_discovery=True)
            preview = run_real(self.root, locate, self.app.name, apply=False, closing=Event(), review=Mock(), progress=Mock(),
                               portable_location=plans[registered[1].key].primary)
            self.assertEqual([copy["command"] for copy in preview["copies"]], [subprocess.list2cmdline(plans[registered[1].key].command)])
            select = self.model("desktop", "packages", "portable_folders", "inspect_c1", "propose_c1", "inspect_c2", "propose_c2",
                                scripted_discovery=True)
            progress = Mock()
            report = run_real(self.root, select, self.app.name, apply=True, closing=Event(), review=Mock(),
                              progress=progress, review_copies=review_copies)
        self.assertEqual(events, ["batch approval", *plans])
        self.assertEqual(report["status"], "removed")
        self.assertEqual([copy["display_target"] for copy in report["copies"]], [command[0] for command in commands.values()])
        self.assertNotIn("--vendor-option", str(progress.call_args_list))

    def test_discovery_rejects_portable_whole_folder_overlap_with_registered_app(self):
        outer = self.root / "Cedar Workspace"
        registered = outer / "Other App"
        registered.mkdir(parents=True)
        executable, other = outer / "Cedar.exe", registered / "Other.exe"
        for path in (executable, other):
            shutil.copyfile(sys.executable, path)
        record = replace(self.app, values={**self.app.values, "InstallLocation": str(registered), "DisplayIcon": str(other)})

        def smaller(context):
            self.assertIn("overlaps a registered installation", context["feedback"])
            return {"target_ids": ["F1"]}

        model = self.model("desktop", "packages", "scan_p1", "inspect_c1", "distribution_c1", "propose_c1",
                           {"target_ids": ["D1"]}, smaller, scripted_discovery=True)
        with patch("uninstallerx.real_apps.installed_apps", return_value=[record]):
            result = run_real(self.root, model, "Cedar", apply=False, closing=Event(), review=Mock(), progress=Mock(),
                              portable_location=executable)
        self.assertEqual(result["status"], "preview")
        self.assertEqual(result["portable_files"], [str(executable)])
        self.assertTrue(other.is_file())

    def test_existing_recovery_file_preserves_authentication_and_conflict_checks(self):
        source = self.root / "original"
        source.mkdir()
        cache = source / "item.bin"
        other_cache = source / "other.bin"
        cache.write_text("residual")
        other_cache.write_text("unrelated")
        journal = RecoveryJournal(self.root, "windows-" + uuid4().hex[:12])
        destination = self.root / ".local" / "quarantine" / journal.job_id
        destination.mkdir(parents=True)
        backup = destination / cache.name
        journal.record_file(cache, backup, self.root)
        cache.rename(backup)
        expected_mtime = backup.stat().st_mtime_ns
        authentic = journal.path.read_bytes()
        edited = json.loads(authentic)
        edited["payload"]["entries"][0]["source"] = str(other_cache)
        journal.path.write_text(json.dumps(edited), encoding="utf-8")
        with self.assertRaisesRegex(PermissionError, "authentication"):
            journal.restore(Mock(return_value=True), Event())
        self.assertTrue(backup.exists())
        journal.path.write_bytes(authentic)
        cache.write_text("new file")
        conflict = journal.restore(Mock(return_value=True), Event())
        self.assertEqual(conflict["restored"], 0)
        self.assertEqual(cache.read_text(), "new file")
        cache.unlink()
        restored = journal.restore(Mock(return_value=True), Event())
        self.assertEqual(restored["restored"], 1)
        self.assertEqual(restored["skipped"], 0)
        self.assertEqual(cache.read_text(), "residual")
        self.assertEqual(cache.stat().st_mtime_ns, expected_mtime)
        self.assertEqual(backup.exists(), False)

    def test_actual_registry_value_is_chosen_backed_up_and_restored(self):
        vendor = f"UXTest-{uuid4().hex[:10]}"
        vendor_path = rf"Software\{vendor}"
        product = "Arbor Editor"
        path = vendor_path + "\\" + product
        with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValueEx(key, "Theme", 0, winreg.REG_DWORD, 2)
            winreg.SetValueEx(key, "ProfileToken", 0, winreg.REG_SZ, "protected fixture")
        try:
            app = Installation(self.app.hive, self.app.view, self.app.key, {"DisplayName": product, "Publisher": vendor})
            command = (str(self.root / "editor" / "uninstall.exe"),)
            plan = RemovalPlan(app, command, "digest", product, vendor, self.root / "editor",
                               self.root / "editor" / "arbor.exe", "verified fixture")

            def propose(context):
                self.assertEqual(context["observed_values"], {"V1": {"key": path, "name": "Theme", "type": "integer", "writable": True}})
                return {"action": "propose", "value_ids": ["V1"]}

            model = self.model("desktop", "inspect_c1", "propose_c1", "list_search_locations", "stop",
                               {"action": "search_k1", "query": vendor}, {"action": "search_k2", "query": product},
                               "read_k3", propose)
            with (
                patch("uninstallerx.real_apps.installed_apps", return_value=[app]),
                patch("uninstallerx.real_apps._registered_target", return_value=command),
                patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
                patch("uninstallerx.real_apps._read_installation", side_effect=[app, None]),
                patch("uninstallerx.real_apps.run_vendor", return_value=VendorRun(0)),
            ):
                report = run_real(self.root, model, product, apply=True, closing=Event(),
                                  review=Mock(return_value=True), progress=Mock())
            self.assertEqual(report["settings_removed_count"], 1)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                self.assertEqual(winreg.QueryValueEx(key, "ProfileToken")[0], "protected fixture")
                with self.assertRaises(FileNotFoundError):
                    winreg.QueryValueEx(key, "Theme")
            result = RecoveryJournal(self.root, report["job_id"]).restore(Mock(return_value=True), Event())
            self.assertEqual(result["restored"], 1)
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                self.assertEqual(winreg.QueryValueEx(key, "Theme"), (2, winreg.REG_DWORD))
        finally:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, vendor_path)

    def test_read_budget_continues_or_stops_without_resetting_counts(self):
        approved = Mock(return_value=True)
        session = ToolSession(Mock(), Event(), AuditLog(self.root / "audit.jsonl"), extend_budget=approved, read_limit=1)
        session.reading("fixture", "first")
        session.reading("fixture", "second")
        approved.assert_called_once_with("read", 1, 26)
        self.assertEqual(session.reads, 2)

        declined = Mock(return_value=False)
        session = ToolSession(Mock(), Event(), AuditLog(self.root / "audit2.jsonl"), extend_budget=declined, read_limit=1)
        session.reading("fixture", "first")
        with self.assertRaisesRegex(InvestigationError, "read limit"):
            session.reading("fixture", "second")
        declined.assert_called_once_with("read", 1, 26)
        self.assertEqual(session.reads, 1)

    def test_change_extension_resumes_the_same_cache_with_new_file_ids(self):
        root = self.root / "product"
        folder = root / "Cache"
        folder.mkdir(parents=True)
        files = {folder / f"{index}.bin" for index in range(4)}
        for file in files:
            file.write_text(file.name)
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, "Arbor Tools", None, None, "verified")
        approve = Mock(return_value=True)
        def propose(context):
            return {"action": "propose", "target_ids": list(context["observed_files"])}

        model = self.model("list_search_locations", "list_d1", "read_d2", "extend_changes", "read_d2", propose)
        session = ToolSession(model, Event(), AuditLog(self.root / "cache-audit.jsonl"), extend_budget=approve, change_limit=2)
        with (
            patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]),
        ):
            selected, _, _ = ResidualDiscovery(plan, session, Mock()).run()
        approve.assert_called_once_with("change", 2, 27)
        self.assertEqual(len(selected), 4)
        self.assertEqual({item.path for item in selected}, files)

    def test_model_selects_ordinary_temp_file_and_leaves_unproposed_file(self):
        temp = self.root / "shared-temporary-storage"
        staging = temp / "a71"
        staging.mkdir(parents=True)
        payload = staging / "part-019.tmp"
        unrelated = staging / "Arbor Editor.tmp"
        payload.write_text("Arbor Tools uninstaller:\nremoving Arbor Editor")
        unrelated.write_text("A separate document with an app-looking name")
        app_root = self.root / "install"
        plan = RemovalPlan(self.app, (str(app_root / "uninstall.exe"),), "different digest",
                           self.app.name, self.app.publisher, app_root, app_root / "editor.exe", "verified")

        def search(context):
            key = next(key for key, action in context["available_actions"].items()
                       if key.startswith("search_") and action["folder"] == str(temp))
            return {"action": key, "query": ".tmp"}

        def inspect(context):
            files = context["observed_files"]
            selected = next(key for key, info in files.items() if info["name"] == payload.name)
            return {"action": f"inspect_{selected}"}

        def propose(context):
            key, observed = next(iter(context["file_inspections"].items()))
            self.assertIn("Arbor Tools uninstaller", observed["text_excerpt"])
            return {"action": "propose", "target_ids": [key]}

        review = Mock(return_value=True)
        model = self.model("desktop", "inspect_c1", "propose_c1", "list_search_locations", search, inspect, propose)
        with (
            patch.dict(os.environ, {"TEMP": str(temp), "TMP": str(temp)}),
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
            patch("uninstallerx.real_apps._registered_target", return_value=plan.command),
            patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
            patch("uninstallerx.real_apps._read_installation", side_effect=[self.app, None]),
            patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
            patch("uninstallerx.real_apps.run_vendor", return_value=VendorRun(0)),
        ):
            result = run_real(self.root, model, self.app.name, apply=True, closing=Event(), review=review, progress=Mock())
        self.assertEqual(result["status"], "removed")
        self.assertEqual(result["residual_deleted_count"], 1, result)
        self.assertEqual(result["cache_files"], [str(payload)])
        self.assertIn(str(temp), result["residual_search_roots"])
        self.assertEqual(review.call_args.args[1], [("Permanently delete file", str(payload))])
        self.assertFalse(payload.exists())
        self.assertTrue(unrelated.is_file())
        self.assertFalse(result["recovery_available"])
        self.assertFalse((self.root / ".local" / "quarantine").exists())

    def test_residual_search_continues_after_an_entry_access_error(self):
        from uninstallerx.real_apps import _drive_path

        root = self.root / "shared"
        root.mkdir()
        inaccessible = root / "session-a.jfm"
        available = root / "session-b.log"
        inaccessible.touch()
        available.touch()
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")

        def check_path(path):
            if path == inaccessible:
                raise PermissionError(13, "Access is denied", str(path))
            return _drive_path(path)

        def propose(context):
            files = context["observed_files"]
            self.assertEqual([value["name"] for value in files.values()], [available.name])
            return {"action": "propose", "target_ids": list(files)}

        model = self.model("list_search_locations", {"action": "search_d1", "query": "session"}, propose)
        audit = AuditLog(self.root / "read-audit.jsonl")
        session = ToolSession(model, Event(), audit)
        with (
            patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]),
            patch("uninstallerx.real_apps._drive_path", side_effect=check_path),
        ):
            targets, roots, limited = ResidualDiscovery(plan, session, Mock()).run()
        self.assertEqual([item.path for item in targets], [available])
        self.assertEqual(roots, [root])
        self.assertTrue(limited)
        self.assertIn("session-a.jfm", audit.path.read_text(encoding="utf-8"))

    def test_residual_review_uses_the_models_verdict_for_abbreviated_names(self):
        root = self.root / "Local"
        other_apps = [root / "System State", root / "Another Publisher", root / "Empty Cache"]
        for folder in other_apps:
            folder.mkdir(parents=True)
        unrelated = root / "Reference.txt"
        unrelated.write_text("An unrelated note")
        app = replace(self.app, values={**self.app.values, "DisplayName": "Moss Creative Studio"})
        linked = root / "MCS"
        linked.mkdir()
        (linked / "opaque.dat").write_bytes(b"\x00\x01")
        plan = RemovalPlan(app, ("uninstall.exe",), "digest", app.name, app.publisher,
                           self.root / "Moss Creative Studio", self.root / "MCS.exe", "verified")

        def propose_all(context):
            self.assertIn(str(linked), context["folder_targets"].values())
            return {"action": "propose", "target_ids": [*context["folder_targets"], *context["observed_files"]]}

        def confirm_linked(context):
            self.assertEqual(context["verified_app"]["executable"], "MCS.exe")
            candidates = context["proposed_targets"]
            self.assertEqual({item["path"] for item in candidates.values()}, {str(path) for path in [linked, *other_apps, unrelated]})
            key, item = next((key, item) for key, item in candidates.items() if Path(item["path"]) == linked)
            self.assertEqual(item["examples"], ["opaque.dat"])
            return {"confirmed_ids": [key]}

        def inspect_unconfirmed(context):
            self.assertEqual(list(context["confirmed_targets"].values()), [str(linked)])
            action = next(name for name, info in context["available_actions"].items() if info.get("file") == str(unrelated))
            return {"action": action}

        model = self.model("list_search_locations", "read_d1", propose_all, inspect_unconfirmed, "stop",
                           review_residuals=confirm_linked)
        audit = AuditLog(self.root / "residual-evidence.jsonl")
        session = ToolSession(model, Event(), audit)
        with patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]):
            targets, _, _ = ResidualDiscovery(plan, session, Mock()).run()
        self.assertEqual([item.path for item in targets], [linked])
        decisions = [json.loads(row) for row in audit.path.read_text(encoding="utf-8").splitlines()]
        denied = {event["target"] for event in decisions if event.get("reason") == "model_did_not_confirm_target"}
        self.assertEqual(denied, {str(item) for item in [*other_apps, unrelated]})
        self.assertTrue(all(item.is_dir() for item in other_apps))
        self.assertTrue(unrelated.is_file())

    def test_residual_review_can_reject_a_mixed_folder(self):
        root = self.root / "Shared Temporary"
        mixed = root / "cache-bin"
        mixed.mkdir(parents=True)
        payload = mixed / "part-219.tmp"
        payload.write_text("Arbor Editor created this temporary file.")
        document = mixed / "unrelated.txt"
        document.write_text("A note for another app.")
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")

        def reject_mixed(context):
            observation = context["proposed_targets"]["d2"]
            self.assertEqual(set(observation["examples"]), {payload.name, document.name})
            return {"confirmed_ids": []}

        model = self.model("list_search_locations", "list_d1", {"action": "propose", "target_ids": ["d2"]},
                           "read_d2", "stop",
                           review_residuals=reject_mixed)
        session = ToolSession(model, Event(), AuditLog(self.root / "mixed-scope.jsonl"))
        with patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]):
            targets, _, _ = ResidualDiscovery(plan, session, Mock()).run()
        self.assertEqual(targets, [])
        self.assertTrue(document.is_file())

    def test_residual_search_continues_after_review_rejects_first_proposal(self):
        local, temp = self.root / "Local", self.root / "Temp"
        local.mkdir()
        temp.mkdir()
        shared_cache = local / "IconCache.db"
        app_cache = temp / "Arbor Editor render.tmp"
        other_folder = local / "Other Application"
        other_folder.mkdir()
        shared_cache.touch()
        app_cache.write_text("Temporary render data for Arbor Editor")
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")
        reviewed = []

        def propose_observed(context):
            return {"action": "propose", "target_ids": list(context["observed_files"])}

        def read_next_location(context):
            self.assertEqual(context["unchecked_search_locations"], ["d2"])
            self.assertIn("d1", context["search_locations"])
            self.assertEqual(context["observed_files"], {})
            self.assertIn(str(other_folder), context["folder_targets"].values())
            self.assertNotIn("propose", context["available_actions"])
            self.assertNotIn("stop", context["available_actions"])
            return {"action": "search_d2", "query": "Arbor"}

        def review(context):
            ref, target = next(iter(context["proposed_targets"].items()))
            reviewed.append(Path(target["path"]))
            return {"confirmed_ids": [ref] if reviewed[-1] == app_cache else []}

        model = self.model("list_search_locations", "read_d1", propose_observed, read_next_location,
                           propose_observed, review_residuals=review)
        audit = AuditLog(self.root / "review-resumed.jsonl")
        session = ToolSession(model, Event(), audit)
        with patch("uninstallerx.real_apps.residual_search_roots", return_value=[local, temp]):
            targets, scopes, limited = ResidualDiscovery(plan, session, Mock()).run()
        self.assertEqual(reviewed, [shared_cache, app_cache])
        self.assertEqual([item.path for item in targets], [app_cache])
        self.assertEqual(scopes, [temp])
        self.assertFalse(limited)
        self.assertTrue(shared_cache.is_file())
        self.assertIn("residual_discovery_resumed", audit.path.read_text(encoding="utf-8"))
        follow_up_schema = model.complete_json.call_args_list[-2].kwargs["schema"]["properties"]
        self.assertEqual(follow_up_schema["target_ids"]["items"]["enum"], ["F2", "d3"])

    def test_partial_residual_review_preserves_confirmed_targets_and_checks_a_distinct_root(self):
        for inside_local in (True, False):
            with self.subTest(inside_local=inside_local):
                root = self.root / str(inside_local)
                local = root / "AppData" / "Local"
                temp = (local if inside_local else root) / "Temp"
                local.mkdir(parents=True)
                temp.mkdir()
                first = temp / "preview.tmp"
                unchanged = temp / "reference.txt"
                second = local / "cache-data.log"
                for path in (first, unchanged, second):
                    path.touch()
                plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                                   None, None, "verified")

                def first_proposal(context):
                    self.assertEqual(context["unchecked_search_locations"], ["d1"])
                    return {"action": "propose", "target_ids": list(context["observed_files"])}

                def next_read(context):
                    self.assertEqual(list(context["confirmed_targets"].values()), [str(first)])
                    self.assertIn("read_d1", context["available_actions"])
                    return {"action": "read_d1"}

                def second_proposal(context):
                    self.assertEqual(context["unchecked_search_locations"], [])
                    files = context["observed_files"]
                    self.assertEqual([item["name"] for item in files.values()], [second.name])
                    return {"action": "propose", "target_ids": list(files)}

                def review(context):
                    return {"confirmed_ids": [ref for ref, item in context["proposed_targets"].items()
                                              if Path(item["path"]) in {first, second}]}

                model = self.model("list_search_locations", "read_d2", first_proposal, next_read, second_proposal,
                                   review_residuals=review)
                session = ToolSession(model, Event(), AuditLog(root / "partial-audit.jsonl"))
                with patch("uninstallerx.real_apps.residual_search_roots", return_value=[local, temp]):
                    targets, scopes, limited = ResidualDiscovery(plan, session, Mock()).run()
                self.assertEqual([item.path for item in targets], [first, second])
                self.assertEqual(scopes, [temp, local])
                self.assertFalse(limited)
                self.assertTrue(unchanged.is_file())

    def test_repeated_completed_search_yields_to_other_observations(self):
        local, temp = self.root / "Local", self.root / "Temp"
        local.mkdir()
        temp.mkdir()
        (local / "draft.log").write_text("Unrelated service log")
        match = temp / "render.log"
        match.write_text("Arbor Editor render log")
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")

        def inspect(context):
            actions = context["available_actions"]
            self.assertNotIn("search_d1", actions)
            self.assertIn("search_d2", actions)
            return {"action": "inspect_F1"}

        def try_another_query(context):
            self.assertIn("search_d1", context["available_actions"])
            return {"action": "search_d1", "query": "draft"}

        model = self.model("list_search_locations", "read_d1",
                           {"action": "search_d1", "query": "render"},
                           {"action": "search_d1", "query": "RENDER"}, inspect, try_another_query,
                           {"action": "search_d2", "query": "render"}, {"action": "propose", "target_ids": ["F2"]})
        audit = AuditLog(self.root / "repeated-search.jsonl")
        session = ToolSession(model, Event(), audit)
        with patch("uninstallerx.real_apps.residual_search_roots", return_value=[local, temp]):
            targets, _, limited = ResidualDiscovery(plan, session, Mock()).run()
        self.assertEqual([item.path for item in targets], [match])
        self.assertFalse(limited)
        events = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines()]
        searches = [(event["directory"], event["query"]) for event in events if event.get("tool") == "search_names"]
        self.assertEqual(searches, [("d1", "render"), ("d1", "draft"), ("d2", "render")])
        self.assertEqual(session.reads, 6)

    def test_partial_residual_listing_and_empty_search_do_not_complete_coverage(self):
        root = self.root / "Temp"
        root.mkdir()
        for index in range(13):
            (root / f"{index:02}-artifact").mkdir()

        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")
        for action in ("list_d1", {"action": "search_d1", "query": "no hits"}):
            with self.subTest(action=action):
                session = ToolSession(self.model("list_search_locations", action, "stop"), Event(),
                                      AuditLog(self.root / "partial-residual-coverage.jsonl"))
                with patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]):
                    targets, _, limited = ResidualDiscovery(plan, session, Mock()).run()
                self.assertEqual(targets, [])
                self.assertTrue(limited)

        def list_next_page(context):
            self.assertTrue(context["available_actions"]["list_d1"]["continue_previous_read"])
            self.assertEqual(len(context["folder_observations"]["d1"]["children"]), 10)
            return {"action": "list_d1"}

        def finish_after_pages(context):
            self.assertNotIn("list_d1", context["available_actions"])
            self.assertEqual(set(context["folder_observations"]["d1"]["children"].values()),
                             {child.name for child in root.iterdir()})
            return {"action": "stop"}

        model = self.model("list_search_locations", "list_d1", list_next_page, finish_after_pages)
        session = ToolSession(model, Event(), AuditLog(self.root / "complete-residual-pages.jsonl"))
        with patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]):
            _, _, limited = ResidualDiscovery(plan, session, Mock()).run()
        self.assertFalse(limited)

        (root / "generated.bin").write_bytes(b"unread file")
        model = self.model("list_search_locations", "list_d1", "list_d1", "stop")
        with patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]):
            _, _, limited = ResidualDiscovery(plan, ToolSession(model, Event(), session.audit), Mock()).run()
        self.assertTrue(limited)

    def test_residual_search_and_cache_read_reach_deep_regular_files(self):
        root = self.root / "Cache"
        deep = root.joinpath(*(f"segment-{index}" for index in range(8)))
        deep.mkdir(parents=True)
        artifact = deep / "render-preview.tmp"
        artifact.write_text("Arbor Editor generated this temporary preview.")
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")
        for action in ("read_d1", {"action": "search_d1", "query": "render-preview"}):
            with self.subTest(action=action):
                def choose_observed_file(context):
                    ref = next(ref for ref, file in context["observed_files"].items() if file["name"] == artifact.name)
                    return {"action": "propose", "target_ids": [ref]}

                model = self.model("list_search_locations", action, choose_observed_file)
                session = ToolSession(model, Event(), AuditLog(self.root / "deep-residuals.jsonl"))
                with patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]):
                    targets, _, limited = ResidualDiscovery(plan, session, Mock()).run()
                self.assertEqual([target.path for target in targets], [artifact])
                self.assertFalse(limited)

    def test_rejected_residual_file_can_be_reviewed_again_with_new_evidence(self):
        root = self.root / "Temp"
        root.mkdir()
        opaque = root / "part-891.tmp"
        opaque.write_text("Arbor Editor generated this temporary file")
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")

        def review(context):
            ref, target = next(iter(context["proposed_targets"].items()))
            if not target.get("text_excerpt"):
                return {"confirmed_ids": []}
            return {"assessments": {ref: {"producer": "verified_app", "purpose": "generated_disposable_output",
                                           "evidence": target["text_excerpt"]}}}

        def inspect_rejected(context):
            self.assertNotIn("propose", context["available_actions"])
            self.assertIn("inspect_F1", context["available_actions"])
            return {"action": "inspect_F1"}

        propose = {"action": "propose", "target_ids": ["F1"]}
        model = self.model("list_search_locations", "read_d1", propose, inspect_rejected, propose, review_residuals=review)
        session = ToolSession(model, Event(), AuditLog(self.root / "rejected-inspection.jsonl"))
        with patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]):
            targets, _, limited = ResidualDiscovery(plan, session, Mock()).run()
        self.assertEqual([item.path for item in targets], [opaque])
        self.assertFalse(limited)
        self.assertTrue(opaque.is_file())
        log = session.audit.path.read_text(encoding="utf-8")
        self.assertIn("residual_text_assessment", log)
        self.assertNotIn("Arbor Editor generated this temporary file", log)

    def test_text_review_requires_observed_evidence_and_leaves_other_scopes_to_regular_review(self):
        observed = {
            "F1": {"type": "file", "text_excerpt": "preview cache written by arbor.exe"},
            "F2": {"type": "file", "text_excerpt": "my project notes for Arbor Editor"},
            "F3": {"type": "file", "text_excerpt": "a shared utility log"},
            "F4": {"type": "file", "text_excerpt": ""},
            "d2": {"type": "whole folder", "examples": ["metadata.bin"]},
        }

        def review(context):
            targets = context["proposed_targets"]
            if "F1" in targets:
                self.assertEqual(set(targets), {"F1", "F2", "F3"})
                return {"assessments": {
                    "F1": {"producer": "verified_app", "purpose": "generated_disposable_output", "evidence": "cache written by arbor.exe"},
                    "F2": {"producer": "verified_app", "purpose": "user_data", "evidence": "my project notes"},
                    "F3": {"producer": "verified_app", "purpose": "generated_disposable_output", "evidence": "cache written by arbor.exe"},
                }}
            self.assertEqual(set(targets), {"F4", "d2"})
            return {"confirmed_ids": ["d2"]}

        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")
        model = self.model(review_residuals=review)
        session = ToolSession(model, Event(), AuditLog(self.root / "review-text.jsonl"))
        confirmed = ResidualDiscovery(plan, session, Mock())._review_proposal(observed)
        self.assertEqual(confirmed, {"F1", "d2"})
        log = session.audit.path.read_text(encoding="utf-8")
        self.assertNotIn("cache written by arbor.exe", log)
        self.assertIn('"quote_matches_excerpt": false', log)

    def test_residual_review_cannot_widen_the_proposed_scope(self):
        folder = self.root / "shared"
        folder.mkdir()
        (folder / "file-a.tmp").touch()
        (folder / "file-b.tmp").touch()
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")
        model = self.model("list_search_locations", "read_d1", {"action": "propose", "target_ids": ["F1"]},
                           review_residuals=lambda _: {"confirmed_ids": ["F1", "F2"]})
        session = ToolSession(model, Event(), AuditLog(self.root / "scope-review.jsonl"))
        with (patch("uninstallerx.real_apps.residual_search_roots", return_value=[folder]),
              self.assertRaisesRegex(InvestigationError, "subset of the inspected targets")):
            ResidualDiscovery(plan, session, Mock()).run()
        self.assertTrue((folder / "file-b.tmp").is_file())

    def test_residual_review_retries_smaller_groups_after_output_limit(self):
        observed_batches = []

        def review(context):
            ids = list(context["proposed_targets"])
            observed_batches.append(ids)
            if len(ids) > 1:
                raise ModelOutputLimitError("The local model response reached its output limit.")
            return {"confirmed_ids": ids if ids == ["F2"] else []}

        model = self.model(review_residuals=review)
        session = ToolSession(model, Event(), AuditLog(self.root / "review-batches.jsonl"))
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher, None, None, "verified")
        observed = {ref: {"path": str(self.root / f"{ref}.tmp")} for ref in ("F1", "F2")}
        confirmed = ResidualDiscovery(plan, session, Mock())._review_proposal(observed)
        self.assertEqual(confirmed, {"F2"})
        self.assertEqual(observed_batches, [["F1", "F2"], ["F1"], ["F2"]])

    def test_locked_file_requires_a_new_model_proposal_and_excludes_only_its_id(self):
        root = self.root / "shared"
        root.mkdir()
        locked = root / "session.jfm"
        remaining = root / "log.tmp"
        locked.touch()
        remaining.touch()
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")
        handles = []

        def propose_both(context):
            self.assertEqual({file["name"] for file in context["observed_files"].values()}, {locked.name, remaining.name})
            handle = _kernel.CreateFileW(str(locked), 0x80000000, 0, None, OPEN_EXISTING, 0, None)
            if handle == INVALID_HANDLE:
                raise ctypes.WinError(ctypes.get_last_error())
            handles.append(handle)
            return {"action": "propose", "target_ids": list(context["observed_files"])}

        def propose_remaining(context):
            self.assertEqual([file["name"] for file in context["observed_files"].values()], [remaining.name])
            return {"action": "propose", "target_ids": list(context["observed_files"])}

        model = self.model("list_search_locations", "read_d1", propose_both, propose_remaining)
        audit = AuditLog(self.root / "locked-audit.jsonl")
        session = ToolSession(model, Event(), audit)
        try:
            with patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]):
                targets, _, limited = ResidualDiscovery(plan, session, Mock()).run()
        finally:
            for handle in handles:
                _kernel.CloseHandle(handle)
        self.assertEqual([item.path for item in targets], [remaining])
        self.assertTrue(limited)
        self.assertEqual(session.violations, 0)
        self.assertTrue(locked.exists())

    def test_residual_pagination_and_a_conflicting_keep_proposal(self):
        root = self.root / "app-data"
        root.mkdir()
        for index in range(20):
            (root / f"data-{index:02}.tmp").touch()
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")
        request = f"Remove {self.app.name}, keep data-00.tmp."

        def next_page(context):
            self.assertEqual(len(context["observed_files"]), 16)
            self.assertTrue(context["available_actions"]["read_d1"]["continue_previous_read"])
            return {"action": "read_d1"}

        def choose(context):
            self.assertEqual(context["user_request"], request)
            self.assertEqual(len(context["observed_files"]), 20)
            kept = next(key for key, value in context["observed_files"].items() if value["name"] == "data-00.tmp")
            removed = next(key for key, value in context["observed_files"].items() if value["name"] == "data-19.tmp")
            choose_remove = removed if "overlaps" in (context.get("feedback") or "") else kept
            return {"action": "propose", "keep_ids": [kept], "target_ids": [choose_remove]}

        model = self.model("list_search_locations", "read_d1", next_page, choose, choose)
        session = ToolSession(model, Event(), AuditLog(self.root / "read-pages.jsonl"))
        with patch("uninstallerx.real_apps.residual_search_roots", return_value=[root]):
            targets, _, limited = ResidualDiscovery(plan, session, Mock(), user_request=request).run()
        self.assertEqual([path.path.name for path in targets], ["data-19.tmp"])
        self.assertFalse(limited)
        self.assertEqual(session.violations, 1)

    def test_truncated_response_retries_with_the_same_residual_evidence(self):
        folder = self.root / "local-data"
        folder.mkdir()
        for index in range(20):
            (folder / f"document-{index:02}.txt").write_text("Keep this document.")
        cache_file = folder / "zz-arbor-render-cache.dat"
        cache_file.write_text("Temporary render cache")
        plan = RemovalPlan(self.app, ("uninstall.exe",), "digest", self.app.name, self.app.publisher,
                           None, None, "verified")
        request = f"Remove {self.app.name} and keep my documents."
        key_file = self.root / ".local" / "runtime" / "api-key.txt"
        key_file.parent.mkdir(parents=True)
        key_file.write_text("test-key", encoding="ascii")
        cut_reply = '{"action":"propose","keep_ids":[' + '"F12",' * 45
        attempts = []

        def completion(http_request, *, timeout):
            body = json.loads(http_request.data)
            instructions, user = body["messages"]
            context = json.loads(user["content"])
            self.assertNotIn("keep_ids", body["response_format"]["schema"]["properties"])
            stop_reason = "stop"
            if "proposed_targets" in context:
                raw = json.dumps({"confirmed_ids": list(context["proposed_targets"])})
            elif "list_search_locations" in context["available_actions"]:
                raw = '{"action":"list_search_locations"}'
            elif len(context["observed_files"]) < 21:
                raw = '{"action":"read_d1"}'
            else:
                attempts.append(context)
                if len(attempts) == 1:
                    raw, stop_reason = cut_reply, "length"
                else:
                    self.assertIn("The last response was cut off", instructions["content"])
                    target = next(ref for ref, item in context["observed_files"].items() if item["name"] == cache_file.name)
                    raw = json.dumps({"action": "propose", "target_ids": [target]})
            return io.StringIO(json.dumps({"choices": [{"finish_reason": stop_reason, "message": {"content": raw}}]}))

        audit = AuditLog(self.root / "truncated-residual.jsonl")
        session = ToolSession(LocalGranite(self.root), Event(), audit)
        with (patch("uninstallerx.model_provider.urllib.request.urlopen", side_effect=completion),
              patch("uninstallerx.real_apps.residual_search_roots", return_value=[folder])):
            targets, _, limited = ResidualDiscovery(plan, session, Mock(), user_request=request).run()
        self.assertEqual(attempts[0], attempts[1])
        self.assertEqual(attempts[0]["user_request"], request)
        self.assertEqual([item.path for item in targets], [cache_file])
        self.assertFalse(limited)
        self.assertTrue(cache_file.is_file())
        events = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines()]
        failure = next(event for event in events if event["event"] == "model_request_failed")
        self.assertEqual(failure["response"], cut_reply)
        self.assertNotIn("keep_ids", failure["reason"])
        self.assertEqual(sum(event["event"] == "model_response_retry" for event in events), 1)

    def test_repeated_output_limit_is_reported_after_one_retry(self):
        cut = '{"action":"propose","target_ids":['
        model = Mock()
        model.complete_json.side_effect = ModelOutputLimitError("The local model response reached its output limit.", response=cut)
        session = ToolSession(model, Event(), AuditLog(self.root / "repeated-truncation.jsonl"))
        with self.assertRaises(ModelOutputLimitError) as failure:
            session.ask("residuals", "Choose the action.", {}, {"propose": {}}, shorter_reply="Return a short proposal.")
        self.assertNotIn("target_ids", str(failure.exception))
        self.assertEqual(model.complete_json.call_count, 2)

    def test_verified_uninstall_reports_incomplete_when_residual_investigation_stops(self):
        command = (str(self.root / "vendor" / "uninstall.exe"),)
        plan = RemovalPlan(self.app, command, "digest", self.app.name, self.app.publisher,
                           self.root / "vendor", self.root / "vendor" / "editor.exe", "verified")
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
            patch("uninstallerx.real_apps._registered_target", return_value=command),
            patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
            patch("uninstallerx.real_apps._read_installation", side_effect=[self.app, None]),
            patch("uninstallerx.real_apps.run_vendor", return_value=VendorRun(19)),
            patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
            patch.object(ResidualDiscovery, "run", side_effect=PermissionError("unreadable test location")),
        ):
            model = self.model("desktop", "inspect_c1", "propose_c1")
            report = run_real(self.root, model, self.app.name, apply=True, closing=Event(),
                              review=Mock(return_value=True), progress=Mock())
        self.assertTrue(report["uninstaller_verified"])
        self.assertEqual(report["status"], "incomplete_cleanup")
        self.assertEqual(report["copies"][0]["status"], "incomplete_cleanup")
        self.assertIn("unreadable test location", report["message"])

    def test_multiple_copy_summary_counts_verified_uninstall_with_pending_cleanup(self):
        separate_copy = replace(self.app, key="another-copy")
        command = (str(self.root / "vendor" / "uninstall.exe"),)
        plan = RemovalPlan(self.app, command, "digest", self.app.name, self.app.publisher,
                           self.root / "vendor", self.root / "vendor" / "editor.exe", "verified")
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[self.app, separate_copy]),
            patch("uninstallerx.real_apps.search_areas", return_value=[]),
            patch("uninstallerx.real_apps._registered_target", return_value=command),
            patch("uninstallerx.real_apps.prepare_uninstall", side_effect=lambda app: replace(plan, app=app)),
            patch("uninstallerx.real_apps._read_installation", side_effect=[self.app, None]),
            patch("uninstallerx.real_apps.run_vendor", return_value=VendorRun(19)) as execute,
            patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
            patch.object(ResidualDiscovery, "run", side_effect=PermissionError("unreadable test location")),
        ):
            model = self.model("inventory", "propose_c1", "propose_c2", scripted_discovery=True)
            report = run_real(self.root, model, self.app.name, apply=True, closing=Event(),
                              review=Mock(), progress=Mock(), review_copies=lambda _: {"c1"})
        self.assertEqual(report["status"], "incomplete_cleanup", report)
        self.assertTrue(report["copies"][0]["uninstaller_verified"])
        self.assertEqual(report["copies"][1]["status"], "declined")
        self.assertIn("Removal confirmed for 1 of 2", report["message"])
        execute.assert_called_once()

    def test_pending_uninstaller_leaves_later_approved_copies_in_place(self):
        app2 = replace(self.app, key="another-copy")
        command = (str(self.root / "vendor" / "uninstall.exe"),)
        plan = RemovalPlan(self.app, command, "digest", self.app.name, self.app.publisher,
                           self.root / "vendor", self.root / "vendor" / "editor.exe", "verified")
        for state, approve_later in (("timed_out", True), ("monitor_failed", True), ("timed_out", False)):
            with (
                self.subTest(state=state, approve_later=approve_later),
                patch("uninstallerx.real_apps.installed_apps", return_value=[self.app, app2]),
                patch("uninstallerx.real_apps.search_areas", return_value=[]),
                patch("uninstallerx.real_apps._registered_target", return_value=command),
                patch("uninstallerx.real_apps.prepare_uninstall", side_effect=lambda app: replace(plan, app=app)),
                patch("uninstallerx.real_apps._read_installation", return_value=self.app),
                patch("uninstallerx.real_apps.run_vendor", return_value=VendorRun(0, state, 2, 1)) as execute,
                patch.object(ResidualDiscovery, "run") as residuals,
            ):
                model = self.model("inventory", "propose_c1", "propose_c2", scripted_discovery=True)
                report = run_real(self.root, model, self.app.name, apply=True, closing=Event(), review=Mock(),
                                  progress=Mock(), review_copies=lambda options: set(options) if approve_later else {"c1"})
                self.assertEqual(report["status"], "uninstaller_unverified")
                self.assertTrue(report["uninstaller_pending"])
                later_status = "stopped" if approve_later else "declined"
                self.assertEqual([copy["status"] for copy in report["copies"]], ["uninstaller_unverified", later_status])
                execute.assert_called_once()
                residuals.assert_not_called()

    def test_report_distinguishes_declined_direct_removal_from_actual_indirect_cleanup(self):
        for mode, declined_first in (("all", False), ("all", True), ("file", False), ("outside_cleanup", False)):
            with self.subTest(mode=mode, declined_first=declined_first):
                root = self.root / f"{mode}-{declined_first}"
                temp = root / "Temp"
                folder = temp / "Second copy"
                folder.mkdir(parents=True)
                executable, settings = folder / "editor.exe", folder / "editor.ini"
                executable.write_bytes(b"fixture executable")
                settings.write_text("fixture settings")
                portable = PortableApp(self.app.name, executable, temp, (fingerprint(executable), fingerprint(settings)))
                install = root / "Installed copy"
                command = (str(install / "uninstall.exe"),)
                plan = RemovalPlan(self.app, command, "digest", self.app.name, self.app.publisher, install,
                                   install / "editor.exe", "verified fixture")
                proposals = [RemovalProposal("c1", self.app, command[0], command),
                             RemovalProposal("c2", portable, str(executable))]
                if declined_first:
                    proposals.reverse()

                def discover(discovery):
                    discovery.proposals.update({proposal.candidate_id: proposal for proposal in proposals})
                    return proposals

                def run_installer(*_, **__):
                    if mode == "outside_cleanup":
                        executable.unlink()
                    return VendorRun(0)

                def choose_file(context):
                    ref = next(ref for ref, item in context["observed_files"].items() if item["name"] == executable.name)
                    return {"action": "propose", "target_ids": [ref]}

                actions = {"all": ("list_d1", {"action": "propose", "target_ids": ["d2"]}),
                           "file": ("list_d1", "read_d2", choose_file), "outside_cleanup": ("stop",)}
                model = self.model("list_search_locations", *actions[mode])
                with (
                    patch.object(LiveDiscovery, "run", discover),
                    patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
                    patch("uninstallerx.real_apps._read_installation", side_effect=[self.app, None]),
                    patch("uninstallerx.real_apps.run_vendor", side_effect=run_installer),
                    patch("uninstallerx.real_apps._protected_installation_paths", return_value=set()),
                    patch("uninstallerx.real_apps.residual_search_roots", return_value=[temp]),
                    patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
                ):
                    report = run_real(root, model, self.app.name, apply=True, closing=Event(),
                                      review=Mock(return_value=True), progress=Mock(), review_copies=lambda _: {"c1"})

                copy = next(item for item in report["copies"] if item["model_candidate_id"] == "c2")
                status = {"all": "removed", "file": "incomplete_cleanup", "outside_cleanup": "declined"}[mode]
                removed = {"all": [str(executable), str(settings)], "file": [str(executable)], "outside_cleanup": []}[mode]
                self.assertEqual(copy["copy_approval"], "declined")
                self.assertEqual(copy["status"], status)
                self.assertEqual(copy.get("removed_during_other_cleanup", []), removed)
                self.assertIn(f"{2 if mode == 'all' else 1} of 2 proposed copies", report["message"])
                self.assertFalse(executable.exists())
                self.assertEqual(settings.exists(), mode != "all")
                disk_report = json.loads(Path(report["report_path"]).read_text(encoding="utf-8"))
                self.assertEqual(disk_report["copies"], report["copies"])
                self.assertEqual(disk_report["residual_deleted_count"], int(mode != "outside_cleanup"))
                self.assertEqual(disk_report["cache_files"], [str(executable)] if mode == "file" else [])
                self.assertEqual(disk_report.get("residual_folders", []), [str(folder)] if mode == "all" else [])
                events = [json.loads(line) for line in Path(report["audit_path"]).read_text(encoding="utf-8").splitlines()]
                result = next(event for event in events if event["event"] == "copy_result" and event["candidate_id"] == "c2")
                self.assertEqual(result["copy_approval"], "declined")
                self.assertEqual(result["status"], status)

    def test_nonstandard_vendor_reboot_and_post_execution_audit_failure(self):
        command = (str(self.root / "vendor" / "uninstall.exe"),)
        plan = RemovalPlan(self.app, command, "digest", "Google Chrome", "Google LLC",
                           self.root / "vendor", self.root / "vendor" / "editor.exe", "verified")
        real_append = AuditLog.append

        for exit_code, audit_failed, status in ((29, False, "restart_required"), (19, True, "incomplete_cleanup"),
                                                (20, False, "incomplete_cleanup")):
            with self.subTest(exit_code=exit_code, audit_failed=audit_failed):
                def append(audit, event, **fields):
                    if audit_failed and event == "uninstaller_exited":
                        raise OSError("audit unavailable")
                    real_append(audit, event, **fields)

                with (patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
                      patch("uninstallerx.real_apps._registered_target", return_value=command),
                      patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
                      patch("uninstallerx.real_apps._read_installation", side_effect=[self.app, None]),
                      patch("uninstallerx.real_apps.run_vendor", return_value=VendorRun(exit_code)),
                      patch.object(AuditLog, "append", append), patch.object(ResidualDiscovery, "run") as residuals):
                    report = run_real(self.root, self.model("desktop", "inspect_c1", "propose_c1"), self.app.name,
                                      apply=True, closing=Event(), review=Mock(return_value=True), progress=Mock())
                self.assertEqual(report["status"], status)
                self.assertEqual(report["exit_code"], exit_code)
                self.assertEqual(report.get("uninstaller_verified", False), exit_code != 29)
                self.assertEqual(bool(report.get("audit_write_errors")), audit_failed)
                residuals.assert_not_called()

    def test_msix_reports_another_version_of_the_same_family(self):
        package = PackageApp("Arbor.Editor", "Arbor.Editor_1.0.0.0_x64__pub", "Arbor.Editor_pub", "CN=Arbor",
                             "1.0.0.0", ("Arbor Editor",), "Store", True, False)
        updated = replace(package, full_name="Arbor.Editor_2.0.0.0_x64__pub", version="2.0.0.0")
        with (patch("uninstallerx.real_apps.packaged_apps", side_effect=[[package], [updated]]),
              patch("uninstallerx.real_apps.remove_package") as remove):
            model = self.model("packages", "inspect_c1", "propose_c1")
            report = run_real(self.root, model, self.app.name, apply=True, closing=Event(),
                              review=Mock(return_value=True), progress=Mock())
        remove.assert_called_once_with(package)
        self.assertEqual(report["status"], "uninstaller_unverified")
        self.assertEqual(report["remaining_package_versions"], [updated.full_name])
        self.assertNotIn("residual_search_roots", report)

    def test_msix_checks_registration_after_an_unsuccessful_remove_command(self):
        item = PackageApp("Spruce.Draw", "Spruce.Draw_1.0.0.0_x64__pub", "Spruce.Draw_pub", "CN=Spruce",
                          "1.0.0.0", ("Spruce Draw",), "Store", True, False)
        for current, expected in (([], "removed"), ([item], "uninstaller_failed"),
                                  (OSError("Inventory unavailable"), "uninstaller_unverified")):
            with self.subTest(current=current):
                with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
                      patch("uninstallerx.real_apps.packaged_apps", side_effect=[[item], current]) as inventory,
                      patch("uninstallerx.real_apps.remove_package", side_effect=OSError("Removal command error")),
                      patch("uninstallerx.real_apps.residual_search_roots", return_value=[]) as residuals):
                    model = self.model("packages", "inspect_c1", "propose_c1", "list_search_locations", "stop")
                    report = run_real(self.root, model, item.name, apply=True, closing=Event(),
                                      review=Mock(return_value=True), progress=Mock())
                self.assertEqual(inventory.call_count, 2)
                self.assertEqual(report["status"], expected, report)
                self.assertEqual(report["package_removal_error"], "Removal command error")
                self.assertEqual(residuals.call_count, int(expected == "removed"))

    def test_msix_timeout_stops_later_copy_removals(self):
        first = PackageApp("Spruce.Draw", "Spruce.Draw_1.0.0.0_x64__pub", "Spruce.Draw_pub", "CN=Spruce",
                           "1.0.0.0", ("Spruce Draw",), "Store", True, False)
        second = replace(first, identity="Spruce.DrawAlt", full_name="Spruce.DrawAlt_1.0.0.0_x64__pub",
                         family="Spruce.DrawAlt_pub")
        model = self.model("inventory", "propose_c1", "propose_c2", scripted_discovery=True)
        with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
              patch("uninstallerx.real_apps.search_areas", return_value=[]),
              patch("uninstallerx.real_apps.packaged_apps", return_value=[first, second]),
              patch("uninstallerx.real_apps.remove_package", side_effect=subprocess.TimeoutExpired("Remove-AppxPackage", 5)) as remove,
              patch("uninstallerx.real_apps.residual_search_roots") as residuals):
            report = run_real(self.root, model, first.name, apply=True, closing=Event(),
                              review=Mock(), progress=Mock(), review_copies=set)
        remove.assert_called_once_with(first)
        residuals.assert_not_called()
        self.assertTrue(report["uninstaller_pending"])
        self.assertEqual([copy["status"] for copy in report["copies"]], ["uninstaller_unverified", "stopped"])

    def test_settings_cannot_finish_while_located_keys_can_still_be_read(self):
        first = r"Software\Arbor Tools\Editor"
        second = r"Software\Arbor Tools\Renderer"
        absent = r"Software\Arbor Tools\Removed Product"
        theme = Setting(first, "Theme", winreg.REG_DWORD, 2)
        quality = Setting(second, "RenderQuality", winreg.REG_DWORD, 3)

        def read_key(ref):
            def choose(context):
                actions = context["available_actions"]
                self.assertNotIn("stop", actions)
                self.assertNotIn("propose", actions)
                self.assertNotIn("read_s3", actions)
                return {"action": f"read_{ref}"}

            return choose

        def choose_settings(context):
            self.assertIn("stop", context["available_actions"])
            self.assertEqual(list(context["observed_values"]), ["V1", "V2"])
            return {"action": "propose", "value_ids": ["V2"]}

        def open_observed_key(path):
            if path == absent:
                raise FileNotFoundError(path)
            return Mock(__enter__=Mock(), __exit__=Mock())

        model = self.model("locate_settings", read_key("s2"), read_key("s1"), choose_settings)
        session = ToolSession(model, Event(), AuditLog(self.root / "settings-complete.jsonl"))
        with (
            patch("uninstallerx.registry_settings.exact_user_key", side_effect=open_observed_key),
            patch("uninstallerx.registry_settings.read_settings", side_effect=[([quality], False), ([theme], False)]) as read,
            patch("uninstallerx.registry_settings.same_setting", return_value=True),
        ):
            targets, limited = investigate_settings(self.app.name, (first, second, absent), session, Mock())
        self.assertEqual([call.args[0] for call in read.call_args_list], [second, first])
        self.assertEqual(targets, [theme])
        self.assertFalse(limited)

    def test_settings_investigation_continues_after_a_key_becomes_unreadable(self):
        first = r"Software\Arbor Tools\Editor"
        second = r"Software\Arbor Tools\Editor Next"
        setting = Setting(second, "Theme", winreg.REG_DWORD, 2)

        def choose_setting(context):
            self.assertNotIn("read_s1", context["available_actions"])
            self.assertEqual(context["observed_values"]["V1"]["key"], second)
            return {"action": "propose", "value_ids": ["V1"]}

        def truncated(context):
            choose_setting(context)
            raise ModelOutputLimitError("The local model response reached its output limit.")

        model = self.model("locate_settings", "read_s1", "read_s2", truncated, choose_setting)
        audit = AuditLog(self.root / "settings-audit.jsonl")
        session = ToolSession(model, Event(), audit)
        with (
            patch("uninstallerx.registry_settings.exact_user_key"),
            patch("uninstallerx.registry_settings.read_settings", side_effect=[PermissionError("denied"), ([setting], False)]),
            patch("uninstallerx.registry_settings.same_setting", return_value=True),
        ):
            targets, limited = investigate_settings(self.app.name, (first, second), session, Mock())
        self.assertEqual(targets, [setting])
        self.assertTrue(limited)
        events = [json.loads(line) for line in audit.path.read_text(encoding="utf-8").splitlines()]
        self.assertTrue(any(event["event"] == "read_failed" and event["key"] == first for event in events))
        self.assertTrue(any(event["event"] == "model_response_retry" and event["phase"] == "settings" for event in events))
        self.assertNotIn("keep_ids", model.complete_json.call_args.kwargs["schema"]["properties"])

    def test_model_can_find_settings_outside_the_verified_publisher(self):
        vendor = f"UXTest-{uuid4().hex[:10]}"
        alias_name = f"AE-{uuid4().hex[:10]}"
        alias = rf"Software\{alias_name}"
        different_name = f"OldVendor-{uuid4().hex[:10]}"
        parent = rf"Software\{different_name}"
        nested = rf"{parent}\Versions\AE"
        other = rf"{parent}\Other Editor"
        shared = rf"{parent}\Shared"
        paths = (alias, nested, other, shared)
        app = replace(self.app, values={**self.app.values, "Publisher": vendor})
        install = self.root / "App"
        command = (str(install / "uninstall.exe"),)
        plan = RemovalPlan(app, command, "digest", app.name, vendor, install, install / "AE.exe", "verified fixture")
        for path in paths:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, path) as key:
                winreg.SetValueEx(key, "ColorTheme", 0, winreg.REG_DWORD, 2)
                winreg.SetValueEx(key, "ProfileToken", 0, winreg.REG_SZ, "test")
        try:
            def choose_alias(context):
                self.assertEqual(context["verified_app"]["executable"], "AE.exe")
                options = context["observed_keys"]
                selected = next(ref for ref, path in options.items() if path == alias)
                return {"action": f"read_{selected}"}

            def propose_value(context):
                values = context["observed_values"]
                self.assertEqual([item["key"] for item in values.values()], [alias, nested, shared])
                self.assertEqual([item["writable"] for item in values.values()], [True, True, False])
                self.assertTrue(all(item["name"] == "ColorTheme" for item in values.values()))
                return {"action": "propose", "value_ids": list(values)}

            def choose(action, path, query=None):
                def based_on_observations(context):
                    ref = next(ref for ref, observed in context["observed_keys"].items() if observed == path)
                    chosen = {"action": f"{action}_{ref}"}
                    if query is not None:
                        chosen["query"] = query
                    return chosen
                return based_on_observations

            model = self.model("desktop", "inspect_c1", "propose_c1", "list_search_locations", "stop",
                               {"action": "search_k1", "query": alias_name}, choose_alias,
                               {"action": "search_k1", "query": different_name}, choose("browse", parent),
                               choose("browse", parent + "\\Versions"), choose("read", nested),
                               choose("search", parent, "Shared"),
                               choose("read", shared), propose_value)
            review = Mock(return_value=True)
            with (
                patch("uninstallerx.real_apps.installed_apps", return_value=[app]),
                patch("uninstallerx.real_apps._registered_target", return_value=command),
                patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
                patch("uninstallerx.real_apps._read_installation", side_effect=[app, None]),
                patch("uninstallerx.real_apps.run_vendor", return_value=VendorRun(0)),
                patch("uninstallerx.real_apps.residual_search_roots", return_value=[]),
            ):
                result = run_real(self.root, model, app.name, apply=True, closing=Event(), review=review, progress=Mock())
            self.assertEqual(result["settings_removed_count"], 2, result)
            first_search = next(call for call in model.complete_json.call_args_list
                                if '"search_k1"' in call.args[1] and '"observed_values":{}' in call.args[1])
            self.assertEqual(set(first_search.kwargs["schema"]["properties"]), {"action", "query"})
            self.assertEqual(review.call_args.args[1], [("Back up and remove registry value", f"HKCU\\{path} :: ColorTheme")
                                                      for path in (alias, nested)])
            for path in (alias, nested):
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                    with self.assertRaises(FileNotFoundError):
                        winreg.QueryValueEx(key, "ColorTheme")
                    self.assertEqual(winreg.QueryValueEx(key, "ProfileToken")[0], "test")
            for path in (other, shared):
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as key:
                    self.assertEqual(winreg.QueryValueEx(key, "ColorTheme")[0], 2)
        finally:
            for path in paths:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent + "\\Versions")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, parent)

    def test_model_proposes_whole_temp_folder_and_exact_file_with_one_review(self):
        for outcome in ("approve", "decline", "contents changed"):
            with self.subTest(outcome=outcome):
                temp = self.root / outcome / "user-temp"
                folder = temp / "work-14"
                child = folder / "nested" / "index.log"
                child.parent.mkdir(parents=True)
                child.write_text("Arbor Editor support")
                other_target = temp / "Arbor Editor.log"
                other_target.write_text("session")
                untouched = temp / "another-app.log"
                untouched.write_text("preserve")
                install = self.root / outcome / "app"
                command = (str(install / "uninstall.exe"),)
                plan = RemovalPlan(self.app, command, "digest", self.app.name, self.app.publisher,
                                   install, install / "arbor.exe", "verified")
                change = folder / "new-after-review.txt"

                def propose(context):
                    folder_id = next(key for key, path in context["folder_targets"].items()
                                     if path == str(folder)[-160:])
                    file_id = next(key for key, info in context["observed_files"].items()
                                   if info["name"] == other_target.name)
                    return {"action": "propose", "target_ids": [folder_id, file_id]}

                def approve(title, rows, detail):
                    if title.startswith("Permanently delete"):
                        self.assertEqual(rows, [("Permanently delete whole folder and all contents", str(folder)),
                                                ("Permanently delete file", str(other_target))])
                        self.assertTrue(child.is_file())
                        self.assertTrue(other_target.is_file())
                        if outcome == "contents changed":
                            change.write_text("created while user was reviewing")
                        return outcome != "decline"
                    return True

                observations = ("list_d1", "inspect_d2", "read_d1") if outcome == "approve" else ("read_d1",)
                model = self.model("desktop", "inspect_c1", "propose_c1", "list_search_locations", *observations, propose)
                with (
                    patch("uninstallerx.real_apps.residual_search_roots", return_value=[temp]),
                    patch("uninstallerx.real_apps.installed_apps", return_value=[self.app]),
                    patch("uninstallerx.real_apps._registered_target", return_value=plan.command),
                    patch("uninstallerx.real_apps.prepare_uninstall", return_value=plan),
                    patch("uninstallerx.real_apps._read_installation", side_effect=[self.app, None]),
                    patch("uninstallerx.real_apps.investigate_settings", return_value=([], False)),
                    patch("uninstallerx.real_apps.run_vendor", return_value=VendorRun(0)),
                ):
                    result = run_real(self.root, model, self.app.name, apply=True, closing=Event(),
                                      review=approve, progress=Mock())
                self.assertEqual(result["residual_folders"], [str(folder)], result)
                self.assertEqual(result["cache_files"], [str(other_target)])
                self.assertEqual(result["residual_deleted_count"], {"approve": 2, "decline": 0, "contents changed": 1}[outcome])
                self.assertEqual(folder.exists(), outcome != "approve")
                self.assertEqual(other_target.exists(), outcome == "decline")
                self.assertTrue(untouched.is_file())
                self.assertFalse(result["recovery_available"])
                self.assertFalse((self.root / ".local" / "quarantine").exists())
                self.assertEqual(result["status"], "removed" if outcome == "approve" else "incomplete_cleanup")
                if outcome == "decline":
                    self.assertEqual(result["residual_declined_count"], 2)
                if outcome == "approve":
                    self.assertFalse(child.exists())
                if outcome == "contents changed":
                    self.assertTrue(child.is_file())
                    self.assertTrue(change.is_file())

    def test_time_extension_preserves_existing_job_state(self):
        approve = Mock(return_value=True)
        session = ToolSession(Mock(), Event(), AuditLog(self.root / "time-audit.jsonl"),
                              reads=4, deadline=time.monotonic() - 0.1, extend_budget=approve)
        session.check_time()
        approve.assert_called_once_with("time", 10, 15)
        self.assertEqual(session.reads, 4)
        self.assertGreater(session.deadline, time.monotonic())

    def test_refuses_unregistered_msi_product(self):
        app = Installation(winreg.HKEY_CURRENT_USER, winreg.KEY_WOW64_32KEY,
                           "{12345678-1234-1234-1234-123456789012}",
                           {"DisplayName": "Arbor Editor", "WindowsInstaller": 1})
        with patch("uninstallerx.real_apps._msi_product", return_value=""):
            with self.assertRaisesRegex(ValueError, "Windows Installer"):
                prepare_uninstall(app)

    def test_msix_uses_exact_package_and_rechecks_registration(self):
        item = PackageApp("Arbor.Editor", "Arbor.Editor_1.0.0.0_x64__pub", "Arbor.Editor_pub", "Arbor Tools",
                          "1.0.0.0", ("Arbor Editor",), "Store", True, False)
        review = Mock(return_value=True)
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[]) as desktop,
            patch("uninstallerx.real_apps.packaged_apps", side_effect=[[item], [item], []]),
            patch("uninstallerx.real_apps.remove_package") as remove,
            patch("uninstallerx.real_apps.residual_search_roots", return_value=[]),
        ):
            preview = run_real(self.root, self.model("packages", "inspect_c1", "propose_c1"), "Arbor Editor", apply=False,
                               closing=Event(), review=review, progress=Mock())
            self.assertEqual(preview["status"], "preview")
            self.assertEqual(preview["package_full_name"], item.full_name)
            remove.assert_not_called()
            review.assert_not_called()
            result = run_real(self.root, self.model("packages", "inspect_c1", "propose_c1", "list_search_locations", "stop"),
                              "Arbor Editor", apply=True,
                              closing=Event(), review=review, progress=Mock())
            remove.assert_called_once_with(item)
        self.assertEqual(result["status"], "removed")
        self.assertIn(("Package", item.full_name), review.call_args.args[1])
        self.assertEqual(desktop.call_count, 2)

    def test_msix_cleans_external_temp_only_after_package_disappears_and_user_approves(self):
        item = PackageApp("Fern.Image", "Fern.Image_3.0.0.0_x64__pub", "Fern.Image_pub", "CN=Fern Lab",
                          "3.0.0.0", ("Fern Image Studio",), "Store", True, False)
        temp = Path(os.environ["TEMP"])
        temp.mkdir()
        leftover = temp / "render-82-log"
        kept = temp / "bookmarks.txt"
        kept.write_text("personal data")

        for approve_cleanup in (False, True):
            with self.subTest(approve_cleanup=approve_cleanup):
                leftover.write_text("Fern.Image_pub created this temporary render cache.")
                remove = Mock()
                inventory = Mock(side_effect=[[item], []])

                def start_residuals(context):
                    remove.assert_called_once_with(item)
                    self.assertEqual(inventory.call_count, 2)
                    self.assertEqual(context["verified_app"]["package_family"], item.family)
                    self.assertEqual(context["verified_app"]["publisher"], item.publisher)
                    return {"action": "list_search_locations"}

                def inspect_leftover(context):
                    ref = next(ref for ref, file in context["observed_files"].items() if file["name"] == leftover.name)
                    return {"action": f"inspect_{ref}"}

                def propose_leftover(context):
                    ref, file = next(iter(context["file_inspections"].items()))
                    self.assertIn(item.family, file["text_excerpt"])
                    return {"action": "propose", "target_ids": [ref]}

                review = Mock(side_effect=[True, approve_cleanup])
                model = self.model("packages", "inspect_c1", "propose_c1", start_residuals, "read_d1",
                                   inspect_leftover, propose_leftover)
                with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
                      patch("uninstallerx.real_apps.packaged_apps", inventory),
                      patch("uninstallerx.real_apps.remove_package", remove)):
                    report = run_real(self.root, model, item.name, apply=True, closing=Event(), review=review, progress=Mock())

                self.assertEqual(review.call_count, 2)
                self.assertEqual(review.call_args.args[1], [("Permanently delete file", str(leftover))])
                self.assertEqual(report["status"], "removed" if approve_cleanup else "incomplete_cleanup", report)
                self.assertTrue(report["primary_removed"])
                self.assertEqual(report["residual_deleted_count"], int(approve_cleanup))
                self.assertEqual(leftover.exists(), not approve_cleanup)
                self.assertEqual(kept.read_text(), "personal data")
                self.assertEqual(report.get("residual_declined_count", 0), int(not approve_cleanup))

    def _run_portable_case(self, root, exe, name, review, *selections, user_request=None,
                           residual_steps=None):
        # Distribution-only tests use an empty inventory of external search locations.
        external_roots = (patch("uninstallerx.real_apps.residual_search_roots", return_value=[])
                          if residual_steps is None else nullcontext())
        with (
            patch("uninstallerx.real_apps.installed_apps", return_value=[]),
            patch("uninstallerx.real_apps.packaged_apps", return_value=[]),
            patch("uninstallerx.portable_apps.search_areas", return_value=[root]),
            patch("uninstallerx.portable_apps._products", return_value={exe: name}),
            external_roots,
        ):
            model = self.model("portable_folders", "scan_p1", "inspect_c1", "distribution_c1",
                               "propose_c1", *selections, *(residual_steps or ("list_search_locations", "stop")))
            return run_real(self.root, model, exe.name, apply=True, portable_roots=(root,),
                            closing=Event(), review=review, progress=Mock(), user_request=user_request)

    def test_portable_cleans_model_selected_temp_file_and_appdata_folder_in_one_approval(self):
        distribution = self.root / "distribution"
        distribution.mkdir()
        executable = distribution / "Silver Draw.exe"
        shutil.copyfile(sys.executable, executable)
        unrelated = distribution / "Project.txt"
        unrelated.write_text("keep the user's drawing")
        temp = Path(os.environ["TEMP"])
        temp.mkdir()
        cache = temp / "7abe.tmp"
        cache.write_text("Silver Draw generated this disposable preview.")
        local_data = Path(os.environ["LOCALAPPDATA"])
        folder = local_data / "SD-previews"
        folder.mkdir(parents=True)
        (folder / "frame.dat").write_bytes(b"\x00\x01")
        kept = local_data / "references.txt"
        kept.write_text("reference notes")

        def start_residuals(context):
            self.assertFalse(executable.exists())
            self.assertEqual(context["verified_app"]["executable_path"], str(executable))
            return {"action": "list_search_locations"}

        def examine_cache(context):
            ref = next(ref for ref, details in context["observed_files"].items() if details["name"] == cache.name)
            return {"action": f"inspect_{ref}"}

        def propose_cache(context):
            ref = next(iter(context["file_inspections"]))
            return {"action": "propose", "target_ids": [ref]}

        def continue_in_appdata(context):
            self.assertIn(str(cache), context["confirmed_targets"].values())
            self.assertIn("d2", context["unchecked_search_locations"])
            self.assertTrue(cache.is_file())
            return {"action": "read_d2"}

        def propose_folder(context):
            ref = next(ref for ref, path in context["folder_targets"].items() if path == str(folder))
            return {"action": "propose", "target_ids": [ref]}

        review = Mock(return_value=True)
        report = self._run_portable_case(distribution, executable, "Silver Draw", review, {"target_ids": ["F1"]},
                                         residual_steps=(start_residuals, "read_d1", examine_cache, propose_cache,
                                                         continue_in_appdata, propose_folder))
        self.assertEqual(report["status"], "removed", report)
        self.assertEqual(report["residual_deleted_count"], 2)
        self.assertEqual(report["residual_unchecked_roots"], [])
        self.assertEqual(review.call_count, 2)
        self.assertEqual(review.call_args_list[0].args[1], [("Permanently delete file", str(executable))])
        self.assertEqual(review.call_args_list[1].args[1], [("Permanently delete file", str(cache)),
                               ("Permanently delete whole folder and all contents", str(folder))])
        self.assertFalse(cache.exists())
        self.assertFalse(folder.exists())
        self.assertEqual(kept.read_text(), "reference notes")
        self.assertEqual(unrelated.read_text(), "keep the user's drawing")

    def test_unregistered_portable_deletes_only_approved_binary(self):
        root = self.root / "portable"
        root.mkdir()
        exe = root / "Arbor Editor.exe"
        shutil.copyfile(sys.executable, exe)
        document = root / "Project.txt"
        document.write_text("user data")
        review = Mock(return_value=True)
        result = self._run_portable_case(root, exe, "Arbor Editor", review, {"target_ids": ["F1"]})
        self.assertEqual(result["status"], "removed")
        self.assertEqual(result["portable_files"], [str(exe)])
        self.assertEqual(result["portable_deleted_count"], 1)
        self.assertFalse(result.get("recovery_available"))
        self.assertFalse((self.root / ".local" / "quarantine").exists())
        self.assertFalse(exe.exists())
        self.assertEqual(document.read_text(), "user data")

    def test_portable_search_can_resume_another_local_volume_beyond_four_levels(self):
        volume = self.root / "another-volume"
        folder = volume.joinpath(*(str(index) for index in range(8)))
        folder.mkdir(parents=True)
        exe = folder / "Hazel Mapper.exe"
        shutil.copyfile(sys.executable, exe)

        with (
            patch.dict(os.environ, {"USERPROFILE": str(self.root / "Profile"), "LOCALAPPDATA": str(self.root / "Local")}),
            patch("uninstallerx.real_apps.installed_apps", return_value=[]),
            patch("uninstallerx.portable_apps._local_drives", return_value=[volume]),
            patch("uninstallerx.portable_apps.PORTABLE_SCAN_ENTRIES", 4),
        ):
            model = self.model("portable_folders", "scan_p1", "scan_p1", "scan_p1", "inspect_c1", "distribution_c1",
                               "propose_c1", {"target_ids": ["F1"]})
            report = run_real(self.root, model, "Hazel Mapper", apply=False, closing=Event(), review=Mock(), progress=Mock())
        self.assertEqual(report["status"], "preview", report)
        self.assertEqual(report["portable_files"], [str(exe)])
        self.assertTrue(exe.is_file())

    def test_malformed_registry_command_does_not_break_other_installation_records(self):
        root = f"Software\\UninstallerXTest-{uuid4().hex}"
        try:
            with winreg.CreateKey(winreg.HKEY_CURRENT_USER, root) as uninstall:
                for key, label, command, kind in (
                    ("malformed", "Other App", ["not", "a command"], winreg.REG_MULTI_SZ),
                    ("valid", "Sample Editor", r'"C:\Program Files\Sample Editor\uninstall.exe" /uninstall', winreg.REG_SZ),
                ):
                    with winreg.CreateKey(uninstall, key) as record:
                        winreg.SetValueEx(record, "DisplayName", 0, winreg.REG_SZ, label)
                        winreg.SetValueEx(record, "UninstallString", 0, kind, command)
            with patch("uninstallerx.real_apps.UNINSTALL_ROOT", root):
                found = {item.key: item for item in installed_apps()}
            self.assertNotIn("UninstallString", found["malformed"].values)
            self.assertTrue(found["valid"].values["UninstallString"].endswith("/uninstall"))
        finally:
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, root + "\\malformed")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, root + "\\valid")
            winreg.DeleteKey(winreg.HKEY_CURRENT_USER, root)

    def test_portable_search_uses_model_query_and_leaves_identity_to_model(self):
        root = self.root / "workspace"
        folder = root / "handoff build 14"
        folder.mkdir(parents=True)
        exe = folder / "entrypoint.exe"
        shutil.copyfile(sys.executable, exe)

        def inspect(context):
            observed = context["available_actions"]["inspect_c1"]
            self.assertEqual(observed["file"], "entrypoint.exe")
            self.assertEqual(observed["name"], "Paper Scanner")
            self.assertEqual(context["search_history"][-1]["query"], "handoff build")
            return {"action": "inspect_c1"}

        with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
              patch("uninstallerx.portable_apps._products", return_value={exe: "Paper Scanner"})):
            model = self.model("desktop", "packages", "portable_folders", {"action": "scan_p1", "query": "handoff build"},
                               inspect, "distribution_c1", "propose_c1", {"target_ids": ["F1"]})
            report = run_real(self.root, model, "Paper Scanner", apply=False, closing=Event(), review=Mock(),
                              progress=Mock(), portable_roots=(root,))
        self.assertEqual(report["status"], "preview", report)
        self.assertEqual(report["portable_files"], [str(exe)])

    def test_portable_can_retry_the_same_location_with_a_distinct_model_query(self):
        root = self.root / "renamed"
        root.mkdir()
        exe = root / "xv-722.exe"
        shutil.copyfile(sys.executable, exe)

        def search_again(context):
            action = context["available_actions"]["rescan_p1"]
            self.assertEqual(action["location"], str(root))
            self.assertEqual(action["previous_queries"], ["Arbor Editor"])
            return {"action": "rescan_p1", "query": "XV722"}

        def select_distribution(context):
            self.assertEqual(context["inspected"]["c1"]["product_metadata"], self.app.name)
            actions = context["available_actions"]
            self.assertEqual(actions["distribution_c1"]["file"], exe.name)
            self.assertNotIn("stop", actions)
            return {"action": "distribution_c1"}

        model = self.model("desktop", "packages", "portable_folders", {"action": "scan_p1", "query": "Arbor Editor"},
                           search_again, "inspect_c1", select_distribution,
                           "propose_c1", {"target_ids": ["F1"]}, "finish", scripted_discovery=True)
        with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
              patch("uninstallerx.real_apps.search_areas", return_value=[root]),
              patch("uninstallerx.portable_apps._products", return_value={exe: self.app.name})):
            report = run_real(self.root, model, self.app.name, apply=False, closing=Event(), review=Mock(), progress=Mock())
        self.assertEqual(report["status"], "preview", report)
        self.assertEqual(report["portable_files"], [str(exe)])
        events = [json.loads(line) for line in Path(report["audit_path"]).read_text(encoding="utf-8").splitlines()]
        searches = [event["query"] for event in events if event.get("tool") == "scan_p1"]
        self.assertEqual(searches, ["Arbor Editor", "XV722"])

    def test_rescan_can_add_a_renamed_copy_after_the_first_match_is_proposed(self):
        root = self.root / "portable"
        root.mkdir()
        files = [root / f"{name}.exe" for name in (self.app.name, "ax-07")]
        for file in files:
            shutil.copyfile(sys.executable, file)
        model = self.model("desktop", "packages", "portable_folders", "scan_p1", "inspect_c1", "distribution_c1",
                           "propose_c1", {"target_ids": ["F1"]}, {"action": "rescan_p1", "query": "AX07"}, "inspect_c2",
                           "distribution_c2", "propose_c2", {"target_ids": ["F1"]}, "finish", scripted_discovery=True)
        session = ToolSession(model, Event(), AuditLog(self.root / "rescan-renamed-copy.jsonl"))
        with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
              patch("uninstallerx.real_apps.search_areas", return_value=[root]),
              patch("uninstallerx.portable_apps._products", return_value=dict.fromkeys(files, self.app.name))):
            proposals = LiveDiscovery(self.app.name, session, (), Mock()).run()
        self.assertEqual([proposal.target for proposal in proposals], list(map(str, files)))
        self.assertEqual([proposal.app.files[0].path for proposal in proposals], files)

    def test_duplicate_portable_query_yields_without_spending_a_read_or_violation(self):
        root = self.root / "portable"
        root.mkdir()

        def browse_instead(context):
            self.assertNotIn("rescan_p1", context["available_actions"])
            return {"action": "browse_p1"}

        model = self.model("desktop", "packages", "portable_folders", {"action": "scan_p1", "query": "Arbor Editor"},
                           {"action": "rescan_p1", "query": "arbor-editor"}, browse_instead, "stop")
        session = ToolSession(model, Event(), AuditLog(self.root / "duplicate-portable-query.jsonl"))
        with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
              patch("uninstallerx.real_apps.search_areas", return_value=[root])):
            result = LiveDiscovery(self.app.name, session, (), Mock()).run()
        self.assertEqual(result, [])
        self.assertEqual(session.violations, 0)
        self.assertEqual(session.reads, 5)

    def test_portable_browse_exposes_unfiltered_executable_paths_and_folders(self):
        root = self.root / "workspace"
        folder = root / "packed build"
        folder.mkdir(parents=True)
        exe = folder / "launcher.exe"
        other = folder / "other.exe"
        for path in (exe, other):
            shutil.copyfile(sys.executable, path)
        candidates = {}

        def browse(context):
            children = context["observed_folders"][-1]["subfolders"]
            return {"action": f"browse_{next(key for key, path in children.items() if path == str(folder))}"}

        def choose(context):
            for key, action in context["available_actions"].items():
                if key.startswith("inspect_c"):
                    candidates[action["file"]] = action["candidate"]
            self.assertEqual(set(candidates), {exe.name, other.name})
            return {"action": f"skip_{candidates[other.name]}", "reason": "unrelated"}

        with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
              patch("uninstallerx.portable_apps._products", return_value={exe: "Paper Scanner", other: "Different product"})):
            model = self.model("desktop", "packages", "portable_folders", "browse_p1", browse, choose,
                               lambda _: {"action": f"inspect_{candidates[exe.name]}"},
                               lambda _: {"action": f"distribution_{candidates[exe.name]}"},
                               lambda _: {"action": f"propose_{candidates[exe.name]}"}, {"target_ids": ["F1"]})
            report = run_real(self.root, model, "Paper Scanner", apply=False, closing=Event(), review=Mock(),
                              progress=Mock(), portable_roots=(root,))
        self.assertEqual(report["status"], "preview", report)
        self.assertEqual(report["portable_files"], [str(exe)])
        self.assertEqual(report["unproposed_candidates"], {})

    def test_portable_location_limits_discovery_to_the_supplied_copy(self):
        first = self.root / "Spare Tools" / "Hazel Mapper.exe"
        other = self.root / "Other Copy" / first.name
        for exe in (first, other):
            exe.parent.mkdir(parents=True)
            shutil.copyfile(sys.executable, exe)

        def choose_location(context):
            self.assertIn("desktop", context["available_actions"])
            self.assertEqual(context["available_actions"]["scan_p1"]["location"], str(location))
            return {"action": "scan_p1"}

        for location in (first, first.parent):
            with self.subTest(location=location), patch("uninstallerx.real_apps.installed_apps", return_value=[]):
                model = self.model(choose_location, "inspect_c1", "distribution_c1",
                                   "propose_c1", {"target_ids": ["F1"]})
                report = run_real(self.root, model, "Hazel Mapper", apply=False, closing=Event(), review=Mock(),
                                  progress=Mock(), portable_roots=(other.parent,), portable_location=location)
                self.assertEqual(report["status"], "preview", report)
                self.assertEqual(report["portable_files"], [str(first)])
        self.assertTrue(first.is_file() and other.is_file())

    def test_named_portable_removes_distinct_copies_and_reads_their_documents(self):
        for decline_second in (False, True):
            with self.subTest(decline_second=decline_second):
                root = self.root / str(decline_second)
                name = "Aster Tool"
                first = root / "Drive One" / "Private Work" / "renamed bundle"
                second = root / "Drive Two" / "Other Tools" / name
                for folder in (first, second):
                    folder.mkdir(parents=True)
                    shutil.copyfile(sys.executable, folder / f"{name}.exe")
                    (folder / "README.md").write_text("The executable and the support directory form the package.\n", encoding="utf-8")
                    (folder / "LICENSE.txt").write_text("This distribution includes the support files.")
                    (folder / "support").mkdir()
                    (folder / "support" / "asset.bin").write_bytes(b"portable support file")
                outside = first.parent / "personal.txt"
                outside.write_text("keep")

                def select_folder(context):
                    texts = {Path(doc["path"]).name: doc["text_excerpt"] for doc in context["documentation"]}
                    self.assertIn("support directory", texts["README.md"])
                    self.assertIn("support files", texts["LICENSE.txt"])
                    return {"target_ids": ["D1"]}

                def scan_second(context):
                    self.assertEqual(context["copies_added_to_plan"], ["c1"])
                    self.assertTrue((first / f"{name}.exe").is_file())
                    return {"action": "scan_p1", "location": context["available_actions"]["scan_p2"]["location"], "query": name}

                review = Mock()
                reviewed = []

                def approve_copies(options):
                    self.assertTrue(all((folder / f"{name}.exe").is_file() for folder in (first, second)))
                    reviewed.extend(scope[0][1] for _, scope in options.values())
                    self.assertEqual(reviewed, [str(first), str(second)])
                    return {"c1"} if decline_second else set(options)

                def empty_residual_inventory(_):
                    self.assertFalse(first.exists())
                    self.assertEqual(second.exists(), decline_second)
                    return []
                docs = (self.read_document("README.md"), self.read_document("LICENSE.txt"))
                model = self.model("desktop", "packages", "portable_folders", "scan_p1", "inspect_c1", "distribution_c1",
                                   "propose_c1", *docs, select_folder, scan_second, "inspect_c2",
                                   {"action": "read_portable_folders", "candidate": "c2"},
                                   "propose_c2", *docs, select_folder, "scan_p3", "finish",
                                   "list_search_locations", "stop", "list_search_locations", "stop", scripted_discovery=True)
                with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
                      patch("uninstallerx.real_apps.residual_search_roots", side_effect=empty_residual_inventory)):
                    report = run_real(self.root, model, name, apply=True, closing=Event(), review=review, progress=Mock(),
                                      portable_roots=(first.parent, second.parent, first), review_copies=approve_copies)
                self.assertEqual(report["status"], "incomplete_cleanup" if decline_second else "removed", report)
                self.assertFalse(report["search_incomplete"])
                self.assertEqual([copy["target"] for copy in report["copies"]], [str(folder / f"{name}.exe") for folder in (first, second)])
                self.assertEqual([copy["status"] for copy in report["copies"]], ["removed", "declined" if decline_second else "removed"])
                review.assert_not_called()
                self.assertFalse(first.exists())
                self.assertEqual(second.exists(), decline_second)
                self.assertTrue(outside.is_file())

    def test_copy_selection_preserves_unchecked_copy_inside_an_outer_folder(self):
        root = self.root / "portable"
        outer = root / "Aster Tool"
        inner = outer / "Older Bundle"
        inner.mkdir(parents=True)
        files = [folder / "Aster Tool.exe" for folder in (outer, inner)]
        for path in files:
            shutil.copyfile(sys.executable, path)
        for blocked in (False, True):
            with self.subTest(blocked=blocked):
                model = self.model("desktop", "packages", "portable_folders", "scan_p1", "inspect_c1", "distribution_c1",
                                   "propose_c1", {"target_ids": ["D1"]}, "inspect_c2", "distribution_c2", "propose_c2",
                                   {"target_ids": ["D1"]}, "finish", scripted_discovery=True)
                snapshots = [set(), OSError("Windows installation state is unavailable.") if blocked else set()]
                snapshots.extend((set(), set()))
                with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
                      patch("uninstallerx.real_apps._protected_installation_paths", side_effect=snapshots)):
                    report = run_real(self.root, model, "Aster Tool", apply=True, closing=Event(), review=Mock(), progress=Mock(),
                                      portable_roots=(root,), review_copies=lambda options: {"c1"})
                self.assertEqual(report["status"], "blocked", report)
                self.assertEqual([copy["status"] for copy in report["copies"]], ["blocked", "blocked" if blocked else "declined"])
                self.assertTrue(all(file.is_file() for file in files))

    def test_approved_portable_copies_share_a_file_without_removing_a_replacement(self):
        for order, replace_shared in (((1, 2), False), ((2, 1), False), ((1, 2), True)):
            with self.subTest(order=order, replace_shared=replace_shared):
                root = self.root / f"{order}-{replace_shared}"
                root.mkdir()
                shared = root / "renderer.dat"
                shared.write_bytes(b"approved shared support data")
                proposals = []
                for index in order:
                    exe = root / f"Iris Editor {index}.exe"
                    shutil.copyfile(sys.executable, exe)
                    app = PortableApp("Iris Editor", exe, root, (fingerprint(exe), fingerprint(shared)))
                    proposals.append(RemovalProposal(f"c{index}", app, str(exe)))

                def discover(discovery):
                    discovery.proposals.update({proposal.candidate_id: proposal for proposal in proposals})
                    return proposals

                def report_progress(message):
                    if replace_shared and message.startswith("Processing copy 2 of 2:"):
                        self.assertFalse(shared.exists())
                        shared.write_bytes(b"unapproved replacement")

                with (patch.object(LiveDiscovery, "run", discover),
                      patch("uninstallerx.real_apps._protected_installation_paths", return_value=set()),
                      patch("uninstallerx.real_apps.residual_search_roots", return_value=[])):
                    model = self.model("list_search_locations", "stop", "list_search_locations", "stop")
                    report = run_real(self.root, model, "Iris Editor", apply=True, closing=Event(),
                                      review=Mock(), progress=report_progress, review_copies=set)

                first, second = report["copies"]
                self.assertEqual(first["status"], "removed", report)
                self.assertFalse(Path(first["target"]).exists())
                self.assertEqual(second["status"], "blocked" if replace_shared else "removed", report)
                self.assertEqual(Path(second["target"]).exists(), replace_shared)
                if replace_shared:
                    self.assertEqual(shared.read_bytes(), b"unapproved replacement")
                else:
                    self.assertFalse(shared.exists())
                    self.assertEqual(second["previously_removed_targets"], [str(shared)])
                    self.assertEqual(second["portable_deleted_count"], 1)

    def test_copy_removed_after_incomplete_search_is_reported_as_partial(self):
        folder = self.root / "first"
        folder.mkdir()
        exe = folder / "Aster Tool.exe"
        shutil.copyfile(sys.executable, exe)
        model = self.model("portable_folders", "scan_p1", "inspect_c1", "distribution_c1", "propose_c1",
                           {"target_ids": ["F1"]}, "invalid", "invalid", "invalid", "list_search_locations", "stop",
                           scripted_discovery=True)
        with (patch("uninstallerx.real_apps.installed_apps", return_value=[]),
              patch("uninstallerx.real_apps.residual_search_roots", return_value=[])):
            report = run_real(self.root, model, "Aster Tool", apply=True, closing=Event(), review=Mock(return_value=True),
                              progress=Mock(), portable_roots=(folder,))
        self.assertEqual(report["status"], "incomplete_cleanup", report)
        self.assertTrue(report["search_incomplete"])
        self.assertEqual(report["copies"][0]["status"], "removed")
        self.assertFalse(exe.exists())

    def test_portable_folder_removal_respects_windows_delete_sharing(self):
        for share_delete in (True, False):
            with self.subTest(share_delete=share_delete):
                root = self.root / str(share_delete)
                folder = root / "Quartz Viewer"
                folder.mkdir(parents=True)
                exe = folder / "Quartz Viewer.exe"
                shutil.copyfile(sys.executable, exe)
                manual = folder / "readme.txt"
                manual.write_text("test package document")
                # FILE_LIST_DIRECTORY, with and without FILE_SHARE_DELETE.
                reader = _kernel.CreateFileW(str(folder), 1, 7 if share_delete else 3, None,
                                             OPEN_EXISTING, BACKUP_SEMANTICS, None)
                if reader == INVALID_HANDLE:
                    raise ctypes.WinError(ctypes.get_last_error())
                try:
                    result = self._run_portable_case(root, exe, "Quartz Viewer", Mock(return_value=True),
                                                     {"target_ids": ["D1"]})
                    if share_delete:
                        self.assertEqual(result["status"], "removed")
                        self.assertFalse(folder.exists())
                    else:
                        self.assertEqual(result["status"], "blocked")
                        self.assertEqual(result["portable_delete_winerror"], 32)
                        self.assertEqual(result["portable_deleted_count"], 0)
                        self.assertTrue(exe.is_file())
                        self.assertTrue(manual.is_file())
                finally:
                    _kernel.CloseHandle(reader)

    def test_portable_distribution_deletes_nested_folder_and_matching_zip(self):
        root = self.root / "search"
        folder = root / "release-7 unpacked"
        nested = folder / "bin"
        nested.mkdir(parents=True)
        exe = nested / "Quill Reader.exe"
        shutil.copyfile(sys.executable, exe)
        manual = folder / "Manual.txt"
        manual.write_text("distributed documentation")
        other = root / "unrelated.txt"
        other.write_text("user data")
        source = root / "renamed-download.zip"
        with ZipFile(source, "w") as archive:
            archive.write(exe, "wrapper/bin/" + exe.name)
            archive.write(manual, "wrapper/" + manual.name)
        decoy = root / "Quill Reader.zip"
        with ZipFile(decoy, "w") as archive:
            archive.writestr("wrapper/bin/" + exe.name, "different content")
        review = Mock(return_value=True)

        result = self._run_portable_case(root, exe, "Quill Reader", review, {"target_ids": ["D1"]}, {"archive_id": "Z1"})

        self.assertEqual(result["status"], "removed")
        self.assertEqual(result["portable_deleted_count"], 3)
        self.assertIn(("Delete this folder and all its contents", str(folder)), review.call_args.args[1])
        self.assertIn(("Permanently delete matching distribution ZIP", str(source)), review.call_args.args[1])
        self.assertFalse(folder.exists())
        self.assertFalse(source.exists())
        self.assertTrue(decoy.is_file())
        self.assertEqual(other.read_text(), "user data")

    def test_portable_removes_readonly_files_and_directories(self):
        root = self.root / "search"
        folder = root / "Aster Tool"
        nested = folder / "support"
        nested.mkdir(parents=True)
        exe = folder / "Aster Tool.exe"
        shutil.copyfile(sys.executable, exe)
        asset = nested / "config.ini"
        asset.write_text("disposable")
        outside = root / "unrelated.txt"
        outside.write_text("keep")
        for path in (asset, nested, folder):
            os.chmod(path, stat.S_IREAD)

        result = self._run_portable_case(root, exe, "Aster Tool", Mock(return_value=True), {"target_ids": ["D1"]})

        self.assertEqual(result["status"], "removed", result)
        self.assertEqual(result["portable_deleted_count"], 2)
        self.assertFalse(folder.exists())
        self.assertEqual(list(root.iterdir()), [outside])

    def test_locked_portable_file_stops_before_the_folder_is_moved(self):
        root = self.root / "search"
        folder = root / "Aster Tool"
        folder.mkdir(parents=True)
        exe = folder / "Aster Tool.exe"
        shutil.copyfile(sys.executable, exe)
        other = folder / "document.txt"
        other.write_text("keep on lock")
        reader = _kernel.CreateFileW(str(other), 0x80000000, 3, None, OPEN_EXISTING, 0, None)
        if reader == INVALID_HANDLE:
            raise ctypes.WinError(ctypes.get_last_error())
        try:
            result = self._run_portable_case(root, exe, "Aster Tool", Mock(return_value=True), {"target_ids": ["D1"]})
        finally:
            _kernel.CloseHandle(reader)
        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual(result["portable_delete_stage"], "check_file_access")
        self.assertEqual(result["portable_delete_operation"], "CreateFileW")
        self.assertEqual(result["portable_delete_winerror"], 32)
        self.assertEqual(result["portable_deleted_count"], 0)
        self.assertTrue(exe.is_file() and other.is_file())
        self.assertEqual(list(root.iterdir()), [folder])

    def test_late_folder_failure_keeps_remaining_files_outside_original_path(self):
        for fail_after_first in (False, True):
            with self.subTest(fail_after_first=fail_after_first):
                root = self.root / str(fail_after_first)
                folder = root / "Aster Tool"
                folder.mkdir(parents=True)
                exe = folder / "Aster Tool.exe"
                shutil.copyfile(sys.executable, exe)
                other = folder / "support.txt"
                other.write_text("remaining file")

                def fail_at(target):
                    self.assertTrue(target.path.parent.name.startswith(".uninstallerx-removing-"))
                    self.assertFalse(folder.exists())
                    if not fail_after_first or target.path.name == other.name:
                        raise ctypes.WinError(5)
                    delete_verified(target)

                with patch("uninstallerx.real_apps.delete_verified", side_effect=fail_at):
                    result = self._run_portable_case(root, exe, "Aster Tool", Mock(return_value=True), {"target_ids": ["D1"]})

                self.assertEqual(result["portable_delete_winerror"], 5, result)
                self.assertEqual(result["portable_deleted_count"], int(fail_after_first))
                if fail_after_first:
                    self.assertEqual(result["status"], "incomplete_cleanup")
                    pending = Path(result["portable_pending_path"])
                    self.assertEqual(pending.parent, root)
                    self.assertFalse(folder.exists())
                    self.assertEqual((pending / other.name).read_text(), "remaining file")
                    self.assertFalse((pending / exe.name).exists())
                else:
                    self.assertEqual(result["status"], "blocked")
                    self.assertNotIn("portable_pending_path", result)
                    self.assertTrue(exe.is_file() and other.is_file())
                    self.assertEqual(list(root.iterdir()), [folder])

    def test_portable_restores_folder_with_unapproved_content_after_relocation(self):
        root = self.root / "search"
        folder = root / "Aster Tool"
        folder.mkdir(parents=True)
        exe = folder / "Aster Tool.exe"
        shutil.copyfile(sys.executable, exe)
        added = "newly created.txt"

        def add_after_moving(source, destination, check_contents=None):
            rename_sibling_verified(source, destination, check_contents)
            if destination != folder:
                (destination / added).write_text("outside approved snapshot")

        with patch("uninstallerx.real_apps.rename_sibling_verified", side_effect=add_after_moving):
            result = self._run_portable_case(root, exe, "Aster Tool", Mock(return_value=True), {"target_ids": ["D1"]})

        self.assertEqual(result["status"], "blocked", result)
        self.assertEqual(result["portable_delete_stage"], "verify_staged_folder")
        self.assertEqual(result["portable_deleted_count"], 0)
        self.assertTrue(exe.is_file())
        self.assertEqual((folder / added).read_text(), "outside approved snapshot")
        self.assertEqual(list(root.iterdir()), [folder])

    def test_portable_distribution_preserves_files_not_in_zip(self):
        root = self.root / "search"
        folder = root / "Meadow Viewer"
        folder.mkdir(parents=True)
        exe = folder / "Meadow Viewer.exe"
        shutil.copyfile(sys.executable, exe)
        config = folder / "factory-settings.ini"
        config.write_text("distributed configuration")
        project = folder / "user-project.txt"
        project.write_text("my work")
        source = root / "setup-less.zip"
        with ZipFile(source, "w") as archive:
            archive.write(exe, exe.name)
            archive.write(config, config.name)

        result = self._run_portable_case(root, exe, "Meadow Viewer", Mock(return_value=True),
                                         {"target_ids": ["B1"]}, {"archive_id": "Z1"})

        self.assertEqual(result["status"], "removed")
        self.assertNotIn("portable_folder", result)
        self.assertFalse(exe.exists())
        self.assertFalse(config.exists())
        self.assertFalse(source.exists())
        self.assertEqual(project.read_text(), "my work")

    def test_partial_zip_still_offers_whole_renamed_folder_with_additional_files(self):
        root = self.root / "search"
        folder = root / "unpacked backup copy"
        folder.mkdir(parents=True)
        exe = folder / "Birch Editor.exe"
        shutil.copyfile(sys.executable, exe)
        settings = folder / "recent-session.ini"
        settings.write_text("generated by Birch Editor")
        (folder / "README.md").write_text("Birch Editor writes recent-session.ini in its own portable folder.")
        source = root / "original.zip"
        with ZipFile(source, "w") as archive:
            archive.write(exe, exe.name)

        def select(context):
            choices = context["targets"]
            self.assertEqual(choices["B1"]["file_count"], 1)
            self.assertEqual(choices["D1"]["folder"], str(folder))
            self.assertEqual(set(choices["D1"]["additional_files_outside_zip"]), {"recent-session.ini", "README.md"})
            self.assertIn("writes recent-session.ini", context["documentation"][0]["text_excerpt"])
            return {"target_ids": ["D1"]}

        result = self._run_portable_case(root, exe, "Birch Editor", Mock(return_value=True),
                                         self.read_document("README.md"), select, {"archive_id": "keep"})
        self.assertEqual(result["status"], "removed", result)
        self.assertFalse(folder.exists())
        self.assertTrue(source.is_file())

    def test_model_can_choose_an_observed_support_file_in_a_mixed_folder(self):
        root = self.root / "downloads"
        folder = root / "extracted"
        folder.mkdir(parents=True)
        exe = folder / "Juniper Viewer.exe"
        shutil.copyfile(sys.executable, exe)
        support = folder / "x73.ini"
        support.write_text("Juniper Viewer portable config")
        personal = folder / "personal notes.txt"
        personal.write_text("keep")
        (folder / "README.md").write_text("Juniper Viewer uses x73.ini for its portable settings.")

        def choose_files(context):
            self.assertIn("uses x73.ini", context["documentation"][0]["text_excerpt"])
            ids = {row["path"]: key for key, row in context["targets"].items() if key.startswith("F")}
            self.assertIn(str(personal), ids)
            return {"target_ids": [ids[str(exe)], ids[str(support)]]}

        review = Mock(return_value=True)
        result = self._run_portable_case(root, exe, "Juniper Viewer", review, self.read_document("README.md"), choose_files)
        self.assertEqual(review.call_args.args[1], [("Permanently delete file", str(exe)),
                                                   ("Permanently delete file", str(support))])
        self.assertEqual(result["status"], "removed", result)
        self.assertFalse(exe.exists() or support.exists())
        self.assertTrue(folder.is_dir() and personal.is_file())

    def test_model_reads_an_arbitrarily_named_file_on_another_page_and_continues_at_byte_boundary(self):
        root = self.root / "search"
        folder = root / "unpacked"
        folder.mkdir(parents=True)
        exe = folder / "Birch Editor.exe"
        shutil.copyfile(sys.executable, exe)
        for index in range(17):
            (folder / f"00-archive-{index:02}.md").write_text("unrequested text")
        document = folder / "z-layout.opaque"
        continuation = "설치 구조는 다음 경로를 따릅니다."
        document.write_text("a" * 1535 + continuation, encoding="utf-8")

        def unobserved(context):
            self.assertEqual(context["documentation"], [])
            self.assertEqual(context["file_inventory_pages"], 2)
            self.assertNotIn(str(document), {file["path"] for file in context["readable_files"].values()})
            return {"action": "read_text", "file_id": "R999"}

        def next_page(context):
            self.assertIn("a file ID", context["feedback"])
            return {"action": "list_files", "page": 2}

        def read_more(context):
            excerpt = context["documentation"][-1]
            self.assertEqual(excerpt["text_excerpt"], "a" * 1535)
            self.assertEqual(excerpt["next_offset"], 1535)
            self.assertEqual(context["next_reads"], [{"action": "read_text", "file_id": excerpt["file_id"], "offset": 1535}])
            return context["next_reads"][0]

        def propose(context):
            excerpts = context["documentation"]
            self.assertEqual({item["path"] for item in excerpts}, {str(document)})
            self.assertEqual(excerpts[-1]["text_excerpt"], continuation)
            self.assertIsNone(excerpts[-1]["next_offset"])
            return {"target_ids": ["F1"]}

        review = Mock(return_value=False)
        result = self._run_portable_case(root, exe, "Birch Editor", review, unobserved, next_page,
                                         self.read_document(document.name), read_more, propose)
        self.assertEqual(result["status"], "declined", result)
        self.assertTrue(exe.is_file() and document.is_file())
        events = [json.loads(line) for line in Path(result["audit_path"]).read_text(encoding="utf-8").splitlines()]
        reads = [(event["path"], event["offset"]) for event in events
                 if event.get("tool") == "read_text" and event["event"] == "read_observation"]
        self.assertEqual(reads, [(str(document), 0), (str(document), 1535)])

    def test_portable_package_rechecks_tree_after_user_approval(self):
        root = self.root / "search"
        folder = root / "Ridge Tool"
        folder.mkdir(parents=True)
        exe = folder / "Ridge Tool.exe"
        shutil.copyfile(sys.executable, exe)
        doc = folder / "readme.txt"
        doc.write_text("distributed documentation")
        result = self._run_portable_case(root, exe, "Ridge Tool", Mock(return_value=False), {"target_ids": ["D1"]})
        self.assertEqual(result["status"], "declined")
        self.assertEqual(result["portable_folder"], str(folder))
        self.assertTrue(exe.is_file())
        self.assertTrue(doc.is_file())

        def approve_with_changed_folder(*_):
            (folder / "late-file.txt").write_text("outside the plan")
            return True

        result = self._run_portable_case(root, exe, "Ridge Tool", approve_with_changed_folder, {"target_ids": ["D1"]})
        self.assertEqual(result["status"], "blocked")
        self.assertEqual(result["portable_deleted_count"], 0)
        self.assertTrue(exe.is_file())
        self.assertTrue(doc.is_file())

    def test_portable_choices_do_not_add_an_observed_folder_or_zip_to_the_plan(self):
        root = self.root / "search"
        folder = root / "Pine Desk"
        folder.mkdir(parents=True)
        exe = folder / "Pine Desk.exe"
        shutil.copyfile(sys.executable, exe)
        manual = folder / "Manual.txt"
        manual.write_text("distribution file")
        source = root / "release.zip"
        with ZipFile(source, "w") as archive:
            archive.write(exe, exe.name)
            archive.write(manual, manual.name)

        def choose_file(context):
            self.assertEqual(context["user_request"], "Remove Pine Desk and keep the ZIP and documents.")
            self.assertEqual(context["targets"]["D1"]["folder"], str(folder))
            return {"target_ids": ["F1"]}

        def keep_archive(context):
            self.assertEqual(context["archives"]["Z1"]["path"], str(source))
            self.assertEqual(list(context["app_targets"]), ["F1"])
            return {"archive_id": "keep"}

        review = Mock(return_value=True)
        result = self._run_portable_case(root, exe, "Pine Desk", review, choose_file, keep_archive,
                                         user_request="Remove Pine Desk and keep the ZIP and documents.")
        self.assertEqual(result["status"], "removed")
        self.assertEqual(review.call_args.args[1], [("Permanently delete file", str(exe))])
        self.assertFalse(exe.exists())
        self.assertTrue(manual.is_file())
        self.assertTrue(source.is_file())

    def test_portable_model_can_select_the_folder_and_one_of_two_matching_zips(self):
        root = self.root / "search"
        folder = root / "Juniper Pad"
        folder.mkdir(parents=True)
        exe = folder / "Juniper Pad.exe"
        shutil.copyfile(sys.executable, exe)
        archives = [root / "copy A.zip", root / "copy B.zip"]
        for path in archives:
            with ZipFile(path, "w") as archive:
                archive.write(exe, exe.name)

        def request_unobserved(context):
            self.assertEqual(context["archives"]["Z1"]["path"], str(archives[0]))
            self.assertEqual(context["archives"]["Z2"]["path"], str(archives[1]))
            return {"archive_id": "Z9"}

        review = Mock(return_value=True)
        declined = self._run_portable_case(root, exe, "Juniper Pad", review, {"target_ids": ["D1"]}, request_unobserved,
                                           "skip_c1", "stop")
        self.assertEqual(declined["status"], "not_found")
        review.assert_not_called()
        self.assertTrue(exe.is_file())

        result = self._run_portable_case(root, exe, "Juniper Pad", review, {"target_ids": ["D1"]}, {"archive_id": "Z2"})
        self.assertEqual(result["status"], "removed")
        self.assertIn(("Permanently delete matching distribution ZIP", str(archives[1])), review.call_args.args[1])
        self.assertFalse(folder.exists())
        self.assertTrue(archives[0].is_file())
        self.assertFalse(archives[1].exists())

    def test_adding_a_zip_does_not_turn_individual_files_into_a_budget_group(self):
        root = self.root / "downloads"
        folder = root / "Quartz Desk"
        folder.mkdir(parents=True)
        exe, manual = folder / "Quartz Desk.exe", folder / "manual.txt"
        shutil.copyfile(sys.executable, exe)
        manual.write_text("documentation")
        archive_path = root / "Quartz Desk.zip"
        with ZipFile(archive_path, "w") as archive:
            for path in (exe, manual):
                archive.write(path, path.name)

        def select_individual(context):
            ids = {key for key, entry in context["targets"].items()
                   if entry.get("path") in {str(exe), str(manual)}}
            self.assertEqual(len(ids), 2)
            return {"target_ids": sorted(ids)}

        small_session = lambda *args, **kwargs: ToolSession(*args, **kwargs, change_limit=2)
        with patch("uninstallerx.real_apps.ToolSession", side_effect=small_session):
            report = self._run_portable_case(root, exe, "Quartz Desk", Mock(return_value=True),
                                             select_individual, {"archive_id": "Z1"})
            self.assertEqual(report["status"], "blocked", report)
            self.assertTrue(all(path.is_file() for path in (exe, manual, archive_path)))
            group = self._run_portable_case(root, exe, "Quartz Desk", Mock(return_value=True),
                                            {"target_ids": ["B1"]}, {"archive_id": "Z1"})
        self.assertEqual(group["status"], "removed", group)
        self.assertTrue(all(not path.exists() for path in (exe, manual, archive_path)))
