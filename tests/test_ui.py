from __future__ import annotations

import unittest
from pathlib import Path, PureWindowsPath
from queue import Queue
from threading import Event
from unittest.mock import Mock, patch

from uninstallerx.ui import RemovalWindow


class RemovalResultTests(unittest.TestCase):
    def test_incomplete_residual_search_does_not_claim_the_limit_was_reached(self):
        window = RemovalWindow.__new__(RemovalWindow)
        window._card = Mock()
        window._label = Mock()
        window.status = Mock()
        window.idle_status = "Ready"
        window.apply = True
        report = {"status": "incomplete_cleanup", "app_name": "Metro", "message": "Search was stopped.",
                  "app_data_roots": [r"C:\Data"], "cache_files": [r"C:\Data\cache.tmp"], "cache_scan_limited": True}
        with patch("uninstallerx.ui.ttk.Button"):
            window._show_real_result(report)
        self.assertIn("Residual targets: 1 · Search incomplete", [call.args[1] for call in window._label.call_args_list])

    def test_result_shows_executable_paths_without_command_arguments(self):
        window = RemovalWindow.__new__(RemovalWindow)
        window._card = Mock()
        window._label = Mock()
        window.status = Mock()
        window.idle_status = "Ready"
        window.apply = False
        first = r"C:\Program Files\Metro\setup.exe"
        second = r"D:\Apps\Metro\setup.exe"
        command = f'"{first}" --vendor-option=remove-local'
        report = {"status": "removed", "app_name": "Metro", "message": "Removal confirmed.",
                  "registry_source": r"HKLM\Software\Example", "display_target": first, "command": command, "evidence": "Verified."}

        for multiple in (False, True):
            with self.subTest(multiple=multiple), patch("uninstallerx.ui.ttk.Button"):
                copies = [{"target": command, "display_target": first, "app_name": "Metro", "message": "Removed."}]
                if multiple:
                    copies.append({"target": f'"{second}" --vendor-option=remove-other',
                                   "display_target": second, "app_name": "Metro", "message": "Removed."})
                window._label.reset_mock()
                window._show_real_result({**report, "copies": copies})
                labels = [call.args[1] for call in window._label.call_args_list]
                self.assertIn(first, labels)
                if multiple:
                    self.assertIn(second, labels)
                self.assertFalse(any("--vendor-option" in label for label in labels))


class SearchFolderTests(unittest.TestCase):
    def test_folder_picker_uses_the_folder_for_this_request(self):
        window = RemovalWindow.__new__(RemovalWindow)
        window.root = Mock()
        window.busy = False
        window.closing = Event()
        window._set_draft = Mock()
        window._submit = Mock()
        request = r'Remove Metro Editor at "C:\Old Tools\Metro"'
        selected = Path(r"D:\Portable Apps\Metro")
        with patch("uninstallerx.ui.filedialog.askdirectory", return_value=str(selected)):
            window._search_another_folder(request)
        window._set_draft.assert_called_once_with(request)
        window._submit.assert_called_once_with(selected)

    def test_job_uses_picker_scope_in_place_of_the_typed_scope(self):
        window = RemovalWindow.__new__(RemovalWindow)
        window.repo_root = Path.cwd()
        window.events = Queue()
        window.apply = False
        window.demo = False
        window.closing = Event()
        window.review_requested = Event()
        window.portable_roots = ()
        request = r'Remove Metro Editor at "C:\Old Tools\Metro"'
        typed = PureWindowsPath(r"C:\Old Tools\Metro")
        selected = Path(r"D:\Portable Apps\Metro")
        model = Mock()
        with (patch("uninstallerx.ui.new_removal_audit"),
              patch("uninstallerx.ui.interpret_live_removal_request", return_value=("Metro Editor", typed, ())) as intent,
              patch("uninstallerx.ui.run_real", return_value={}) as run):
            window._run(model, request, selected)
        intent.assert_called_once_with(model, request)
        self.assertEqual(run.call_args.kwargs["portable_location"], selected)
        self.assertEqual(run.call_args.kwargs["user_request"], request)
