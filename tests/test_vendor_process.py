import json
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from threading import Event

from uninstallerx.vendor_process import run_vendor


class VendorProcessTests(unittest.TestCase):
    def test_direct_process_keeps_the_approved_arguments_and_exit_code(self):
        with tempfile.TemporaryDirectory(prefix="uninstallerx process ") as directory:
            root = Path(directory)
            arguments = ("", "space in argument", 'quotes" end\\', "한글", "& literal > argument")
            code = "import json,pathlib,sys; pathlib.Path('arguments.json').write_text(json.dumps(sys.argv[1:])); sys.exit(259)"
            result = run_vendor((sys.executable, "-c", code, *arguments), cwd=root, closing=Event(), on_event=lambda *_, **__: None)
            self.assertEqual((result.state, result.exit_code, result.active_processes), ("completed", 259, 0))
            self.assertEqual(json.loads((root / "arguments.json").read_text()), list(arguments))

    def test_timeout_cancellation_and_explicit_breakaway_preserve_the_child(self):
        worker = (
            "import pathlib,sys,time\n"
            "release,done = map(pathlib.Path, sys.argv[1:])\n"
            "for attempt in range(100):\n"
            " if release.exists():\n"
            "  done.touch()\n"
            "  break\n"
            " time.sleep(0.05)\n"
        )
        launcher = "import subprocess,sys; subprocess.Popen(sys.argv[2:], creationflags=int(sys.argv[1]))"
        for state in ("timed_out", "cancelled", "completed"):
            with self.subTest(state=state), tempfile.TemporaryDirectory() as directory:
                root = Path(directory)
                release, done = root / "release", root / "done"
                closing = Event()
                events = []

                def record(event, **_):
                    events.append(event)
                    if state == "cancelled" and event == "uninstaller_waiting_for_children":
                        closing.set()

                # The explicit breakaway case stands in for activity outside the Windows job.
                flags = str(subprocess.CREATE_BREAKAWAY_FROM_JOB if state == "completed" else 0)
                command = (sys.executable, "-c", launcher, flags, sys.executable, "-c", worker,
                           str(release), str(done))
                try:
                    outcome = run_vendor(command, cwd=Path(sys.executable).parent, closing=closing,
                                         on_event=record, timeout=2)
                    self.assertEqual((outcome.state, outcome.exit_code), (state, 0))
                    self.assertEqual(outcome.active_processes > 0, state != "completed")
                    if state != "completed":
                        self.assertIn("uninstaller_waiting_for_children", events)
                    self.assertFalse(done.exists())
                finally:
                    release.touch()
                    for _ in range(50):
                        if done.exists():
                            break
                        time.sleep(0.05)
                self.assertTrue(done.exists(), "The child should keep running after monitoring ends.")

    def test_launch_is_skipped_if_cancelled_and_missing_executable_is_an_error(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            missing = (str(root / "missing.exe"),)
            closing = Event()
            closing.set()
            outcome = run_vendor(missing, cwd=root, closing=closing, on_event=lambda *_, **__: None)
            self.assertEqual((outcome.state, outcome.total_processes), ("cancelled", 0))
            closing.clear()
            with self.assertRaises(FileNotFoundError):
                run_vendor(missing, cwd=root, closing=closing, on_event=lambda *_, **__: None)
