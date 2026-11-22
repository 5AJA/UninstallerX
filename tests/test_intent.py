from __future__ import annotations

import unittest
from pathlib import PureWindowsPath
from unittest.mock import Mock

from uninstallerx.intent import interpret_live_removal_request, interpret_removal, interpret_removal_request


class IntentTests(unittest.TestCase):
    def test_live_model_chooses_lookup_names_and_can_preserve_a_product_suffix(self):
        for request, product, queries in (
            ("오처드 앱 지워줘", "Orchard Viewer", ["Orchard", "Orchard Viewer"]),
            ('Remove the "Notes App"', "Notes App", ["Notes App"]),
            ('Remove "Arbor: Editor/UHD"', "Arbor: Editor/UHD", ["Editor/UHD"]),
        ):
            with self.subTest(request=request):
                model = Mock()
                model.complete_json.return_value = ({"operation": "remove_app", "app_names": [product],
                                                     "lookup_names": queries, "location": None}, "")
                self.assertEqual(interpret_live_removal_request(model, request), (product, None, tuple(queries)))
                self.assertEqual(model.complete_json.call_args.args[1], request)

    def test_live_search_terms_cannot_supply_an_unrequested_location_or_approve(self):
        model = Mock()
        answer = {"operation": "remove_app", "app_names": ["Orchard Viewer"],
                  "lookup_names": [], "location": None}
        for extra in ({"location": r"D:\Apps"}, {"approved": True}, {"lookup_names": ["one\nmore"]}):
            with self.subTest(extra=extra), self.assertRaises(ValueError):
                model.complete_json.return_value = ({**answer, **extra}, "")
                interpret_live_removal_request(model, "Remove Orchard Viewer")

    def test_user_message_reaches_model_verbatim_and_supplies_app_name(self):
        model = Mock()
        model.complete_json.return_value = ({"operation": "remove_app", "app_names": ["별빛 편집기"]}, "")
        request = "  '별빛 편집기'를 지워줄래?  "
        self.assertEqual(interpret_removal(model, request), "별빛 편집기")
        self.assertEqual(model.complete_json.call_args.args[1], request)

    def test_untrusted_intent_cannot_supply_a_path_invent_name_or_approve(self):
        for request, answer in (
            ("Keep Aurora Editor", {"operation": "unsupported", "app_names": []}),
            (r"Remove C:\Windows", {"operation": "remove_app", "app_names": [r"C:\Windows"]}),
            ("Remove NUL.txt", {"operation": "remove_app", "app_names": ["NUL.txt"]}),
            ("Remove Aurora Editor", {"operation": "remove_app", "app_names": ["Invented Editor"]}),
            ("Remove Aurora Editor", {"operation": "remove_app", "app_names": ["Aurora Editor"], "approved": True}),
        ):
            with self.subTest(answer=answer):
                model = Mock()
                model.complete_json.return_value = (answer, "")
                with self.assertRaises(ValueError):
                    interpret_removal(model, request)

    def test_multiple_reported_apps_are_rejected(self):
        model = Mock()
        model.complete_json.return_value = ({"operation": "remove_app", "app_names": ["Arbor Editor", "Meadow Viewer"]}, "")
        with self.assertRaisesRegex(ValueError, "Name one app"):
            interpret_removal(model, "Remove Arbor Editor and Meadow Viewer")

    def test_executable_name_is_allowed_but_not_extracted_from_a_path(self):
        model = Mock()
        model.complete_json.return_value = ({"operation": "remove_app", "app_names": ["OrchardViewer.exe"]}, "")
        self.assertEqual(interpret_removal(model, "Remove OrchardViewer.exe"), "OrchardViewer.exe")
        for path in (r"D:\Tools\OrchardViewer.exe", "Tools/OrchardViewer.exe", r"\\server\Tools\OrchardViewer.exe"):
            with self.subTest(path=path), self.assertRaisesRegex(ValueError, "without a file path"):
                interpret_removal(model, f"Remove {path}")

    def test_desktop_accepts_user_supplied_absolute_paths_only_as_search_hints(self):
        name = "OrchardViewer"
        for text, returned, accepted in (
            (r'Remove OrchardViewer at "D:\Spare Tools\OrchardViewer"', r"D:\Spare Tools\OrchardViewer", True),
            (r'Remove OrchardViewer at D:\Spare\OrchardViewer.exe', r"D:\Spare\OrchardViewer.exe", True),
            (r'Remove OrchardViewer at D:\Spare\OrchardViewer.exe', r"D:\Spare", False),
            (r'Remove OrchardViewer at "D:\Spare Tools\OrchardViewer"', r"D:\Spare", False),
            (r'Remove OrchardViewer at D:\Spare\OrchardViewer.exe', r"C:\Somewhere\OrchardViewer.exe", False),
            (r'Remove OrchardViewer at \\server\OrchardViewer.exe', r"\\server\OrchardViewer.exe", False),
            (r'Remove OrchardViewer at D:\Spare\..\OrchardViewer.exe', r"D:\Spare\..\OrchardViewer.exe", False),
        ):
            with self.subTest(text=text, returned=returned):
                model = Mock()
                model.complete_json.return_value = ({"operation": "remove_app", "app_names": [name], "location": returned}, "")
                if accepted:
                    app_name, path = interpret_removal_request(model, text)
                    self.assertIn(app_name, (name, f"{name}.exe"))
                    self.assertEqual(path, PureWindowsPath(returned))
                else:
                    with self.assertRaises(ValueError):
                        interpret_removal_request(model, text)
