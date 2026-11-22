import unittest
from pathlib import PureWindowsPath

from uninstallerx.vendor_policy import (
    RESTART_EXIT_CODES, BinaryInfo, approval_warning, primary_matches, related, unconfirmed_removal, uninstaller_identity,
)


FOLDER = PureWindowsPath(r"C:\Program Files\Arbor Editor")


class VendorPolicyTests(unittest.TestCase):
    def identity(self, signer, product, *, file="Uninstall.exe", same_folder=True, publisher="Arbor Tools"):
        return uninstaller_identity("Arbor Editor (64-bit)", publisher, FOLDER / file, BinaryInfo(signer, product), same_folder)

    def test_signature_must_identify_the_registered_app(self):
        self.assertTrue(self.identity("Arbor Tools", "Arbor Editor").verified)
        # A stock installer engine carries no product metadata, so the publisher and a dedicated file name decide.
        for product in ("", "Inno Setup", "Nullsoft Install System"):
            with self.subTest(product=product):
                engine = self.identity("Arbor Tools Ltd", product, file="unins000.exe")
                self.assertTrue(engine.verified and engine.generic_engine and not engine.product_match)
        rejected = {
            "another publisher": self.identity("Birch Works", ""),
            "another product": self.identity("Arbor Tools", "Birch Viewer"),
            "ordinary file name": self.identity("Arbor Tools", "", file="setup.exe"),
            "outside the app folder": self.identity("Arbor Tools", "", same_folder=False),
            "no registered publisher": self.identity("Arbor Tools", "", publisher=""),
        }
        for case, identity in rejected.items():
            with self.subTest(case=case):
                self.assertFalse(identity.verified)
                self.assertIn("do not identify the registered app", identity.concern)

    def test_missing_signature_is_never_verified(self):
        for product in ("Arbor Editor", "Inno Setup", ""):
            with self.subTest(product=product):
                unsigned = self.identity("", product)
                self.assertFalse(unsigned.verified)
                self.assertIn("no valid publisher signature", unsigned.concern)

    def test_app_executable_must_share_the_uninstaller_certificate(self):
        uninstaller = BinaryInfo("Arbor Tools", "Arbor Editor", "CN=Arbor Tools")
        self.assertTrue(primary_matches("Arbor Editor", BinaryInfo("arbor tools", "Arbor Editor", "cn=arbor tools"), uninstaller, False))
        self.assertFalse(primary_matches("Arbor Editor", BinaryInfo("Arbor Tools", "Arbor Editor", "CN=Other"), uninstaller, False))
        self.assertFalse(primary_matches("Arbor Editor", BinaryInfo("Birch Works", "Arbor Editor", "CN=Arbor Tools"), uninstaller, False))
        self.assertFalse(primary_matches("Arbor Editor", BinaryInfo("Arbor Tools", "Birch Viewer", "CN=Arbor Tools"), uninstaller, False))
        engine = BinaryInfo("Arbor Tools", "Inno Setup", "CN=Arbor Tools")
        app = BinaryInfo("Arbor Tools", "Arbor Editor", "CN=Arbor Tools")
        self.assertEqual([primary_matches("Arbor Editor", app, engine, generic) for generic in (True, False)], [True, False])

    def test_name_matching_uses_whole_words(self):
        self.assertTrue(related("Arbor Editor (64-bit)", "arbor editor"))
        self.assertTrue(related("Arbor", "Arbor Editor"))
        self.assertFalse(related("Arb", "Arbor Editor"))
        self.assertFalse(related("", "Arbor Editor"))

    def test_warning_names_locations_a_standard_user_can_change(self):
        concern = "The uninstaller has no valid publisher signature."
        protected = approval_warning(concern, machine_record=True, in_program_files=True)
        self.assertTrue(protected.startswith(concern))
        self.assertNotIn("standard user", protected)
        for machine_record, in_program_files in ((False, True), (True, False), (False, False)):
            with self.subTest(machine_record=machine_record, in_program_files=in_program_files):
                self.assertIn("standard user", approval_warning(concern, machine_record=machine_record,
                                                                 in_program_files=in_program_files))

    def test_exit_code_only_grades_an_unconfirmed_removal(self):
        cases = (
            (1, False, False, False, "uninstaller_failed", "still lists the app and its program file is still present"),
            (0, False, False, False, "uninstaller_unverified", "still lists the app and its program file is still present"),
            (0, True, False, False, "uninstaller_unverified", "no longer lists the app, but its program file is still present"),
            (73, False, True, False, "uninstaller_failed", "program is gone, but Windows still lists the app"),
            (1603, True, False, True, "uninstaller_failed", "no longer lists the app, but Windows Installer still reports the product"),
        )
        for exit_code, registration_removed, program_removed, msi, status, observed in cases:
            with self.subTest(exit_code=exit_code, registration_removed=registration_removed, program_removed=program_removed):
                result = unconfirmed_removal(exit_code, registration_removed=registration_removed,
                                             program_removed=program_removed, msi=msi)
                self.assertEqual(result[0], status)
                self.assertIn(observed, result[1])
                self.assertIn(f"exited with code {exit_code}.", result[1])
        self.assertEqual(RESTART_EXIT_CODES, {1641, 3010})


if __name__ == "__main__":
    unittest.main()
