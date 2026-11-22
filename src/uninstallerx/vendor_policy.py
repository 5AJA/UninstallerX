"""Security decisions for a registered vendor uninstaller.

Callers read the Windows state and pass the observed facts in. Nothing here calls Windows,
so the policy can be tested on any platform.
"""
from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import PurePath


INSTALLER_ENGINE_PRODUCTS = {"inno setup", "nullsoft install system", "nullsoft scriptable install system", "installshield"}
RESTART_EXIT_CODES = {1641, 3010}


@dataclass(frozen=True)
class BinaryInfo:
    signer: str
    product: str
    subject: str = ""


@dataclass(frozen=True)
class UninstallerIdentity:
    product_match: bool
    generic_engine: bool
    concern: str

    @property
    def verified(self) -> bool:
        return not self.concern


def label(value: str) -> str:
    value = re.sub(r"\s+\([^)]*\)\s*$", "", value)
    return " ".join(re.findall(r"[\w+]+", value.casefold()))


def related(left: str, right: str) -> bool:
    left, right = label(left), label(right)
    return bool(left and right and (f" {left} " in f" {right} " or f" {right} " in f" {left} "))


def uninstaller_identity(app_name: str, app_publisher: str, uninstaller: PurePath,
                         info: BinaryInfo, same_folder: bool) -> UninstallerIdentity:
    """Decide whether the uninstaller's signature identifies the registered app."""
    product_match = related(info.product, app_name)
    name = uninstaller.stem.casefold()
    dedicated = ("uninstall" in name or bool(re.fullmatch(r"unins[0-9]+", name))
                 or uninstaller.parent.name.casefold() == "uninstall")
    engine_product = label(info.product)
    # Stock installer engines ship an uninstaller without the app's product metadata.
    generic_engine = (same_folder and dedicated and (not engine_product or engine_product in INSTALLER_ENGINE_PRODUCTS)
                      and related(app_publisher, info.signer))
    if not info.signer:
        concern = "The uninstaller has no valid publisher signature."
    elif not (product_match or generic_engine):
        concern = (f"The uninstaller is signed by {info.signer[:80]}, "
                   "but its signature and product details do not identify the registered app.")
    else:
        concern = ""
    return UninstallerIdentity(product_match, generic_engine, concern)


def primary_matches(app_name: str, info: BinaryInfo, uninstall_info: BinaryInfo, generic_engine: bool) -> bool:
    """Accept an app executable only when it shares the uninstaller's signing certificate."""
    return (label(info.signer) == label(uninstall_info.signer)
            and info.subject.casefold() == uninstall_info.subject.casefold()
            and related(info.product, app_name)
            and (generic_engine or related(info.product, uninstall_info.product)))


def approval_warning(concern: str, *, machine_record: bool, in_program_files: bool) -> str:
    """Explain to the approver why the installation record is the only ownership evidence."""
    notes = [concern, "Only the Windows installation record links this file to the app."]
    if not (machine_record and in_program_files):
        notes.append("The record or the file is in a location that standard user accounts can usually change.")
    return " ".join(notes)


def unconfirmed_removal(exit_code: int | None, *, registration_removed: bool, program_removed: bool,
                        msi: bool) -> tuple[str, str]:
    """Report an installation that is still observed after the uninstaller exits.

    The observed state decides the outcome. A vendor's exit code only separates a reported
    failure from an unverified result.
    """
    program = "Windows Installer still reports the product" if msi else "its program file is still present"
    if registration_removed:
        observed = f"Windows no longer lists the app, but {program}."
    elif program_removed:
        observed = "The program is gone, but Windows still lists the app."
    else:
        observed = f"Windows still lists the app and {program}."
    status = "uninstaller_failed" if exit_code else "uninstaller_unverified"
    return status, (f"The uninstaller exited with code {exit_code}. {observed} "
                    "It may have been cancelled, may need a restart, or may have failed. Remaining files were left in place.")
