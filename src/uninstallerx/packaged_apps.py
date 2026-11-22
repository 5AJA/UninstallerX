from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass

from .windows import system_directory


PACKAGE_ID = re.compile(r"[A-Za-z0-9._-]{1,250}")
TRUSTED_SIGNATURES = {"Store", "Enterprise", "Developer"}


@dataclass(frozen=True)
class PackageApp:
    identity: str
    full_name: str
    family: str
    publisher: str
    version: str
    aliases: tuple[str, ...]
    signature: str
    removable: bool
    bundle: bool
    location: str = ""

    @property
    def name(self) -> str:
        return self.aliases[0] if self.aliases else self.identity


def powershell(script: str, *, environment: dict[str, str] | None = None, timeout: int = 30) -> str:
    executable = system_directory() / "WindowsPowerShell" / "v1.0" / "powershell.exe"
    result = subprocess.run(
        [str(executable), "-NoProfile", "-NonInteractive", "-Command",
         "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8; $ErrorActionPreference = 'Stop'; " + script],
        env={**os.environ, **(environment or {})}, capture_output=True, timeout=timeout, creationflags=subprocess.CREATE_NO_WINDOW,
    )
    if result.returncode != 0:
        details = result.stderr.decode("utf-8", errors="replace").strip()
        raise OSError(details.splitlines()[0][:500] if details else "Windows PowerShell returned an error.")
    return result.stdout.decode("utf-8-sig")


def packaged_apps() -> list[PackageApp]:
    output = powershell(r"""
        $names = @{}
        if (Get-Command Get-StartApps -ErrorAction SilentlyContinue) {
            foreach ($entry in Get-StartApps) {
                if ($entry.AppID -notmatch '^([^!]+)!') { continue }
                $family = $Matches[1]
                $names[$family] = @($names[$family]) + @($entry.Name)
            }
        }
        $items = @(Get-AppxPackage -PackageTypeFilter Main,Bundle | ForEach-Object {
            @{
                identity = $_.Name; full_name = $_.PackageFullName; family = $_.PackageFamilyName
                publisher = $_.Publisher; version = [string]$_.Version
                location = [string]$_.InstallLocation
                aliases = @($names[$_.PackageFamilyName] | Where-Object { $_ } | Sort-Object -Unique)
                signature = [string]$_.SignatureKind; bundle = [bool]$_.IsBundle
                removable = ($_.NonRemovable -eq $false -and -not $_.IsFramework -and -not $_.IsResourcePackage -and $_.Status -eq 'Ok')
            }
        })
        ConvertTo-Json -InputObject $items -Depth 4 -Compress
    """)
    entries: dict[str, PackageApp] = {}
    for item in json.loads(output):
        if not PACKAGE_ID.fullmatch(item["full_name"]) or not PACKAGE_ID.fullmatch(item["family"]):
            continue
        item["aliases"] = tuple(item["aliases"])
        package = PackageApp(**item)
        key = package.family.casefold()
        earlier = entries.get(key)
        if earlier is None or (package.bundle and not earlier.bundle):
            entries[key] = package
    return list(entries.values())


def removal_block(app: PackageApp) -> str | None:
    if not app.removable or app.signature not in TRUSTED_SIGNATURES or app.identity.casefold() == "microsoft.windowsstore":
        return "Windows reports a protected, unhealthy, or unverified package. Removal is blocked."
    return None


def remove_package(app: PackageApp) -> None:
    if removal_block(app) or not PACKAGE_ID.fullmatch(app.full_name) or not PACKAGE_ID.fullmatch(app.family):
        raise ValueError("The approved package is no longer eligible for removal.")
    powershell(r"""
        $matches = @(Get-AppxPackage -PackageTypeFilter Main,Bundle | Where-Object {
            $_.PackageFullName -ceq $env:UNINSTALLERX_PACKAGE_FULL -and
            $_.PackageFamilyName -ceq $env:UNINSTALLERX_PACKAGE_FAMILY
        })
        if ($matches.Count -ne 1) { throw 'The exact approved package is no longer installed.' }
        $item = $matches[0]
        if ($item.NonRemovable -ne $false -or $item.IsFramework -or $item.IsResourcePackage -or
            $item.Status -ne 'Ok' -or ([string]$item.SignatureKind) -notin 'Store','Enterprise','Developer' -or
            ([string]$item.SignatureKind) -cne $env:UNINSTALLERX_PACKAGE_SIGNATURE -or
            $item.Publisher -cne $env:UNINSTALLERX_PACKAGE_PUBLISHER -or $item.Name -ieq 'Microsoft.WindowsStore') {
            throw 'The approved package identity or eligibility changed.'
        }
        Remove-AppxPackage -Package $item.PackageFullName -Confirm:$false
    """, environment={"UNINSTALLERX_PACKAGE_FULL": app.full_name, "UNINSTALLERX_PACKAGE_FAMILY": app.family,
                      "UNINSTALLERX_PACKAGE_SIGNATURE": app.signature,
                      "UNINSTALLERX_PACKAGE_PUBLISHER": app.publisher}, timeout=180)
