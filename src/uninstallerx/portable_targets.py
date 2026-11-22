from __future__ import annotations

from dataclasses import replace
from pathlib import Path

from .portable_apps import PortableApp, PortableDistribution
from .windows import is_within


class PortableTargets:
    def __init__(self, app: PortableApp, distributions: tuple[PortableDistribution, ...],
                 readable: dict[Path, tuple[int, int, int, int]]) -> None:
        self.app = app
        self.readable = {f"R{index}": (path, readable[path]) for index, path in enumerate(sorted(readable), 1)}
        observed = {file.path: file for file in app.files}
        archive_paths = {item.package.archive.file.path for item in distributions if item.package.archive}
        for item in distributions:
            for file in item.files:
                if file.path not in archive_paths:
                    observed.setdefault(file.path, file)
        self.files = {f"F{index}": file for index, file in enumerate(list(observed.values())[:24], 1)}
        self.unlisted_files = len(observed) - len(self.files)
        self.groups: dict[str, PortableDistribution] = {}
        self.archives: dict[str, PortableDistribution] = {}
        for index, distribution in enumerate(distributions, 1):
            package = distribution.package
            if package.directories:
                self.groups[f"D{index}"] = distribution
            if package.archive:
                self.groups[f"B{index}"] = replace(distribution, files=distribution.archive_files,
                                                    package=replace(package, directories=(), evidence="These files match the distribution ZIP by SHA-256."))
                self.archives[f"Z{index}"] = distribution

    @property
    def readable_pages(self) -> int:
        return max(1, (len(self.readable) + 15) // 16)

    def readable_page(self, page: int) -> dict[str, dict]:
        if type(page) is not int or not 1 <= page <= self.readable_pages:
            raise ValueError("Choose an available page from the observed file inventory.")
        start = (page - 1) * 16
        return {key: {"path": str(path), "size_bytes": identity[2]}
                for key, (path, identity) in list(self.readable.items())[start:start + 16]}

    def describe(self) -> dict[str, dict]:
        options = {}
        for key, distribution in self.groups.items():
            package = distribution.package
            row = {"kind": "whole folder" if package.directories else "ZIP-matching files",
                   "folder": str(package.folder), "file_count": len(distribution.files),
                   "examples": [str(file.path.relative_to(package.folder)) for file in distribution.files[:6]],
                   "evidence": package.evidence}
            if package.directories and package.archive and is_within(package.archive.file.path, package.folder):
                row["required_zip_id"] = "Z" + key[1:]
            if package.directories and distribution.archive_files:
                matched = {file.path for file in distribution.archive_files}
                additional = [str(file.path.relative_to(package.folder)) for file in distribution.files if file.path not in matched]
                row["additional_file_count"] = len(additional)
                row["additional_files_outside_zip"] = additional[:12]
            options[key] = row
        options.update({key: {"kind": "individual observed file", "path": str(file.path)} for key, file in self.files.items()})
        for key, distribution in self.archives.items():
            options[key] = {"kind": "matching distribution ZIP", "path": str(distribution.package.archive.file.path),
                            "matching_files": len(distribution.archive_files)}
        return options

    def select(self, ids: object) -> PortableApp | None:
        if ids == []:
            return None
        options = self.files.keys() | self.groups.keys() | self.archives.keys()
        if not isinstance(ids, list) or not ids or not all(isinstance(key, str) and key in options for key in ids):
            raise ValueError("Use only the observed portable target IDs.")
        selected = tuple(dict.fromkeys(ids))
        files = tuple(self.files[key] for key in selected if key in self.files)
        groups = [self.groups[key] for key in selected if key in self.groups]
        archives = [self.archives[key] for key in selected if key in self.archives]
        if len(groups) > 1 or (groups and files) or len(archives) > 1:
            raise ValueError("Choose one folder or file group, or individual files, plus at most one ZIP.")

        archive = archives[0].package.archive if archives else None
        if groups:
            files, package = groups[0].files, groups[0].package
            source = package.archive
            if package.directories and source and is_within(source.file.path, package.folder) and archive != source:
                raise ValueError("This folder contains its ZIP. Select the matching ZIP ID with the folder, or select files.")
            package = replace(package, archive=archive)
        else:
            package = replace(archives[0].package, directories=()) if archives else None
        if not any(file.path == self.app.executable for file in files):
            raise ValueError("The proposed application targets must include its executable.")
        if archive and any(file.path == archive.file.path for file in files):
            raise ValueError("The selected ZIP is already part of the selected files.")
        return replace(self.app, files=files, package=package, grouped_files=bool(groups))
