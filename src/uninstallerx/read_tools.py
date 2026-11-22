from __future__ import annotations

import os
import winreg
from pathlib import Path
from typing import Any

from .types import AppRecord, Observation
from .windows import has_reparse_component, is_within, normalized_path


class ToolDenied(ValueError):
    pass


class ReadTools:
    def __init__(self, record: AppRecord, ref_prefix: str = "obs") -> None:
        self.record = record
        self.ref_prefix = ref_prefix
        self.observations: list[Observation] = []
        self.denials = 0

    def _allowed_path(self, target: str) -> Path:
        path = Path(target)
        if not path.is_absolute():
            raise ToolDenied("absolute_path_required")
        roots = (self.record.install_root, self.record.appdata_root)
        if not any(is_within(path, root) for root in roots):
            raise ToolDenied("outside_read_roots")
        if has_reparse_component(path, self.record.fixture_root):
            raise ToolDenied("reparse_point_in_path")
        return path

    def _allowed_registry_key(self, target: str) -> str:
        key = target.removeprefix("HKCU\\")
        allowed = [self.record.settings_key]
        if self.record.install_record_key:
            allowed.append(self.record.install_record_key)
        if key.casefold() not in {value.casefold() for value in allowed}:
            raise ToolDenied("outside_read_registry_keys")
        return key

    def call(self, tool: str, target: str) -> Observation:
        if tool == "list_dir":
            path = self._allowed_path(target)
            if not path.is_dir():
                raise ToolDenied("not_a_directory")
            entries: list[dict[str, Any]] = []
            with os.scandir(path) as listing:
                for entry in sorted(listing, key=lambda item: item.name.casefold())[:30]:
                    entries.append(
                        {
                            "name": entry.name,
                            "path": str(Path(entry.path)),
                            "kind": "reparse" if entry.is_symlink() or os.path.isjunction(entry.path) else ("dir" if entry.is_dir(follow_symlinks=False) else "file"),
                        }
                    )
            result: dict[str, Any] = {"entries": entries}
            target = str(path)
        elif tool == "read_text":
            path = self._allowed_path(target)
            if not path.is_file() or path.suffix.lower() not in {".txt", ".ini", ".json", ".md"}:
                raise ToolDenied("not_an_allowed_text_file")
            with path.open("rb") as handle:
                raw = handle.read(1801)
            content = raw[:1800].decode("utf-8", errors="replace")
            result = {"content": content, "truncated": len(raw) > 1800}
            target = str(path)
        elif tool == "list_registry_values":
            key = self._allowed_registry_key(target)
            try:
                with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key, 0, winreg.KEY_READ) as handle:
                    values: list[dict[str, Any]] = []
                    index = 0
                    while index < 30:
                        try:
                            name, value, value_type = winreg.EnumValue(handle, index)
                        except OSError:
                            break
                        values.append({"name": name, "value": str(value)[:2048], "type": value_type})
                        index += 1
            except FileNotFoundError as exc:
                raise ToolDenied("registry_key_missing") from exc
            result = {"values": values}
            target = "HKCU\\" + key
        else:
            raise ToolDenied("unknown_read_tool")
        observation = Observation(f"{self.ref_prefix}-{len(self.observations) + 1}", tool, target, result)
        self.observations.append(observation)
        return observation

    def denied(self, error: ToolDenied) -> None:
        self.denials += 1


def observation_supports_file(observation: Observation, target: str) -> bool:
    if observation.tool == "read_text":
        return normalized_path(observation.target) == normalized_path(target)
    if observation.tool == "list_dir":
        return any(normalized_path(item["path"]) == normalized_path(target) and item["kind"] == "file" for item in observation.result["entries"])
    return False


def observation_supports_registry_value(observation: Observation, key: str, name: str) -> bool:
    return (
        observation.tool == "list_registry_values"
        and observation.target.casefold() == ("HKCU\\" + key).casefold()
        and any(item["name"].casefold() == name.casefold() for item in observation.result["values"])
    )
