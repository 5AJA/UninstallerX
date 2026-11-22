from __future__ import annotations

import json


class RuleOnlyBaseline:
    """Reproducible no-LLM baseline for the current synthetic target catalog."""

    model_id = "rule-only-synthetic-catalog-v1"

    def complete_json(self, system: str, user: str) -> tuple[dict, str]:
        context = json.loads(user)
        if "finish candidate selector" in system:
            candidates = context["candidates"]
            kind = context.get("kind")
            install = self._install_folder(candidates["install_dirs"], kind)
            if install is None:
                raise ValueError("rule_baseline_cannot_locate_app_folders")
            appdata = next(item for item in candidates["appdata_dirs"] if item["parent"].casefold() == "appdata")
            result = {
                "install_id": install["id"],
                "appdata_id": appdata["id"],
                "settings_id": candidates["settings_keys"][0]["id"],
                "record_ref": candidates["record_refs"][0] if install["parent"].casefold() == "installed" else "",
            }
        elif "read-only Windows app investigator" in system:
            result = self._discover(context)
        elif '"read_ids"' in system:
            result = {"read_ids": [item["id"] for item in context["read_options"]]}
        else:
            accepted_locations = {"installation-record", "app-install", "appdata", "app-settings-registry"}
            result = {
                "target_ids": [item["id"] for item in context["targets"] if item["location"] in accepted_locations]
            }
        return result, json.dumps(result, separators=(",", ":"))

    @staticmethod
    def _install_folder(folders: list[dict], kind: str | None) -> dict | None:
        parents = {kind} if kind is not None else {"installed", "portable"}
        return next((item for item in folders if item["parent"].casefold() in parents), None)

    @staticmethod
    def _discover(context: dict) -> dict:
        task = context["task"]
        observations = context["observations"]
        app_name = task["app_name"]
        kind = task.get("kind")
        record_search = next((item for item in observations if item["tool"] == "search_uninstall"), None)
        if kind != "portable" and record_search is None:
            return {"tool": "search_uninstall", "target": app_name}
        folder_search = next((item for item in observations if item["tool"] == "find_named_dirs"), None)
        if folder_search is None:
            return {"tool": "find_named_dirs", "target": app_name}
        settings_search = next((item for item in observations if item["tool"] == "search_settings"), None)
        if kind != "installed" and settings_search is None:
            return {"tool": "search_settings", "target": app_name}
        folders = folder_search["directories"]
        install = RuleOnlyBaseline._install_folder(folders, kind)
        appdata = next((item for item in folders if item["parent"].casefold() == "appdata"), None)
        if install is None or appdata is None:
            raise ValueError("rule_baseline_cannot_locate_app_folders")
        listed = {item["path_id"] for item in observations if item["tool"] == "list_dir"}
        for folder in (install, appdata):
            if folder["id"] not in listed:
                return {"tool": "list_dir", "target": folder["id"]}
        record = None
        if record_search is not None:
            record = next((item for item in record_search["records"] if item["name"].casefold() == app_name.casefold() and item["install_id"] == install["id"]), None)
        if install["parent"].casefold() == "installed" and record is None:
            raise ValueError("rule_baseline_cannot_locate_install_record")
        settings = (
            {"id": record["settings_id"], "name": app_name} if record else
            next((item for item in settings_search["keys"] if item["name"].casefold() == app_name.casefold()), None)
        )
        if settings is None:
            raise ValueError("rule_baseline_cannot_locate_settings")
        if not any(item["tool"] == "list_registry_values" and item["key_id"] == settings["id"] for item in observations):
            return {"tool": "list_registry_values", "target": settings["id"]}
        return {
            "tool": "finish", "install_id": install["id"], "appdata_id": appdata["id"],
            "settings_id": settings["id"], "record_ref": record_search["ref"] if record else "",
        }
