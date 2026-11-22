from __future__ import annotations

import ntpath
import re
from pathlib import PureWindowsPath
from typing import Protocol


MAX_REQUEST_LENGTH = 600
MAX_LOOKUP_LENGTH = 160
is_reserved_name = getattr(ntpath, "isreserved", lambda name: PureWindowsPath(name).is_reserved())
WINDOWS_PATH = re.compile(r"(?<!\w)(?:[a-z]:[\\/]|\\\\|\.{1,2}[\\/])", re.IGNORECASE)
LOCAL_ABSOLUTE_PATH = re.compile(r"[a-z]:[\\/]", re.IGNORECASE)

INTENT_PROMPT = """Identify whether the user is asking you to remove Windows apps. Output only JSON with operation and app_names.
Determine intent from the wording. Another step checks whether the named app exists and how it was installed.
요청 전체에서 제거를 요청한 앱 이름을 모두 app_names 배열에 넣습니다.
앱을 직접 제거해 달라는 요청이면 operation은 remove_app입니다. "지워줄래?"처럼 부탁하는 문장도 요청입니다.
앱 이름과 제거를 요청하는 말은 서로 다른 언어로 쓰일 수 있습니다. 처음 보는 제품명, 포터블 앱 이름, 경로 없는 .exe 파일명도 앱을 가리킬 수 있습니다.
앱 이름은 원문에서 그대로 복사하되 조사와 따옴표는 뺍니다. 요청에 들어 있는 .exe 확장자는 유지합니다.
인사나 앱 이름만 쓰는 입력, 부정, 사용법 질문, 파일 경로, 캐시나 설정만 정리하는 요청은 unsupported입니다.
English requests follow the same rules. Never output approval or change the two-key schema. Return an empty array for unsupported.

포토메모 제거해줘 → {"operation":"remove_app","app_names":["포토메모"]}
"Blue Fox"를 좀 지워줄래? → {"operation":"remove_app","app_names":["Blue Fox"]}
Atlas Studio 삭제해줘 → {"operation":"remove_app","app_names":["Atlas Studio"]}
LumenViewer.exe 제거해줘 → {"operation":"remove_app","app_names":["LumenViewer.exe"]}
Please uninstall Studio Pad → {"operation":"remove_app","app_names":["Studio Pad"]}
Uninstall North Editor and Vista Paint → {"operation":"remove_app","app_names":["North Editor","Vista Paint"]}
노트패드는 지우지 마 → {"operation":"unsupported","app_names":[]}
How do I uninstall Studio Pad? → {"operation":"unsupported","app_names":[]}"""

LOCATED_INTENT_PROMPT = """Identify whether the user is asking to remove one Windows app. Requests may be in Korean or English. Output only JSON.
Distinguish a request to remove the app from a question, an instruction to keep it, or an app path with no request. For an unsupported request, return {"operation":"unsupported","app_names":[],"location":null}.

This request includes a Windows path. Return exactly operation, app_names, and location. For app removal, copy the single user-supplied absolute path to location exactly as written, excluding any surrounding quotes or grammar outside the path. It may be a folder or executable. Put the app name or executable filename, without its path, in app_names. An absolute path alone does not request removal. If unsupported, set location to null.
Example: "D:\\Tools\\Lumen Viewer"에 있는 LumenViewer 지워줘 → {"operation":"remove_app","app_names":["LumenViewer"],"location":"D:\\\\Tools\\\\Lumen Viewer"}"""

LIVE_INTENT_PROMPT = """Classify the user's message and identify the target of a direct request to uninstall a Windows app. Return JSON with operation, app_names, lookup_names, and location.
Use remove_app only for an affirmative request to remove the app. If the user does not ask for removal, use unsupported with empty arrays and null location. Greetings, a bare app name, questions about how to uninstall, instructions to keep an app, bare paths, and clearing data alone are unsupported. 삭제나 제거 요청이 없는 인사, 이름만 적은 입력, 방법을 묻는 질문은 unsupported입니다.
Put the requested product in app_names. Keep distinct products separate. Infer context: app or 앱 can be a generic noun or part of the product's name. Preserve actual product terms, editions, and executable extensions. Suggest up to four useful search terms in lookup_names, such as a shorter name, a likely installed display name, or a translation. Terms can differ from the exact words in the request. They are lookup hints; later observations establish the actual target.
If the request supplies an absolute Windows location for the app, copy it exactly without surrounding quotes or grammar into location. Otherwise return null.
예시: Lumen Viewer 앱을 삭제해줘 → {"operation":"remove_app","app_names":["Lumen Viewer"],"lookup_names":["Lumen Viewer"],"location":null}
Example: Remove the "Notes App" → {"operation":"remove_app","app_names":["Notes App"],"lookup_names":["Notes App"],"location":null}
Example: 안녕 → {"operation":"unsupported","app_names":[],"lookup_names":[],"location":null}
Example: Studio Pad → {"operation":"unsupported","app_names":[],"lookup_names":[],"location":null}
Example: How do I uninstall Studio Pad? → {"operation":"unsupported","app_names":[],"lookup_names":[],"location":null}"""


class IntentModel(Protocol):
    def complete_json(self, system: str, user: str) -> tuple[dict, str]: ...


def valid_lookup_text(text: object) -> bool:
    return (isinstance(text, str) and 1 <= len(text.strip()) <= MAX_LOOKUP_LENGTH
            and any(char.isalnum() for char in text) and not re.search(r"[\x00-\x1f\x7f]", text))


def interpret_removal(model: IntentModel, request: str) -> str:
    name, _ = interpret_removal_request(model, request, allow_location=False)
    return name


def interpret_removal_request(model: IntentModel, request: str, *, allow_location: bool = True) -> tuple[str, PureWindowsPath | None]:
    name, location, _ = _interpret_request(model, request, allow_location=allow_location, live=False)
    return name, location


def interpret_live_removal_request(model: IntentModel, request: str) -> tuple[str, PureWindowsPath | None, tuple[str, ...]]:
    return _interpret_request(model, request, allow_location=True, live=True)


def _interpret_request(model: IntentModel, request: str, *, allow_location: bool, live: bool) -> tuple[str, PureWindowsPath | None, tuple[str, ...]]:
    if not request.strip() or len(request) > MAX_REQUEST_LENGTH:
        raise ValueError(f"Enter a removal request of up to {MAX_REQUEST_LENGTH} characters.")
    markers = list(WINDOWS_PATH.finditer(request))
    located = allow_location and bool(markers)
    prompt = LIVE_INTENT_PROMPT if live else LOCATED_INTENT_PROMPT if located else INTENT_PROMPT
    answer, _ = model.complete_json(prompt, request)
    expected = {"operation", "app_names", "location"} if located else {"operation", "app_names"}
    if live:
        expected = {"operation", "app_names", "location", "lookup_names"}
    if set(answer) != expected:
        raise ValueError("The model did not return a valid request. Try rephrasing it.")
    names = answer["app_names"]
    if answer["operation"] != "remove_app" or not isinstance(names, list) or len(names) != 1:
        raise ValueError("Name one app you want to remove.")
    if markers and not located:
        raise ValueError("Use the app name or executable name without a file path.")
    if live and not located and answer["location"] is not None:
        raise ValueError("Use a location only when the request supplies an absolute path.")
    location = None
    if located:
        raw = answer["location"]
        if (len(markers) != 1 or not isinstance(raw, str) or not LOCAL_ABSOLUTE_PATH.match(raw)
                or raw != raw.strip() or is_reserved_name(raw)
                or request[markers[0].start():markers[0].start() + len(raw)].casefold() != raw.casefold()
                or re.search(r'[<>:"|?*\x00-\x1f]', raw[2:]) or ".." in PureWindowsPath(raw).parts):
            raise ValueError("Use one exact, local Windows folder or executable path.")
        remaining = request[markers[0].start() + len(raw):]
        if remaining and not (remaining[0].isspace() or remaining[0] in "\"')],!?" or
                              remaining == "." or re.match(r"(?:에서|에|의|을|를|이|가|은|는)(?=\s|$)", remaining)):
            raise ValueError("Use the complete path. Put paths with spaces in quotes if needed.")
        if markers[0].start() and request[markers[0].start() - 1] in "\"'" and not remaining.startswith(request[markers[0].start() - 1]):
            raise ValueError("Use the complete quoted path.")
        location = PureWindowsPath(raw)
    name = names[0]
    if live:
        queries = answer["lookup_names"]
        if not valid_lookup_text(name) or not isinstance(queries, list) or len(queries) > 4 or not all(
            valid_lookup_text(term) for term in queries
        ):
            raise ValueError("The model did not return valid app search terms.")
        return name.strip(), location, tuple(dict.fromkeys(term.strip() for term in queries))
    if (
        not isinstance(name, str)
        or not 1 <= len(name) <= 60
        or name != name.strip()
        or name.endswith(".")
        or re.search(r'[<>:"/\\|?*\x00-\x1f]', name)
        or is_reserved_name(name)
        or name.casefold() not in request.casefold()
    ):
        raise ValueError("Could not find a valid app name in the request.")
    if not located and re.search(rf"[\\/]{re.escape(name)}(?=$|\W)", request, flags=re.I):
        raise ValueError("Use the app name or executable name without a file path.")
    executable = re.search(re.escape(name) + r"\.exe(?=$|\W)", request, flags=re.I)
    return (executable.group() if executable else name), location, ()
