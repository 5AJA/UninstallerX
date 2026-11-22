from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from threading import Event
from typing import Protocol

from .audit import AuditLog
from .intent import IntentModel
from .model_provider import ModelContextError, ModelError, ModelOutputLimitError


class InvestigationError(ValueError):
    pass


class InvestigationModel(IntentModel, Protocol):
    def complete_json(self, system: str, user: str, *, schema: dict | None = None) -> tuple[dict, str]: ...


BudgetApproval = Callable[[str, int, int], bool]


def _compact_context(context: dict, limit: int) -> dict:
    """Bound model observations without shortening the user's request."""
    core = {key: value for key, value in context.items()
            if key in {"user_request", "app_name", "app", "requested_location", "lookup_names"}}
    remaining = limit - len(json.dumps(core, ensure_ascii=False).encode("utf-8"))
    for key, value in context.items():
        if key in core or remaining <= 0:
            continue
        values = list(value.items()) if isinstance(value, dict) else value if isinstance(value, list) else [value]
        recent = []
        for item in reversed(values):
            size = len(json.dumps(item, ensure_ascii=False).encode("utf-8"))
            if size > remaining:
                continue
            recent.append(item)
            remaining -= size + len(key) + 8
        if recent:
            recent.reverse()
            core[key] = dict(recent) if isinstance(value, dict) else recent if isinstance(value, list) else recent[0]
    return core


@dataclass
class ToolSession:
    model: InvestigationModel
    closing: Event
    audit: AuditLog
    reads: int = 0
    decisions: int = 0
    violations: int = 0
    deadline: float = field(default_factory=lambda: time.monotonic() + 600)
    extend_budget: BudgetApproval | None = None
    read_limit: int = 50
    change_limit: int = 50
    time_limit: int = 10
    changes: int = 0
    declined: set[str] = field(default_factory=set)

    def request_extension(self, kind: str) -> bool:
        field_name, increment, ceiling = {
            "read": ("read_limit", 25, 200),
            "change": ("change_limit", 25, 200),
            "time": ("time_limit", 5, 30),
        }[kind]
        previous = getattr(self, field_name)
        requested = min(previous + increment, ceiling)
        if self.closing.is_set() or kind in self.declined or requested == previous or self.extend_budget is None:
            return False
        with self.waiting_for_user():
            approved = bool(self.extend_budget(kind, previous, requested)) and not self.closing.is_set()
        self.audit.append("budget_extension", kind=kind, previous=previous, requested=requested, approved=approved)
        if approved:
            setattr(self, field_name, requested)
            if kind == "time":
                self.deadline += (requested - previous) * 60
        else:
            self.declined.add(kind)
        return approved

    @contextmanager
    def waiting_for_user(self) -> Iterator[None]:
        started = time.monotonic()
        try:
            yield
        finally:
            self.deadline += time.monotonic() - started

    @property
    def remaining_changes(self) -> int:
        return self.change_limit - self.changes

    def consume_changes(self, count: int) -> None:
        self.check_time()
        while count > self.remaining_changes:
            if not self.request_extension("change"):
                raise InvestigationError("The change limit was reached. No additional targets were changed.")
        self.changes += count

    def check_time(self) -> None:
        if self.closing.is_set():
            raise InvestigationError("Investigation was cancelled.")
        if time.monotonic() >= self.deadline:
            if not self.request_extension("time") or time.monotonic() >= self.deadline:
                raise InvestigationError("The investigation reached its time limit.")

    def reject(self, phase: str, reason: str) -> str:
        self.violations += 1
        self.audit.append("model_proposal_rejected", phase=phase, reason=reason)
        if self.violations >= 3:
            raise InvestigationError(reason)
        return reason

    def respond(self, phase: str, prompt: str, payload: dict | str, *, schema: dict | None = None,
                log_response: bool = True) -> dict:
        self.check_time()
        self.decisions += 1
        if self.decisions > self.read_limit + 25:
            raise InvestigationError("The model decision limit was reached.")
        user = payload if isinstance(payload, str) else json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        options = {"schema": schema} if schema is not None else {}
        started = time.monotonic()
        self.audit.append("model_request_started", phase=phase, decision=self.decisions)
        try:
            answer, raw = self.model.complete_json(prompt, user, **options)
        except ModelError as exc:
            diagnostic = {"response": exc.response} if log_response and exc.response is not None else {}
            self.audit.append("model_request_failed", phase=phase, decision=self.decisions,
                              duration_ms=round((time.monotonic() - started) * 1000), reason=str(exc), **diagnostic)
            raise
        self.check_time()
        diagnostic = {"response": raw} if log_response else {}
        self.audit.append("model_step", phase=phase, duration_ms=round((time.monotonic() - started) * 1000),
                          **diagnostic)
        return answer

    def ask(self, phase: str, prompt: str, context: dict, actions: dict[str, dict], *, schema: dict | None = None,
            fields: dict | None = None, shorter_reply: str | None = None) -> dict:
        feedback = None
        pages = None
        page = 0
        context_limit = 2100
        properties = dict(schema["properties"]) if schema is not None else dict(fields or {})
        while True:
            menu = actions
            payload = dict(context)
            if pages is not None:
                menu = dict(pages[page])
                if page:
                    menu["menu_previous"] = {"tool": "Show the previous page of available actions"}
                if page + 1 < len(pages):
                    menu["menu_next"] = {"tool": "Show the next page of available actions"}
                payload = _compact_context(context, context_limit)
                payload["action_menu_page"] = page + 1
                payload["action_menu_pages"] = len(pages)
            payload["available_actions"] = menu
            if feedback:
                payload["feedback"] = feedback
            action_schema = {"type": "object", "properties": {**properties, "action": {"type": "string", "enum": list(menu)}},
                             "required": ["action"], "additionalProperties": False}
            try:
                answer = self.respond(phase, prompt, payload, schema=action_schema)
            except ModelOutputLimitError:
                if shorter_reply is None:
                    raise
                prompt += "\n" + shorter_reply
                shorter_reply = None
                self.audit.append("model_response_retry", phase=phase, reason="output_limit")
                continue
            except ModelContextError:
                if pages is not None:
                    if context_limit == 350:
                        raise
                    context_limit = 350
                else:
                    entries = list(actions.items())
                    pages = [entries[index:index + 6] for index in range(0, len(entries), 6)]
                    self.audit.append("model_action_menu_paginated", phase=phase, pages=len(pages))
                continue
            action = answer.get("action") if isinstance(answer, dict) else None
            if pages is not None and isinstance(action, str) and action in {"menu_next", "menu_previous"} and action in menu:
                page += 1 if action == "menu_next" else -1
                feedback = None
                continue
            if isinstance(action, str) and action in menu:
                return answer
            if isinstance(action, str):
                candidate = answer.get("candidate")
                matching = [key for key, option in menu.items()
                            if action in (option.get("tool"), option.get("operation"), *option.get("aliases", ()))
                            and (candidate is None or option.get("candidate") == candidate)]
                location = answer.get("location")
                if not matching and action.startswith(("scan_", "browse_")) and isinstance(location, str):
                    family = action.split("_", 1)[0] + "_"
                    matching = [key for key, option in menu.items()
                                if key.startswith(family) and option.get("location", "").casefold() == location.casefold()]
                if len(matching) == 1:
                    self.audit.append("model_action_resolved", phase=phase, label=action, action=matching[0])
                    return {**answer, "action": matching[0]}
            feedback = self.reject(phase, "Choose an exact key from the current menu: " + ", ".join(menu))

    def reading(self, phase: str, action: str) -> None:
        self.check_time()
        if self.reads >= self.read_limit and not self.request_extension("read"):
            raise InvestigationError("The investigation reached its read limit.")
        self.reads += 1
        self.audit.append("model_read_requested", phase=phase, action=action)
