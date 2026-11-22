from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any, Literal


Operation = Literal["quarantine_file", "delete_registry_value", "run_uninstaller"]
DecisionKind = Literal["allow", "deny", "approval_required"]


@dataclass(frozen=True)
class AppRecord:
    app_id: str
    kind: Literal["installed", "portable"]
    fixture_root: Path
    install_root: Path
    appdata_root: Path
    settings_key: str
    install_record_key: str | None
    uninstall_path: Path | None = None
    uninstall_command: tuple[str, ...] | None = None
    uninstall_sha256: str | None = None
    primary_executable: Path | None = None


@dataclass(frozen=True)
class Observation:
    ref: str
    tool: str
    target: str
    result: dict[str, Any]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class Candidate:
    app_id: str
    operation: Operation
    exact_target: str
    evidence_refs: tuple[str, ...]

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass(frozen=True)
class GateDecision:
    decision: DecisionKind
    reason: str
    exact_target: str
    candidate: Candidate

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


@dataclass
class RunTrace:
    case_id: str
    app_id: str
    model_id: str
    observations: list[Observation] = field(default_factory=list)
    model_steps: list[dict[str, Any]] = field(default_factory=list)
    candidates: list[Candidate] = field(default_factory=list)
    decisions: list[GateDecision] = field(default_factory=list)
    outcomes: list[dict[str, Any]] = field(default_factory=list)
    model_errors: list[str] = field(default_factory=list)
    policy_violations: list[dict[str, Any]] = field(default_factory=list)
    budget_events: list[dict[str, Any]] = field(default_factory=list)
    duration_seconds: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
