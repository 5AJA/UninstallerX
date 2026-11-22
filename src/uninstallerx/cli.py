from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from threading import Event

from .baseline import RuleOnlyBaseline
from .fixture import AppKind, Scenario
from .model_provider import LocalGranite, ModelError
from .recovery import RecoveryJournal
from .runner import run_case, run_sandbox, summarize_reports
from .types import RunTrace


SCENARIOS: tuple[Scenario, ...] = ("benign", "injection", "false_ownership", "path_redirect", "approval_spoof")
KINDS: tuple[AppKind, ...] = ("installed", "portable")


def _approval(mode: str):
    if mode == "approve":
        return lambda _target, _reason: True
    if mode == "deny":
        return lambda _target, _reason: False

    def ask(target: str, reason: str) -> bool:
        print(f"Approval requested for exact target: {target}\nReason: {reason}")
        return input("Type YES to approve this target: ").strip() == "YES"

    return ask


def _print_case(report: dict) -> None:
    print(json.dumps({
        "case_id": report["case_id"],
        "scenario": report["scenario"],
        "kind": report["kind"],
        "job_status": report["job_status"],
        "candidates": len(report["trace"]["candidates"]),
        "gate_decisions": [{"decision": d["decision"], "reason": d["reason"], "target": d["exact_target"]} for d in report["trace"]["decisions"]],
        "removed_allowed_count": report["removed_allowed_count"],
        "allowed_target_count": report["allowed_target_count"],
        "unauthorized_change_count": len(report["unauthorized_changes"]),
        "attack_target_selected": report["attack_target_selected"],
        "attack_block_layer": report["attack_block_layer"],
        "model_errors": report["trace"]["model_errors"],
        "duration_seconds": report["trace"]["duration_seconds"],
        "report_path": report["report_path"],
    }, ensure_ascii=False, indent=2))


def _confirm_interactive_plan(trace: RunTrace) -> bool:
    stage = trace.model_steps[0].get("stage", "unknown") if trace.model_steps else "unknown"
    print(f"\n{stage} proposal and security-gate decisions:")
    for index, decision in enumerate(trace.decisions, 1):
        print(f"{index}. [{decision.decision}] {decision.candidate.operation}: {decision.exact_target}")
        print(f"   reason: {decision.reason}")
    if trace.model_errors:
        print(f"Model errors: {trace.model_errors}")
    if not trace.decisions or not any(decision.decision != "deny" for decision in trace.decisions):
        print("No executable targets were proposed.")
        return False
    return input("\nType YES to execute the allowed plan: ").strip() == "YES"


def _extend_interactive_budget(kind: str, previous: int, requested: int) -> bool:
    return input(f"{kind} budget would increase from {previous} to {requested}. Type YES to approve: ").strip() == "YES"


def _confirm_recovery(title: str, rows: list[tuple[str, str]], note: str) -> bool:
    print(title)
    for label, target in rows:
        print(f"  {label}: {target}")
    print(note)
    return input("Type YES to restore the listed targets: ").strip() == "YES"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="UninstallerX Windows app removal and synthetic evaluation")
    parser.add_argument("--port", type=int, default=18089, help="Local model server port")
    sub = parser.add_subparsers(dest="command", required=True)
    ui = sub.add_parser("ui", help="Open the desktop removal interface")
    modes = ui.add_mutually_exclusive_group()
    modes.add_argument("--apply", action="store_true", help="Enable approved changes to real Windows apps")
    modes.add_argument("--demo", action="store_true", help="Run the isolated synthetic demonstration")
    ui.add_argument("--portable-root", type=Path, action="append", default=[],
                    help="Add a local folder to the portable-app search (can be repeated)")
    restore = sub.add_parser("restore", help="Restore approved backups from a real removal job")
    restore.add_argument("job_id", help="Windows removal job ID from the report")
    demo = sub.add_parser("demo", help="Run one synthetic fixture")
    demo.add_argument("--scenario", choices=SCENARIOS, default="benign")
    demo.add_argument("--kind", choices=KINDS, default="installed")
    demo.add_argument("--approval", choices=("ask", "approve", "deny"), default="ask")
    demo.add_argument("--keep-fixture", action="store_true")
    interactive = sub.add_parser("interactive", help="Type your own removal request and review the plan")
    interactive.add_argument("--kind", choices=KINDS, default="installed")
    interactive.add_argument("--app-name", help="Name of the temporary synthetic app to create")
    sandbox = sub.add_parser("sandbox", help="Investigate and remove an externally prepared synthetic app")
    sandbox.add_argument("--root", type=Path, required=True)
    sandbox.add_argument("--app", required=True)
    sandbox.add_argument("--kind", choices=KINDS, required=True)
    sandbox.add_argument("--registry-root", required=True)
    evaluate = sub.add_parser("evaluate", help="Run a small matrix of synthetic fixtures")
    evaluate.add_argument("--variants", type=int, default=1)
    evaluate.add_argument("--approval", choices=("approve", "deny"), default="approve")
    evaluate.add_argument("--backend", choices=("model", "rule"), default="model")
    args = parser.parse_args(argv)
    repo_root = Path(__file__).resolve().parents[2]
    try:
        if args.command == "ui":
            from .ui import launch

            launch(repo_root, args.port, apply=args.apply, demo=args.demo, portable_roots=tuple(args.portable_root))
            return 0
        if args.command == "restore":
            restored = RecoveryJournal(repo_root, args.job_id).restore(_confirm_recovery, Event())
            print(json.dumps(restored, indent=2))
            return 2 if restored["skipped"] else 0
        model = RuleOnlyBaseline() if args.command == "evaluate" and args.backend == "rule" else LocalGranite(repo_root, port=args.port)
        if args.command == "demo":
            report = run_case(repo_root, model, args.scenario, args.kind, _approval(args.approval), keep_fixture=args.keep_fixture)
            _print_case(report)
            return 0 if report["job_status"] == "completed" and not report["unauthorized_changes"] else 2
        if args.command == "interactive":
            app_name = args.app_name or ("AppOne" if args.kind == "installed" else "ToolOne")
            print(f"This session creates a temporary synthetic {args.kind} app named {app_name}.")
            request = input(f"Enter your removal request for {app_name}: ").strip()
            if app_name.casefold() not in request.casefold():
                print(f"Request must name {app_name}; nothing was changed.")
                return 1
            if not any(word in request.casefold() for word in ("remove", "uninstall", "delete", "clean", "제거", "삭제", "지워", "정리", "없애")):
                print("Request must explicitly ask for removal or cleanup; nothing was changed.")
                return 1
            report = run_case(
                repo_root, model, "benign", args.kind, _approval("ask"),
                user_request=request, app_name=app_name, confirm_plan=_confirm_interactive_plan,
                extend_budget=_extend_interactive_budget,
            )
            print("\nSession result:")
            print(f"Job status: {report['job_status']}")
            print(f"Plan approved: {report['plan_approved']}")
            print(f"App-owned targets removed: {report['removed_allowed_count']}/{report['allowed_target_count']}")
            print(f"Out-of-scope changes: {len(report['unauthorized_changes'])}")
            if report["trace"]["model_errors"]:
                print(f"Model errors: {report['trace']['model_errors']}")
            print(f"Detailed report: {report['report_path']}")
            return 0 if report["job_status"] in {"completed", "plan_declined"} and not report["unauthorized_changes"] and not report["trace"]["model_errors"] else 2
        if args.command == "sandbox":
            report = run_sandbox(
                repo_root, model, args.root, args.app, args.kind, args.registry_root,
                _approval("ask"), confirm_plan=_confirm_interactive_plan,
                extend_budget=_extend_interactive_budget,
            )
            print(json.dumps({
                "case_id": report["case_id"], "job_status": report["job_status"],
                "plan_approved": report["plan_approved"], "model_errors": report["trace"]["model_errors"],
                "report_path": report["report_path"],
            }, ensure_ascii=False, indent=2))
            return 0 if report["job_status"] in {"execution_completed_unscored", "plan_declined"} and not report["trace"]["model_errors"] else 2
        if args.variants < 1 or args.variants > 3:
            parser.error("--variants must be between 1 and 3")
        reports = []
        for variant in range(args.variants):
            for scenario in SCENARIOS:
                for kind in KINDS:
                    print(f"Running {scenario}/{kind} variant {variant}...", flush=True)
                    report = run_case(repo_root, model, scenario, kind, _approval(args.approval), variant=variant)
                    _print_case(report)
                    reports.append(report)
        summary = summarize_reports(reports)
        summary["case_reports"] = [report["report_path"] for report in reports]
        name = "evaluation-" + datetime.now().strftime("%Y%m%d-%H%M%S") + ".json"
        path = repo_root / ".local" / "reports" / name
        path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
        print(json.dumps({**summary, "summary_path": str(path)}, ensure_ascii=False, indent=2))
        return 0 if not summary["unauthorized_change_jobs"] and not summary["incomplete_jobs"] else 2
    except (OSError, ModelError, RuntimeError, ValueError) as exc:
        print(f"UninstallerX error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
