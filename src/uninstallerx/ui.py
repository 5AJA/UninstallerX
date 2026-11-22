from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import time
import tkinter as tk
from collections.abc import Iterator
from contextlib import contextmanager
from ctypes import wintypes
from dataclasses import dataclass, field
from pathlib import Path
from queue import Empty, Queue
from threading import Event, Thread
from tkinter import filedialog, messagebox, ttk
from typing import Any

from .intent import MAX_REQUEST_LENGTH, interpret_live_removal_request, interpret_removal_request
from .model_provider import LocalGranite, ModelError
from .model_runtime import ManagedModel
from .real_apps import new_removal_audit, run_real
from .recovery import RecoveryJournal
from .runner import run_case
from .types import RunTrace


KIND_LABELS = {"installed": "Installed", "portable": "Portable"}
PHASES = {"uninstall": "Run uninstaller", "residual_files": "Clean remaining files", "residual_settings": "Clean app settings"}
OPERATIONS = {
    "run_uninstaller": "Run app uninstaller",
    "quarantine_file": "Move file to recovery folder",
    "delete_registry_value": "Delete app setting",
}
OPERATION_RESULTS = {
    "run_uninstaller": "App uninstaller finished",
    "quarantine_file": "Moved to recovery folder",
    "delete_registry_value": "App setting deleted",
}
FILE_STORAGE_NOTE = "Files move out of their original location and are kept for recovery."
TOOLS = {
    "search_uninstall": "Installation records", "find_named_dirs": "App folder search",
    "search_settings": "App settings search", "list_dir": "Folder contents",
    "list_registry_values": "Registry values", "read_text": "App documentation",
}
RESULTS = {
    "completed": "Cleanup complete", "incomplete_cleanup": "Some targets remain",
    "plan_declined": "Job stopped", "uninstaller_not_found": "Uninstaller not found",
    "uninstaller_not_completed": "The uninstaller did not complete",
    "model_error": "Could not process the model response", "budget_exceeded": "The job reached its limit",
}
PROGRESS_EVENTS = {"job_started", "read_tool", "discovery_completed", "phase_started", "execution_started", "execution_outcome"}

BG = "#11121a"
SURFACE = "#1b1d29"
INPUT = "#222435"
INK = "#f2f0ff"
MUTED = "#a7a9c0"
ACCENT = "#c1b2ff"
EDGE = "#34364c"
WARN = "#f1ba8b"
REQUEST = "#2a2443"
FONT = "Segoe UI"


@dataclass
class ApprovalPrompt:
    title: str
    rows: list[tuple[str, str]]
    note: str = ""
    copies: dict[str, tuple[str, list[tuple[str, str]]]] = field(default_factory=dict)
    reply: Queue[bool | set[str]] = field(default_factory=lambda: Queue(maxsize=1))


class RemovalWindow:
    def __init__(
        self, root: tk.Tk, repo_root: Path, port: int, *, apply: bool = False,
        demo: bool = False, portable_roots: tuple[Path, ...] = (),
    ) -> None:
        self.root = root
        self.repo_root = repo_root
        self.apply = apply
        self.demo = demo
        self.portable_roots = portable_roots
        self.runtime = ManagedModel(repo_root, port)
        self.model: LocalGranite | None = None
        self.preparing = False
        self.preparation_start = 0.0
        self.events: Queue[tuple[str, Any]] = Queue()
        self.closing = Event()
        self.busy = False
        self.sent_request = ""
        self.input_focused = False
        self.follow_latest = True
        self.scroll_layout_job: str | None = None
        self.pending: tuple[ApprovalPrompt, tuple[ttk.Button, ttk.Button]] | None = None
        self.live_card: tk.Frame | None = None
        self.live_label: tk.Label | None = None
        self.live_stage = ""
        self.live_started = 0.0
        self.live_second = -1
        self.review_requested = Event()
        self.review_button: ttk.Button | None = None
        self.root.title("UninstallerX")
        self.root.geometry("460x740")
        self.root.minsize(330, 450)
        self.root.configure(bg=BG)
        self.root.protocol("WM_DELETE_WINDOW", self.close)
        self._build()
        self.root.after(50, self._poll)
        self.root.after(100, self._start_preparation)

    def _build(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")
        style.configure("TButton", font=(FONT, 10), padding=(10, 5), background=SURFACE, foreground=INK,
                        bordercolor=EDGE, lightcolor=SURFACE, darkcolor=SURFACE, focuscolor=ACCENT)
        style.map("TButton", background=[("active", EDGE)], foreground=[("disabled", "#686b84")])
        style.configure("Primary.TButton", background=ACCENT, foreground=BG, bordercolor=ACCENT,
                        lightcolor=ACCENT, darkcolor=ACCENT, focuscolor=BG)
        style.map("Primary.TButton", background=[("disabled", EDGE), ("active", "#ddd4ff")],
                  bordercolor=[("disabled", EDGE)], foreground=[("disabled", MUTED)])
        style.configure("Send.TButton", font=("Segoe UI", 15, "bold"), padding=(5, 0), width=2,
                        background=ACCENT, foreground=BG, bordercolor=ACCENT,
                        lightcolor=ACCENT, darkcolor=ACCENT, focuscolor=BG)
        style.map("Send.TButton", background=[("disabled", EDGE), ("active", "#ddd4ff")],
                  bordercolor=[("disabled", EDGE)], foreground=[("disabled", MUTED)])
        style.layout("Timeline.Vertical.TScrollbar", [
            ("Vertical.Scrollbar.trough", {"sticky": "ns", "children": [
                ("Vertical.Scrollbar.thumb", {"expand": "1", "sticky": "nswe"}),
            ]}),
        ])
        style.configure("Timeline.Vertical.TScrollbar", width=8, troughcolor=BG,
                        background=EDGE, bordercolor=BG, lightcolor=EDGE, darkcolor=EDGE)
        style.map("Timeline.Vertical.TScrollbar", background=[("active", "#676488")])
        style.configure("Startup.Horizontal.TProgressbar", background=ACCENT, troughcolor=EDGE,
                        bordercolor=BG, lightcolor=ACCENT, darkcolor=ACCENT, thickness=4)

        header = tk.Frame(self.root, bg=BG, padx=18, pady=12)
        header.pack(fill="x")
        tk.Label(header, text="UninstallerX", bg=BG, fg=INK, font=("Segoe UI", 15, "bold")).pack(side="left")
        self.clear_button = ttk.Button(header, text="Clear history", command=self._clear_timeline)
        self.clear_button.state(["disabled"])
        header.pack_propagate(False)
        header.configure(height=self.clear_button.winfo_reqheight() + 24)
        tk.Frame(self.root, height=1, bg=EDGE).pack(fill="x")

        self.workspace = tk.Frame(self.root, bg=BG)
        self._build_startup()

        footer = tk.Frame(self.workspace, bg=BG, padx=16, pady=10)
        footer.pack(side="bottom", fill="x")
        composer_canvas = tk.Canvas(footer, bg=BG, highlightthickness=0)
        composer_canvas.pack(fill="x")
        outline = composer_canvas.create_polygon(0, 0, 0, 0, fill=INPUT, outline=EDGE, smooth=True)
        composer = tk.Frame(composer_canvas, bg=INPUT)
        composer_window = composer_canvas.create_window(12, 9, window=composer, anchor="nw")

        def shape_composer(event: tk.Event) -> None:
            right, bottom = event.width - 1, event.height - 1
            radius = 14
            composer_canvas.coords(
                outline, radius, 1, right - radius, 1, right, 1, right, radius,
                right, bottom - radius, right, bottom, right - radius, bottom,
                radius, bottom, 1, bottom, 1, bottom - radius, 1, radius, 1, 1,
            )
            composer_canvas.itemconfigure(composer_window, width=max(1, event.width - 24))

        composer_canvas.bind("<Configure>", shape_composer)
        composer.columnconfigure(0, weight=1)
        input_area = tk.Frame(composer, bg=INPUT)
        input_area.grid(row=0, column=0, sticky="ew", padx=(0, 7))
        self.entry = tk.Text(input_area, height=2, width=1, wrap="word", undo=True, bg=INPUT, fg=INK,
                             insertbackground=ACCENT, selectbackground=REQUEST, selectforeground=INK,
                             font=(FONT, 11), borderwidth=0, highlightthickness=0, padx=2, pady=2, cursor="xterm")
        self.entry.pack(fill="x")
        self.placeholder = tk.Label(input_area, text="Which app should I remove?", bg=INPUT, fg=MUTED,
                                    font=(FONT, 11), cursor="xterm")
        self.placeholder.bind("<Button-1>", self._focus_placeholder)
        self.entry.bind("<Button-1>", lambda _: self.placeholder.place_forget())
        self.entry.bind("<<Modified>>", self._on_draft_modified)
        # Leave plain Return to Tk and the Windows input method.
        self.entry.bind("<Control-Return>", self._submit_key)
        self.entry.bind("<MouseWheel>", self._wheel)

        def update_focus(focused: bool) -> None:
            self.input_focused = focused
            composer_canvas.itemconfigure(outline, outline=ACCENT if focused else EDGE)
            self._update_draft()

        self.entry.bind("<FocusIn>", lambda _: update_focus(True))
        self.entry.bind("<FocusOut>", lambda _: update_focus(False))
        self.submit_button = ttk.Button(composer, text="↑", style="Send.TButton", command=self._submit)
        self.submit_button.grid(row=0, column=1, sticky="se")
        composer_canvas.configure(height=composer.winfo_reqheight() + 18)
        composer.bind("<Configure>", lambda event: composer_canvas.configure(height=event.height + 18))
        self._update_draft()
        tk.Label(footer, text="Ctrl+Enter to send   ·   Enter for a new line", bg=BG, fg=MUTED, font=(FONT, 8)).pack(anchor="w", pady=(6, 0))

        status_bar = tk.Frame(self.workspace, bg=BG, padx=18, pady=3)
        status_bar.pack(side="bottom", fill="x")
        self.idle_status = "Synthetic demo" if self.demo else "Review and approve before removal" if self.apply else "Preview mode · read-only"
        self.status = tk.StringVar(value=self.idle_status)
        status_bar.columnconfigure(0, weight=1)
        tk.Label(status_bar, textvariable=self.status, bg=BG, fg=MUTED, font=(FONT, 9)).grid(row=0, column=0, sticky="w")
        self.latest_button = ttk.Button(status_bar, text="Latest ↓", command=self._jump_to_latest)
        status_bar.rowconfigure(0, minsize=self.latest_button.winfo_reqheight())

        area = tk.Frame(self.workspace, bg=BG)
        area.pack(fill="both", expand=True)
        rail = tk.Frame(area, bg=BG, width=15)
        rail.pack(side="right", fill="y")
        rail.pack_propagate(False)
        self.scroll = ttk.Scrollbar(rail, orient="vertical", style="Timeline.Vertical.TScrollbar", command=self._manual_scroll)
        self.canvas = tk.Canvas(area, bg=BG, highlightthickness=0, yscrollincrement=1,
                                yscrollcommand=self._update_scrollbar)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.timeline = tk.Frame(self.canvas, bg=BG, padx=16, pady=12)
        self.timeline_id = self.canvas.create_window((0, 0), window=self.timeline, anchor="nw")
        self.timeline.bind("<Configure>", self._queue_scroll_layout)
        self.canvas.bind("<Configure>", self._resize_timeline)
        self.root.bind("<MouseWheel>", self._wheel, add="+")

    def _build_startup(self) -> None:
        self.startup = tk.Frame(self.root, bg=BG)
        self.startup.pack(fill="both", expand=True)
        panel = tk.Frame(self.startup, bg=BG)
        panel.place(relx=0.5, rely=0.44, relwidth=0.86, anchor="center")
        self.startup_title = tk.Label(panel, text="Preparing model", bg=BG, fg=INK, font=(FONT, 17, "bold"))
        self.startup_title.pack(fill="x")
        self.startup_details = tk.Label(panel, text="Checking the local setup.", bg=BG, fg=MUTED,
                                        font=(FONT, 10), justify="center", wraplength=270)
        self.startup_details.pack(fill="x", pady=(8, 20))
        panel.bind("<Configure>", lambda event: self.startup_details.configure(wraplength=max(180, event.width - 8)))
        self.startup_bar_slot = tk.Frame(panel, bg=BG, width=218, height=12)
        self.startup_bar_slot.pack()
        self.startup_bar = ttk.Progressbar(self.startup_bar_slot, style="Startup.Horizontal.TProgressbar")
        self.startup_bar.place(relwidth=1, relheight=1)
        self.startup_retry = ttk.Button(panel, text="Retry", style="Primary.TButton", command=self._start_preparation)

    def _start_preparation(self) -> None:
        if self.preparing or self.closing.is_set():
            return
        self.preparing = True
        self.preparation_start = time.monotonic()
        self.startup_retry.pack_forget()
        self.startup_title.configure(text="Preparing model", fg=INK)
        self.startup_details.configure(text="Checking the local setup.", fg=MUTED)
        self.startup_bar.configure(mode="indeterminate", value=0)
        self.startup_bar_slot.pack()
        self.startup_bar.start(28)
        Thread(target=self._prepare_model, name="uninstallerx-prepare-model").start()

    def _prepare_model(self) -> None:
        try:
            model = self.runtime.prepare(lambda status: self.events.put(("startup_progress", status)), self.closing)
            self.events.put(("startup_complete", model))
        except (ModelError, OSError, ValueError, subprocess.SubprocessError) as exc:
            self.runtime.stop()
            self.events.put(("startup_failed", str(exc)))
        except Exception:
            self.runtime.stop()
            logging.exception("Local model preparation failed")
            self.events.put(("startup_failed", "Could not prepare the model. See the terminal for details."))

    def _show_prepared(self) -> None:
        self.startup_bar.stop()
        self.startup_bar.configure(mode="determinate", value=100)
        self.startup_title.configure(text="Model ready", fg=ACCENT)
        self.startup_details.configure(text="Opening the input screen.")
        self.root.after(520, self._fade_startup, 0)

    def _fade_startup(self, step: int) -> None:
        if self.closing.is_set():
            return
        if step == 10:
            self.startup.destroy()
            self.clear_button.pack(side="right")
            self.workspace.pack(fill="both", expand=True)
            return

        def fade(color: str) -> str:
            fraction = step / 10
            start = bytes.fromhex(color[1:])
            end = bytes.fromhex(BG[1:])
            return "#" + bytes(round(a + (b - a) * fraction) for a, b in zip(start, end)).hex()

        self.startup_title.configure(fg=fade(ACCENT))
        self.startup_details.configure(fg=fade(MUTED))
        ttk.Style(self.root).configure("Startup.Horizontal.TProgressbar", background=fade(ACCENT),
                                       lightcolor=fade(ACCENT), darkcolor=fade(ACCENT), troughcolor=fade(EDGE))
        self.root.after(30, self._fade_startup, step + 1)

    def _queue_scroll_layout(self, _event: tk.Event | None = None) -> None:
        if self.scroll_layout_job is None:
            self.scroll_layout_job = self.root.after_idle(self._scroll_region)

    def _scroll_region(self) -> None:
        self.scroll_layout_job = None
        width = self.canvas.winfo_width()
        content_height = self.timeline.winfo_reqheight() if self.timeline.winfo_children() else 0
        height = max(self.canvas.winfo_height(), content_height)
        self.canvas.configure(scrollregion=(0, 0, width, height))
        if self.follow_latest:
            self.canvas.yview_moveto(1)

    def _resize_timeline(self, event: tk.Event) -> None:
        self.canvas.itemconfigure(self.timeline_id, width=event.width)
        for card in self.timeline.winfo_children():
            for label in card.winfo_children():
                if isinstance(label, tk.Label):
                    label.configure(wraplength=max(160, event.width - 68))
        self._queue_scroll_layout()

    def _update_scrollbar(self, first: str, last: str) -> None:
        self.scroll.set(first, last)
        if float(first) == 0.0 and float(last) == 1.0:
            self.scroll.pack_forget()
        elif not self.scroll.winfo_manager():
            self.scroll.pack(fill="both", expand=True, padx=(0, 4))
        if float(last) >= 0.999:
            self.latest_button.grid_remove()
        else:
            self.latest_button.configure(text="Approval ↓" if self.pending else "Latest ↓")
            self.latest_button.grid(row=0, column=1, sticky="e")

    def _manual_scroll(self, *args: str) -> None:
        self.canvas.yview(*args)
        self.follow_latest = self.canvas.yview()[1] >= 0.999

    def _jump_to_latest(self) -> None:
        self.follow_latest = True
        self.canvas.yview_moveto(1)

    def _wheel(self, event: tk.Event) -> str | None:
        hovered = self.root.winfo_containing(event.x_root, event.y_root)
        if hovered is None or not (str(hovered).startswith(str(self.canvas)) or hovered == self.scroll):
            return None
        distance = round(-event.delta / 2)
        if distance:
            self.canvas.yview_scroll(distance, "units")
            self.follow_latest = self.canvas.yview()[1] >= 0.999
        return "break"

    def _label(self, parent: tk.Frame, value: str, *, color: str = MUTED, bold: bool = False) -> tk.Label:
        label = tk.Label(parent, text=value, bg=parent.cget("background"), fg=color, anchor="w", justify="left",
                         font=(FONT, 10, "bold" if bold else "normal"),
                         wraplength=max(160, self.canvas.winfo_width() - 68))
        label.pack(fill="x", anchor="w", pady=(0, 3))
        return label

    def _card(self, title: str, body: str = "", *, color: str = INK, background: str = SURFACE) -> tk.Frame:
        card = tk.Frame(self.timeline, bg=background, padx=13, pady=10, highlightthickness=1, highlightbackground=EDGE)
        card.pack(fill="x", pady=(0, 8))
        self._label(card, title, color=color, bold=True)
        if body:
            self._label(card, body)
        self._queue_scroll_layout()
        return card

    def _clear_timeline(self) -> None:
        if self.busy:
            return
        for item in self.timeline.winfo_children():
            item.destroy()
        self.follow_latest = True
        self.canvas.yview_moveto(0)
        self.clear_button.state(["disabled"])
        self._queue_scroll_layout()
        self.status.set(self.idle_status)
        self.entry.focus_set()

    def _set_draft(self, text: str) -> None:
        self.entry.delete("1.0", "end")
        self.entry.insert("1.0", text)
        self.entry.edit_reset()
        self._update_draft()
        self.entry.focus_set()

    def _on_draft_modified(self, _event: tk.Event) -> None:
        if self.entry.edit_modified():
            self.entry.edit_modified(False)
            self._update_draft()

    def _update_draft(self) -> None:
        draft = self.entry.get("1.0", "end-1c")
        if draft or self.busy or self.input_focused:
            self.placeholder.place_forget()
        else:
            self.placeholder.place(x=2, y=1)
        self.submit_button.state(["!disabled"] if draft.strip() and not self.busy else ["disabled"])

    def _submit_key(self, _event: tk.Event) -> str:
        self._submit()
        return "break"

    def _focus_placeholder(self, _event: tk.Event) -> str:
        self.entry.focus_set()
        self.placeholder.place_forget()
        return "break"

    def _submit(self, chosen_folder: Path | None = None) -> None:
        if self.model is None or not self.workspace.winfo_ismapped() or self.busy or self.closing.is_set():
            return
        request = self.entry.get("1.0", "end-1c")
        if not request.strip() or len(request) > MAX_REQUEST_LENGTH:
            self.status.set(f"Enter a request of up to {MAX_REQUEST_LENGTH} characters.")
            return
        self.busy = True
        self.review_requested.clear()
        self.sent_request = request
        self.entry.delete("1.0", "end")
        self._update_draft()
        self.entry.configure(state="disabled")
        self.clear_button.state(["disabled"])
        self._jump_to_latest()
        self._card("You", request, color=ACCENT, background=REQUEST)
        if chosen_folder is not None:
            self._card("Search folder", str(chosen_folder))
        if not self.demo:
            self.live_card = self._card("In progress", color=ACCENT)
            self.live_label = self._label(self.live_card, "")
            self.review_button = ttk.Button(self.live_card, text="Review found copies", command=self._request_review)
        self._set_live_stage("The local model is reading your request…")
        Thread(target=self._run, args=(self.model, request, chosen_folder), name="uninstallerx-job").start()

    def _set_live_stage(self, stage: str) -> None:
        self.status.set(stage if self.live_label is None else "Working…")
        if stage != self.live_stage:
            self.live_stage = stage
            self.live_started = time.monotonic()
            self.live_second = -1
        self._update_live_stage()

    def _update_live_stage(self) -> None:
        if self.live_label is None:
            return
        seconds = int(time.monotonic() - self.live_started)
        if seconds != self.live_second:
            self.live_second = seconds
            self.live_label.configure(text=f"{self.live_stage}  ·  {seconds // 60}:{seconds % 60:02d}")

    def _request_review(self) -> None:
        self.review_requested.set()
        if self.review_button is not None:
            self.review_button.state(["disabled"])
        self._set_live_stage("Stopping the search to review the current proposals…")

    def _run(self, model: LocalGranite, request: str, chosen_folder: Path | None = None) -> None:
        audit = None
        try:
            if not self.demo:
                audit = new_removal_audit(self.repo_root)
                audit.append("model_request_started", phase="intent")
            started = time.monotonic()
            try:
                if self.demo:
                    name, location = interpret_removal_request(model, request, allow_location=False)
                    lookup_names = None
                else:
                    name, location, lookup_names = interpret_live_removal_request(model, request)
            except (ModelError, ValueError) as exc:
                if audit is not None:
                    diagnostic = {"response": exc.response} if isinstance(exc, ModelError) and exc.response is not None else {}
                    audit.append("model_request_failed", phase="intent", duration_ms=round((time.monotonic() - started) * 1000),
                                 reason=str(exc), **diagnostic)
                raise
            if audit is not None:
                audit.append("intent_resolved", app_name=name, lookup_names=lookup_names,
                             duration_ms=round((time.monotonic() - started) * 1000))
            if self.closing.is_set():
                self.events.put(("stopped", None))
                return
            self.events.put(("intent", name))
            if not self.demo:
                report = run_real(
                    self.repo_root, model, name, apply=self.apply, closing=self.closing,
                    review=lambda title, rows, note: self._ask(title, rows, note=note),
                    progress=lambda message: self.events.put(("real_progress", message)),
                    portable_roots=self.portable_roots, extend_budget=self._extend_budget, user_request=request, lookup_names=lookup_names,
                    portable_location=chosen_folder if chosen_folder is not None else Path(location) if location is not None else None,
                    review_copies=self._ask_copies,
                    review_requested=self.review_requested,
                    review_available=lambda available: self.events.put(("review_available", available)), audit=audit,
                )
                self.events.put(("real_result", report))
                return
            report = run_case(self.repo_root, model, "benign", None, self._approve_target,
                              app_name=name, user_request=request, confirm_plan=self._confirm_plan,
                              extend_budget=self._extend_budget, on_event=self._progress)
            self.events.put(("result", report))
        except ModelError as exc:
            detail = f"{exc}\n\nAudit log: {audit.path}" if audit is not None else str(exc)
            self.events.put(("error", detail))
        except (OSError, RuntimeError, ValueError) as exc:
            self.events.put(("error", str(exc)))
        except Exception:
            logging.exception("UninstallerX job failed")
            self.events.put(("error", "An unexpected error occurred. See the terminal for details."))

    def _progress(self, record: dict[str, Any]) -> None:
        if record["event"] in PROGRESS_EVENTS:
            self.events.put(("progress", record))

    def _confirm_plan(self, trace: RunTrace) -> bool:
        stage = trace.model_steps[0]["stage"]
        rows = []
        for decision in trace.decisions:
            label = OPERATIONS[decision.candidate.operation]
            detail = decision.exact_target
            if decision.decision == "approval_required":
                label += " · Individual approval required"
            elif decision.decision == "deny":
                label += " · Blocked"
                detail += f"\n{decision.reason}"
            rows.append((label, detail))
        if not any(d.decision != "deny" for d in trace.decisions):
            self.events.put(("blocked", (f"No eligible targets for {PHASES[stage].lower()}", rows)))
            return False
        stores_files = any(d.candidate.operation == "quarantine_file" and d.decision != "deny" for d in trace.decisions)
        return self._ask(f"Approve plan: {PHASES[stage]}", rows, note=FILE_STORAGE_NOTE if stores_files else "")

    def _approve_target(self, target: str, reason: str) -> bool:
        labels = {
            "appdata_residual_requires_approval": "Move AppData file to recovery folder",
            "direct_executable_removal_requires_approval": "Move remaining executable to recovery folder",
        }
        if reason in labels:
            return self._ask("Move this file to the recovery folder?", [(labels[reason], target)], note=FILE_STORAGE_NOTE)
        if reason == "vendor_uninstaller_requires_approval":
            return self._ask("Run this app's uninstaller?", [(OPERATIONS["run_uninstaller"], target)])
        return self._ask("Approve this action?", [(reason, target)])

    def _extend_budget(self, kind: str, previous: int, requested: int) -> bool:
        label = {"read": "Read operations", "change": "Change targets", "time": "Job duration (minutes)"}.get(kind, kind)
        return self._ask("Increase the job limit?", [(label, f"{previous} → {requested}")],
                         note="This continues the current investigation. Changes require separate approval.")

    def _ask(self, title: str, rows: list[tuple[str, str]], *, note: str = "") -> bool:
        return self._await_approval(ApprovalPrompt(title, rows, note)) is True

    def _ask_copies(self, copies: dict[str, tuple[str, list[tuple[str, str]]]]) -> set[str]:
        prompt = ApprovalPrompt("Remove the selected copies?", [],
                                "Review each copy and its operation before approving.", copies)
        answer = self._await_approval(prompt)
        return answer if isinstance(answer, set) else set()

    def _await_approval(self, prompt: ApprovalPrompt) -> bool | set[str]:
        if not self.closing.is_set():
            self.events.put(("approval", prompt))
        while not self.closing.is_set():
            try:
                answer = prompt.reply.get(timeout=0.15)
                return False if self.closing.is_set() else answer
            except Empty:
                continue
        return False

    def _show_rows(self, title: str, rows: list[tuple[str, str]]) -> tk.Frame:
        card = self._card(title, color=WARN)
        for label, detail in rows:
            self._label(card, label, color=INK, bold=True)
            self._label(card, detail)
        return card

    def _show_approval(self, prompt: ApprovalPrompt) -> None:
        card = self._show_rows(prompt.title, prompt.rows)
        if prompt.note:
            self._label(card, prompt.note)
        choices = {}
        for key, (target_label, rows) in prompt.copies.items():
            selected = tk.BooleanVar(master=card, value=True)
            choices[key] = selected
            ttk.Checkbutton(card, text="Include this copy", variable=selected).pack(anchor="w", pady=(8, 0))
            self._label(card, target_label, color=INK, bold=True)
            for label, detail in rows:
                self._label(card, label, color=INK, bold=True)
                self._label(card, detail)
        actions = tk.Frame(card, bg=SURFACE)
        actions.pack(fill="x", pady=(8, 0))
        labels = ("Approve selected", "Decline all") if choices else ("Approve", "Decline")
        yes = ttk.Button(actions, text=labels[0], style="Primary.TButton",
                         command=lambda: self._decide(prompt, {key for key, selected in choices.items() if selected.get()} if choices else True))
        no = ttk.Button(actions, text=labels[1], command=lambda: self._decide(prompt, False))
        yes.pack(side="right")
        no.pack(side="right", padx=(0, 8))
        self.pending = (prompt, (yes, no))
        self.latest_button.configure(text="Approval ↓")
        self._set_live_stage("Waiting for approval")

    def _decide(self, prompt: ApprovalPrompt, approved: bool | set[str]) -> None:
        if self.pending is None or self.pending[0] is not prompt or self.closing.is_set():
            return
        buttons = self.pending[1]
        self.pending = None
        self.latest_button.configure(text="Latest ↓")
        actions = buttons[0].master
        card = actions.master
        actions.destroy()
        for widget in card.winfo_children():
            if isinstance(widget, ttk.Checkbutton):
                widget.state(["disabled"])
        label = "Approved" if approved else "Declined"
        self._label(card, label, color=ACCENT if approved else WARN)
        self._set_live_stage("Applying your decision…")
        prompt.reply.put_nowait(approved)

    def _show_progress(self, record: dict[str, Any]) -> None:
        event = record["event"]
        if event == "job_started":
            self.status.set("Inspecting installation and settings…")
        elif event == "read_tool":
            self.status.set(f"Last checked · {TOOLS[record['observation']['tool']]}")
        elif event == "discovery_completed":
            install = Path(record["install_root"])
            appdata = Path(record["appdata_root"])
            kind = KIND_LABELS[record["kind"]]
            self._card(f"App identified · {kind}", f"App folder  {install.parent.name}\\{install.name}\nApp data  {appdata.parent.name}\\{appdata.name}")
        elif event == "phase_started":
            label = PHASES[record["phase"]]
            self._card(label)
            self.status.set(f"Checking targets: {label.lower()}…")
        elif event == "execution_started":
            self.status.set(f"{OPERATIONS[record['operation']]}…")
        elif event == "execution_outcome":
            outcome = record["outcome"]
            completed = outcome["status"] == "completed"
            title = OPERATION_RESULTS[outcome["operation"]] if completed else "Action failed"
            self._card(title, outcome["target"], color=ACCENT if completed else WARN)

    def _show_result(self, report: dict[str, Any]) -> None:
        title = RESULTS.get(report["job_status"], report["job_status"])
        blocked = sum(d["decision"] == "deny" for d in report["trace"]["decisions"])
        declined = sum(o["status"] == "approval_declined" for o in report["trace"]["outcomes"])
        outside = len(report["unauthorized_changes"])
        body = (f"Targets handled: {report['removed_allowed_count']}/{report['allowed_target_count']}"
                f"\nBlocked: {blocked} · Declined: {declined} · Out of scope: {outside}")
        if outside:
            title = "Changes outside the approved scope detected"
        card = self._card(title, body, color=ACCENT if report["job_status"] == "completed" and not outside else WARN)
        ttk.Button(card, text="Open report folder", command=lambda: self._open_report_folder(report)).pack(anchor="w", pady=(4, 0))
        self.status.set(title)

    def _open_report_folder(self, report: dict[str, Any]) -> None:
        path = report.get("report_path") or report.get("audit_path")
        if not path:
            return
        try:
            os.startfile(Path(path).parent)
        except OSError as exc:
            messagebox.showerror("Could not open the report folder", str(exc), parent=self.root)

    def _search_another_folder(self, request: str) -> None:
        if self.busy or self.closing.is_set():
            return
        folder = filedialog.askdirectory(parent=self.root, title="Choose a folder to search for portable apps", mustexist=True)
        if folder:
            self._set_draft(request)
            self._submit(Path(folder))

    def _start_recovery(self, job_id: str) -> None:
        if self.busy or self.closing.is_set() or not self.apply:
            return
        self.busy = True
        self.entry.configure(state="disabled")
        self._update_draft()
        self.clear_button.state(["disabled"])
        self._jump_to_latest()
        self.status.set("Checking the recovery journal…")
        Thread(target=self._run_recovery, args=(job_id,), name="uninstallerx-restore").start()

    def _run_recovery(self, job_id: str) -> None:
        try:
            result = RecoveryJournal(self.repo_root, job_id).restore(
                lambda title, rows, note: self._ask(title, rows, note=note), self.closing,
            )
            self.events.put(("restore_result", result))
        except (OSError, ValueError) as exc:
            self.events.put(("restore_error", str(exc)))

    def _show_real_result(self, report: dict[str, Any]) -> None:
        status = report["status"]
        if status in {"preview", "removed"}:
            title = f'{report["app_name"]} · {"Removal plan" if status == "preview" else "Removal result"}'
            color = ACCENT
        elif status == "incomplete_cleanup":
            title = f'{report["app_name"]} · Partial removal'
            color = WARN
        else:
            title = f'{report["app_name"]} · Stopped'
            color = WARN
        card = self._card(title, report["message"], color=color)
        if len(report.get("copies", [])) > 1:
            self._label(card, "Copies in this request", bold=True)
            for copy in report["copies"]:
                self._label(card, copy.get("display_target") or copy["app_name"])
                self._label(card, copy["message"])
        if unproposed := report.get("unproposed_candidates"):
            self._label(card, "Observed candidates outside the proposal", bold=True)
            for candidate in unproposed.values():
                self._label(card, candidate.get("folder") or candidate.get("package") or candidate["name"])
        if report.get("app_kind"):
            self._label(card, "App type", bold=True)
            self._label(card, report["app_kind"])
        if report.get("package_full_name"):
            self._label(card, "Windows package", bold=True)
            self._label(card, report["package_full_name"])
            if entries := report.get("package_entries"):
                self._label(card, "App entries: " + ", ".join(entries))
        if path := report.get("portable_folder"):
            self._label(card, "Portable folder in the plan", bold=True)
            self._label(card, path)
        if path := report.get("portable_archive"):
            self._label(card, "Matching distribution ZIP in the plan", bold=True)
            self._label(card, path)
        if files := report.get("portable_files"):
            self._label(card, f"Portable files in the plan ({len(files)})", bold=True)
            for path in files[:4]:
                self._label(card, path)
            if len(files) > 4:
                self._label(card, "Open the report to see all paths.")
        if report.get("registry_source"):
            self._label(card, "Windows installation record", bold=True)
            self._label(card, report["registry_source"])
            if path := report.get("display_target"):
                self._label(card, "Uninstaller", bold=True)
                self._label(card, path)
        if report.get("app_data_roots"):
            residuals = [("Folder", path) for path in report.get("residual_folders", [])]
            residuals.extend(("File", path) for path in report["cache_files"])
            total = len(residuals)
            limited = " · Search incomplete" if report.get("cache_scan_limited") else ""
            self._label(card, f"Residual targets: {total}{limited}", bold=True)
            for path in report["app_data_roots"]:
                self._label(card, path)
            for kind, path in residuals[:4]:
                self._label(card, f"{kind}: {path}")
            if total > 4:
                self._label(card, "Open the report to see all candidates.")
        if settings := report.get("settings_candidates"):
            self._label(card, f"Registry setting candidates: {len(settings)}", bold=True)
            for target in settings[:4]:
                self._label(card, target)
            if len(settings) > 4:
                self._label(card, "Open the report to see all candidates.")
        ttk.Button(card, text="Open report folder", command=lambda: self._open_report_folder(report)).pack(anchor="w", pady=(4, 0))
        if self.apply and report.get("recovery_available"):
            ttk.Button(card, text="Restore backups…", command=lambda: self._start_recovery(report["job_id"])).pack(anchor="w", pady=(4, 0))
        if status == "not_found" or report.get("search_incomplete"):
            ttk.Button(card, text="Search another folder…",
                       command=lambda request=self.sent_request: self._search_another_folder(request)).pack(anchor="w", pady=(4, 0))
        self.status.set(self.idle_status)

    def _poll(self) -> None:
        event = None
        payload = None
        try:
            while True:
                event, payload = self.events.get_nowait()
                if event in {"startup_complete", "startup_failed"}:
                    self.preparing = False
                    if self.closing.is_set():
                        self.root.destroy()
                        return
                    if event == "startup_failed":
                        self.startup_bar.stop()
                        self.startup_bar_slot.pack_forget()
                        self.startup_title.configure(text="Model setup failed", fg=WARN)
                        self.startup_details.configure(text=payload)
                        self.startup_retry.pack()
                    else:
                        self.model = payload
                        elapsed_ms = round((time.monotonic() - self.preparation_start) * 1000)
                        self.root.after(max(0, 950 - elapsed_ms), self._show_prepared)
                elif event == "startup_progress":
                    if not self.closing.is_set():
                        self.startup_details.configure(text=payload)
                elif event in {"result", "real_result", "error", "stopped", "restore_result", "restore_error"}:
                    self.busy = False
                    if self.closing.is_set():
                        self.root.destroy()
                        return
                    if self.live_card is not None:
                        self.live_card.destroy()
                        self.live_card = None
                        self.live_label = None
                        self.review_button = None
                    self.entry.configure(state="normal")
                    self.clear_button.state(["!disabled"])
                    if event == "result":
                        self._set_draft("")
                        self._show_result(payload)
                    elif event == "real_result":
                        self._set_draft("")
                        self._show_real_result(payload)
                    elif event == "error":
                        self._set_draft(self.sent_request)
                        self._card("Could not complete the request", payload, color=WARN)
                        self.status.set("You can try another request")
                    elif event == "restore_result":
                        message = ("Recovery declined." if payload["declined"] else
                                   f"Restored: {payload['restored']} · Skipped: {payload['skipped']}")
                        self._card("Recovery result", message, color=WARN if payload["skipped"] else ACCENT)
                        self._update_draft()
                        self.status.set(self.idle_status)
                    elif event == "restore_error":
                        self._card("Could not restore backups", payload, color=WARN)
                        self._update_draft()
                        self.status.set(self.idle_status)
                    self.entry.focus_set()
                elif not self.closing.is_set():
                    if event == "approval":
                        self._show_approval(payload)
                    elif event == "intent":
                        self._card("Requested app", payload)
                    elif event == "progress":
                        self._show_progress(payload)
                    elif event == "real_progress":
                        self._set_live_stage(payload)
                    elif event == "review_available" and self.review_button is not None:
                        if payload:
                            self.review_button.pack(anchor="w", pady=(4, 0))
                        else:
                            self.review_button.pack_forget()
                    elif event == "blocked":
                        self._show_rows(*payload)
        except Empty:
            self._update_live_stage()
        except Exception:
            logging.exception("Could not display an UninstallerX update")
            if event == "approval" and isinstance(payload, ApprovalPrompt) and payload.reply.empty():
                payload.reply.put_nowait(False)
                self.pending = None
            self.status.set("Could not display the latest update.")
        finally:
            if not self.closing.is_set() or self.busy or self.preparing:
                self.root.after(50, self._poll)

    def close(self) -> None:
        self.closing.set()
        if self.preparing:
            self.startup_details.configure(text="Stopping model setup…")
        elif self.busy:
            self.status.set("Finishing the current operation…")
            if self.pending:
                for button in self.pending[1]:
                    button.state(["disabled"])
        else:
            self.root.destroy()


@contextmanager
def _window_icon(root: tk.Tk, path: Path) -> Iterator[None]:
    # Load ICO frames through Windows so PNG-compressed frames retain their alpha channel.
    user = ctypes.WinDLL("user32", use_last_error=True)
    user.LoadImageW.argtypes = [wintypes.HINSTANCE, wintypes.LPCWSTR, wintypes.UINT,
                                ctypes.c_int, ctypes.c_int, wintypes.UINT]
    user.LoadImageW.restype = wintypes.HANDLE
    user.SendMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user.SendMessageW.restype = wintypes.LPARAM
    user.DestroyIcon.argtypes = [wintypes.HICON]

    root.update_idletasks()
    hwnd = int(root.frame(), 16)
    icons = []
    try:
        for icon_kind, width_metric, height_metric in ((0, 49, 50), (1, 11, 12)):
            width = user.GetSystemMetrics(width_metric)
            height = user.GetSystemMetrics(height_metric)
            icon = user.LoadImageW(None, str(path), 1, width, height, 0x10)  # IMAGE_ICON, LR_LOADFROMFILE
            if not icon:
                raise ctypes.WinError(ctypes.get_last_error())
            icons.append(icon)
            user.SendMessageW(hwnd, 0x0080, icon_kind, icon)  # WM_SETICON
        yield
    finally:
        for icon in icons:
            user.DestroyIcon(icon)


def launch(
    repo_root: Path, port: int, *, apply: bool = False, demo: bool = False,
    portable_roots: tuple[Path, ...] = (),
) -> None:
    if apply and not demo:
        from .windows import require_interactive_account

        require_interactive_account()
    repo_root = repo_root.resolve()
    portable_roots = tuple(path.absolute() for path in portable_roots)
    # A process's working directory stays open on Windows.
    os.chdir(repo_root)
    root = tk.Tk()
    window = RemovalWindow(root, repo_root, port, apply=apply, demo=demo, portable_roots=portable_roots)
    try:
        with _window_icon(root, repo_root / "img" / "logo.ico"):
            root.mainloop()
    finally:
        window.runtime.stop()
