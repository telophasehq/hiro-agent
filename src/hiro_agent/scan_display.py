"""Live TTY display for scan progress and per-skill activity."""

import asyncio
import shutil
import sys
import threading
import time as _time

_DIM = "\033[2m"
_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_GREEN = "\033[32m"
_RESET = "\033[0m"
_CLEAR_LINE = "\033[2K\r"
_UP = "\033[A"

# Keep the live display compact; avoid terminal overflow and flicker.
_MAX_TODO_LINES = 3


def _get_terminal_width() -> int:
    """Best-effort terminal width for truncation logic."""
    try:
        return shutil.get_terminal_size((100, 20)).columns
    except OSError:
        return 100


def _get_terminal_height() -> int:
    """Best-effort terminal height for display capping."""
    try:
        return shutil.get_terminal_size((100, 20)).lines
    except OSError:
        return 20


def _truncate(text: str, max_len: int) -> str:
    """Truncate long strings with ellipsis for stable single-line rendering."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


def _print_text_block(text: str) -> None:
    """Print markdown-like text above the dynamic display block."""
    text = text.strip()
    if not text:
        return
    print(file=sys.stderr, flush=True)
    print(text, file=sys.stderr, flush=True)
    print(file=sys.stderr, flush=True)

_DEBOUNCE_MS = 50


class _ScanDisplay:
    """Live scan display with per-agent status lines.

    Thread-safe: uses a lock for concurrent updates from 8 agents.
    """

    # States: pending='○', running='◆', completed='✓', incomplete='⚠'

    def __init__(self, skill_names: list[str]) -> None:
        self._skill_names = list(skill_names)
        self._phase = 0  # 0=init, 1=recon, 2=investigations, 3=report, 4=done
        self._agent_status: dict[str, str] = {
            n: "pending" for n in skill_names}
        self._agent_tool: dict[str, str] = {}  # name -> "ToolName(summary)"
        # name -> sub-agent's current tool
        self._agent_subtool: dict[str, str] = {}
        # name -> sub-agent type (e.g. "explore")
        self._agent_subname: dict[str, str] = {}
        self._recon_tool_info: str = ""  # current tool during recon
        # monotonic time when recon started thinking
        self._recon_thinking_since: float = 0.0
        self._recon_todos: list[dict] = []  # recon's TodoWrite plan
        self._agent_thinking_since: dict[str,
                                         float] = {}  # name -> monotonic time
        # name -> when sub-agent started
        self._agent_subagent_since: dict[str, float] = {}
        # name -> when current parent tool step was last updated
        self._agent_tool_since: dict[str, float] = {}
        # name -> when current sub-agent tool step was last updated
        self._agent_subtool_since: dict[str, float] = {}
        self._agent_started_at: dict[str, float] = {}  # name -> monotonic time
        self._agent_elapsed_s: dict[str, float] = {}  # name -> elapsed seconds when completed
        self._agent_todos: dict[str, list[dict]] = {}
        # name -> (done, total)
        self._agent_todo_progress: dict[str, tuple[int, int]] = {}
        # name -> unique finding JSON basenames written so far
        self._agent_finding_files: dict[str, set[str]] = {}
        self._lines_on_screen = 0
        self._lock = threading.Lock()
        self._last_render = 0.0
        self._investigations_start: float = 0.0
        self._tick_task: asyncio.Task | None = None

    # -- phase transitions ---------------------------------------------------

    def start_recon(self) -> None:
        with self._lock:
            self._phase = 1
            self._render()
        self._start_tick()

    def start_investigations(self) -> None:
        with self._lock:
            self._phase = 2
            self._recon_tool_info = ""
            self._investigations_start = _time.monotonic()
            for n in self._skill_names:
                self._agent_status[n] = "pending"
            self._agent_todo_progress.clear()
            self._agent_finding_files.clear()
            self._agent_tool_since.clear()
            self._agent_subtool_since.clear()
            self._agent_started_at.clear()
            self._agent_elapsed_s.clear()
            self._render()
        self._start_tick()

    def _start_tick(self) -> None:
        """Start a background task to update the elapsed timer every second."""
        if self._tick_task is not None:
            return
        try:
            loop = asyncio.get_running_loop()
        except RuntimeError:
            return
        self._tick_task = loop.create_task(self._tick_loop())

    async def _tick_loop(self) -> None:
        try:
            while True:
                await asyncio.sleep(1)
                with self._lock:
                    if self._phase not in (1, 2):
                        break
                    self._render()
        except asyncio.CancelledError:
            pass

    def start_report(self) -> None:
        """Finalize the display permanently, then report streams below."""
        if self._tick_task:
            self._tick_task.cancel()
            self._tick_task = None
        with self._lock:
            self._phase = 4  # jump to done — all ✓
            self._agent_tool.clear()
            self._render()
            self._lines_on_screen = 0  # permanent — report streams below
            print(file=sys.stderr, flush=True)  # blank line before report

    def finish(self) -> None:
        """No-op — display was finalized in start_report()."""
        pass

    # -- agent lifecycle ------------------------------------------------------

    def recon_tool(self, tool_name: str, summary: str) -> None:
        """Update the recon line with current tool activity."""
        with self._lock:
            if tool_name:
                self._recon_tool_info = f"{tool_name}({summary})"
                self._recon_thinking_since = 0.0
            else:
                self._recon_tool_info = "Thinking…"
                self._recon_thinking_since = _time.monotonic()
            self._debounced_render()

    def recon_text(self, text: str) -> None:
        """Print recon reasoning above the display, then redraw."""
        with self._lock:
            self._clear_lines()
            _print_text_block(text)
            self._recon_tool_info = ""
            self._recon_thinking_since = 0.0
            lines = self._build_lines()
            for line in lines:
                print(line, file=sys.stderr, flush=True)
            self._lines_on_screen = len(lines)

    def recon_todos(self, todos: list[dict]) -> None:
        """Update the recon plan checklist."""
        with self._lock:
            self._recon_todos = todos
            self._debounced_render()

    def show_recon_summary(self, summary: str) -> None:
        """Print the final recon summary permanently above the display."""
        if not summary.strip():
            return
        with self._lock:
            self._clear_lines()
            self._lines_on_screen = 0
        _print_text_block(summary)

    def agent_started(self, name: str) -> None:
        with self._lock:
            now = _time.monotonic()
            self._agent_status[name] = "running"
            self._agent_started_at[name] = now
            self._agent_elapsed_s.pop(name, None)
            self._agent_tool_since.pop(name, None)
            self._agent_subtool_since.pop(name, None)
            self._agent_todo_progress.pop(name, None)
            self._agent_finding_files.pop(name, None)
            self._debounced_render()

    def agent_tool(self, name: str, tool_name: str, summary: str, is_subagent: bool = False) -> None:
        with self._lock:
            now = _time.monotonic()
            self._agent_status[name] = "running"
            if is_subagent:
                # Sub-agent tool — show below parent line
                if tool_name:
                    self._agent_subtool[name] = f"{tool_name}({summary})"
                else:
                    self._agent_subtool[name] = "Thinking…"
                    self._agent_thinking_since[name] = _time.monotonic()
                self._agent_subtool_since[name] = now
                if name not in self._agent_subagent_since:
                    self._agent_subagent_since[name] = now
            else:
                # Parent tool — update main line, clear sub-agent state
                if tool_name == "Task":
                    # Spawning a sub-agent — keep sub state, record type
                    self._agent_subname[name] = "explore"
                else:
                    self._agent_subtool.pop(name, None)
                    self._agent_subname.pop(name, None)
                    self._agent_subagent_since.pop(name, None)
                    self._agent_subtool_since.pop(name, None)
                if tool_name:
                    self._agent_tool[name] = f"{tool_name}({summary})"
                    self._agent_thinking_since.pop(name, None)
                    self._agent_tool_since[name] = now
                    # Track findings progress from write calls.
                    if tool_name == "Write":
                        file_name = summary.strip()
                        prefix = f"finding-{name}-"
                        if file_name.startswith(prefix) and file_name.endswith(".json"):
                            files = self._agent_finding_files.setdefault(name, set())
                            files.add(file_name)
                else:
                    self._agent_tool[name] = "Thinking…"
                    self._agent_thinking_since[name] = now
                    self._agent_tool_since[name] = now
            self._debounced_render()

    def agent_todos(self, name: str, todos: list[dict]) -> None:
        """Update the todo checklist for an agent."""
        with self._lock:
            self._agent_todos[name] = todos
            self._agent_todo_progress[name] = self._todo_progress(todos)
            self._debounced_render()

    def agent_completed(self, name: str) -> None:
        with self._lock:
            self._agent_status[name] = "completed"
            started_at = self._agent_started_at.pop(name, 0.0)
            if started_at:
                self._agent_elapsed_s[name] = _time.monotonic() - started_at
            todos = self._agent_todos.get(name, [])
            if todos:
                self._agent_todo_progress[name] = self._todo_progress(todos)
            self._agent_tool.pop(name, None)
            self._agent_tool_since.pop(name, None)
            self._agent_subtool.pop(name, None)
            self._agent_subname.pop(name, None)
            self._agent_thinking_since.pop(name, None)
            self._agent_subagent_since.pop(name, None)
            self._agent_subtool_since.pop(name, None)
            self._agent_todos.pop(name, None)
            self._debounced_render()

    def agent_incomplete(self, name: str) -> None:
        with self._lock:
            self._agent_status[name] = "incomplete"
            started_at = self._agent_started_at.pop(name, 0.0)
            if started_at:
                self._agent_elapsed_s[name] = _time.monotonic() - started_at
            todos = self._agent_todos.get(name, [])
            if todos:
                self._agent_todo_progress[name] = self._todo_progress(todos)
            self._agent_tool.pop(name, None)
            self._agent_tool_since.pop(name, None)
            self._agent_subtool.pop(name, None)
            self._agent_subname.pop(name, None)
            self._agent_thinking_since.pop(name, None)
            self._agent_subagent_since.pop(name, None)
            self._agent_subtool_since.pop(name, None)
            self._agent_todos.pop(name, None)
            self._debounced_render()

    # -- rendering ------------------------------------------------------------

    def _debounced_render(self) -> None:
        """Render at most every _DEBOUNCE_MS milliseconds."""
        now = _time.monotonic() * 1000
        if now - self._last_render < _DEBOUNCE_MS:
            return
        self._render()

    def _clear_lines(self) -> None:
        for _ in range(self._lines_on_screen):
            print(f"{_UP}{_CLEAR_LINE}", end="", file=sys.stderr, flush=True)

    def _todo_progress(self, todos: list[dict]) -> tuple[int, int]:
        total = len(todos)
        done = sum(1 for t in todos if t.get("status") == "completed")
        return done, total

    def _format_elapsed(self, elapsed: float) -> str:
        secs_total = int(max(0.0, elapsed))
        mins, secs = divmod(secs_total, 60)
        return f"{mins}m {secs:02d}s" if mins else f"{secs}s"

    def _todo_progress_suffix(self, name: str) -> str:
        done, total = self._agent_todo_progress.get(name, (0, 0))
        findings = len(self._agent_finding_files.get(name, set()))
        parts: list[str] = []
        if total > 0:
            parts.append(f"{done}/{total} tasks")
        noun = "finding" if findings == 1 else "findings"
        parts.append(f"{findings} {noun}")
        return f" {_DIM}({' · '.join(parts)}){_RESET}"

    def _build_lines(self) -> list[str]:
        lines: list[str] = []

        # Phase 1: Reconnaissance
        if self._phase == 1:
            if self._recon_tool_info:
                info = self._recon_tool_info
                if self._recon_thinking_since:
                    elapsed = int(_time.monotonic() -
                                  self._recon_thinking_since)
                    mins, secs = divmod(elapsed, 60)
                    time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
                    info = f"{info} ({time_str})"
                width = _get_terminal_width()
                info = _truncate(info, width - 22)
                lines.append(
                    f"  {_CYAN}◆{_RESET} Reconnaissance"
                    f"  {_DIM}{info}{_RESET}"
                )
                if self._recon_thinking_since:
                    slow_elapsed = _time.monotonic() - self._recon_thinking_since
                    if slow_elapsed >= 10:
                        lines.append(
                            f"      {_DIM}Slowest step: waiting for model/tool response "
                            f"({self._format_elapsed(slow_elapsed)}){_RESET}"
                        )
            else:
                lines.append(f"  {_CYAN}◆{_RESET} Reconnaissance")
            # Recon plan checklist (sorted: in_progress → pending → completed)
            if self._recon_todos:
                width = _get_terminal_width()
                in_prog = [t for t in self._recon_todos if t.get("status") == "in_progress"]
                pending = [t for t in self._recon_todos if t.get("status", "pending") == "pending"]
                done = [t for t in self._recon_todos if t.get("status") == "completed"]
                visible = in_prog + pending + done
                hidden = len(visible) - min(len(visible), _MAX_TODO_LINES)
                shown = 0
                for todo in visible:
                    if shown >= _MAX_TODO_LINES:
                        break
                    s = todo.get("status", "pending")
                    sym = f"{_GREEN}✓{_RESET}" if s == "completed" else (
                        f"{_CYAN}◆{_RESET}" if s == "in_progress" else f"{_DIM}○{_RESET}")
                    content = _truncate(todo.get("content", ""), width - 12)
                    lines.append(f"      {sym} {_DIM}{content}{_RESET}")
                    shown += 1
                if hidden > 0:
                    lines.append(f"      {_DIM}… +{hidden} more{_RESET}")
        else:
            lines.append(f"  {_GREEN}✓{_RESET} {_DIM}Reconnaissance{_RESET}")

        lines.append("")

        # Phase 2: Investigations
        _single_agent = len(self._skill_names) == 1
        if self._phase < 2:
            lines.append(f"  {_DIM}○ Investigation{_RESET}")
        elif self._phase == 2:
            done = sum(
                1 for s in self._agent_status.values()
                if s in {"completed", "incomplete"}
            )
            total = len(self._skill_names)
            elapsed = _time.monotonic() - self._investigations_start

            if _single_agent:
                # Compact single-agent display: one line with tool info
                name = self._skill_names[0]
                status = self._agent_status.get(name, "pending")
                tool_info = (
                    self._agent_subtool.get(name)
                    or self._agent_tool.get(name)
                    or ""
                )
                thinking_since = self._agent_thinking_since.get(name)
                if thinking_since and name not in self._agent_subagent_since:
                    think_elapsed = int(_time.monotonic() - thinking_since)
                    mins, secs = divmod(think_elapsed, 60)
                    time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
                    if tool_info:
                        tool_info = f"{tool_info} ({time_str})"
                    else:
                        tool_info = f"Thinking… ({time_str})"
                elif not tool_info:
                    tool_info = "Thinking…"
                width = _get_terminal_width()
                tool_info = _truncate(tool_info, width - 22)
                lines.append(
                    f"  {_CYAN}◆{_RESET} Investigation"
                    f"  {_DIM}{tool_info}{_RESET}"
                )
                # Sub-agent child line (if explore agent is running)
                subtool = self._agent_subtool.get(name, "")
                if subtool and name in self._agent_subname:
                    subname = self._agent_subname.get(name, "")
                    sub_since = (
                        self._agent_subtool_since.get(name)
                        or self._agent_subagent_since.get(name)
                    )
                    if sub_since:
                        sub_elapsed = int(_time.monotonic() - sub_since)
                        mins, secs = divmod(sub_elapsed, 60)
                        time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
                        subtool = f"{subtool} ({time_str})"
                    subtool = _truncate(subtool, width - len(subname) - 14)
                    if subname:
                        lines.append(
                            f"      {_DIM}⎿{_RESET} {_CYAN}{subname}{_RESET}"
                            f"  {_DIM}{subtool}{_RESET}"
                        )
                    else:
                        lines.append(
                            f"      {_DIM}⎿{_RESET} {_DIM}{subtool}{_RESET}"
                        )
            else:
                # Multi-agent display: header with progress counter
                mins, secs = divmod(int(elapsed), 60)
                time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
                lines.append(
                    f"  {_CYAN}◆{_RESET} Investigations"
                    f"  {_DIM}({done}/{total} · {time_str}){_RESET}"
                )
                running = [n for n in self._skill_names if self._agent_status.get(n) == "running"]
                if running:
                    now = _time.monotonic()
                    def _activity_elapsed(agent_name: str) -> float:
                        if agent_name in self._agent_subtool:
                            started = (
                                self._agent_subtool_since.get(agent_name)
                                or self._agent_subagent_since.get(agent_name)
                                or self._agent_started_at.get(agent_name, now)
                            )
                            return max(0.0, now - started)
                        if agent_name in self._agent_tool:
                            started = (
                                self._agent_tool_since.get(agent_name)
                                or self._agent_thinking_since.get(agent_name)
                                or self._agent_started_at.get(agent_name, now)
                            )
                            return max(0.0, now - started)
                        if agent_name in self._agent_thinking_since:
                            return max(0.0, now - self._agent_thinking_since.get(agent_name, now))
                        return max(0.0, now - self._agent_started_at.get(agent_name, now))
                    slowest = max(
                        running,
                        key=_activity_elapsed,
                    )
                    slow_elapsed = _activity_elapsed(slowest)
                    step = (
                        self._agent_subtool.get(slowest)
                        or self._agent_tool.get(slowest)
                        or "Thinking…"
                    )
                    step = _truncate(step, _get_terminal_width() - len(slowest) - 28)
                    lines.append(
                        f"      {_DIM}Slowest active: {slowest} — {step} "
                        f"({self._format_elapsed(slow_elapsed)}){_RESET}"
                    )
                elif self._agent_elapsed_s:
                    slowest, elapsed_s = max(
                        self._agent_elapsed_s.items(),
                        key=lambda item: item[1],
                    )
                    lines.append(
                        f"      {_DIM}Slowest completed: {slowest} "
                        f"({self._format_elapsed(elapsed_s)}){_RESET}"
                    )
        else:
            lines.append(f"  {_GREEN}✓{_RESET} {_DIM}Investigation{'s' if not _single_agent else ''}{_RESET}")

        # Per-agent status lines (during phase 2+, multi-agent only)
        if self._phase >= 2 and not _single_agent:
            width = _get_terminal_width()
            for name in self._skill_names:
                status = self._agent_status.get(name, "pending")
                if status == "completed":
                    progress = self._todo_progress_suffix(name)
                    done, total = self._agent_todo_progress.get(name, (0, 0))
                    if total > 0 and done < total:
                        lines.append(
                            f"    {_YELLOW}⚠{_RESET} {_DIM}{name}{_RESET}{progress}"
                        )
                    else:
                        lines.append(
                            f"    {_GREEN}✓{_RESET} {_DIM}{name}{_RESET}{progress}"
                        )
                elif status == "incomplete":
                    progress = self._todo_progress_suffix(name)
                    lines.append(
                        f"    {_YELLOW}⚠{_RESET} {_DIM}{name}{_RESET}{progress}"
                    )
                elif status == "running":
                    # Prefer latest todo list for in-flight progress.
                    todos = self._agent_todos.get(name, [])
                    if todos:
                        self._agent_todo_progress[name] = self._todo_progress(
                            todos)
                    progress = self._todo_progress_suffix(name)
                    tool_info = self._agent_tool.get(name, "")
                    if tool_info:
                        thinking_since = self._agent_thinking_since.get(name)
                        # Only show thinking timer on parent line if no sub-agent
                        if thinking_since and name not in self._agent_subagent_since:
                            elapsed = int(_time.monotonic() - thinking_since)
                            mins, secs = divmod(elapsed, 60)
                            time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
                            tool_info = f"{tool_info} ({time_str})"
                        tool_info = _truncate(
                            tool_info, width - len(name) - 10)
                        lines.append(
                            f"    {_CYAN}◆{_RESET} {name}"
                            f"{progress}  {_DIM}{tool_info}{_RESET}"
                        )
                    else:
                        lines.append(f"    {_CYAN}◆{_RESET} {name}{progress}")
                    # Sub-agent child line
                    subtool = self._agent_subtool.get(name, "")
                    if subtool:
                        subname = self._agent_subname.get(name, "")
                        sub_since = self._agent_subtool_since.get(name) or self._agent_subagent_since.get(name)
                        if sub_since:
                            elapsed = int(_time.monotonic() - sub_since)
                            mins, secs = divmod(elapsed, 60)
                            time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
                            subtool = f"{subtool} ({time_str})"
                        subtool = _truncate(subtool, width - len(subname) - 14)
                        if subname:
                            lines.append(
                                f"      {_DIM}⎿{_RESET} {_CYAN}{subname}{_RESET}"
                                f"  {_DIM}{subtool}{_RESET}"
                            )
                        else:
                            lines.append(
                                f"      {_DIM}⎿{_RESET} {_DIM}{subtool}{_RESET}"
                            )
                    # Todo items — show active tasks first, then queued,
                    # then completed tasks.
                    todos = self._agent_todos.get(name, [])
                    if todos:
                        # Partition by status, preserving original order
                        # within each group.
                        in_progress = [t for t in todos if t.get("status") == "in_progress"]
                        pending = [t for t in todos if t.get("status", "pending") == "pending"]
                        completed = [t for t in todos if t.get("status") == "completed"]
                        visible = in_progress + pending + completed
                        hidden = len(todos) - min(len(visible), _MAX_TODO_LINES)
                        shown = 0
                        for todo in visible:
                            if shown >= _MAX_TODO_LINES:
                                break
                            s = todo.get("status", "pending")
                            sym = f"{_GREEN}✓{_RESET}" if s == "completed" else (
                                f"{_CYAN}◆{_RESET}" if s == "in_progress" else f"{_DIM}○{_RESET}")
                            content = _truncate(
                                todo.get("content", ""), width - 12)
                            lines.append(
                                f"        {sym} {_DIM}{content}{_RESET}")
                            shown += 1
                        if hidden > 0:
                            lines.append(
                                f"        {_DIM}… +{hidden} more{_RESET}")
                else:
                    lines.append(f"    {_DIM}○ {name}{_RESET}")

        lines.append("")

        # Phase 3: Report
        if self._phase < 3:
            lines.append(f"  {_DIM}○ Report{_RESET}")
        elif self._phase == 3:
            lines.append(f"  {_CYAN}◆{_RESET} Report")
        else:
            lines.append(f"  {_GREEN}✓{_RESET} {_DIM}Report{_RESET}")

        # Cap to terminal height to prevent scroll-off rendering bugs.
        # When the display exceeds the terminal, _UP escape codes can't
        # reach lines that scrolled off, causing stacking artifacts.
        max_height = _get_terminal_height() - 2
        if len(lines) > max_height:
            footer = lines[-2:]  # blank + Report line
            body = lines[: max_height - len(footer) - 1]
            lines = body + [f"    {_DIM}…{_RESET}"] + footer

        return lines

    def _render(self) -> None:
        lines = self._build_lines()
        # Prevent scroll-off: never print more lines than we can clear.
        # The display can grow by at most 1 line per render cycle (tick).
        if self._lines_on_screen > 0 and len(lines) > self._lines_on_screen:
            max_grow = self._lines_on_screen + 1
            if len(lines) > max_grow:
                footer = lines[-2:]  # blank + Report line
                available = max_grow - len(footer) - 1
                if available > 0:
                    lines = lines[:available] + [f"    {_DIM}…{_RESET}"] + footer
                else:
                    lines = lines[:max_grow]
        self._clear_lines()
        for line in lines:
            print(line, file=sys.stderr, flush=True)
        self._lines_on_screen = len(lines)
        self._last_render = _time.monotonic() * 1000
