"""Live TTY display for review agent progress."""

import asyncio
import shutil
import sys
import threading
import time as _time

_DIM = "\033[2m"
_CYAN = "\033[36m"
_GREEN = "\033[32m"
_RESET = "\033[0m"
_CLEAR_LINE = "\033[2K\r"
_UP = "\033[A"


def _get_terminal_width() -> int:
    """Best-effort terminal width for truncation logic."""
    try:
        return shutil.get_terminal_size((100, 20)).columns
    except OSError:
        return 100


def _truncate(text: str, max_len: int) -> str:
    """Truncate long strings with ellipsis for stable single-line rendering."""
    if len(text) <= max_len:
        return text
    return text[: max_len - 1] + "…"


_DEBOUNCE_MS = 50


class _ScanDisplay:
    """Live single-agent display showing current tool activity.

    Thread-safe: uses a lock for concurrent updates.

    Shows:
      ◆ Review  Read(file.py)        — while working
        ⎿ explore  Grep(pattern)     — when explore subagent active
      ✓ Review                       — when done
    """

    def __init__(self, skill_names: list[str], *, skip_phases: bool = False) -> None:
        self._skill_names = list(skill_names)
        self._agent_status: dict[str, str] = {
            n: "pending" for n in skill_names}
        self._agent_tool: dict[str, str] = {}
        self._agent_subtool: dict[str, str] = {}
        self._agent_subname: dict[str, str] = {}
        self._agent_thinking_since: dict[str, float] = {}
        self._agent_subagent_since: dict[str, float] = {}
        self._agent_tool_since: dict[str, float] = {}
        self._agent_subtool_since: dict[str, float] = {}
        self._agent_started_at: dict[str, float] = {}
        self._lines_on_screen = 0
        self._lock = threading.Lock()
        self._last_render = 0.0
        self._investigations_start: float = 0.0
        self._tick_task: asyncio.Task | None = None
        self._running = False

    # -- lifecycle ------------------------------------------------------------

    def start_investigations(self) -> None:
        with self._lock:
            self._running = True
            self._investigations_start = _time.monotonic()
            for n in self._skill_names:
                self._agent_status[n] = "pending"
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
                    if not self._running:
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
            self._running = False
            self._agent_tool.clear()
            # Mark all agents as completed for final render
            for n in self._skill_names:
                if self._agent_status.get(n) == "running":
                    self._agent_status[n] = "completed"
            self._render()
            self._lines_on_screen = 0  # permanent — report streams below
            print(file=sys.stderr, flush=True)  # blank line before report

    def finish(self) -> None:
        """No-op — display was finalized in start_report()."""
        pass

    # -- agent lifecycle ------------------------------------------------------

    def agent_started(self, name: str) -> None:
        with self._lock:
            now = _time.monotonic()
            self._agent_status[name] = "running"
            self._agent_started_at[name] = now
            self._debounced_render()

    def agent_tool(self, name: str, tool_name: str, summary: str, is_subagent: bool = False) -> None:
        with self._lock:
            now = _time.monotonic()
            self._agent_status[name] = "running"
            if is_subagent:
                if tool_name:
                    self._agent_subtool[name] = f"{tool_name}({summary})"
                else:
                    self._agent_subtool[name] = "Thinking…"
                    self._agent_thinking_since[name] = _time.monotonic()
                self._agent_subtool_since[name] = now
                if name not in self._agent_subagent_since:
                    self._agent_subagent_since[name] = now
            else:
                if tool_name == "Task":
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
                else:
                    self._agent_tool[name] = "Thinking…"
                    self._agent_thinking_since[name] = now
                    self._agent_tool_since[name] = now
            self._debounced_render()

    def agent_completed(self, name: str) -> None:
        with self._lock:
            self._agent_status[name] = "completed"
            self._agent_tool.pop(name, None)
            self._agent_tool_since.pop(name, None)
            self._agent_subtool.pop(name, None)
            self._agent_subname.pop(name, None)
            self._agent_thinking_since.pop(name, None)
            self._agent_subagent_since.pop(name, None)
            self._agent_subtool_since.pop(name, None)
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

    def _build_lines(self) -> list[str]:
        lines: list[str] = []
        name = self._skill_names[0]
        status = self._agent_status.get(name, "pending")
        width = _get_terminal_width()

        if status == "completed":
            lines.append(f"  {_GREEN}✓{_RESET} {_DIM}Review{_RESET}")
        elif status == "running":
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
            tool_info = _truncate(tool_info, width - 14)
            lines.append(
                f"  {_CYAN}◆{_RESET} Review"
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
            lines.append(f"  {_DIM}○ Review{_RESET}")

        return lines

    def _render(self) -> None:
        lines = self._build_lines()
        self._clear_lines()
        for line in lines:
            print(line, file=sys.stderr, flush=True)
        self._lines_on_screen = len(lines)
        self._last_render = _time.monotonic() * 1000
