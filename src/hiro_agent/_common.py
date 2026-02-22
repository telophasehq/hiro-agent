"""Shared agent runner for local security review agents.

CLAUDECODE="" prevents claude-agent-sdk from detecting a nested Claude Code
session and rejecting the spawn. This is intentional — the review agent is
a separate subprocess, not a nested invocation of the caller's session.
"""

import asyncio
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import sys
import threading
import time as _time
from typing import Callable

import structlog
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    ResultMessage,
    TextBlock,
    ToolUseBlock,
    UserMessage,
    query,
)
from claude_agent_sdk._errors import MessageParseError
from claude_agent_sdk.types import AgentDefinition, McpHttpServerConfig, ToolResultBlock

logger = structlog.get_logger(__name__)

# Hardcoded — not configurable to prevent SSRF. HTTPS enforced.
HIRO_MCP_URL = "https://api.hiro.is/mcp/architect/mcp"
HIRO_BACKEND_URL = "https://api.hiro.is"

_EXPLORE_AGENT = AgentDefinition(
    description="Fast, read-only codebase explorer for file discovery and code search.",
    prompt=(
        "You are a fast codebase explorer. Search for files, read code, and return "
        "findings concisely. Do not modify any files. Skip dependency directories "
        "(node_modules, .venv, vendor, dist, build, .git, __pycache__).\n\n"
        "## CRITICAL: File reading limits\n\n"
        "NEVER read more than 500 lines at once (roughly 25,000 characters). "
        "For any file, ALWAYS pass `limit: 500` to the Read tool. If you need "
        "more of the file, make multiple reads with `offset` to page through it. "
        "Reading a full large file in one call will crash your context window.\n\n"
        "## Prefer Grep over Read\n\n"
        "Use Grep to find specific patterns, functions, or code constructs "
        "BEFORE reading files. Only Read the specific sections you need. "
        "Examples:\n"
        "- To find auth middleware: Grep for `auth|middleware|protect` first\n"
        "- To find SQL queries: Grep for `SELECT|INSERT|execute|query` first\n"
        "- To find config: Grep for `SECRET|KEY|PASSWORD|config` first\n\n"
        "Grep with targeted patterns, then Read only the relevant lines."
    ),
    tools=["Read", "Grep", "Glob"],
    model="haiku",
)

SKILL_TOOLS = ["Task", "Write", "TodoWrite", "TodoRead"]


def _get_api_key() -> str:
    """Resolve Hiro API key: env var first, then .hiro/config.json."""
    key = os.environ.get("HIRO_API_KEY", "")
    if key:
        return key
    config_file = Path(".hiro/config.json")
    if config_file.exists():
        try:
            return json.loads(config_file.read_text()).get("api_key", "")
        except Exception:
            return ""
    return ""


def _get_mcp_config() -> dict[str, McpHttpServerConfig]:
    """Build MCP server config for connecting to Hiro.

    Returns an empty dict when no API key is available (MCP context
    tools will be unavailable but the review still runs).
    """
    key = _get_api_key()
    if not key:
        return {}
    return {
        "hiro": McpHttpServerConfig(
            type="http",
            url=HIRO_MCP_URL,
            headers={"Authorization": f"Bearer {key}"},
        ),
    }


def _check_mcp_connection(api_key: str) -> str | None:
    """Pre-flight check: verify MCP server is reachable and key is valid.

    Sends a minimal POST and reads only the status line — the MCP
    Streamable HTTP response is an SSE stream that never terminates,
    so we must not wait for the full body.

    Returns an error string on failure, None on success.
    """
    import http.client
    import ssl
    from urllib.parse import urlparse

    parsed = urlparse(HIRO_MCP_URL)
    try:
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=5,
            context=ssl.create_default_context(),
        )
        conn.request(
            "POST",
            parsed.path,
            body=b'{"jsonrpc":"2.0","method":"ping","id":0}',
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        resp = conn.getresponse()
        # Any 2xx means server is up and auth passed
        if 200 <= resp.status < 300:
            conn.close()
            return None
        conn.close()
        return f"HTTP {resp.status} {resp.reason}"
    except Exception as e:
        return f"{e}"


def _mcp_call_tool(api_key: str, tool_name: str, arguments: dict | None = None, *, timeout: int = 5) -> str | None:
    """Call an MCP tool via direct JSON-RPC POST and return the text result.

    Sends a JSON-RPC request to the MCP Streamable HTTP endpoint and parses
    the SSE response to extract the tool result. Returns None on any failure
    (network error, timeout, bad response) so callers can degrade gracefully.
    """
    import http.client
    import ssl
    from urllib.parse import urlparse

    parsed = urlparse(HIRO_MCP_URL)
    body = json.dumps({
        "jsonrpc": "2.0",
        "method": "tools/call",
        "params": {"name": tool_name, "arguments": arguments or {}},
        "id": 1,
    })
    try:
        conn = http.client.HTTPSConnection(
            parsed.hostname,
            parsed.port or 443,
            timeout=timeout,
            context=ssl.create_default_context(),
        )
        conn.request(
            "POST",
            parsed.path,
            body=body.encode(),
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json, text/event-stream",
            },
        )
        resp = conn.getresponse()
        if resp.status < 200 or resp.status >= 300:
            conn.close()
            return None
        raw = resp.read().decode("utf-8", errors="replace")
        conn.close()

        # Parse SSE: look for "data:" lines containing JSON-RPC result
        for line in raw.splitlines():
            if not line.startswith("data:"):
                continue
            payload = line[len("data:"):].strip()
            if not payload:
                continue
            try:
                msg = json.loads(payload)
            except json.JSONDecodeError:
                continue
            # Extract text content from JSON-RPC result
            result = msg.get("result", {})
            content = result.get("content", [])
            texts = [c.get("text", "") for c in content if c.get("type") == "text"]
            if texts:
                return "\n".join(texts)
        return None
    except Exception:
        return None


async def _prefetch_mcp_context(api_key: str) -> tuple[str | None, str | None]:
    """Fetch org context and security policy in parallel via direct HTTP.

    Returns (org_context, security_policy) — either may be None on failure.
    """
    org_ctx, sec_pol = await asyncio.gather(
        asyncio.to_thread(_mcp_call_tool, api_key, "get_org_context"),
        asyncio.to_thread(_mcp_call_tool, api_key, "get_security_policy"),
    )
    return org_ctx, sec_pol


@dataclass
class McpSetup:
    """Result of MCP preflight + prefetch. Shared across agents."""
    mcp_config: dict
    mcp_tools: list[str] = field(default_factory=list)
    org_context: str | None = None
    security_policy: str | None = None


async def prepare_mcp(*, is_tty: bool = True) -> McpSetup:
    """MCP preflight + prefetch. Called once, result shared across agents."""
    mcp_config = _get_mcp_config()
    if not mcp_config:
        return McpSetup(mcp_config={})

    api_key = _get_api_key()
    err = await asyncio.to_thread(_check_mcp_connection, api_key)
    if err:
        if is_tty:
            print(
                f"  {_YELLOW}warning:{_RESET} Hiro MCP unavailable ({err})"
                f" — proceeding without org context",
                file=sys.stderr, flush=True,
            )
        else:
            print(
                f"warning: Hiro MCP unavailable ({err})"
                " — proceeding without org context",
                file=sys.stderr, flush=True,
            )
        return McpSetup(mcp_config={})

    org_ctx, sec_pol = await _prefetch_mcp_context(api_key)
    return McpSetup(
        mcp_config=mcp_config,
        mcp_tools=["mcp__hiro__recall"],
        org_context=org_ctx,
        security_policy=sec_pol,
    )


def _inject_prefetched_context(system_prompt: str, org_context: str | None, security_policy: str | None) -> str:
    """Prepend pre-fetched MCP context sections to the system prompt.

    Returns the prompt unchanged if both values are None.
    """
    sections: list[str] = []
    if org_context:
        sections.append(f"## Organizational Context (pre-loaded)\n\n{org_context}")
    if security_policy:
        sections.append(f"## Security Policy (pre-loaded)\n\n{security_policy}")
    if not sections:
        return system_prompt
    return "\n\n".join(sections) + "\n\n" + system_prompt


def _get_agent_env() -> dict[str, str]:
    """Build env vars for the agent subprocess.

    When a Hiro API key is available, route LLM calls through the Hiro
    backend proxy to Bedrock (keeps source code within AWS infrastructure).
    Otherwise the agent uses the developer's ANTHROPIC_API_KEY directly.
    """
    env: dict[str, str] = {"CLAUDECODE": ""}
    api_key = _get_api_key()
    if api_key:
        env["ANTHROPIC_BASE_URL"] = f"{HIRO_BACKEND_URL}/api/llm-proxy"
        env["ANTHROPIC_API_KEY"] = api_key
    return env


def _patch_message_parser() -> None:
    """Patch the SDK message parser to skip unknown message types.

    claude-agent-sdk 0.1.38 raises MessageParseError for message types
    added in newer Claude CLI versions (e.g. rate_limit_event). This
    terminates the entire stream. We patch parse_message to return None
    for unknown types instead of raising.
    """
    import claude_agent_sdk._internal.message_parser as parser_mod
    import claude_agent_sdk._internal.client as client_mod

    _original_parse = parser_mod.parse_message

    def _tolerant_parse(data):
        try:
            return _original_parse(data)
        except MessageParseError:
            return None

    parser_mod.parse_message = _tolerant_parse
    client_mod.parse_message = _tolerant_parse


_patch_message_parser()


async def run_review_agent(
    prompt: str,
    system_prompt: str,
    *,
    cwd: str | None = None,
    allowed_tools: list[str] | None = None,
    max_turns: int = 15,
    model: str = "opus",
    mcp_setup: McpSetup | None = None,
) -> str:
    """Run a local review agent and return its final text output.

    The agent connects to the Hiro MCP server for organizational context
    (memories, security policy, org profile) and optionally has filesystem
    access via Read/Grep/Glob tools.

    Only read-only MCP tools are allowed — remember, set_org_context, and
    forget are explicitly excluded to prevent the review agent from
    modifying organizational state.

    When ``mcp_setup`` is provided, skip internal MCP setup and use the
    pre-computed values. When None (default), call internal MCP setup
    for backward compatibility.
    """
    if mcp_setup is not None:
        mcp_config = mcp_setup.mcp_config
        mcp_tools = list(mcp_setup.mcp_tools)
        system_prompt = _inject_prefetched_context(
            system_prompt, mcp_setup.org_context, mcp_setup.security_policy,
        )
    else:
        mcp_config = _get_mcp_config()
        mcp_tools = []
        if mcp_config:
            api_key = _get_api_key()
            err = await asyncio.to_thread(_check_mcp_connection, api_key)
            if err:
                logger.warning("mcp_preflight_failed", error=err)
                mcp_config = {}
            else:
                org_ctx, sec_pol = await _prefetch_mcp_context(api_key)
                system_prompt = _inject_prefetched_context(system_prompt, org_ctx, sec_pol)
                mcp_tools = ["mcp__hiro__recall"]

    options = ClaudeAgentOptions(
        cwd=cwd,
        allowed_tools=(allowed_tools or []) + mcp_tools,
        system_prompt=system_prompt,
        mcp_servers=mcp_config,
        permission_mode="acceptEdits",
        max_turns=max_turns,
        model=model,
        agents={"explore": _EXPLORE_AGENT},
        env=_get_agent_env(),
        stderr=lambda _: None,  # Suppress CLI subprocess output
    )

    summary = ""
    async for message in query(prompt=prompt, options=options):
        if message is None:
            continue
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    summary = block.text

    return summary


_DIM = "\033[2m"
_BOLD = "\033[1m"
_CYAN = "\033[36m"
_YELLOW = "\033[33m"
_RED = "\033[31m"
_GREEN = "\033[32m"
_RESET = "\033[0m"
_CLEAR_LINE = "\033[2K\r"
_UP = "\033[A"
_SPINNER = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]
_MAX_SUBAGENT_LINES = 5
_MAX_TODO_LINES = 3


def _get_terminal_width() -> int:
    try:
        return os.get_terminal_size().columns
    except OSError:
        return 80


def _get_terminal_height() -> int:
    try:
        return os.get_terminal_size().lines
    except OSError:
        return 24


def _truncate(text: str, max_len: int) -> str:
    if max_len > 0 and len(text) > max_len:
        return text[: max_len - 1] + "…"
    return text



class _PlanDisplay:
    """Live plan display that updates in-place on stderr.

    Shows three phases (recon → investigations → report) with status
    indicators. Phase 2 expands to show individual task items when
    sub-agents are spawned. A rolling window of sub-agent activity
    renders below the plan.
    """

    # phase: 1 = recon, 2 = investigations, 3 = report, 4 = done
    def __init__(self) -> None:
        self._phase = 0
        self._items: list[dict] = []   # {id, desc, status}
        self._activity: list[str] = []  # rolling sub-agent lines
        self._lines_on_screen = 0
        self.active = False

    # -- mutation ----------------------------------------------------------

    def start(self) -> None:
        """Show the initial plan with Phase 1 in-progress.

        This is a one-shot print — it does NOT track lines for clearing
        because parent-agent output (reasoning, tool calls) will print
        below it during Phase 1.  A fresh plan is drawn when Phase 2
        starts via ``set_tasks()``.
        """
        self._phase = 1
        self.active = True
        # Print once — don't track lines (can't clear with output below)
        for line in self._build_lines():
            print(line, file=sys.stderr, flush=True)
        print(file=sys.stderr, flush=True)  # blank line before agent output

    def set_tasks(self, tasks: list[tuple[str, str]]) -> None:
        """Expand Phase 2 with task items from ``(tool_use_id, desc)``."""
        self._phase = 2
        self._items = [
            {"id": tid, "desc": desc, "status": "pending"}
            for tid, desc in tasks
        ]
        self._activity.clear()
        self._render()

    def complete_task(self, task_id: str) -> None:
        for item in self._items:
            if item["id"] == task_id:
                item["status"] = "completed"
        self._render()

    def add_activity(self, line: str) -> None:
        self._activity.append(line)
        if len(self._activity) > _MAX_SUBAGENT_LINES:
            self._activity.pop(0)
        self._render()

    def start_report(self) -> None:
        """All tasks done — move to Phase 3."""
        for item in self._items:
            item["status"] = "completed"
        self._phase = 3
        self._activity.clear()
        self._render()

    def finish(self) -> None:
        """Print the final permanent version and deactivate."""
        self._phase = 4
        for item in self._items:
            item["status"] = "completed"
        self._render()
        self._lines_on_screen = 0  # don't clear — it's permanent
        self.active = False

    def clear(self) -> None:
        """Remove the entire managed block from the terminal."""
        self._clear_lines()
        self._lines_on_screen = 0
        self._activity.clear()
        self.active = False

    # -- rendering ---------------------------------------------------------

    def _clear_lines(self) -> None:
        for _ in range(self._lines_on_screen):
            print(f"{_UP}{_CLEAR_LINE}", end="", file=sys.stderr, flush=True)

    def _build_lines(self) -> list[str]:
        lines: list[str] = []

        # Phase 1: Reconnaissance
        if self._phase == 1:
            lines.append(f"  {_CYAN}◆{_RESET} Reconnaissance")
        else:
            lines.append(f"  {_GREEN}✓{_RESET} {_DIM}Reconnaissance{_RESET}")

        # Phase 2: Deep-dive investigations
        if self._phase < 2:
            lines.append(f"  {_DIM}○ Deep-dive investigations{_RESET}")
        elif self._phase == 2:
            lines.append(f"  {_CYAN}◆{_RESET} Deep-dive investigations")
        else:
            lines.append(f"  {_GREEN}✓{_RESET} {_DIM}Deep-dive investigations{_RESET}")

        # Phase 2 sub-items (only when expanded)
        if self._items:
            for item in self._items:
                if item["status"] == "completed":
                    lines.append(
                        f"    {_GREEN}✓{_RESET} {_DIM}{item['desc']}{_RESET}"
                    )
                else:
                    lines.append(f"    {_CYAN}⏳{_RESET} {item['desc']}")

        # Phase 3: Report synthesis
        if self._phase < 3:
            lines.append(f"  {_DIM}○ Report synthesis{_RESET}")
        elif self._phase == 3:
            lines.append(f"  {_CYAN}◆{_RESET} Report synthesis")
        else:
            lines.append(f"  {_GREEN}✓{_RESET} {_DIM}Report synthesis{_RESET}")

        # Sub-agent activity (only during Phase 2)
        if self._phase == 2 and self._activity:
            lines.append("")
            lines.append(f"  {_DIM}running sub-agents{_RESET}")
            lines.extend(self._activity)

        return lines

    def _render(self) -> None:
        self._clear_lines()
        lines = self._build_lines()

        for line in lines:
            print(line, file=sys.stderr, flush=True)

        self._lines_on_screen = len(lines)


class _Spinner:
    """Async spinner that shows activity on stderr."""

    def __init__(self) -> None:
        self._task: asyncio.Task | None = None
        self._status = ""
        self._idx = 0
        self._paused = False

    def update(self, status: str) -> None:
        self._status = status

    def start(self) -> None:
        self._task = asyncio.create_task(self._run())

    def pause(self) -> None:
        """Pause the spinner (e.g. while streaming text)."""
        self._paused = True
        self.clear()

    def resume(self) -> None:
        """Resume the spinner."""
        self._paused = False

    async def _run(self) -> None:
        try:
            while True:
                if not self._paused:
                    char = _SPINNER[self._idx % len(_SPINNER)]
                    status = self._status
                    line = f"{_CLEAR_LINE}  {_CYAN}{char}{_RESET} {status}"
                    print(line, end="", file=sys.stderr, flush=True)
                    self._idx += 1
                await asyncio.sleep(0.1)
        except asyncio.CancelledError:
            self.clear()

    def clear(self) -> None:
        print(_CLEAR_LINE, end="", file=sys.stderr, flush=True)

    def stop(self) -> None:
        if self._task:
            self._task.cancel()
            self._task = None


async def run_streaming_agent(
    prompt: str,
    system_prompt: str,
    *,
    cwd: str | None = None,
    allowed_tools: list[str] | None = None,
    max_turns: int = 30,
    verbose: bool = False,
    model: str = "opus",
    mcp_setup: McpSetup | None = None,
) -> None:
    """Run an agent showing reasoning + tool activity.

    When stderr is a TTY: rich output with spinner, ANSI colors, and
    in-place plan display.  When piped (non-TTY): plain text output
    that won't be garbled by escape codes.

    Final report always prints to stdout.

    When ``mcp_setup`` is provided, skip internal MCP setup and use the
    pre-computed values. When None (default), call internal MCP setup
    for backward compatibility.
    """
    is_tty = sys.stderr.isatty()

    if mcp_setup is not None:
        mcp_config = mcp_setup.mcp_config
        mcp_tools = list(mcp_setup.mcp_tools)
        system_prompt = _inject_prefetched_context(
            system_prompt, mcp_setup.org_context, mcp_setup.security_policy,
        )
    else:
        mcp_config = _get_mcp_config()
        mcp_tools = []
        if mcp_config:
            api_key = _get_api_key()
            err = await asyncio.to_thread(_check_mcp_connection, api_key)
            if err:
                if is_tty:
                    print(
                        f"  {_YELLOW}warning:{_RESET} Hiro MCP unavailable ({err})"
                        f" — proceeding without org context",
                        file=sys.stderr, flush=True,
                    )
                else:
                    print(
                        f"warning: Hiro MCP unavailable ({err})"
                        " — proceeding without org context",
                        file=sys.stderr, flush=True,
                    )
                mcp_config = {}
            else:
                org_ctx, sec_pol = await _prefetch_mcp_context(api_key)
                system_prompt = _inject_prefetched_context(system_prompt, org_ctx, sec_pol)
                mcp_tools = ["mcp__hiro__recall"]

    cli_errors: list[str] = []

    def _capture_stderr(line: str) -> None:
        if '"level":"error"' in line or "Error:" in line:
            cli_errors.append(line)

    options = ClaudeAgentOptions(
        cwd=cwd,
        allowed_tools=(allowed_tools or []) + mcp_tools,
        system_prompt=system_prompt,
        mcp_servers=mcp_config,
        permission_mode="acceptEdits",
        max_turns=max_turns,
        model=model,
        agents={"explore": _EXPLORE_AGENT},
        env=_get_agent_env(),
        stderr=_capture_stderr,
    )

    if is_tty:
        await _run_streaming_tty(options, prompt, allowed_tools, cli_errors)
    else:
        await _run_streaming_plain(options, prompt)


async def _run_streaming_plain(
    options: ClaudeAgentOptions,
    prompt: str,
) -> None:
    """Non-TTY streaming: plain text, no ANSI, no spinner."""
    last_text = ""

    async for message in query(prompt=prompt, options=options):
        if message is None:
            continue

        if isinstance(message, UserMessage):
            blocks = message.content if isinstance(message.content, list) else []
            for b in blocks:
                if isinstance(b, ToolResultBlock) and b.is_error:
                    err_text = b.content if isinstance(b.content, str) else str(b.content)
                    err_text = _strip_xml_tags(err_text)
                    if "sibling tool call errored" in err_text.lower():
                        continue
                    err_short = err_text[:200].split("\n")[0]
                    print(f"error: {err_short}", file=sys.stderr, flush=True)
            continue

        if not isinstance(message, AssistantMessage):
            continue

        for block in message.content:
            if isinstance(block, TextBlock) and block.text.strip():
                last_text = block.text
            elif isinstance(block, ToolUseBlock):
                inp = block.input if isinstance(block.input, dict) else {}
                summary = _tool_summary(block.name, inp)
                print(
                    f"  {block.name}({summary})",
                    file=sys.stderr, flush=True,
                )

    if last_text:
        print(last_text, flush=True)


async def _run_streaming_tty(
    options: ClaudeAgentOptions,
    prompt: str,
    allowed_tools: list[str] | None,
    cli_errors: list[str],
) -> None:
    """TTY streaming: rich output with spinner, ANSI colors, plan display."""
    last_text = ""
    current_tool_line = ""  # Track current spinner tool for freezing
    repeat_tool = ""  # Name of tool currently in spinner (for collapsing)
    repeat_count = 0  # Consecutive calls of same tool
    active_tasks = 0  # Track pending Task sub-agents
    active_task_ids: set[str] = set()  # tool_use_ids of Task calls
    has_tasks = "Task" in (allowed_tools or [])
    plan = _PlanDisplay()
    spinner = _Spinner()
    spinner.update(f"{_CYAN}Thinking…{_RESET}")
    spinner.start()

    # Show the plan immediately for scan-type agents
    if has_tasks:
        plan.start()

    try:
        async for message in query(prompt=prompt, options=options):
            if message is None:
                continue

            # Show tool errors from UserMessage results
            if isinstance(message, UserMessage):
                blocks = message.content if isinstance(message.content, list) else []
                for b in blocks:
                    if isinstance(b, ToolResultBlock) and b.is_error:
                        err_text = b.content if isinstance(b.content, str) else str(b.content)
                        err_text = _strip_xml_tags(err_text)
                        if "sibling tool call errored" in err_text.lower():
                            continue
                        if active_tasks > 0:
                            continue
                        err_short = err_text[:200].split("\n")[0]
                        spinner.pause()
                        _freeze_spinner(spinner, current_tool_line)
                        current_tool_line = ""
                        print(
                            f"    {_RED}error: {err_short}{_RESET}",
                            file=sys.stderr, flush=True,
                        )
                        spinner.resume()
                # Check if Task results are coming back (match by tool_use_id)
                if active_tasks > 0:
                    for b in blocks:
                        if isinstance(b, ToolResultBlock) and b.tool_use_id in active_task_ids:
                            active_task_ids.discard(b.tool_use_id)
                            active_tasks -= 1
                            spinner.pause()
                            plan.complete_task(b.tool_use_id)
                            spinner.resume()
                    if active_tasks <= 0:
                        active_tasks = 0
                        active_task_ids.clear()
                        spinner.pause()
                        plan.start_report()
                        spinner.resume()
                continue

            if not isinstance(message, AssistantMessage):
                continue

            # Separate text and tool blocks
            text_blocks = [
                b for b in message.content
                if isinstance(b, TextBlock) and b.text.strip()
            ]
            tool_blocks = [
                b for b in message.content if isinstance(b, ToolUseBlock)
            ]

            # --- Sub-agent activity: rolling display ---
            if active_tasks > 0:
                for block in tool_blocks:
                    name = block.name
                    inp = block.input if isinstance(block.input, dict) else {}
                    summary = _tool_summary(name, inp)
                    line = f"      {_DIM}⎿{_RESET} {_CYAN}{name}{_RESET}{_DIM}({summary}){_RESET}"
                    spinner.pause()
                    plan.add_activity(line)
                    spinner.update(
                        f"{_CYAN}{name}{_RESET} {_DIM}{summary}{_RESET}"
                    )
                    spinner.resume()
                continue

            # --- Parent agent activity ---
            spinner.pause()

            # Show reasoning text
            for tb in text_blocks:
                last_text = tb.text
                _freeze_tool(spinner, current_tool_line, repeat_tool, repeat_count)
                current_tool_line = ""
                repeat_tool = ""
                repeat_count = 0
                _print_text_block(tb.text)

            # Group parallel tool calls by name
            if tool_blocks:
                # Only activate plan display for agents that explicitly
                # use Task (e.g. scan). For others (e.g. review-plan with
                # explore sub-agent), Task calls render as normal tools.
                if has_tasks:
                    task_blocks = [b for b in tool_blocks if b.name == "Task"]
                    other_blocks = [b for b in tool_blocks if b.name != "Task"]
                else:
                    task_blocks = []
                    other_blocks = tool_blocks

                if task_blocks:
                    _freeze_tool(spinner, current_tool_line, repeat_tool, repeat_count)
                    current_tool_line = ""
                    repeat_tool = ""
                    repeat_count = 0

                    # Track active tasks by tool_use_id
                    task_plan: list[tuple[str, str]] = []
                    for b in task_blocks:
                        active_task_ids.add(b.id)
                        inp = b.input if isinstance(b.input, dict) else {}
                        desc = inp.get("description", inp.get("prompt", ""))[:60]
                        task_plan.append((b.id, desc))
                    active_tasks += len(task_blocks)

                    # Render the live plan
                    print(file=sys.stderr, flush=True)
                    plan.set_tasks(task_plan)

                    current_tool_line = ""
                    spinner.update(
                        f"{_DIM}waiting for sub-agents…{_RESET}"
                    )

                # Show non-Task tools normally
                if other_blocks:
                    groups: dict[str, list[str]] = {}
                    for block in other_blocks:
                        name = block.name
                        inp = block.input if isinstance(block.input, dict) else {}
                        summary = _tool_summary(name, inp)
                        groups.setdefault(name, []).append(summary)

                    group_lines = []
                    for name, summaries in groups.items():
                        line = _format_tool_group(name, summaries)
                        group_lines.append((name, summaries, line))

                    # Print all groups except the last
                    for name, summaries, line in group_lines[:-1]:
                        _freeze_tool(spinner, current_tool_line, repeat_tool, repeat_count)
                        current_tool_line = ""
                        repeat_tool = ""
                        repeat_count = 0
                        print(line, file=sys.stderr, flush=True)

                    last_name, last_summaries, last_line = group_lines[-1]
                    total = len(last_summaries)

                    if last_name == repeat_tool:
                        # Same tool as spinner — collapse, don't freeze
                        repeat_count += total
                    else:
                        # Different tool — freeze previous, start new
                        _freeze_tool(spinner, current_tool_line, repeat_tool, repeat_count)
                        repeat_tool = last_name
                        repeat_count = total
                        current_tool_line = last_line

                    # Update spinner with latest summary + count
                    combined = ", ".join(last_summaries[:2])
                    if len(last_summaries) > 2:
                        combined += f" +{len(last_summaries) - 2}"
                    if repeat_count > 1:
                        combined += f" ×{repeat_count}"
                    spinner.update(
                        f"{_CYAN}{last_name}{_RESET} {_DIM}{combined}{_RESET}"
                    )

            spinner.resume()

        spinner.clear()
        _freeze_tool(spinner, current_tool_line, repeat_tool, repeat_count)
        if plan.active:
            plan.finish()
        if last_text:
            print(last_text, flush=True)

        if cli_errors:
            print(f"\n{_DIM}---{_RESET}", file=sys.stderr, flush=True)
            for err in cli_errors:
                print(f"{_DIM}{err}{_RESET}", file=sys.stderr, flush=True)
    finally:
        spinner.stop()


def _strip_xml_tags(text: str) -> str:
    """Remove XML-style tags from error text."""
    import re
    return re.sub(r"<[^>]+>", "", text).strip()


def _format_tool_group(name: str, summaries: list[str]) -> str:
    """Format a group of parallel tool calls as a single line."""
    if len(summaries) == 1:
        return f"    {_CYAN}{name}{_RESET}{_DIM}({summaries[0]}){_RESET}"
    combined = ", ".join(summaries[:3])
    if len(summaries) > 3:
        combined += f" +{len(summaries) - 3} more"
    return f"    {_CYAN}{name}{_RESET}{_DIM}({combined}){_RESET}"


def _freeze_spinner(spinner: "_Spinner", tool_line: str) -> None:
    """Freeze the current spinner as a permanent line on stderr."""
    if tool_line:
        spinner.clear()
        print(tool_line, file=sys.stderr, flush=True)


def _freeze_tool(
    spinner: "_Spinner",
    tool_line: str,
    tool_name: str,
    count: int,
) -> None:
    """Freeze the current tool, collapsing consecutive repeats into ×N."""
    if not tool_line:
        return
    spinner.clear()
    if count > 1:
        print(
            f"    {_CYAN}{tool_name}{_RESET}{_DIM} ×{count}{_RESET}",
            file=sys.stderr, flush=True,
        )
    else:
        print(tool_line, file=sys.stderr, flush=True)



def _print_text_block(text: str) -> None:
    """Print agent text to stderr as clean markdown.

    No indentation — the output is markdown that Claude Code (or any
    markdown-capable reader) will render directly.
    """
    text = text.strip()
    if not text:
        return
    print(file=sys.stderr, flush=True)
    print(text, file=sys.stderr, flush=True)
    print(file=sys.stderr, flush=True)



def _tool_summary(name: str, inp: dict) -> str:
    """One-line summary of a tool call for the spinner."""
    if name == "Bash":
        cmd = inp.get("command", "")
        parts = [l.strip() for l in cmd.strip().splitlines() if l.strip()]
        raw = parts[-1] if parts else cmd
    elif name in ("Read", "Edit", "Write"):
        raw = os.path.basename(inp.get("file_path", ""))
    elif name == "Glob":
        raw = inp.get("pattern", "")
    elif name == "Grep":
        raw = inp.get("pattern", "")
    elif name == "Task":
        raw = inp.get("description", inp.get("prompt", ""))[:60]
    elif name == "TodoWrite":
        todos = inp.get("todos", [])
        raw = f"{len(todos)} items"
    elif name == "TodoRead":
        raw = "checking progress"
    else:
        raw = next((v for v in inp.values() if isinstance(v, str) and v), "")[:60]

    raw = " ".join(raw.split())
    width = _get_terminal_width()
    return _truncate(raw, width - len(name) - 6)


# ---------------------------------------------------------------------------
# Scan-specific helpers: _run_tracked_agent, _run_report_stream, _ScanDisplay
# ---------------------------------------------------------------------------

async def _run_tracked_agent(
    *,
    name: str,
    prompt: str,
    system_prompt: str,
    cwd: str | None,
    allowed_tools: list[str],
    mcp_setup: McpSetup,
    max_turns: int = 15,
    model: str = "sonnet",
    on_tool: Callable[[str, str, str, bool], None] | None = None,
    on_text: Callable[[str], None] | None = None,
    on_todos: Callable[[str, list[dict]], None] | None = None,
) -> tuple[str, str]:
    """Run a single skill agent and return its final text output.

    On each ``ToolUseBlock`` emitted by the agent, calls
    ``on_tool(agent_name, tool_name, summary, is_subagent)`` so the
    display can show per-agent progress.  ``is_subagent`` is True when
    the tool call comes from a Task sub-agent (e.g. explore).

    When ``on_text`` is provided, calls it with each intermediate
    ``TextBlock.text`` (for showing agent reasoning to the user).

    When ``on_todos`` is provided, calls it with ``(agent_name, todos)``
    whenever the agent calls ``TodoWrite``, so the display can render
    the investigation checklist.
    """
    full_system = _inject_prefetched_context(
        system_prompt, mcp_setup.org_context, mcp_setup.security_policy,
    )

    parent_tools = allowed_tools + list(mcp_setup.mcp_tools)
    # Auto-approve sub-agent tools (Read/Grep/Glob) so explore agents
    # can actually use them — without this they're silently blocked.
    subagent_tools = list(_EXPLORE_AGENT.tools or [])
    options = ClaudeAgentOptions(
        cwd=cwd,
        tools=parent_tools,
        allowed_tools=parent_tools + subagent_tools,
        system_prompt=full_system,
        mcp_servers=mcp_setup.mcp_config,
        permission_mode="acceptEdits",
        max_turns=max_turns,
        model=model,
        agents={"explore": _EXPLORE_AGENT},
        env=_get_agent_env(),
        stderr=lambda _: None,
    )

    summary = ""
    session_id = ""
    active_task_ids: set[str] = set()  # Track Task sub-agent tool_use_ids

    async for message in query(prompt=prompt, options=options):
        if message is None:
            continue
        if isinstance(message, UserMessage):
            # Check for Task sub-agent results completing
            blocks = message.content if isinstance(message.content, list) else []
            for b in blocks:
                if isinstance(b, ToolResultBlock) and b.tool_use_id in active_task_ids:
                    active_task_ids.discard(b.tool_use_id)
            if on_tool is not None:
                on_tool(name, "", "", bool(active_task_ids))
        elif isinstance(message, AssistantMessage):
            # If active Task IDs exist, this message is from a sub-agent
            is_subagent = bool(active_task_ids)
            for block in message.content:
                if isinstance(block, TextBlock):
                    summary = block.text
                    if on_text is not None and block.text.strip():
                        on_text(block.text)
                elif isinstance(block, ToolUseBlock):
                    if block.name == "Task":
                        active_task_ids.add(block.id)
                    inp = block.input if isinstance(block.input, dict) else {}
                    if block.name == "TodoWrite" and on_todos is not None:
                        todos = inp.get("todos", [])
                        if todos:
                            on_todos(name, todos)
                    if on_tool is not None:
                        tool_summary = _tool_summary(block.name, inp)
                        on_tool(name, block.name, tool_summary, is_subagent)
        elif isinstance(message, ResultMessage):
            session_id = message.session_id

    return summary, session_id


async def _run_skill_waves(
    *,
    name: str,
    system_prompt: str,
    skill_prompt: str,
    scratchpad_path: Path,
    cwd: str | None,
    mcp_setup: McpSetup,
    waves: int = 2,
    turns_per_wave: int = 8,
    model: str = "opus",
    on_tool: Callable[[str, str, str, bool], None] | None = None,
    on_text: Callable[[str], None] | None = None,
    on_todos: Callable[[str, list[dict]], None] | None = None,
) -> tuple[str, int]:
    """Run a skill investigation in multiple waves with scratchpad compaction.

    Each wave starts a fresh agent session, carrying only the compacted
    scratchpad from prior waves. This keeps peak context per wave at ~40K
    tokens instead of 100K+.

    Returns (synthesis_result, total_tool_calls).
    """
    from hiro_agent.prompts import SKILL_SYNTHESIS_PROMPT

    total_tool_calls = 0

    def _counting_on_tool(agent_name: str, tool_name: str, summary: str, is_subagent: bool) -> None:
        nonlocal total_tool_calls
        if tool_name:
            total_tool_calls += 1
        if on_tool is not None:
            on_tool(agent_name, tool_name, summary, is_subagent)

    # Inject turn budget into system prompt
    system_prompt = system_prompt.replace("{turns_per_wave}", str(turns_per_wave))

    for wave in range(waves):
        # Build prompt: skill_prompt + prior scratchpad contents
        parts = [skill_prompt]
        if scratchpad_path.exists():
            prior = scratchpad_path.read_text()
            if prior.strip():
                parts.append(f"\n## Prior Findings (from scratchpad)\n\n{prior}")

        wave_prompt = "\n".join(parts)

        await _run_tracked_agent(
            name=name,
            prompt=wave_prompt,
            system_prompt=system_prompt,
            cwd=cwd,
            allowed_tools=SKILL_TOOLS,
            mcp_setup=mcp_setup,
            max_turns=turns_per_wave,
            model=model,
            on_tool=_counting_on_tool,
            on_text=on_text,
            on_todos=on_todos,
        )

        # Between waves: compact scratchpad if it's large
        if wave < waves - 1 and scratchpad_path.exists():
            content = scratchpad_path.read_text()
            if len(content) > 2000:
                compact_mcp = McpSetup(mcp_config={})
                compacted, _ = await _run_tracked_agent(
                    name=f"{name}-compact",
                    prompt=(
                        "Compress the following security investigation notes into a "
                        "concise summary. Preserve ALL findings: file paths, line "
                        "numbers, severity, what was found. Drop verbose descriptions "
                        "and filler. Output only the compressed notes.\n\n"
                        f"{content}"
                    ),
                    system_prompt="You are a concise technical summarizer. Output only the compressed notes.",
                    cwd=cwd,
                    allowed_tools=[],
                    mcp_setup=compact_mcp,
                    max_turns=1,
                    model="sonnet",
                )
                if compacted.strip():
                    scratchpad_path.write_text(compacted)

    # Synthesis: read scratchpad, produce final findings
    scratchpad_content = ""
    if scratchpad_path.exists():
        scratchpad_content = scratchpad_path.read_text().strip()

    if not scratchpad_content:
        return "No findings recorded.", total_tool_calls

    compact_mcp = McpSetup(mcp_config={})
    synthesis, _ = await _run_tracked_agent(
        name=f"{name}-synthesis",
        prompt=scratchpad_content,
        system_prompt=SKILL_SYNTHESIS_PROMPT,
        cwd=cwd,
        allowed_tools=[],
        mcp_setup=compact_mcp,
        max_turns=1,
        model="sonnet",
    )

    return synthesis or "No findings recorded.", total_tool_calls


async def _run_report_stream(
    *,
    prompt: str,
    system_prompt: str,
    mcp_setup: McpSetup,
    model: str = "opus",
    is_tty: bool = True,
) -> None:
    """Stream the final report to stdout. No tools, single turn."""
    full_system = _inject_prefetched_context(
        system_prompt, mcp_setup.org_context, mcp_setup.security_policy,
    )

    options = ClaudeAgentOptions(
        allowed_tools=list(mcp_setup.mcp_tools),
        system_prompt=full_system,
        mcp_servers=mcp_setup.mcp_config,
        permission_mode="acceptEdits",
        max_turns=1,
        model=model,
        env=_get_agent_env(),
        stderr=lambda _: None,
    )

    # Show a spinner with elapsed timer while waiting for first text
    spinner: _Spinner | None = None
    thinking_since = _time.monotonic()

    if is_tty:
        spinner = _Spinner()
        spinner.update(f"{_DIM}Thinking…{_RESET}")
        spinner.start()

    async def _update_thinking() -> None:
        """Tick the spinner with elapsed time."""
        try:
            while True:
                await asyncio.sleep(1)
                elapsed = int(_time.monotonic() - thinking_since)
                mins, secs = divmod(elapsed, 60)
                time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
                if spinner:
                    spinner.update(f"{_DIM}Thinking… ({time_str}){_RESET}")
        except asyncio.CancelledError:
            pass

    tick_task = asyncio.create_task(_update_thinking()) if is_tty else None
    first_text = True

    try:
        async for message in query(prompt=prompt, options=options):
            if message is None:
                continue
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock) and block.text.strip():
                        if first_text and spinner:
                            spinner.stop()
                            spinner.clear()
                            if tick_task:
                                tick_task.cancel()
                            first_text = False
                        print(block.text, flush=True)
    finally:
        if tick_task:
            tick_task.cancel()
        if spinner:
            spinner.stop()


_DEBOUNCE_MS = 50


class _ScanDisplay:
    """Live scan display with per-agent status lines.

    Thread-safe: uses a lock for concurrent updates from 8 agents.
    """

    # States: pending='○', running='◆', completed='✓'

    def __init__(self, skill_names: list[str]) -> None:
        self._skill_names = list(skill_names)
        self._phase = 0  # 0=init, 1=recon, 2=investigations, 3=report, 4=done
        self._agent_status: dict[str, str] = {n: "pending" for n in skill_names}
        self._agent_tool: dict[str, str] = {}  # name -> "ToolName(summary)"
        self._agent_subtool: dict[str, str] = {}  # name -> sub-agent's current tool
        self._agent_subname: dict[str, str] = {}  # name -> sub-agent type (e.g. "explore")
        self._recon_tool_info: str = ""  # current tool during recon
        self._recon_thinking_since: float = 0.0  # monotonic time when recon started thinking
        self._recon_todos: list[dict] = []  # recon's TodoWrite plan
        self._agent_thinking_since: dict[str, float] = {}  # name -> monotonic time
        self._agent_subagent_since: dict[str, float] = {}  # name -> when sub-agent started
        self._agent_todos: dict[str, list[dict]] = {}
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
            self._agent_status[name] = "running"
            self._debounced_render()

    def agent_tool(self, name: str, tool_name: str, summary: str, is_subagent: bool = False) -> None:
        with self._lock:
            self._agent_status[name] = "running"
            if is_subagent:
                # Sub-agent tool — show below parent line
                if tool_name:
                    self._agent_subtool[name] = f"{tool_name}({summary})"
                else:
                    self._agent_subtool[name] = "Thinking…"
                    self._agent_thinking_since[name] = _time.monotonic()
                if name not in self._agent_subagent_since:
                    self._agent_subagent_since[name] = _time.monotonic()
            else:
                # Parent tool — update main line, clear sub-agent state
                if tool_name == "Task":
                    # Spawning a sub-agent — keep sub state, record type
                    self._agent_subname[name] = "explore"
                else:
                    self._agent_subtool.pop(name, None)
                    self._agent_subname.pop(name, None)
                    self._agent_subagent_since.pop(name, None)
                if tool_name:
                    self._agent_tool[name] = f"{tool_name}({summary})"
                    self._agent_thinking_since.pop(name, None)
                else:
                    self._agent_tool[name] = "Thinking…"
                    self._agent_thinking_since[name] = _time.monotonic()
            self._debounced_render()

    def agent_todos(self, name: str, todos: list[dict]) -> None:
        """Update the todo checklist for an agent."""
        with self._lock:
            self._agent_todos[name] = todos
            self._debounced_render()

    def agent_completed(self, name: str) -> None:
        with self._lock:
            self._agent_status[name] = "completed"
            self._agent_tool.pop(name, None)
            self._agent_subtool.pop(name, None)
            self._agent_subname.pop(name, None)
            self._agent_thinking_since.pop(name, None)
            self._agent_subagent_since.pop(name, None)
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

    def _build_lines(self) -> list[str]:
        lines: list[str] = []

        # Phase 1: Reconnaissance
        if self._phase == 1:
            if self._recon_tool_info:
                info = self._recon_tool_info
                if self._recon_thinking_since:
                    elapsed = int(_time.monotonic() - self._recon_thinking_since)
                    mins, secs = divmod(elapsed, 60)
                    time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
                    info = f"{info} ({time_str})"
                width = _get_terminal_width()
                info = _truncate(info, width - 22)
                lines.append(
                    f"  {_CYAN}◆{_RESET} Reconnaissance"
                    f"  {_DIM}{info}{_RESET}"
                )
            else:
                lines.append(f"  {_CYAN}◆{_RESET} Reconnaissance")
            # Recon plan checklist
            if self._recon_todos:
                width = _get_terminal_width()
                for todo in self._recon_todos:
                    s = todo.get("status", "pending")
                    sym = f"{_GREEN}✓{_RESET}" if s == "completed" else (f"{_CYAN}◆{_RESET}" if s == "in_progress" else f"{_DIM}○{_RESET}")
                    content = _truncate(todo.get("content", ""), width - 10)
                    lines.append(f"      {sym} {_DIM}{content}{_RESET}")
        else:
            lines.append(f"  {_GREEN}✓{_RESET} {_DIM}Reconnaissance{_RESET}")

        lines.append("")

        # Phase 2: Investigations
        if self._phase < 2:
            lines.append(f"  {_DIM}○ Investigations{_RESET}")
        elif self._phase == 2:
            done = sum(1 for s in self._agent_status.values() if s == "completed")
            total = len(self._skill_names)
            elapsed = _time.monotonic() - self._investigations_start
            mins, secs = divmod(int(elapsed), 60)
            time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
            lines.append(
                f"  {_CYAN}◆{_RESET} Investigations"
                f"  {_DIM}({done}/{total} · {time_str}){_RESET}"
            )
        else:
            lines.append(f"  {_GREEN}✓{_RESET} {_DIM}Investigations{_RESET}")

        # Per-agent status lines (during phase 2+)
        if self._phase >= 2:
            width = _get_terminal_width()
            for name in self._skill_names:
                status = self._agent_status.get(name, "pending")
                if status == "completed":
                    lines.append(
                        f"    {_GREEN}✓{_RESET} {_DIM}{name}{_RESET}"
                    )
                elif status == "running":
                    tool_info = self._agent_tool.get(name, "")
                    if tool_info:
                        thinking_since = self._agent_thinking_since.get(name)
                        # Only show thinking timer on parent line if no sub-agent
                        if thinking_since and name not in self._agent_subagent_since:
                            elapsed = int(_time.monotonic() - thinking_since)
                            mins, secs = divmod(elapsed, 60)
                            time_str = f"{mins}m {secs:02d}s" if mins else f"{secs}s"
                            tool_info = f"{tool_info} ({time_str})"
                        tool_info = _truncate(tool_info, width - len(name) - 10)
                        lines.append(
                            f"    {_CYAN}◆{_RESET} {name}"
                            f"  {_DIM}{tool_info}{_RESET}"
                        )
                    else:
                        lines.append(f"    {_CYAN}◆{_RESET} {name}")
                    # Sub-agent child line
                    subtool = self._agent_subtool.get(name, "")
                    if subtool:
                        subname = self._agent_subname.get(name, "")
                        sub_since = self._agent_subagent_since.get(name)
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
                    # Todo items (capped to _MAX_TODO_LINES)
                    todos = self._agent_todos.get(name, [])
                    if todos:
                        shown = 0
                        for todo in todos:
                            if shown >= _MAX_TODO_LINES:
                                remaining = len(todos) - shown
                                lines.append(f"        {_DIM}… +{remaining} more{_RESET}")
                                break
                            s = todo.get("status", "pending")
                            sym = f"{_GREEN}✓{_RESET}" if s == "completed" else (f"{_CYAN}◆{_RESET}" if s == "in_progress" else f"{_DIM}○{_RESET}")
                            content = _truncate(todo.get("content", ""), width - 12)
                            lines.append(f"        {sym} {_DIM}{content}{_RESET}")
                            shown += 1
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
        self._clear_lines()
        lines = self._build_lines()
        for line in lines:
            print(line, file=sys.stderr, flush=True)
        self._lines_on_screen = len(lines)
        self._last_render = _time.monotonic() * 1000
