"""Shared agent runner for local security review agents.

CLAUDECODE="" prevents claude-agent-sdk from detecting a nested Claude Code
session and rejecting the spawn. This is intentional — the review agent is
a separate subprocess, not a nested invocation of the caller's session.
"""

import asyncio
import contextlib
from dataclasses import dataclass, field
import json
import os
from pathlib import Path
import re
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

from hiro_agent.scope_gating import (
    IGNORED_DIRS,
    build_seed_scope,
    evaluate_expansion_requests,
    format_expansion_feedback,
    get_skill_gate_policy,
    list_first_party_files,
    normalize_tool_read_path,
    parse_expand_requests,
    render_scope_gate_block,
    resolve_wave_modes,
)

logger = structlog.get_logger(__name__)

# Hardcoded — not configurable to prevent SSRF. HTTPS enforced.
HIRO_MCP_URL = "https://api.hiro.is/mcp/architect/mcp"
HIRO_NOTIFICATIONS_MCP_URL = "https://api.hiro.is/mcp/notifications/mcp"
HIRO_BACKEND_URL = "https://api.hiro.is"

_EXPLORE_AGENT = AgentDefinition(
    description="Read-only code retriever. Returns raw code — never analyzes or evaluates.",
    prompt=(
        "You are a code retriever. Your ONLY job is to fetch code and return it verbatim.\n\n"
        "## Rules\n\n"
        "1. Return RAW CODE with file paths and line numbers. Copy-paste exactly what you see.\n"
        "2. NEVER analyze, interpret, or evaluate code. No opinions. No conclusions.\n"
        "3. NEVER say things like 'this is a vulnerability' or 'this is insecure'.\n"
        "4. NEVER fabricate content. If a file doesn't contain what was asked about, "
        "say 'NOT FOUND: [pattern] not present in [file]'.\n"
        "5. NEVER invent commit hashes, line numbers, or code that isn't there.\n"
        "6. If Grep returns no matches, say 'NO MATCHES' — do not guess.\n\n"
        "## Output format\n\n"
        "For each file you read, return:\n"
        "```\n"
        "FILE: path/to/file.py (lines X-Y)\n"
        "[exact code from the file]\n"
        "```\n\n"
        "For each Grep search, return:\n"
        "```\n"
        "GREP: pattern in glob\n"
        "[exact matching lines with file:line prefixes, or NO MATCHES]\n"
        "```\n\n"
        "## File reading limits\n\n"
        "NEVER read more than 500 lines at once. ALWAYS pass `limit: 500` to Read. "
        "If you need more, make multiple reads with `offset`.\n\n"
        "## Prefer Grep over Read\n\n"
        "Use Grep to find specific patterns BEFORE reading files. "
        "Only Read the specific sections that matched."
    ),
    tools=["Read", "Grep"],
    model="sonnet",
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
            texts = [c.get("text", "")
                     for c in content if c.get("type") == "text"]
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


async def _prefetch_review_context(api_key: str, diff: str) -> str | None:
    """Fetch infrastructure-aware review context for a diff via MCP.

    Calls get_review_context on the backend which parses the diff for
    infrastructure signals, queries memories, and makes live API calls
    to connected integrations. Uses a 30s timeout to allow live queries.

    Returns the context string or None on failure.
    """
    return await asyncio.to_thread(
        _mcp_call_tool, api_key, "get_review_context", {"diff": diff}, timeout=30,
    )


@dataclass
class McpSetup:
    """Result of MCP preflight + prefetch. Shared across agents."""
    mcp_config: dict
    mcp_tools: list[str] = field(default_factory=list)
    org_context: str | None = None
    security_policy: str | None = None
    review_context: str | None = None


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


def _inject_prefetched_context(
    system_prompt: str,
    org_context: str | None,
    security_policy: str | None,
    review_context: str | None = None,
) -> str:
    """Prepend pre-fetched MCP context sections to the system prompt.

    Returns the prompt unchanged if all values are None.
    """
    sections: list[str] = []
    if org_context:
        sections.append(
            f"## Organizational Context (pre-loaded)\n\n{org_context}")
    if security_policy:
        sections.append(
            f"## Security Policy (pre-loaded)\n\n{security_policy}")
    if review_context:
        sections.append(
            f"## Infrastructure Context (pre-loaded)\n\n{review_context}")
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


def _install_cancel_scope_handler() -> None:
    """Suppress anyio cancel-scope RuntimeError from SDK async-generator finalization.

    When the SDK's ``process_query`` async generator is finalized (e.g. on
    Ctrl-C or GC), anyio may try to exit a cancel scope from a different
    asyncio task than the one that entered it.  The resulting RuntimeError
    surfaces as "Task exception was never retrieved".  Installing a custom
    event-loop exception handler silences this specific (harmless) error.
    """
    loop = asyncio.get_running_loop()
    _orig_handler = loop.get_exception_handler()

    def _handler(loop: asyncio.AbstractEventLoop, context: dict) -> None:
        exc = context.get("exception")
        if isinstance(exc, RuntimeError):
            msg = str(exc)
            if "cancel scope" in msg and "different task" in msg:
                logger.debug("suppressed_cancel_scope_error", error=msg)
                return
        if _orig_handler is not None:
            _orig_handler(loop, context)
        else:
            loop.default_exception_handler(context)

    loop.set_exception_handler(_handler)


async def _safe_close_query_stream(stream: object, *, context: str) -> None:
    """Best-effort close for SDK query streams.

    Explicit close avoids async-generator finalizer shutdown on a different task,
    which can surface AnyIO cancel-scope RuntimeError on some SDK/runtime combos.
    """
    aclose = getattr(stream, "aclose", None)
    if not callable(aclose):
        return
    try:
        await aclose()
    except RuntimeError as exc:
        msg = str(exc)
        if ("cancel scope" in msg and "different task" in msg) or "already running" in msg:
            logger.warning(
                "query_stream_close_suppressed",
                context=context,
                error=msg,
            )
            return
        raise
    except Exception as exc:
        logger.warning(
            "query_stream_close_suppressed",
            context=context,
            error=str(exc),
        )


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
    access via Read/Grep tools.

    Only read-only MCP tools are allowed — remember, set_org_context, and
    forget are explicitly excluded to prevent the review agent from
    modifying organizational state.

    When ``mcp_setup`` is provided, skip internal MCP setup and use the
    pre-computed values. When None (default), call internal MCP setup
    for backward compatibility.
    """
    _install_cancel_scope_handler()

    if mcp_setup is not None:
        mcp_config = mcp_setup.mcp_config
        mcp_tools = list(mcp_setup.mcp_tools)
        system_prompt = _inject_prefetched_context(
            system_prompt, mcp_setup.org_context, mcp_setup.security_policy,
            mcp_setup.review_context,
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
                system_prompt = _inject_prefetched_context(
                    system_prompt, org_ctx, sec_pol)
                mcp_tools = ["mcp__hiro__recall"]

    tools_list = (allowed_tools or []) + mcp_tools
    options = ClaudeAgentOptions(
        cwd=cwd,
        tools=tools_list,
        allowed_tools=tools_list,
        system_prompt=system_prompt,
        mcp_servers=mcp_config,
        permission_mode="acceptEdits",
        max_turns=max_turns,
        model=model,
        effort="high",
        env=_get_agent_env(),
        stderr=lambda line: logger.debug("cli_stderr", agent="review", line=line.rstrip()),
    )

    summary = ""
    stream = query(prompt=prompt, options=options)
    try:
        async for message in stream:
            if message is None:
                continue
            if isinstance(message, AssistantMessage):
                for block in message.content:
                    if isinstance(block, TextBlock):
                        summary = block.text
    finally:
        await _safe_close_query_stream(stream, context="run_review_agent")

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
            lines.append(
                f"  {_GREEN}✓{_RESET} {_DIM}Deep-dive investigations{_RESET}")

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
    output_file: str | None = None,
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
    _install_cancel_scope_handler()

    is_tty = sys.stderr.isatty()

    if mcp_setup is not None:
        mcp_config = mcp_setup.mcp_config
        mcp_tools = list(mcp_setup.mcp_tools)
        system_prompt = _inject_prefetched_context(
            system_prompt, mcp_setup.org_context, mcp_setup.security_policy,
            mcp_setup.review_context,
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
                system_prompt = _inject_prefetched_context(
                    system_prompt, org_ctx, sec_pol)
                mcp_tools = ["mcp__hiro__recall"]

    cli_errors: list[str] = []

    def _capture_stderr(line: str) -> None:
        if '"level":"error"' in line or "Error:" in line:
            cli_errors.append(line)

    tools_list = (allowed_tools or []) + mcp_tools
    options = ClaudeAgentOptions(
        cwd=cwd,
        tools=tools_list,
        allowed_tools=tools_list,
        system_prompt=system_prompt,
        mcp_servers=mcp_config,
        permission_mode="acceptEdits",
        max_turns=max_turns,
        model=model,
        effort="medium",
        env=_get_agent_env(),
        stderr=_capture_stderr,
    )

    if is_tty:
        await _run_streaming_tty(options, prompt, allowed_tools, cli_errors, output_file=output_file)
    else:
        await _run_streaming_plain(options, prompt, output_file=output_file)


async def _run_streaming_plain(
    options: ClaudeAgentOptions,
    prompt: str,
    output_file: str | None = None,
) -> None:
    """Non-TTY streaming: plain text, no ANSI, no spinner."""
    last_text = ""

    stream = query(prompt=prompt, options=options)
    try:
        async for message in stream:
            if message is None:
                continue

            if isinstance(message, UserMessage):
                blocks = message.content if isinstance(
                    message.content, list) else []
                for b in blocks:
                    if isinstance(b, ToolResultBlock) and b.is_error:
                        err_text = b.content if isinstance(
                            b.content, str) else str(b.content)
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
    finally:
        await _safe_close_query_stream(stream, context="run_streaming_plain")

    if last_text:
        if output_file:
            Path(output_file).write_text(last_text)
        else:
            print(last_text, flush=True)


async def _run_streaming_tty(
    options: ClaudeAgentOptions,
    prompt: str,
    allowed_tools: list[str] | None,
    cli_errors: list[str],
    output_file: str | None = None,
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

    stream = query(prompt=prompt, options=options)
    try:
        async for message in stream:
            if message is None:
                continue

            # Show tool errors from UserMessage results
            if isinstance(message, UserMessage):
                blocks = message.content if isinstance(
                    message.content, list) else []
                for b in blocks:
                    if isinstance(b, ToolResultBlock) and b.is_error:
                        err_text = b.content if isinstance(
                            b.content, str) else str(b.content)
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
                _freeze_tool(spinner, current_tool_line,
                             repeat_tool, repeat_count)
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
                    _freeze_tool(spinner, current_tool_line,
                                 repeat_tool, repeat_count)
                    current_tool_line = ""
                    repeat_tool = ""
                    repeat_count = 0

                    # Track active tasks by tool_use_id
                    task_plan: list[tuple[str, str]] = []
                    for b in task_blocks:
                        active_task_ids.add(b.id)
                        inp = b.input if isinstance(b.input, dict) else {}
                        desc = inp.get(
                            "description", inp.get("prompt", ""))[:60]
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
                        inp = block.input if isinstance(
                            block.input, dict) else {}
                        summary = _tool_summary(name, inp)
                        groups.setdefault(name, []).append(summary)

                    group_lines = []
                    for name, summaries in groups.items():
                        line = _format_tool_group(name, summaries)
                        group_lines.append((name, summaries, line))

                    # Print all groups except the last
                    for name, summaries, line in group_lines[:-1]:
                        _freeze_tool(spinner, current_tool_line,
                                     repeat_tool, repeat_count)
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
                        _freeze_tool(spinner, current_tool_line,
                                     repeat_tool, repeat_count)
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
            if output_file:
                Path(output_file).write_text(last_text)
            else:
                print(last_text, flush=True)

        if cli_errors:
            print(f"\n{_DIM}---{_RESET}", file=sys.stderr, flush=True)
            for err in cli_errors:
                print(f"{_DIM}{err}{_RESET}", file=sys.stderr, flush=True)
    finally:
        spinner.stop()
        await _safe_close_query_stream(stream, context="run_streaming_tty")


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
        pattern = inp.get("pattern", "")
        glob = inp.get("glob", "")
        # When pattern is trivial (e.g. "."), show the glob filter instead
        if glob and len(pattern) <= 2:
            raw = glob
        else:
            raw = pattern
    elif name == "Task":
        raw = inp.get("description", inp.get("prompt", ""))[:60]
    elif name == "TodoWrite":
        todos = inp.get("todos", [])
        raw = f"{len(todos)} items"
    elif name == "TodoRead":
        raw = "checking progress"
    else:
        raw = next((v for v in inp.values()
                   if isinstance(v, str) and v), "")[:60]

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
    effort: str | None = None,
    on_tool: Callable[[str, str, str, bool], None] | None = None,
    on_tool_event: Callable[[str, str, dict, bool], None] | None = None,
    on_result: Callable[[ResultMessage], None] | None = None,
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
    _install_cancel_scope_handler()

    full_system = _inject_prefetched_context(
        system_prompt, mcp_setup.org_context, mcp_setup.security_policy,
        mcp_setup.review_context,
    )

    parent_tools = allowed_tools + list(mcp_setup.mcp_tools)
    # Auto-approve sub-agent tools (Read/Grep) so explore agents
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
        effort=effort,
        agents={"explore": _EXPLORE_AGENT},
        env=_get_agent_env(),
        stderr=lambda line: logger.debug("cli_stderr", agent=name, line=line.rstrip()),
    )

    run_started_at = _time.monotonic()
    logger.info(
        "agent_run_started",
        agent=name,
        model=model,
        max_turns=max_turns,
        effort=effort or "",
        prompt_chars=len(prompt),
        system_prompt_chars=len(full_system),
        parent_tools=len(parent_tools),
        allowed_tools=len(parent_tools + subagent_tools),
    )

    summary = ""
    all_text_blocks: list[str] = []  # Accumulate all primary agent text
    session_id = ""
    active_task_ids: set[str] = set()  # Track Task sub-agent tool_use_ids
    tool_start_times: dict[str, float] = {}
    tool_meta: dict[str, tuple[str, bool, str]] = {}
    callback_error: BaseException | None = None
    first_message_s: float | None = None
    messages_seen = 0
    assistant_messages = 0
    user_messages = 0
    result_messages = 0
    tool_started_count = 0
    tool_finished_count = 0
    tool_error_count = 0
    # Timeout: break the loop if no messages arrive for this many seconds.
    # Cannot use asyncio.wait_for — cancelling __anext__() triggers AnyIO
    # cancel scope errors inside the SDK. Instead, we wrap __anext__() in
    # asyncio.wait with a timeout, then cancel the orphaned task on stall.
    # A watchdog also watches for the primary-agent-silent case (sub-agent
    # chatting but primary stuck) and sets a flag checked after each message.
    _default_stall_timeout = 120.0 if model == "sonnet" else 300.0
    try:
        stall_timeout = float(os.environ.get("HIRO_AGENT_STALL_TIMEOUT", str(_default_stall_timeout)))
    except ValueError:
        stall_timeout = _default_stall_timeout
    try:
        idle_log_interval = float(os.environ.get("HIRO_AGENT_IDLE_LOG_INTERVAL", "30"))
    except ValueError:
        idle_log_interval = 30.0
    idle_log_interval = max(5.0, idle_log_interval)
    next_idle_log_at = idle_log_interval
    last_message_at = _time.monotonic()
    last_primary_message_at = _time.monotonic()
    stall_timed_out = False

    def _capture_callback_error(exc: BaseException) -> None:
        nonlocal callback_error
        if callback_error is None:
            callback_error = exc

    stream = query(prompt=prompt, options=options)

    async def _stall_watchdog() -> None:
        nonlocal stall_timed_out, next_idle_log_at
        while True:
            await asyncio.sleep(10)
            # Use primary agent activity — sub-agent messages should not
            # reset the stall timer, as the primary agent may be genuinely
            # stuck while sub-agents chatter.
            elapsed = _time.monotonic() - last_primary_message_at
            if elapsed >= next_idle_log_at:
                logger.info(
                    "agent_waiting_for_messages",
                    agent=name,
                    idle_s=round(elapsed, 1),
                    timeout_s=stall_timeout,
                )
                next_idle_log_at += idle_log_interval
            if elapsed >= stall_timeout:
                stall_timed_out = True
                logger.error(
                    "agent_stall_timeout",
                    agent=name,
                    timeout_s=stall_timeout,
                    elapsed_s=round(elapsed, 1),
                )
                # Don't try to close the stream — aclose() from a different
                # task triggers "cancel scope in a different task" RuntimeError
                # and fails silently. The main loop checks stall_timed_out
                # after each message and breaks.
                return

    watchdog = asyncio.create_task(_stall_watchdog())
    run_error: BaseException | None = None
    try:
        while True:
            # Wrap __anext__() in asyncio.wait so we can enforce a hard
            # per-message timeout without cancelling the stream's scope.
            _next = asyncio.ensure_future(stream.__anext__())
            done, _ = await asyncio.wait({_next}, timeout=stall_timeout)
            if not done:
                # Hard per-message timeout fired.
                stall_timed_out = True
                logger.error(
                    "agent_stall_timeout",
                    agent=name,
                    timeout_s=stall_timeout,
                    elapsed_s=round(_time.monotonic() - last_primary_message_at, 1),
                )
                _next.cancel()
                with contextlib.suppress(asyncio.CancelledError, RuntimeError, StopAsyncIteration):
                    await _next
                break
            # asyncio.wait returned — get the result (may be StopAsyncIteration).
            try:
                message = _next.result()
            except StopAsyncIteration:
                break
            except RuntimeError as exc:
                # AnyIO cancel-scope cleanup can raise when the SDK generator
                # exits naturally inside the ensure_future task (different task
                # than the one that entered the scope). Treat as stream end.
                if "cancel scope" in str(exc) and "different task" in str(exc):
                    logger.debug("stream_cancel_scope_on_exit", agent=name, error=str(exc))
                    break
                raise

            # Check watchdog flag (primary-agent-silent while sub-agents chatter).
            if stall_timed_out:
                break

            now = _time.monotonic()
            last_message_at = now
            messages_seen += 1
            # Reset primary timer for non-sub-agent messages only.
            # Sub-agent chatter should not mask a stalled primary agent.
            if not active_task_ids:
                last_primary_message_at = now
            if first_message_s is None:
                first_message_s = now - run_started_at
                logger.info(
                    "agent_first_message",
                    agent=name,
                    first_message_s=round(first_message_s, 1),
                )
            if message is None:
                continue
            if isinstance(message, UserMessage):
                user_messages += 1
                # Check for Task sub-agent results completing
                blocks = message.content if isinstance(
                    message.content, list) else []
                for b in blocks:
                    if isinstance(b, ToolResultBlock) and b.tool_use_id in active_task_ids:
                        active_task_ids.discard(b.tool_use_id)
                    if isinstance(b, ToolResultBlock):
                        tool_finished_count += 1
                        tool_use_id = str(getattr(b, "tool_use_id", "") or "")
                        started_at = tool_start_times.pop(tool_use_id, None)
                        tool_name, tool_is_subagent, tool_summary = tool_meta.pop(
                            tool_use_id,
                            ("unknown", bool(active_task_ids), ""),
                        )
                        is_error = bool(getattr(b, "is_error", False))
                        if is_error:
                            tool_error_count += 1
                        logger.info(
                            "agent_tool_finished",
                            agent=name,
                            tool=tool_name,
                            tool_use_id=tool_use_id,
                            is_subagent=tool_is_subagent,
                            status="error" if is_error else "ok",
                            duration_s=(
                                round(now - started_at, 3)
                                if started_at is not None
                                else None
                            ),
                            elapsed_s=round(now - run_started_at, 1),
                            summary=tool_summary,
                        )
                if on_tool is not None:
                    try:
                        on_tool(name, "", "", bool(active_task_ids))
                    except BaseException as exc:
                        _capture_callback_error(exc)
                        break
            elif isinstance(message, AssistantMessage):
                assistant_messages += 1
                # If active Task IDs exist, this message is from a sub-agent
                is_subagent = bool(active_task_ids)
                for block in message.content:
                    if isinstance(block, TextBlock):
                        summary = block.text
                        if not is_subagent and block.text.strip():
                            all_text_blocks.append(block.text)
                        if on_text is not None and block.text.strip():
                            try:
                                on_text(block.text)
                            except BaseException as exc:
                                _capture_callback_error(exc)
                                break
                    elif isinstance(block, ToolUseBlock):
                        if block.name == "Task":
                            active_task_ids.add(block.id)
                        inp = block.input if isinstance(block.input, dict) else {}
                        tool_summary = _tool_summary(block.name, inp)
                        tool_started_count += 1
                        tool_start_times[block.id] = now
                        tool_meta[block.id] = (block.name, is_subagent, tool_summary)
                        logger.info(
                            "agent_tool_started",
                            agent=name,
                            tool=block.name,
                            tool_use_id=block.id,
                            is_subagent=is_subagent,
                            summary=tool_summary,
                            elapsed_s=round(now - run_started_at, 1),
                        )
                        if on_tool_event is not None:
                            try:
                                on_tool_event(name, block.name, inp, is_subagent)
                            except BaseException as exc:
                                _capture_callback_error(exc)
                                break
                        if block.name == "TodoWrite" and on_todos is not None:
                            todos = inp.get("todos", [])
                            if todos:
                                try:
                                    on_todos(name, todos)
                                except BaseException as exc:
                                    _capture_callback_error(exc)
                                    break
                        if on_tool is not None:
                            try:
                                on_tool(name, block.name, tool_summary, is_subagent)
                            except BaseException as exc:
                                _capture_callback_error(exc)
                                break
                if callback_error is not None:
                    break
            elif isinstance(message, ResultMessage):
                result_messages += 1
                session_id = message.session_id
                logger.info(
                    "agent_result_received",
                    agent=name,
                    subtype=str(message.subtype or ""),
                    num_turns=message.num_turns,
                    is_error=message.is_error,
                    duration_ms=message.duration_ms,
                    elapsed_s=round(now - run_started_at, 1),
                )
                if on_result is not None:
                    try:
                        on_result(message)
                    except BaseException as exc:
                        _capture_callback_error(exc)
                        break
    except BaseException as exc:
        run_error = exc
        raise
    finally:
        watchdog.cancel()
        try:
            await watchdog
        except (asyncio.CancelledError, RuntimeError):
            pass
        await _safe_close_query_stream(stream, context=f"run_tracked_agent:{name}")
        logger.info(
            "agent_run_finished",
            agent=name,
            total_s=round(_time.monotonic() - run_started_at, 1),
            first_message_s=round(first_message_s, 1) if first_message_s is not None else None,
            messages_seen=messages_seen,
            assistant_messages=assistant_messages,
            user_messages=user_messages,
            result_messages=result_messages,
            tool_started=tool_started_count,
            tool_finished=tool_finished_count,
            tool_errors=tool_error_count,
            tools_inflight=len(tool_start_times),
            active_tasks=len(active_task_ids),
            stall_timed_out=stall_timed_out,
            callback_error=callback_error is not None,
            error_type=(
                type(run_error).__name__
                if run_error is not None
                else (type(callback_error).__name__ if callback_error is not None else "")
            ),
        )

    if stall_timed_out:
        raise TimeoutError(f"Agent '{name}' stalled for {stall_timeout}s with no messages")

    if callback_error is not None:
        raise callback_error

    # Return all accumulated text from the primary agent, joined.
    # Falls back to last TextBlock if nothing was accumulated.
    full_output = "\n\n".join(all_text_blocks) if all_text_blocks else summary
    return full_output, session_id


def _find_ignored_segment(value: str) -> str | None:
    """Return the ignored path segment if present in a path/pattern string."""
    raw = value.strip().strip("`\"'")
    if not raw:
        return None
    cleaned = raw.replace("\\", "/")
    for part in re.split(r"/+", cleaned):
        part = part.strip()
        if not part or part in {"*", "**", ".", ".."}:
            continue
        if part in IGNORED_DIRS:
            return part
    return None


def get_tool_policy_violation(
    *,
    tool_name: str,
    tool_input: dict,
    forbid_structure_discovery: bool = False,
) -> tuple[str, str] | None:
    """Return (path_or_pattern, reason) when a tool call violates file-scope policy."""
    if tool_name == "Read":
        file_path = str(tool_input.get("file_path", "")).strip()
        ignored = _find_ignored_segment(file_path)
        if ignored:
            return file_path, f"read into ignored directory `{ignored}` is blocked"
        return None

    if tool_name not in {"Grep", "Glob"}:
        return None

    path_value = str(tool_input.get("path", "")).strip()
    pattern_value = str(tool_input.get("pattern", "")).strip()

    for candidate in (path_value, pattern_value):
        ignored = _find_ignored_segment(candidate)
        if ignored:
            return candidate, f"{tool_name} into ignored directory `{ignored}` is blocked"

    if forbid_structure_discovery and tool_name == "Glob":
        broad_patterns = {
            "**/*.py",
            "**/*.ts",
            "**/*.js",
            "**/*.go",
            "**/*.java",
            "**/*.rb",
            "**/*.php",
            "**/*.cs",
            "**/*.swift",
            "**/*.kt",
        }
        if pattern_value in broad_patterns:
            return pattern_value, "repository-wide structure discovery is blocked; use shared index"

    if tool_name == "Glob" and pattern_value.strip() == "**/*":
        return pattern_value, "greedy Glob(\"**/*\") is blocked"

    return None


class ToolPolicyViolationError(RuntimeError):
    """Raised when a tool call violates first-party file-scope policy."""

    def __init__(self, path: str, reason: str, *, tool_name: str = "") -> None:
        super().__init__(path)
        self.path = path
        self.reason = reason
        self.tool_name = tool_name


class _ScopeViolationError(ToolPolicyViolationError):
    """Raised when a sub-agent read escapes the current allowed scope."""


_NON_INVESTIGATION_TODO_MARKERS: tuple[str, ...] = (
    "scratchpad",
    "todo",
    "checklist",
    "write findings",
    "save findings",
    "record findings",
    "final write",
    "update findings",
    "summarize findings",
    "summarize notes",
)


def _is_investigation_todo(todo: dict) -> bool:
    """Return True when a todo item describes investigation work."""
    content = str(todo.get("content", "")).strip().lower()
    if not content:
        return False
    return not any(marker in content for marker in _NON_INVESTIGATION_TODO_MARKERS)


def _filter_investigation_todos(todos: list[dict]) -> list[dict]:
    """Drop housekeeping/plumbing todos and keep investigation-focused items."""
    return [todo for todo in todos if isinstance(todo, dict) and _is_investigation_todo(todo)]


_TURN_LIMIT_MARKERS: tuple[str, ...] = (
    "max_turns",
    "max turns",
    "turn limit",
    "turn_limit",
    "turns exhausted",
)


def _is_true_turn_limit(result: ResultMessage, *, max_turns: int) -> tuple[bool, str]:
    """Classify whether a ResultMessage indicates true turn-budget truncation.

    We intentionally avoid using ``num_turns >= max_turns`` alone because agents can
    finish successfully exactly at budget without being truncated.
    """
    subtype = str(getattr(result, "subtype", "") or "").strip().lower()
    result_text = str(getattr(result, "result", "") or "").strip().lower()

    if any(marker in subtype for marker in _TURN_LIMIT_MARKERS):
        return True, f"subtype={subtype or 'unknown'}"
    if result_text and any(marker in result_text for marker in _TURN_LIMIT_MARKERS):
        return True, "result_text_hint"
    if result.num_turns > max_turns:
        # Defensive fallback for unexpected SDK counting behavior.
        return True, f"num_turns>{max_turns}"

    return False, "no_turn_limit_signal"


def _read_skill_findings(findings_dir: Path, name: str) -> list[dict]:
    """Read all finding-{name}-*.json files, return parsed dicts."""
    findings = []
    for path in sorted(findings_dir.glob(f"finding-{name}-*.json")):
        try:
            findings.append(json.loads(path.read_text()))
        except (json.JSONDecodeError, OSError):
            continue
    return findings


def _format_prior_findings(findings: list[dict]) -> str:
    """Format prior findings as a brief list for the next wave prompt."""
    if not findings:
        return ""
    lines = ["## Prior Findings (already recorded — do not re-report)"]
    for f in findings:
        lines.append(f"- {f.get('location', '?')} — {f.get('issue', '?')}")
    return "\n".join(lines)


async def _run_skill_waves(
    *,
    name: str,
    system_prompt: str,
    skill_prompt: str,
    findings_dir: Path,
    cwd: str | None,
    mcp_setup: McpSetup,
    waves: int | None = None,
    turns_per_wave: int | None = None,
    model: str = "sonnet",
    effort: str | None = "medium",
    on_tool: Callable[[str, str, str, bool], None] | None = None,
    on_text: Callable[[str], None] | None = None,
    on_todos: Callable[[str, list[dict]], None] | None = None,
    run_stats: dict[str, object] | None = None,
    semaphore: asyncio.Semaphore | None = None,
) -> tuple[str, int]:
    """Run a skill investigation in multiple waves with per-finding JSON files.

    Each wave starts a fresh agent session. Prior findings are injected as
    a brief summary list. After all waves, findings are read directly from
    JSON files — no compaction, no synthesis.

    Returns (formatted_findings, total_tool_calls).
    """

    def _default_waves_for_mode(mode: str) -> int:
        if mode == "trace":
            return 2
        if mode == "breadth":
            return 1
        # hybrid = 1 breadth + N trace
        return 3

    def _turn_budget_for_mode(mode: str, override: int | None) -> int:
        if override is not None:
            return override
        # Sonnet is fast — more turns per wave cost less wall-clock time.
        return 14 if mode == "breadth" else 20

    def _has_pending_untraced_edges() -> bool:
        state_path = findings_dir / f"{name}-state.md"
        if not state_path.exists():
            return False
        for line in state_path.read_text(encoding="utf-8").splitlines():
            if line.strip().startswith("UNTRACED_EDGE|"):
                return True
        return False

    total_tool_calls = 0
    policy = get_skill_gate_policy(name)
    all_first_party_files = list_first_party_files(cwd)
    starter_files = build_seed_scope(
        name,
        cwd=cwd,
        context_text=skill_prompt,
        max_seeds=policy.max_seed_files,
        all_files=all_first_party_files,
    )
    allowed_files = set(starter_files)
    requested_waves = max(1, waves) if waves is not None else _default_waves_for_mode(policy.mode)
    turn_override = max(1, turns_per_wave) if turns_per_wave is not None else None
    effective_waves, wave_modes = resolve_wave_modes(policy, requested_waves)
    if effective_waves != requested_waves:
        logger.info(
            "skill_wave_override",
            skill=name,
            mode=policy.mode,
            requested_waves=requested_waves,
            effective_waves=effective_waves,
        )
    wave_plan = list(wave_modes)
    logger.info(
        "skill_wave_plan",
        skill=name,
        mode=policy.mode,
        requested_waves=requested_waves,
        effective_waves=len(wave_plan),
        wave_modes=list(wave_plan),
        turn_override=turn_override,
        seed_files=len(starter_files),
    )

    used_expansions = 0
    seen_ticket_keys: set[str] = set()
    gate_feedback = ""
    blocked_scope_reads = 0
    breadth_read_files: set[str] = set()
    current_wave_mode = wave_plan[0] if wave_plan else "trace"
    latest_todos: list[dict] = []
    expansion_followups: dict[str, bool] = {}
    turn_limited = False
    turn_limited_waves = 0
    turn_limited_reasons: list[str] = []
    continuation_wave_used = False
    findings_dir_resolved = findings_dir.resolve()
    state_path_resolved = (findings_dir / f"{name}-state.md").resolve()

    def _counting_on_tool(agent_name: str, tool_name: str, summary: str, is_subagent: bool) -> None:
        nonlocal total_tool_calls
        if tool_name:
            total_tool_calls += 1
        if on_tool is not None:
            on_tool(agent_name, tool_name, summary, is_subagent)

    def _combined_todos() -> list[dict]:
        combined = list(latest_todos)
        for idx, path in enumerate(sorted(expansion_followups)):
            combined.append(
                {
                    "id": f"expand:{idx + 1}",
                    "content": f"Follow approved expansion target: {path}",
                    "status": "completed" if expansion_followups[path] else "pending",
                }
            )
        return combined

    def _emit_todos() -> None:
        if on_todos is None:
            return
        todos = _combined_todos()
        if todos:
            on_todos(name, todos)

    def _capturing_todos(agent_name: str, todos: list[dict]) -> None:
        nonlocal latest_todos
        incoming = _filter_investigation_todos(todos)
        # Merge instead of replace so checklist counts don't shrink when the
        # model rewrites TodoWrite with a shorter subset mid-run.
        def _todo_key(todo: dict) -> str:
            content = str(todo.get("content", "")).strip()
            if content:
                return f"content:{content.lower()}"
            todo_id = str(todo.get("id", "")).strip()
            if todo_id:
                return f"id:{todo_id}"
            return f"raw:{json.dumps(todo, sort_keys=True)}"

        status_rank = {"pending": 0, "in_progress": 1, "completed": 2}
        existing_by_key: dict[str, dict] = {}
        ordered_keys: list[str] = []
        for todo in latest_todos:
            if not isinstance(todo, dict):
                continue
            key = _todo_key(todo)
            if key in existing_by_key:
                continue
            existing_by_key[key] = dict(todo)
            ordered_keys.append(key)

        for todo in incoming:
            key = _todo_key(todo)
            prev = existing_by_key.get(key, {})
            merged = dict(prev)
            merged.update(todo)
            prev_status = str(prev.get("status", "pending"))
            new_status = str(todo.get("status", "pending"))
            merged["status"] = (
                prev_status
                if status_rank.get(prev_status, 0) >= status_rank.get(new_status, 0)
                else new_status
            )
            existing_by_key[key] = merged
            if key not in ordered_keys:
                ordered_keys.append(key)

        latest_todos = [existing_by_key[key] for key in ordered_keys if key in existing_by_key]
        _emit_todos()

    def _is_allowed_internal_read(file_path: str) -> bool:
        """Allow only the current skill's scratchpad state/findings reads."""
        raw = str(file_path or "").strip().strip("`\"'")
        if not raw:
            return False

        root = Path(cwd or ".").resolve()
        candidate = Path(raw)
        if not candidate.is_absolute():
            candidate = root / candidate
        try:
            resolved = candidate.resolve(strict=False)
        except OSError:
            return False

        if resolved == state_path_resolved:
            return True
        return (
            resolved.parent == findings_dir_resolved
            and resolved.name.startswith(f"finding-{name}-")
            and resolved.suffix == ".json"
        )

    def _enforce_scope(agent_name: str, tool_name: str, tool_input: dict, is_subagent: bool) -> None:
        if tool_name == "Read":
            file_path = str(tool_input.get("file_path", ""))
            if _is_allowed_internal_read(file_path):
                return

        # Enforce scope on all tool calls (skill agents read directly).
        violation = get_tool_policy_violation(
            tool_name=tool_name,
            tool_input=tool_input,
            forbid_structure_discovery=True,
        )
        if violation is not None:
            blocked_path, reason = violation
            raise _ScopeViolationError(
                blocked_path, reason, tool_name=tool_name)
        if tool_name != "Read":
            return
        file_path = str(tool_input.get("file_path", ""))
        normalized = normalize_tool_read_path(file_path, cwd=cwd)
        if not normalized:
            return
        if normalized in expansion_followups and not expansion_followups[normalized]:
            expansion_followups[normalized] = True
            _emit_todos()
        if current_wave_mode == "breadth":
            breadth_read_files.add(normalized)
            if len(breadth_read_files) > policy.max_breadth_files:
                raise _ScopeViolationError(
                    normalized, "breadth file budget exceeded")
            return
        if allowed_files and normalized not in allowed_files:
            raise _ScopeViolationError(normalized, "blocked out-of-scope read")

    base_system_prompt = system_prompt
    wave = 0
    while wave < len(wave_plan):
        current_wave_mode = wave_plan[wave]
        wave_turn_budget = _turn_budget_for_mode(current_wave_mode, turn_override)
        wave_started_at = _time.monotonic()
        wave_tool_calls_before = total_tool_calls
        wave_status = "completed"
        wave_error: BaseException | None = None
        wave_turn_limited = False
        wave_turn_count = 0
        wave_turn_limit_reason = ""
        wave_result_subtype = ""

        def _on_result(result: ResultMessage) -> None:
            nonlocal wave_turn_limited, wave_turn_count, wave_turn_limit_reason, wave_result_subtype
            wave_turn_count = result.num_turns
            wave_result_subtype = str(result.subtype or "")
            wave_turn_limited, wave_turn_limit_reason = _is_true_turn_limit(
                result,
                max_turns=wave_turn_budget,
            )

        wave_system_prompt = base_system_prompt.replace(
            "{turns_per_wave}", str(wave_turn_budget))

        if policy.mode == "hybrid" and wave == 1:
            trace_context = skill_prompt
            state_path = findings_dir / f"{name}-state.md"
            if state_path.exists():
                trace_context = f"{trace_context}\n{state_path.read_text()}"
            prior = _read_skill_findings(findings_dir, name)
            if prior:
                trace_context = f"{trace_context}\n" + "\n".join(
                    f.get("location", "") for f in prior
                )
            if breadth_read_files:
                trace_context = f"{trace_context}\n" + \
                    "\n".join(sorted(breadth_read_files))
            reseeded = build_seed_scope(
                name,
                cwd=cwd,
                context_text=trace_context,
                max_seeds=policy.max_seed_files,
                all_files=all_first_party_files,
            )
            if reseeded:
                allowed_files = set(reseeded)
            elif breadth_read_files:
                allowed_files = set(sorted(breadth_read_files)[
                                    : policy.max_seed_files])

        scoped_files = starter_files if current_wave_mode == "breadth" else sorted(
            allowed_files)
        logger.info(
            "skill_wave_started",
            skill=name,
            wave=wave + 1,
            total_waves=len(wave_plan),
            mode=current_wave_mode,
            max_turns=wave_turn_budget,
            allowed_file_count=len(scoped_files),
            allowed_file_preview=scoped_files[:8],
            pending_expansion_followups=sum(
                1 for done in expansion_followups.values() if not done
            ),
            findings_so_far=len(_read_skill_findings(findings_dir, name)),
        )
        gate_block = render_scope_gate_block(
            skill_name=name,
            policy=policy,
            mode=current_wave_mode,
            wave_index=wave,
            total_waves=len(wave_plan),
            allowed_files=scoped_files,
            used_expansions=used_expansions,
            feedback=gate_feedback,
        )

        # Build prompt: skill_prompt + current scope contract + prior notes
        parts = [skill_prompt, gate_block]
        pending_followups = sorted(
            path for path, done in expansion_followups.items() if not done
        )
        if pending_followups:
            parts.append(
                "## Approved Expansion Follow-ups\n\n"
                "From previous waves, the following expansion targets were approved. "
                "Update TodoWrite to include them and trace each target this wave:\n"
                + "\n".join(f"- {path}" for path in pending_followups)
            )
        prior = _read_skill_findings(findings_dir, name)
        if prior:
            parts.append(_format_prior_findings(prior))

        wave_prompt = "\n".join(parts)

        # Per-wave semaphore: acquire a slot before running the agent,
        # release between waves so other skills can start.
        if semaphore is not None:
            await semaphore.acquire()
        try:
            await _run_tracked_agent(
                name=name,
                prompt=wave_prompt,
                system_prompt=wave_system_prompt,
                cwd=cwd,
                allowed_tools=SKILL_TOOLS,
                mcp_setup=mcp_setup,
                max_turns=wave_turn_budget,
                model=model,
                effort=effort,
                on_tool=_counting_on_tool,
                on_tool_event=_enforce_scope,
                on_result=_on_result,
                on_text=on_text,
                on_todos=_capturing_todos,
            )
        except _ScopeViolationError as exc:
            wave_status = "scope_violation"
            blocked_scope_reads += 1
            logger.warning(
                "scope_violation_blocked",
                skill=name,
                wave=wave + 1,
                path=exc.path,
                mode=current_wave_mode,
                reason=exc.reason,
            )
            state_path = findings_dir / f"{name}-state.md"
            findings_dir.mkdir(parents=True, exist_ok=True)
            with state_path.open("a", encoding="utf-8") as handle:
                handle.write(
                    f"\nUNTRACED_EDGE|{exc.reason}|"
                    f"{exc.path}\n"
                )
        except TimeoutError as exc:
            wave_status = "stall_timeout"
            wave_turn_limited = True
            logger.warning(
                "skill_wave_stall_timeout",
                skill=name,
                wave=wave + 1,
                error=str(exc),
            )
        except BaseException as exc:
            wave_status = "error"
            wave_error = exc
            raise
        finally:
            if semaphore is not None:
                semaphore.release()
            logger.info(
                "skill_wave_finished",
                skill=name,
                wave=wave + 1,
                total_waves=len(wave_plan),
                mode=current_wave_mode,
                status=wave_status,
                duration_s=round(_time.monotonic() - wave_started_at, 1),
                tool_calls=total_tool_calls - wave_tool_calls_before,
                num_turns=wave_turn_count,
                max_turns=wave_turn_budget,
                turn_limited=wave_turn_limited,
                turn_limited_reason=wave_turn_limit_reason,
                subtype=wave_result_subtype,
                error_type=type(wave_error).__name__ if wave_error is not None else "",
            )

        if wave_turn_limited:
            turn_limited = True
            turn_limited_waves += 1
            turn_limited_reasons.append(
                f"wave={wave + 1}|mode={current_wave_mode}|reason={wave_turn_limit_reason}"
            )
            logger.warning(
                "skill_wave_turn_limited",
                skill=name,
                wave=wave + 1,
                mode=current_wave_mode,
                num_turns=wave_turn_count,
                max_turns=wave_turn_budget,
                subtype=wave_result_subtype,
                reason=wave_turn_limit_reason,
            )
        elif wave_turn_count >= wave_turn_budget:
            logger.info(
                "skill_wave_completed_at_budget",
                skill=name,
                wave=wave + 1,
                mode=current_wave_mode,
                num_turns=wave_turn_count,
                max_turns=wave_turn_budget,
                subtype=wave_result_subtype,
            )

        # Process newly requested EXPAND tickets only in trace waves.
        state_path = findings_dir / f"{name}-state.md"
        if current_wave_mode == "trace" and state_path.exists():
            content = state_path.read_text()
            tickets = parse_expand_requests(content)
            decisions, used_expansions = evaluate_expansion_requests(
                tickets,
                policy=policy,
                allowed_files=allowed_files,
                seen_request_keys=seen_ticket_keys,
                cwd=cwd,
                used_expansions=used_expansions,
            )
            gate_feedback = format_expansion_feedback(
                decisions=decisions,
                policy=policy,
                used_expansions=used_expansions,
            )
            for decision in decisions:
                if decision.approved and decision.approved_path:
                    expansion_followups.setdefault(decision.approved_path, False)
            if decisions:
                _emit_todos()
        elif current_wave_mode == "breadth":
            gate_feedback = (
                "Breadth mode active. EXPAND tickets are optional and "
                "will only be processed in trace waves."
            )

        is_last_wave = wave == len(wave_plan) - 1
        followups_remaining = any(not done for done in expansion_followups.values())
        todos_remaining = any(
            t.get("status", "pending") != "completed"
            for t in latest_todos
            if isinstance(t, dict)
        ) or followups_remaining
        untraced_remaining = _has_pending_untraced_edges()

        # One guarded continuation wave when the agent was cut off at turn cap
        # and still has explicitly recorded unfinished work.
        if (
            is_last_wave
            and wave_turn_limited
            and not continuation_wave_used
            and (todos_remaining or untraced_remaining)
        ):
            continuation_mode = "breadth" if current_wave_mode == "breadth" else "trace"
            wave_plan.append(continuation_mode)
            continuation_wave_used = True
            logger.info(
                "skill_auto_continuation_queued",
                skill=name,
                mode=continuation_mode,
                todos_remaining=todos_remaining,
                untraced_remaining=untraced_remaining,
                next_wave=len(wave_plan),
            )

        # Between waves: no compaction needed — prior findings are
        # injected as a brief list from the JSON files at wave start.
        wave += 1

    logger.info(
        "skill_scope_gating",
        skill=name,
        mode=policy.mode,
        waves=len(wave_plan),
        default_waves=requested_waves,
        default_turn_override=turn_override,
        turn_limited=turn_limited,
        turn_limited_waves=turn_limited_waves,
        turn_limited_reasons=turn_limited_reasons,
        continuation_wave_used=continuation_wave_used,
        seed_files=len(allowed_files),
        expansions_used=used_expansions,
        scope_blocks=blocked_scope_reads,
        breadth_files_read=len(breadth_read_files),
    )

    # Read findings directly from JSON files — no synthesis needed.
    findings = _read_skill_findings(findings_dir, name)

    if run_stats is not None:
        run_stats.clear()
        run_stats.update(
            {
                "planned_waves": requested_waves,
                "executed_waves": len(wave_plan),
                "turn_limited": turn_limited,
                "turn_limited_waves": turn_limited_waves,
                "turn_limited_reasons": list(turn_limited_reasons),
                "continuation_wave_used": continuation_wave_used,
                "has_pending_todos": any(
                    t.get("status", "pending") != "completed"
                    for t in latest_todos
                    if isinstance(t, dict)
                ) or any(not done for done in expansion_followups.values()),
                "has_untraced_edges": _has_pending_untraced_edges(),
                "pending_expansion_followups": sum(
                    1 for done in expansion_followups.values() if not done
                ),
                "policy_mode": policy.mode,
            }
        )

    if not findings:
        return "No findings recorded.", total_tool_calls

    formatted = "\n\n".join(
        f"- **{f.get('severity', '?')}** {f.get('location', '?')} — {f.get('issue', '?')}"
        for f in findings
    )
    return formatted, total_tool_calls


async def _run_report_stream(
    *,
    prompt: str,
    system_prompt: str,
    mcp_setup: McpSetup,
    model: str = "opus",
    is_tty: bool = True,
    output_file: str | None = None,
) -> None:
    """Stream the final report to stdout (or a file via ``output_file``). No tools, single turn."""
    _install_cancel_scope_handler()

    full_system = _inject_prefetched_context(
        system_prompt, mcp_setup.org_context, mcp_setup.security_policy,
        mcp_setup.review_context,
    )

    options = ClaudeAgentOptions(
        allowed_tools=list(mcp_setup.mcp_tools),
        system_prompt=full_system,
        mcp_servers=mcp_setup.mcp_config,
        permission_mode="acceptEdits",
        max_turns=1,
        model=model,
        effort="medium",
        env=_get_agent_env(),
        stderr=lambda line: logger.debug("cli_stderr", agent="report", line=line.rstrip()),
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

    out_fh = open(output_file, "w") if output_file else None  # noqa: SIM115
    stream = query(prompt=prompt, options=options)
    try:
        async for message in stream:
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
                        if out_fh:
                            out_fh.write(block.text + "\n")
                            out_fh.flush()
                        else:
                            print(block.text, flush=True)
    finally:
        await _safe_close_query_stream(stream, context="run_report_stream")
        if tick_task:
            tick_task.cancel()
        if spinner:
            spinner.stop()
        if out_fh:
            out_fh.close()



# Scan display lives in a dedicated module for readability.
from hiro_agent.scan_display import _ScanDisplay
