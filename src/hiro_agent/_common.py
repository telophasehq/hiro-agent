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

IGNORED_DIRS: frozenset[str] = frozenset({
    ".cache", ".git", ".mypy_cache", ".next", ".nuxt", ".npm", ".pnp",
    ".pytest_cache", ".ruff_cache", ".serverless", ".terraform", ".venv",
    ".yarn", "__pycache__", "build", "dist", "env", "external",
    "node_modules", "out", "site-packages", "target", "third_party",
    "vendor", "venv",
})

logger = structlog.get_logger(__name__)

# Hardcoded — not configurable to prevent SSRF. HTTPS enforced.
HIRO_MCP_URL = "https://api.hiro.is/mcp/architect/mcp"
HIRO_INTERNAL_MCP_URL = "https://api.hiro.is/mcp/architect/internal/mcp"
HIRO_AGENTS_MCP_URL = "https://api.hiro.is/mcp/agents/mcp"
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


def _mcp_call_tool(api_key: str, tool_name: str, arguments: dict | None = None, *, timeout: int = 5, url: str | None = None) -> str | None:
    """Call an MCP tool via direct JSON-RPC POST and return the text result.

    Sends a JSON-RPC request to the MCP Streamable HTTP endpoint and parses
    the SSE response to extract the tool result. Returns None on any failure
    (network error, timeout, bad response) so callers can degrade gracefully.

    Args:
        url: Override the MCP endpoint URL. Defaults to HIRO_MCP_URL.
    """
    import http.client
    import ssl
    from urllib.parse import urlparse

    parsed = urlparse(url or HIRO_MCP_URL)
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
        asyncio.to_thread(_mcp_call_tool, api_key, "get_org_context", None, url=HIRO_INTERNAL_MCP_URL),
        asyncio.to_thread(_mcp_call_tool, api_key, "get_security_policy", None, url=HIRO_INTERNAL_MCP_URL),
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
        _mcp_call_tool, api_key, "get_review_context", {"diff": diff}, timeout=30, url=HIRO_INTERNAL_MCP_URL,
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
    backend proxy to Bedrock (billing attribution, audit, provider
    swapping). Otherwise fall back to the Claude CLI's own auth.
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
# Agent runner and display helpers
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
    thinking_budget: int | None = None,
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

    # Mutable timestamp updated by the stderr callback as a heartbeat.
    # Stderr lines arrive on a background task even while __anext__() is
    # blocked during extended thinking, preventing false stall timeouts.
    _heartbeat = [_time.monotonic()]

    def _stderr_heartbeat(line: str) -> None:
        _heartbeat[0] = _time.monotonic()
        logger.debug("cli_stderr", agent=name, line=line.rstrip())

    # Opus 4.7 on Bedrock rejects ``thinking.type = enabled`` — it requires
    # ``adaptive`` with a companion ``output_config.effort``. Pre-4.7 models
    # accepted ``enabled`` with an explicit budget. Use adaptive uniformly
    # for Opus and map ``thinking_budget`` to the effort bucket; non-Opus
    # models still get the legacy shape so their behaviour is unchanged.
    if thinking_budget is None:
        _thinking_config = None
    elif model == "opus":
        _thinking_config = {"type": "adaptive"}
        if not effort:
            # Translate a rough budget → effort bucket. These thresholds
            # mirror what the CLI used to spend at the corresponding
            # max_thinking_tokens on 4.6.
            if thinking_budget >= 24_000:
                effort = "high"
            elif thinking_budget >= 8_000:
                effort = "medium"
            else:
                effort = "low"
    else:
        _thinking_config = {"type": "enabled", "budget_tokens": thinking_budget}
    # Block MCP tools that internally call LLMs (Bedrock Opus) to prevent
    # nested Opus-calling-Opus loops that can run for 60+ minutes.
    _disallowed_mcp_tools = [
        "mcp__hiro__review_diff",
        "mcp__hiro__ask",
    ]
    options = ClaudeAgentOptions(
        cwd=cwd,
        tools=parent_tools,
        allowed_tools=parent_tools + subagent_tools,
        disallowed_tools=_disallowed_mcp_tools,
        system_prompt=full_system,
        mcp_servers=mcp_setup.mcp_config,
        permission_mode="acceptEdits",
        max_turns=max_turns,
        model=model,
        effort=effort,
        thinking=_thinking_config,
        agents={"explore": _EXPLORE_AGENT},
        env=_get_agent_env(),
        stderr=_stderr_heartbeat,
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
    _default_stall_timeout = 120.0 if model == "sonnet" else 900.0
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
            now = _time.monotonic()
            # Use the most recent activity signal: primary-agent messages
            # OR stderr heartbeats (which arrive during extended thinking).
            last_activity = max(last_primary_message_at, _heartbeat[0])
            elapsed = now - last_activity
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
            # Use short polling intervals so stderr heartbeats (which
            # arrive during extended thinking) can prevent false stalls.
            _next = asyncio.ensure_future(stream.__anext__())
            _poll_interval = 30.0
            _msg_ready = False
            while True:
                done, _ = await asyncio.wait({_next}, timeout=_poll_interval)
                if done:
                    _msg_ready = True
                    break
                # Check heartbeat: stderr activity resets the clock.
                last_activity = max(last_primary_message_at, _heartbeat[0])
                if (_time.monotonic() - last_activity) >= stall_timeout:
                    stall_timed_out = True
                    logger.error(
                        "agent_stall_timeout",
                        agent=name,
                        timeout_s=stall_timeout,
                        elapsed_s=round(_time.monotonic() - last_activity, 1),
                    )
                    break
                # Also bail if the watchdog already flagged a stall.
                if stall_timed_out:
                    break
            if not _msg_ready:
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


_POST_REPORT_PATTERNS = re.compile(
    r"^(Let me |I need to |Now let me |I('ll| will) |I should |Let's )",
)



def _strip_post_report_text(text: str) -> str:
    """Remove trailing narration the model appends after the structured report.

    The model sometimes finishes the report then adds text like
    "Let me verify..." or "I need to check...". We detect the first line
    that matches a narration pattern after the last markdown heading/table
    and truncate there.
    """
    lines = text.split("\n")
    # Find the last line that's part of the report structure.
    last_report_line = 0
    for i, line in enumerate(lines):
        s = line.strip()
        if s.startswith(("#", "|", "- ", "* ", "> ", "```", "---", "**")):
            last_report_line = i
    # Scan forward from there for narration.
    cut_at = len(lines)
    for i in range(last_report_line + 1, len(lines)):
        s = lines[i].strip()
        if s and _POST_REPORT_PATTERNS.search(s):
            cut_at = i
            break
    return "\n".join(lines[:cut_at]).rstrip()


# Display lives in a dedicated module for readability.
from hiro_agent.scan_display import _ScanDisplay
