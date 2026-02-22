"""Tests for hiro_agent._common — shared agent runner."""

import asyncio
import json
import logging
import os
import time
from pathlib import Path
from unittest.mock import patch

import pytest
import structlog

from hiro_agent._common import (
    HIRO_BACKEND_URL,
    HIRO_MCP_URL,
    McpSetup,
    SKILL_TOOLS,
    _EXPLORE_AGENT,
    _ScanDisplay,
    _get_agent_env,
    _get_api_key,
    _get_mcp_config,
    _inject_prefetched_context,
    _mcp_call_tool,
    _prefetch_mcp_context,
    _run_skill_waves,
    _run_tracked_agent,
    prepare_mcp,
    run_review_agent,
    run_streaming_agent,
)


class TestGetApiKey:
    """Test _get_api_key() resolution order."""

    def test_env_var_takes_precedence(self, tmp_path: Path):
        """Env var should win over config file."""
        config_file = tmp_path / ".hiro" / "config.json"
        config_file.parent.mkdir(parents=True)
        config_file.write_text(json.dumps({"api_key": "from_config"}))
        with patch.dict(os.environ, {"HIRO_API_KEY": "from_env"}):
            assert _get_api_key() == "from_env"

    def test_falls_back_to_config_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Should read from .hiro/config.json when env var is unset."""
        config_file = tmp_path / ".hiro" / "config.json"
        config_file.parent.mkdir(parents=True)
        config_file.write_text(json.dumps({"api_key": "from_config"}))
        monkeypatch.chdir(tmp_path)
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("HIRO_API_KEY", None)
            assert _get_api_key() == "from_config"

    def test_returns_empty_when_nothing_configured(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Should return empty string when no key is available."""
        monkeypatch.chdir(tmp_path)
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("HIRO_API_KEY", None)
            assert _get_api_key() == ""


class TestGetMcpConfig:
    """Test _get_mcp_config() MCP server configuration."""

    def test_returns_empty_without_api_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Without HIRO_API_KEY, should return empty dict."""
        monkeypatch.chdir(tmp_path)
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("HIRO_API_KEY", None)
            config = _get_mcp_config()
            assert config == {}

    def test_returns_config_with_api_key(self):
        """With HIRO_API_KEY, should return hiro MCP config."""
        with patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test123"}):
            config = _get_mcp_config()
            assert "hiro" in config
            assert config["hiro"]["url"] == HIRO_MCP_URL
            assert config["hiro"]["headers"]["Authorization"] == "Bearer hiro_ak_test123"

    def test_hardcoded_mcp_url(self):
        """MCP URL should be hardcoded constant (not configurable)."""
        assert HIRO_MCP_URL == "https://api.hiro.is/mcp/architect/mcp"

    def test_hardcoded_backend_url(self):
        """Backend URL should be hardcoded constant."""
        assert HIRO_BACKEND_URL == "https://api.hiro.is"


class TestGetAgentEnv:
    """Test _get_agent_env() environment variable builder."""

    def test_always_clears_claudecode(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """CLAUDECODE should always be empty string."""
        monkeypatch.chdir(tmp_path)
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("HIRO_API_KEY", None)
            env = _get_agent_env()
            assert env["CLAUDECODE"] == ""

    def test_no_proxy_without_api_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Without HIRO_API_KEY, should not set ANTHROPIC_BASE_URL."""
        monkeypatch.chdir(tmp_path)
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("HIRO_API_KEY", None)
            env = _get_agent_env()
            assert "ANTHROPIC_BASE_URL" not in env
            assert "ANTHROPIC_API_KEY" not in env

    def test_proxy_with_api_key(self):
        """With HIRO_API_KEY, should route through proxy."""
        with patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test123"}):
            env = _get_agent_env()
            assert env["ANTHROPIC_BASE_URL"] == f"{HIRO_BACKEND_URL}/api/llm-proxy"
            assert env["ANTHROPIC_API_KEY"] == "hiro_ak_test123"


class TestRunReviewAgent:
    """Test run_review_agent() orchestration."""

    @pytest.mark.asyncio
    async def test_calls_query_with_options(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Should call claude-agent-sdk query with correct options."""
        monkeypatch.chdir(tmp_path)
        from claude_agent_sdk import AssistantMessage, TextBlock

        mock_message = AssistantMessage(
            content=[TextBlock(text="No security issues found.")],
            model="claude-sonnet-4-5-20250514",
        )

        async def mock_query(prompt, options):
            yield mock_message

        with patch("hiro_agent._common.query", side_effect=mock_query):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("HIRO_API_KEY", None)
                result = await run_review_agent(
                    prompt="Review this code",
                    system_prompt="You are a reviewer",
                    cwd="/tmp",
                    allowed_tools=["Read", "Grep"],
                    max_turns=5,
                )

        assert result == "No security issues found."

    @pytest.mark.asyncio
    async def test_returns_last_text_block(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Should return the text from the last AssistantMessage."""
        monkeypatch.chdir(tmp_path)
        from claude_agent_sdk import AssistantMessage, TextBlock

        messages = [
            AssistantMessage(content=[TextBlock(text="First response")], model="claude-sonnet-4-5-20250514"),
            AssistantMessage(content=[TextBlock(text="Final review output")], model="claude-sonnet-4-5-20250514"),
        ]

        async def mock_query(prompt, options):
            for msg in messages:
                yield msg

        with patch("hiro_agent._common.query", side_effect=mock_query):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("HIRO_API_KEY", None)
                result = await run_review_agent(
                    prompt="Review",
                    system_prompt="System",
                )

        assert result == "Final review output"

    @pytest.mark.asyncio
    async def test_includes_mcp_tools_when_connected(self):
        """When HIRO_API_KEY is set, only recall should be in allowed_tools (context is pre-fetched)."""
        captured_options = {}

        async def mock_query(prompt, options):
            captured_options.update(vars(options))
            return
            yield  # make it an async generator

        with patch("hiro_agent._common.query", side_effect=mock_query):
            with patch("hiro_agent._common._check_mcp_connection", return_value=None):
                with patch("hiro_agent._common._prefetch_mcp_context", return_value=(None, None)):
                    with patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test"}):
                        await run_review_agent(
                            prompt="Review",
                            system_prompt="System",
                            allowed_tools=["Read"],
                        )

        allowed = captured_options["allowed_tools"]
        assert "Read" in allowed
        assert "mcp__hiro__recall" in allowed
        # Pre-fetched tools should NOT be in allowed_tools
        assert "mcp__hiro__get_org_context" not in allowed
        assert "mcp__hiro__get_security_policy" not in allowed
        # Write tools should NOT be allowed
        assert "mcp__hiro__remember" not in allowed
        assert "mcp__hiro__set_org_context" not in allowed
        assert "mcp__hiro__forget" not in allowed
        # Model should default to opus
        assert captured_options["model"] == "opus"

    @pytest.mark.asyncio
    async def test_prefetched_context_injected_into_prompt(self):
        """When pre-fetch returns content, it should be injected into the system prompt."""
        captured_options = {}

        async def mock_query(prompt, options):
            captured_options.update(vars(options))
            return
            yield

        with patch("hiro_agent._common.query", side_effect=mock_query):
            with patch("hiro_agent._common._check_mcp_connection", return_value=None):
                with patch("hiro_agent._common._prefetch_mcp_context", return_value=("Org: Acme Corp", "Policy: No plaintext secrets")):
                    with patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test"}):
                        await run_review_agent(
                            prompt="Review",
                            system_prompt="You are a reviewer",
                            allowed_tools=["Read"],
                        )

        sp = captured_options["system_prompt"]
        assert "Organizational Context (pre-loaded)" in sp
        assert "Org: Acme Corp" in sp
        assert "Security Policy (pre-loaded)" in sp
        assert "Policy: No plaintext secrets" in sp
        assert "You are a reviewer" in sp

    @pytest.mark.asyncio
    async def test_no_mcp_tools_without_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Without HIRO_API_KEY, MCP tools should not be in allowed_tools."""
        monkeypatch.chdir(tmp_path)
        captured_options = {}

        async def mock_query(prompt, options):
            captured_options.update(vars(options))
            return
            yield

        with patch("hiro_agent._common.query", side_effect=mock_query):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("HIRO_API_KEY", None)
                await run_review_agent(
                    prompt="Review",
                    system_prompt="System",
                    allowed_tools=["Read"],
                )

        allowed = captured_options["allowed_tools"]
        assert allowed == ["Read"]


class TestMcpCallTool:
    """Test _mcp_call_tool() direct JSON-RPC calls."""

    def test_parses_sse_response(self):
        """Should extract text content from SSE data lines."""
        sse_body = (
            'event: message\n'
            'data: {"jsonrpc":"2.0","id":1,"result":{"content":[{"type":"text","text":"Hello org"}]}}\n'
            '\n'
        )
        mock_resp = type("Resp", (), {"status": 200, "read": lambda self: sse_body.encode()})()
        mock_conn = type("Conn", (), {
            "request": lambda self, *a, **kw: None,
            "getresponse": lambda self: mock_resp,
            "close": lambda self: None,
        })()

        with patch("http.client.HTTPSConnection", return_value=mock_conn):
            result = _mcp_call_tool("key", "get_org_context")

        assert result == "Hello org"

    def test_returns_none_on_http_error(self):
        """Should return None on non-2xx status."""
        mock_resp = type("Resp", (), {"status": 401, "reason": "Unauthorized"})()
        mock_conn = type("Conn", (), {
            "request": lambda self, *a, **kw: None,
            "getresponse": lambda self: mock_resp,
            "close": lambda self: None,
        })()

        with patch("http.client.HTTPSConnection", return_value=mock_conn):
            result = _mcp_call_tool("bad_key", "get_org_context")

        assert result is None

    def test_returns_none_on_network_error(self):
        """Should return None on connection failure."""
        with patch("http.client.HTTPSConnection", side_effect=ConnectionError("refused")):
            result = _mcp_call_tool("key", "get_org_context")

        assert result is None

    def test_returns_none_on_empty_sse(self):
        """Should return None when SSE has no data lines."""
        sse_body = "event: message\n\n"
        mock_resp = type("Resp", (), {"status": 200, "read": lambda self: sse_body.encode()})()
        mock_conn = type("Conn", (), {
            "request": lambda self, *a, **kw: None,
            "getresponse": lambda self: mock_resp,
            "close": lambda self: None,
        })()

        with patch("http.client.HTTPSConnection", return_value=mock_conn):
            result = _mcp_call_tool("key", "get_org_context")

        assert result is None


class TestPrefetchMcpContext:
    """Test _prefetch_mcp_context() parallel fetching."""

    @pytest.mark.asyncio
    async def test_returns_both_on_success(self):
        """Should return (org_context, security_policy) when both succeed."""
        def mock_call(api_key, tool_name, arguments=None, **kwargs):
            if tool_name == "get_org_context":
                return "Acme Corp context"
            if tool_name == "get_security_policy":
                return "Security policy text"
            return None

        with patch("hiro_agent._common._mcp_call_tool", side_effect=mock_call):
            org, sec = await _prefetch_mcp_context("key")

        assert org == "Acme Corp context"
        assert sec == "Security policy text"

    @pytest.mark.asyncio
    async def test_partial_failure(self):
        """Should return None for failed tool, value for successful one."""
        def mock_call(api_key, tool_name, arguments=None, **kwargs):
            if tool_name == "get_org_context":
                return "Acme Corp context"
            return None

        with patch("hiro_agent._common._mcp_call_tool", side_effect=mock_call):
            org, sec = await _prefetch_mcp_context("key")

        assert org == "Acme Corp context"
        assert sec is None

    @pytest.mark.asyncio
    async def test_both_fail(self):
        """Should return (None, None) when both fail."""
        with patch("hiro_agent._common._mcp_call_tool", return_value=None):
            org, sec = await _prefetch_mcp_context("key")

        assert org is None
        assert sec is None


class TestInjectPrefetchedContext:
    """Test _inject_prefetched_context() prompt modification."""

    def test_injects_both(self):
        """Should prepend both sections when both are provided."""
        result = _inject_prefetched_context("Base prompt", "Org data", "Policy data")
        assert result.startswith("## Organizational Context (pre-loaded)")
        assert "Org data" in result
        assert "## Security Policy (pre-loaded)" in result
        assert "Policy data" in result
        assert result.endswith("Base prompt")

    def test_injects_only_org(self):
        """Should prepend only org section when policy is None."""
        result = _inject_prefetched_context("Base prompt", "Org data", None)
        assert "Organizational Context" in result
        assert "Security Policy" not in result
        assert result.endswith("Base prompt")

    def test_injects_only_policy(self):
        """Should prepend only policy section when org is None."""
        result = _inject_prefetched_context("Base prompt", None, "Policy data")
        assert "Organizational Context" not in result
        assert "Security Policy" in result
        assert result.endswith("Base prompt")

    def test_returns_unchanged_when_both_none(self):
        """Should return prompt unchanged when both are None."""
        result = _inject_prefetched_context("Base prompt", None, None)
        assert result == "Base prompt"

    def test_returns_unchanged_when_both_empty(self):
        """Should return prompt unchanged when both are empty strings."""
        result = _inject_prefetched_context("Base prompt", "", "")
        assert result == "Base prompt"


class TestExploreAgent:
    """Test _EXPLORE_AGENT definition."""

    def test_explore_agent_defined(self):
        """Explore agent should use haiku model with read-only tools."""
        assert _EXPLORE_AGENT.model == "haiku"
        assert set(_EXPLORE_AGENT.tools) == {"Read", "Grep", "Glob"}
        assert "read-only" in _EXPLORE_AGENT.description.lower() or "explorer" in _EXPLORE_AGENT.description.lower()


class TestModelParameter:
    """Test model parameter forwarding for both runners."""

    @pytest.mark.asyncio
    async def test_default_model_is_opus_review(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """run_review_agent should default to opus."""
        captured_options = {}

        async def mock_query(prompt, options):
            captured_options.update(vars(options))
            return
            yield

        monkeypatch.chdir(tmp_path)
        with patch("hiro_agent._common.query", side_effect=mock_query):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("HIRO_API_KEY", None)
                await run_review_agent(prompt="Review", system_prompt="System")

        assert captured_options["model"] == "opus"
        assert "explore" in captured_options["agents"]
        assert captured_options["agents"]["explore"].model == "haiku"

    @pytest.mark.asyncio
    async def test_default_model_is_opus_streaming(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """run_streaming_agent should default to opus."""
        captured_options = {}

        async def mock_query(prompt, options):
            captured_options.update(vars(options))
            return
            yield

        monkeypatch.chdir(tmp_path)
        with patch("hiro_agent._common.query", side_effect=mock_query):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("HIRO_API_KEY", None)
                await run_streaming_agent(prompt="Review", system_prompt="System")

        assert captured_options["model"] == "opus"
        assert "explore" in captured_options["agents"]

    @pytest.mark.asyncio
    async def test_model_parameter_forwarded(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Custom model value should reach ClaudeAgentOptions."""
        captured_options = {}

        async def mock_query(prompt, options):
            captured_options.update(vars(options))
            return
            yield

        monkeypatch.chdir(tmp_path)
        with patch("hiro_agent._common.query", side_effect=mock_query):
            with patch.dict(os.environ, {}, clear=True):
                os.environ.pop("HIRO_API_KEY", None)
                await run_review_agent(
                    prompt="Review", system_prompt="System", model="sonnet",
                )

        assert captured_options["model"] == "sonnet"


class TestNoEventLoopBlocking:
    """Verify that MCP and LLM proxy I/O runs in threads, not on the event loop.

    Each test mocks a slow I/O call (time.sleep), runs it alongside an async
    canary task, and asserts the canary was NOT starved.  If the I/O ran on
    the event loop the canary would get zero ticks during the sleep.
    """

    @pytest.mark.asyncio
    async def test_mcp_preflight_does_not_block(self):
        """_check_mcp_connection should run in a thread via asyncio.to_thread."""
        BLOCK_SECONDS = 0.4
        ticks = 0

        async def canary():
            nonlocal ticks
            for _ in range(20):
                await asyncio.sleep(0.02)
                ticks += 1

        def slow_check(api_key):
            time.sleep(BLOCK_SECONDS)
            return None  # success

        async def mock_query(prompt, options):
            return
            yield

        with (
            patch("hiro_agent._common.query", side_effect=mock_query),
            patch("hiro_agent._common._check_mcp_connection", side_effect=slow_check),
            patch("hiro_agent._common._prefetch_mcp_context", return_value=(None, None)),
            patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test"}),
        ):
            await asyncio.gather(
                run_review_agent(prompt="Review", system_prompt="System"),
                canary(),
            )

        # Canary should have ticked freely during the blocking sleep
        assert ticks >= 5, f"Event loop was blocked: only {ticks} canary ticks"

    @pytest.mark.asyncio
    async def test_mcp_prefetch_does_not_block(self):
        """_prefetch_mcp_context uses asyncio.to_thread for both tool calls."""
        BLOCK_SECONDS = 0.3
        ticks = 0

        async def canary():
            nonlocal ticks
            for _ in range(20):
                await asyncio.sleep(0.02)
                ticks += 1

        def slow_tool(api_key, tool_name, arguments=None, **kwargs):
            time.sleep(BLOCK_SECONDS)
            return f"result for {tool_name}"

        with patch("hiro_agent._common._mcp_call_tool", side_effect=slow_tool):
            _, _ = await asyncio.gather(
                _prefetch_mcp_context("key"),
                canary(),
            )

        assert ticks >= 5, f"Event loop was blocked: only {ticks} canary ticks"

    @pytest.mark.asyncio
    async def test_streaming_agent_mcp_preflight_does_not_block(self):
        """run_streaming_agent's preflight check should also run in a thread."""
        BLOCK_SECONDS = 0.4
        ticks = 0

        async def canary():
            nonlocal ticks
            for _ in range(20):
                await asyncio.sleep(0.02)
                ticks += 1

        def slow_check(api_key):
            time.sleep(BLOCK_SECONDS)
            return None

        async def mock_query(prompt, options):
            return
            yield

        with (
            patch("hiro_agent._common.query", side_effect=mock_query),
            patch("hiro_agent._common._check_mcp_connection", side_effect=slow_check),
            patch("hiro_agent._common._prefetch_mcp_context", return_value=(None, None)),
            patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test"}),
        ):
            await asyncio.gather(
                run_streaming_agent(prompt="Review", system_prompt="System"),
                canary(),
            )

        assert ticks >= 5, f"Event loop was blocked: only {ticks} canary ticks"


class TestPrepareMcp:
    """Test prepare_mcp() shared setup."""

    @pytest.mark.asyncio
    async def test_returns_empty_without_api_key(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Without HIRO_API_KEY, should return empty McpSetup."""
        monkeypatch.chdir(tmp_path)
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("HIRO_API_KEY", None)
            setup = await prepare_mcp()

        assert setup.mcp_config == {}
        assert setup.mcp_tools == []
        assert setup.org_context is None
        assert setup.security_policy is None

    @pytest.mark.asyncio
    async def test_returns_tools_on_success(self):
        """When MCP is available, should return recall tool and prefetched data."""
        with (
            patch("hiro_agent._common._check_mcp_connection", return_value=None),
            patch("hiro_agent._common._prefetch_mcp_context", return_value=("org", "policy")),
            patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test"}),
        ):
            setup = await prepare_mcp()

        assert "hiro" in setup.mcp_config
        assert setup.mcp_tools == ["mcp__hiro__recall"]
        assert setup.org_context == "org"
        assert setup.security_policy == "policy"

    @pytest.mark.asyncio
    async def test_degrades_on_connection_failure(self):
        """When MCP connection fails, should return empty config."""
        with (
            patch("hiro_agent._common._check_mcp_connection", return_value="connection refused"),
            patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test"}),
        ):
            setup = await prepare_mcp(is_tty=False)

        assert setup.mcp_config == {}
        assert setup.mcp_tools == []


class TestRunTrackedAgent:
    """Test _run_tracked_agent() per-skill query."""

    @pytest.mark.asyncio
    async def test_returns_last_text(self):
        """Should return text from the last TextBlock."""
        from claude_agent_sdk import AssistantMessage, TextBlock

        msg = AssistantMessage(
            content=[TextBlock(text="skill findings here")],
            model="claude-sonnet-4-5-20250514",
        )

        async def mock_query(prompt, options):
            yield msg

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common.query", side_effect=mock_query):
            text, session_id = await _run_tracked_agent(
                name="auth",
                prompt="investigate auth",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["Read"],
                mcp_setup=setup,
            )

        assert text == "skill findings here"
        assert session_id == ""  # No ResultMessage in mock

    @pytest.mark.asyncio
    async def test_calls_on_tool_callback(self):
        """Should call on_tool for each ToolUseBlock."""
        from claude_agent_sdk import AssistantMessage, TextBlock, ToolUseBlock

        msg = AssistantMessage(
            content=[
                ToolUseBlock(id="t1", name="Read", input={"file_path": "/src/auth.py"}),
                TextBlock(text="done"),
            ],
            model="claude-sonnet-4-5-20250514",
        )

        async def mock_query(prompt, options):
            yield msg

        tool_calls = []

        def on_tool(agent_name, tool_name, summary, is_subagent=False):
            tool_calls.append((agent_name, tool_name, summary))

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common.query", side_effect=mock_query):
            await _run_tracked_agent(
                name="auth",
                prompt="investigate",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["Read"],
                mcp_setup=setup,
                on_tool=on_tool,
            )

        assert len(tool_calls) == 1
        assert tool_calls[0][0] == "auth"
        assert tool_calls[0][1] == "Read"

    @pytest.mark.asyncio
    async def test_todowrite_triggers_on_todos(self):
        """TodoWrite ToolUseBlock should call the on_todos callback with parsed todos."""
        from claude_agent_sdk import AssistantMessage, TextBlock, ToolUseBlock

        todos_data = [
            {"id": "1", "content": "Check auth flow", "status": "pending"},
            {"id": "2", "content": "Verify tokens", "status": "in_progress"},
        ]
        msg = AssistantMessage(
            content=[
                ToolUseBlock(id="t1", name="TodoWrite", input={"todos": todos_data}),
                TextBlock(text="done"),
            ],
            model="claude-sonnet-4-5-20250514",
        )

        async def mock_query(prompt, options):
            yield msg

        captured_todos = []

        def on_todos(agent_name, todos):
            captured_todos.append((agent_name, todos))

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common.query", side_effect=mock_query):
            await _run_tracked_agent(
                name="injection",
                prompt="investigate",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["TodoWrite"],
                mcp_setup=setup,
                on_todos=on_todos,
            )

        assert len(captured_todos) == 1
        assert captured_todos[0][0] == "injection"
        assert captured_todos[0][1] == todos_data


class TestScanDisplay:
    """Test _ScanDisplay phase transitions and agent lifecycle."""

    def test_phase_transitions(self):
        """Should progress through phases correctly."""
        display = _ScanDisplay(["auth", "injection"])

        display.start_recon()
        assert display._phase == 1

        display.start_investigations()
        assert display._phase == 2

        # start_report() jumps to phase 4 (finalized) so the display
        # shows all ✓ before the report streams below it.
        display.start_report()
        assert display._phase == 4

        display.finish()  # no-op
        assert display._phase == 4

    def test_agent_lifecycle(self):
        """Agent status should transition: pending → running → completed."""
        display = _ScanDisplay(["auth", "secrets"])
        display._phase = 2

        assert display._agent_status["auth"] == "pending"

        display.agent_started("auth")
        assert display._agent_status["auth"] == "running"

        display.agent_tool("auth", "Read", "auth.py")
        assert display._agent_tool["auth"] == "Read(auth.py)"

        display.agent_completed("auth")
        assert display._agent_status["auth"] == "completed"
        assert "auth" not in display._agent_tool

    def test_build_lines_pending(self):
        """All agents pending should show ○ markers."""
        display = _ScanDisplay(["auth"])
        display._phase = 2
        lines = display._build_lines()
        joined = "\n".join(lines)
        assert "○ auth" in joined

    def test_build_lines_completed(self):
        """Completed agents should show ✓ markers."""
        display = _ScanDisplay(["auth"])
        display._phase = 2
        display._agent_status["auth"] = "completed"
        lines = display._build_lines()
        joined = "\n".join(lines)
        assert "✓" in joined

    def test_agent_todos_tracked(self):
        """agent_todos() should store items, agent_completed() should clear them."""
        display = _ScanDisplay(["auth", "injection"])
        display._phase = 2

        todos = [
            {"id": "1", "content": "Check auth flow", "status": "pending"},
            {"id": "2", "content": "Verify tokens", "status": "completed"},
        ]
        display.agent_todos("auth", todos)
        assert display._agent_todos["auth"] == todos

        display.agent_completed("auth")
        assert "auth" not in display._agent_todos

    def test_build_lines_shows_todos(self):
        """Todo items should appear in _build_lines() output for running agents."""
        display = _ScanDisplay(["auth"])
        display._phase = 2
        display._agent_status["auth"] = "running"
        display._agent_tool["auth"] = "Read(auth.py)"
        display._agent_todos["auth"] = [
            {"id": "1", "content": "Scan for raw SQL", "status": "completed"},
            {"id": "2", "content": "Check parameterized queries", "status": "in_progress"},
            {"id": "3", "content": "Verify ORM layer", "status": "pending"},
        ]

        lines = display._build_lines()
        joined = "\n".join(lines)

        assert "Scan for raw SQL" in joined
        assert "Check parameterized queries" in joined
        assert "Verify ORM layer" in joined
        # Completed todo should have ✓, in_progress ◆, pending ○
        # Find the specific lines
        todo_lines = [l for l in lines if "Scan for raw SQL" in l or "Check parameterized" in l or "Verify ORM" in l]
        assert len(todo_lines) == 3
        assert "✓" in todo_lines[0]
        assert "◆" in todo_lines[1]
        assert "○" in todo_lines[2]

    def test_build_lines_caps_todos(self):
        """Should cap todo items at _MAX_TODO_LINES and show overflow indicator."""
        from hiro_agent._common import _MAX_TODO_LINES

        display = _ScanDisplay(["auth"])
        display._phase = 2
        display._agent_status["auth"] = "running"
        display._agent_tool["auth"] = "Read(auth.py)"
        display._agent_todos["auth"] = [
            {"id": str(i), "content": f"Item {i}", "status": "pending"}
            for i in range(8)
        ]

        lines = display._build_lines()
        joined = "\n".join(lines)

        # Only first _MAX_TODO_LINES items should appear
        for i in range(_MAX_TODO_LINES):
            assert f"Item {i}" in joined
        assert f"Item {_MAX_TODO_LINES}" not in joined

        # Should show overflow indicator
        remaining = 8 - _MAX_TODO_LINES
        assert f"+{remaining} more" in joined

    def test_build_lines_capped_to_terminal_height(self):
        """Display should be capped to terminal height to prevent scroll-off stacking."""
        display = _ScanDisplay(["a", "b", "c", "d", "e", "f", "g", "h", "i"])
        display._phase = 2
        # Make all agents running with todos to inflate line count
        for name in display._skill_names:
            display._agent_status[name] = "running"
            display._agent_tool[name] = f"Read({name}.py)"
            display._agent_todos[name] = [
                {"id": "1", "content": f"Todo for {name}", "status": "pending"},
                {"id": "2", "content": f"Another for {name}", "status": "pending"},
                {"id": "3", "content": f"Third for {name}", "status": "pending"},
            ]

        # Simulate a small terminal (20 lines)
        with patch("hiro_agent._common._get_terminal_height", return_value=20):
            lines = display._build_lines()

        # Should be capped at terminal height - 2
        assert len(lines) <= 18
        # Footer (blank + Report) should still be present
        joined = "\n".join(lines)
        assert "Report" in joined
        # Truncation indicator should be present
        assert "…" in joined

    def test_show_recon_summary_prints_text(self, capsys):
        """show_recon_summary should print the summary to stderr."""
        display = _ScanDisplay(["auth"])
        display._phase = 1

        display.show_recon_summary("## Scan Strategy\n\nFocusing on auth...")

        captured = capsys.readouterr()
        assert "Scan Strategy" in captured.err

    def test_show_recon_summary_always_prints(self, capsys):
        """show_recon_summary should always print, even if recon_text showed the same text."""
        display = _ScanDisplay(["auth"])
        display._phase = 1

        summary = "## Scan Strategy\n\nFocusing on auth..."
        display.recon_text(summary)
        capsys.readouterr()  # clear

        display.show_recon_summary(summary)

        captured = capsys.readouterr()
        assert "Scan Strategy" in captured.err

    def test_build_lines_no_todos_for_completed(self):
        """Completed agents should not show todo items."""
        display = _ScanDisplay(["auth"])
        display._phase = 2
        display._agent_status["auth"] = "completed"
        # Even if todos exist in state (shouldn't happen, but be safe)
        display._agent_todos["auth"] = [
            {"id": "1", "content": "Should not appear", "status": "pending"},
        ]

        lines = display._build_lines()
        joined = "\n".join(lines)
        assert "Should not appear" not in joined


class TestSkillTools:
    """Test SKILL_TOOLS constant."""

    def test_includes_task_and_write(self):
        """SKILL_TOOLS should include Task and Write."""
        assert "Task" in SKILL_TOOLS
        assert "Write" in SKILL_TOOLS


class TestRunSkillWaves:
    """Test _run_skill_waves() multi-wave investigation."""

    @pytest.mark.asyncio
    async def test_two_waves_executed(self, tmp_path: Path):
        """Should call _run_tracked_agent for each wave plus synthesis."""
        scratchpad = tmp_path / "test.md"
        call_names = []

        async def mock_tracked(*, name, prompt, **kwargs):
            call_names.append(name)
            if name == "test-synthesis":
                return ("Synthesized findings", "")
            # Simulate writing to scratchpad
            scratchpad.write_text("## Finding 1\nSome issue at file.py:10")
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            result, tool_calls = await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                scratchpad_path=scratchpad,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
            )

        # Two waves + synthesis = 3 calls to _run_tracked_agent
        assert call_names.count("test") == 2
        assert "test-synthesis" in call_names

    @pytest.mark.asyncio
    async def test_compaction_triggered_when_large(self, tmp_path: Path):
        """Scratchpad > 2000 chars should trigger compaction between waves."""
        scratchpad = tmp_path / "test.md"
        call_names = []

        async def mock_tracked(*, name, prompt, **kwargs):
            call_names.append(name)
            if name == "test-compact":
                return ("compacted notes", "")
            if name == "test-synthesis":
                return ("Synthesized", "")
            # Write large scratchpad content
            scratchpad.write_text("x" * 3000)
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                scratchpad_path=scratchpad,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
            )

        assert "test-compact" in call_names

    @pytest.mark.asyncio
    async def test_empty_scratchpad_returns_no_findings(self, tmp_path: Path):
        """When agent writes nothing, should return 'No findings recorded.'"""
        scratchpad = tmp_path / "test.md"

        async def mock_tracked(*, name, **kwargs):
            # Don't write anything to scratchpad
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            result, _ = await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                scratchpad_path=scratchpad,
                cwd=str(tmp_path),
                mcp_setup=setup,
            )

        assert result == "No findings recorded."

    @pytest.mark.asyncio
    async def test_tool_calls_accumulated(self, tmp_path: Path):
        """Tool calls should be counted across all waves."""
        scratchpad = tmp_path / "test.md"

        async def mock_tracked(*, name, on_tool=None, **kwargs):
            if on_tool and not name.endswith("-synthesis"):
                for i in range(3):
                    on_tool(name, "Task", f"explore{i}", False)
            if name == "test-synthesis":
                return ("Synthesized", "")
            scratchpad.write_text("findings")
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            _, tool_calls = await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                scratchpad_path=scratchpad,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
            )

        # 3 tool calls per wave × 2 waves = 6
        assert tool_calls == 6

    @pytest.mark.asyncio
    async def test_on_todos_callback_forwarded(self, tmp_path: Path):
        """on_todos should be passed through to _run_tracked_agent."""
        scratchpad = tmp_path / "test.md"
        captured_kwargs = []

        async def mock_tracked(*, name, on_todos=None, **kwargs):
            captured_kwargs.append({"name": name, "on_todos": on_todos})
            if name == "test-synthesis":
                return ("Synthesized", "")
            scratchpad.write_text("findings")
            return ("wave output", "")

        def my_on_todos(agent_name, todos):
            pass

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                scratchpad_path=scratchpad,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
                on_todos=my_on_todos,
            )

        # Wave call should have on_todos set
        wave_calls = [k for k in captured_kwargs if k["name"] == "test"]
        assert len(wave_calls) == 1
        assert wave_calls[0]["on_todos"] is my_on_todos

    @pytest.mark.asyncio
    async def test_prior_scratchpad_in_prompt(self, tmp_path: Path):
        """Wave 2 prompt should include prior scratchpad contents."""
        scratchpad = tmp_path / "test.md"
        captured_prompts = []

        async def mock_tracked(*, name, prompt, **kwargs):
            if name == "test":
                captured_prompts.append(prompt)
                if len(captured_prompts) == 1:
                    scratchpad.write_text("WAVE1_FINDINGS_TOKEN")
            if name == "test-synthesis":
                return ("Synthesized", "")
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                scratchpad_path=scratchpad,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
            )

        # Wave 2 prompt should contain wave 1's scratchpad contents
        assert len(captured_prompts) == 2
        assert "WAVE1_FINDINGS_TOKEN" in captured_prompts[1]


class TestConfigureFileLogging:
    """Test _configure_file_logging() from CLI module."""

    def test_creates_log_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """Should create .hiro/logs/ dir and return a valid path."""
        monkeypatch.chdir(tmp_path)
        from hiro_agent.cli import _configure_file_logging

        log_path = _configure_file_logging()

        assert os.path.exists(log_path)
        assert ".hiro/logs/hiro-" in log_path
        assert log_path.endswith(".log")

    def test_structlog_writes_to_file(self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
        """After configuring, structlog output should go to the log file."""
        monkeypatch.chdir(tmp_path)
        from hiro_agent.cli import _configure_file_logging

        log_path = _configure_file_logging()

        test_logger = structlog.get_logger("test")
        test_logger.info("test_event", key="value")

        # Flush by reading the file
        content = Path(log_path).read_text()
        assert "test_event" in content
        assert "key" in content
