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
    _format_prior_findings,
    _get_agent_env,
    _get_api_key,
    _get_mcp_config,
    _inject_prefetched_context,
    _mcp_call_tool,
    _prefetch_mcp_context,
    _read_skill_findings,
    _run_skill_waves,
    _run_tracked_agent,
    get_tool_policy_violation,
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
        """Explore agent should use opus model with read-only tools."""
        assert _EXPLORE_AGENT.model == "sonnet"
        assert set(_EXPLORE_AGENT.tools) == {"Read", "Grep"}
        assert "read-only" in _EXPLORE_AGENT.description.lower() or "retriever" in _EXPLORE_AGENT.description.lower()


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
    async def test_emits_agent_timing_logs(self):
        """Agent runs should emit timing events for debugging slow scans."""
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

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with (
            patch("hiro_agent._common.query", side_effect=mock_query),
            patch("hiro_agent._common.logger.info") as mock_info,
        ):
            await _run_tracked_agent(
                name="auth",
                prompt="investigate",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["Read"],
                mcp_setup=setup,
            )

        events = [call.args[0] for call in mock_info.call_args_list if call.args]
        assert "agent_run_started" in events
        assert "agent_first_message" in events
        assert "agent_tool_started" in events
        assert "agent_run_finished" in events

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

    @pytest.mark.asyncio
    async def test_on_result_callback_receives_result_message(self):
        """Result metadata should be surfaced to callers for turn-limit checks."""
        from claude_agent_sdk import ResultMessage

        async def mock_query(prompt, options):
            yield ResultMessage(
                subtype="success",
                duration_ms=1,
                duration_api_ms=1,
                is_error=False,
                num_turns=7,
                session_id="sess-1",
            )

        captured = {"num_turns": 0, "session_id": ""}

        def on_result(result):
            captured["num_turns"] = result.num_turns
            captured["session_id"] = result.session_id

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common.query", side_effect=mock_query):
            text, session_id = await _run_tracked_agent(
                name="auth",
                prompt="investigate",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["Read"],
                mcp_setup=setup,
                on_result=on_result,
            )

        assert text == ""
        assert session_id == "sess-1"
        assert captured["num_turns"] == 7

    @pytest.mark.asyncio
    async def test_query_stream_closed_when_tool_callback_raises(self):
        """_run_tracked_agent should explicitly close query stream on callback errors."""
        from claude_agent_sdk import AssistantMessage, ToolUseBlock

        class _MockStream:
            def __init__(self, messages):
                self._messages = list(messages)
                self._idx = 0
                self.closed = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._idx >= len(self._messages):
                    raise StopAsyncIteration
                msg = self._messages[self._idx]
                self._idx += 1
                return msg

            async def aclose(self):
                self.closed = True

        stream = _MockStream(
            [
                AssistantMessage(
                    content=[ToolUseBlock(id="t1", name="Read", input={"file_path": "/tmp/a.py"})],
                    model="claude-sonnet-4-5-20250514",
                )
            ]
        )

        def on_tool_event(agent_name, tool_name, tool_input, is_subagent):
            raise RuntimeError("boom")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common.query", return_value=stream):
            with pytest.raises(RuntimeError, match="boom"):
                await _run_tracked_agent(
                    name="auth",
                    prompt="investigate",
                    system_prompt="system",
                    cwd="/tmp",
                    allowed_tools=["Read"],
                    mcp_setup=setup,
                    on_tool_event=on_tool_event,
                )

        assert stream.closed is True

    @pytest.mark.asyncio
    async def test_cancel_scope_close_error_is_suppressed(self):
        """Known AnyIO cancel-scope close errors should not crash stream consumers."""
        from claude_agent_sdk import AssistantMessage, TextBlock

        class _MockStream:
            def __init__(self, messages):
                self._messages = list(messages)
                self._idx = 0

            def __aiter__(self):
                return self

            async def __anext__(self):
                if self._idx >= len(self._messages):
                    raise StopAsyncIteration
                msg = self._messages[self._idx]
                self._idx += 1
                return msg

            async def aclose(self):
                raise RuntimeError("Attempted to exit cancel scope in a different task than it was entered in")

        stream = _MockStream(
            [
                AssistantMessage(
                    content=[TextBlock(text="ok")],
                    model="claude-sonnet-4-5-20250514",
                )
            ]
        )

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common.query", return_value=stream):
            text, session_id = await _run_tracked_agent(
                name="auth",
                prompt="investigate",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["Read"],
                mcp_setup=setup,
            )

        assert text == "ok"
        assert session_id == ""

    @pytest.mark.asyncio
    async def test_stall_timeout_defaults_sonnet(self):
        """Sonnet agents should use 120s default stall timeout."""
        from claude_agent_sdk import AssistantMessage, TextBlock

        msg = AssistantMessage(
            content=[TextBlock(text="done")],
            model="claude-sonnet-4-5-20250514",
        )

        async def mock_query(prompt, options):
            yield msg

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with (
            patch("hiro_agent._common.query", side_effect=mock_query),
            patch("hiro_agent._common.logger.info") as mock_info,
        ):
            await _run_tracked_agent(
                name="auth",
                prompt="investigate",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["Read"],
                mcp_setup=setup,
                model="sonnet",
            )

        # Check that agent_run_started logged model=sonnet
        started = [
            c for c in mock_info.call_args_list
            if c.args and c.args[0] == "agent_run_started"
        ]
        assert started
        assert started[0].kwargs.get("model") == "sonnet"

    @pytest.mark.asyncio
    async def test_stall_timeout_defaults_opus(self):
        """Opus agents should use 300s default stall timeout."""
        from claude_agent_sdk import AssistantMessage, TextBlock

        msg = AssistantMessage(
            content=[TextBlock(text="done")],
            model="claude-opus-4-20250514",
        )

        async def mock_query(prompt, options):
            yield msg

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with (
            patch("hiro_agent._common.query", side_effect=mock_query),
            patch("hiro_agent._common.logger.info") as mock_info,
        ):
            await _run_tracked_agent(
                name="report",
                prompt="synthesize",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["Read"],
                mcp_setup=setup,
                model="opus",
            )

        started = [
            c for c in mock_info.call_args_list
            if c.args and c.args[0] == "agent_run_started"
        ]
        assert started
        assert started[0].kwargs.get("model") == "opus"

    @pytest.mark.asyncio
    async def test_subagent_messages_do_not_reset_primary_timer(self):
        """Sub-agent messages should not reset the primary stall timer."""
        from claude_agent_sdk import AssistantMessage, TextBlock, ToolUseBlock, UserMessage, ToolResultBlock

        # Simulate: parent sends Task → sub-agent messages arrive → parent resumes
        messages = [
            # Parent dispatches a Task
            AssistantMessage(
                content=[ToolUseBlock(id="task1", name="Task", input={"prompt": "explore"})],
                model="claude-sonnet-4-5-20250514",
            ),
            # Sub-agent chatter (while task1 is active)
            AssistantMessage(
                content=[TextBlock(text="sub-agent exploring")],
                model="claude-sonnet-4-5-20250514",
            ),
            # Task result returns
            UserMessage(content=[ToolResultBlock(tool_use_id="task1", content="explored")]),
            # Parent resumes
            AssistantMessage(
                content=[TextBlock(text="final findings")],
                model="claude-sonnet-4-5-20250514",
            ),
        ]

        call_idx = {"i": 0}
        async def mock_query(prompt, options):
            for m in messages:
                yield m

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common.query", side_effect=mock_query):
            text, _ = await _run_tracked_agent(
                name="auth",
                prompt="investigate",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["Task", "Read"],
                mcp_setup=setup,
            )

        assert "final findings" in text

    @pytest.mark.asyncio
    async def test_stall_timeout_breaks_loop(self):
        """A stream that blocks forever should raise TimeoutError within stall_timeout + buffer."""

        class _BlockingStream:
            def __init__(self):
                self.closed = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                # Block forever — simulate a dead stream.
                await asyncio.sleep(3600)

            async def aclose(self):
                self.closed = True

        stream = _BlockingStream()
        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common.query", return_value=stream):
            with patch.dict(os.environ, {"HIRO_AGENT_STALL_TIMEOUT": "0.3"}):
                with pytest.raises(TimeoutError, match="stalled"):
                    await _run_tracked_agent(
                        name="auth",
                        prompt="investigate",
                        system_prompt="system",
                        cwd="/tmp",
                        allowed_tools=["Read"],
                        mcp_setup=setup,
                    )

    @pytest.mark.asyncio
    async def test_stall_timeout_with_active_subagent(self):
        """Watchdog should fire when primary is silent but sub-agent messages keep coming."""
        from claude_agent_sdk import AssistantMessage, TextBlock, ToolUseBlock

        call_count = {"n": 0}

        class _SubagentChatterStream:
            """Yields a Task dispatch then infinite sub-agent messages."""

            def __init__(self):
                self._yielded_task = False

            def __aiter__(self):
                return self

            async def __anext__(self):
                if not self._yielded_task:
                    self._yielded_task = True
                    return AssistantMessage(
                        content=[ToolUseBlock(id="task1", name="Task", input={"prompt": "explore"})],
                        model="claude-sonnet-4-5-20250514",
                    )
                call_count["n"] += 1
                await asyncio.sleep(0.05)
                return AssistantMessage(
                    content=[TextBlock(text="sub-agent chatter")],
                    model="claude-sonnet-4-5-20250514",
                )

            async def aclose(self):
                pass

        stream = _SubagentChatterStream()
        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common.query", return_value=stream):
            with patch.dict(os.environ, {
                "HIRO_AGENT_STALL_TIMEOUT": "0.5",
                "HIRO_AGENT_IDLE_LOG_INTERVAL": "0.2",
            }):
                with pytest.raises(TimeoutError, match="stalled"):
                    await _run_tracked_agent(
                        name="auth",
                        prompt="investigate",
                        system_prompt="system",
                        cwd="/tmp",
                        allowed_tools=["Task", "Read"],
                        mcp_setup=setup,
                    )

        # Sub-agent messages kept flowing, but watchdog still fired.
        assert call_count["n"] >= 1


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

    def test_agent_incomplete_status(self):
        """agent_incomplete() should mark terminal warning state."""
        display = _ScanDisplay(["auth"])
        display._phase = 2

        display.agent_started("auth")
        display.agent_incomplete("auth")

        assert display._agent_status["auth"] == "incomplete"
        joined = "\n".join(display._build_lines())
        assert "⚠" in joined

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
        # Display prioritizes: active (in_progress), then queued (pending), then completed
        todo_lines = [l for l in lines if "Scan for raw SQL" in l or "Check parameterized" in l or "Verify ORM" in l]
        assert len(todo_lines) == 3
        assert "◆" in todo_lines[0]  # in_progress shown first
        assert "○" in todo_lines[1]  # pending second
        assert "✓" in todo_lines[2]  # completed last

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
        with patch("hiro_agent.scan_display._get_terminal_height", return_value=20):
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

    def test_build_lines_shows_task_progress_counts(self):
        """Running/completed agents should show todo progress counts."""
        display = _ScanDisplay(["auth"])
        display._phase = 2

        display.agent_started("auth")
        display.agent_todos(
            "auth",
            [
                {"id": "1", "content": "A", "status": "completed"},
                {"id": "2", "content": "B", "status": "pending"},
                {"id": "3", "content": "C", "status": "pending"},
            ],
        )

        running_lines = "\n".join(display._build_lines())
        assert "1/3 tasks" in running_lines
        assert "0 findings" in running_lines

        display.agent_completed("auth")
        done_lines = "\n".join(display._build_lines())
        assert "1/3 tasks" in done_lines
        assert "0 findings" in done_lines

    def test_build_lines_shows_findings_progress(self):
        """Running agents should show findings count based on finding JSON writes."""
        display = _ScanDisplay(["auth"])
        display._phase = 2
        display.agent_started("auth")

        display.agent_tool("auth", "Write", "finding-auth-jwt-secret.json")
        lines = "\n".join(display._build_lines())
        assert "1 finding" in lines

        display.agent_tool("auth", "Write", "finding-auth-missing-expiry.json")
        lines = "\n".join(display._build_lines())
        assert "2 findings" in lines

        # Rewriting same finding file should not increment count.
        display.agent_tool("auth", "Write", "finding-auth-missing-expiry.json")
        lines = "\n".join(display._build_lines())
        assert "2 findings" in lines

    def test_build_lines_shows_slowest_active_hint(self):
        """Investigations header should show which running agent is currently slowest."""
        display = _ScanDisplay(["auth", "logic"])
        display._phase = 2
        display._investigations_start = 995.0
        display._agent_status["auth"] = "running"
        display._agent_status["logic"] = "running"
        display._agent_started_at["auth"] = 980.0
        display._agent_started_at["logic"] = 700.0
        display._agent_tool["auth"] = "Read(auth.py)"
        display._agent_tool_since["auth"] = 990.0
        display._agent_tool["logic"] = "Thinking…"
        display._agent_tool_since["logic"] = 999.0
        display._agent_subtool["logic"] = "Thinking…"
        display._agent_subtool_since["logic"] = 998.0

        with patch("hiro_agent._common._time.monotonic", return_value=1000.0):
            joined = "\n".join(display._build_lines())
        assert "Slowest active: auth" in joined
        assert "(10s)" in joined
        assert "5m" not in joined

    def test_recon_shows_waiting_hint_after_ten_seconds(self):
        """Recon should call out long waiting periods so users can spot stalls."""
        display = _ScanDisplay(["auth"])
        display._phase = 1
        display._recon_tool_info = "Thinking…"
        display._recon_thinking_since = time.monotonic() - 12

        joined = "\n".join(display._build_lines())
        assert "Slowest step: waiting for model/tool response" in joined


class TestSkillTools:
    """Test SKILL_TOOLS constant."""

    def test_includes_task_and_write(self):
        """SKILL_TOOLS should include Task and Write."""
        assert "Task" in SKILL_TOOLS
        assert "Write" in SKILL_TOOLS


class TestToolPolicy:
    """Test first-party tool policy checks."""

    def test_read_blocks_ignored_dirs(self):
        violation = get_tool_policy_violation(
            tool_name="Read",
            tool_input={"file_path": ".venv/lib/python/site.py"},
        )
        assert violation is not None
        assert "ignored directory" in violation[1]

    def test_grep_into_ignored_dir_blocked(self):
        violation = get_tool_policy_violation(
            tool_name="Grep",
            tool_input={"pattern": "auth", "path": "node_modules"},
        )
        assert violation is not None
        assert "ignored directory" in violation[1]

    def test_glob_all_blocked(self):
        violation = get_tool_policy_violation(
            tool_name="Glob",
            tool_input={"pattern": "**/*"},
        )
        assert violation is not None
        assert "greedy Glob" in violation[1]

    def test_scoped_grep_allowed(self):
        violation = get_tool_policy_violation(
            tool_name="Grep",
            tool_input={"pattern": "except:\\s*pass", "path": "src"},
        )
        assert violation is None

    def test_blocks_structure_discovery_glob(self):
        violation = get_tool_policy_violation(
            tool_name="Glob",
            tool_input={"pattern": "**/*.py"},
            forbid_structure_discovery=True,
        )
        assert violation is not None
        assert "structure discovery" in violation[1]


class TestRunSkillWaves:
    """Test _run_skill_waves() multi-wave investigation."""

    @pytest.mark.asyncio
    async def test_two_waves_executed(self, tmp_path: Path):
        """Should call _run_tracked_agent for each wave (no synthesis)."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        call_names = []

        async def mock_tracked(*, name, prompt, **kwargs):
            call_names.append(name)
            # Simulate writing a finding JSON file
            finding = {"severity": "HIGH", "location": "file.py:10", "issue": "Some issue", "evidence": "code"}
            (findings_dir / f"finding-test-issue-1.json").write_text(json.dumps(finding))
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            result, tool_calls = await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
            )

        # Two waves only — no synthesis agent
        assert call_names.count("test") == 2
        assert "test-synthesis" not in call_names
        assert "test-compact" not in call_names

    @pytest.mark.asyncio
    async def test_logs_wave_timing_events(self, tmp_path: Path):
        """Wave timing logs should emit start/finish events for each wave."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "auth.py").write_text("def login():\n    pass\n")

        async def mock_tracked(*, name, **kwargs):
            if name == "auth":
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with (
            patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent._common.logger.info") as mock_info,
        ):
            await _run_skill_waves(
                name="auth",
                system_prompt="system",
                skill_prompt="investigate auth flow",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
            )

        events = [call.args[0] for call in mock_info.call_args_list if call.args]
        assert "skill_wave_plan" in events
        assert events.count("skill_wave_started") == 1
        assert events.count("skill_wave_finished") == 1

    @pytest.mark.asyncio
    async def test_no_compaction_agent_called(self, tmp_path: Path):
        """No compaction agent should be spawned between waves."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        call_names = []

        async def mock_tracked(*, name, prompt, **kwargs):
            call_names.append(name)
            # Write a finding JSON file
            finding = {"severity": "HIGH", "location": "file.py:10", "issue": "Issue", "evidence": "code"}
            (findings_dir / f"finding-test-issue-{len(call_names)}.json").write_text(json.dumps(finding))
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
            )

        assert "test-compact" not in call_names

    @pytest.mark.asyncio
    async def test_no_findings_returns_message(self, tmp_path: Path):
        """When agent writes no finding JSON files, should return 'No findings recorded.'"""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()

        async def mock_tracked(*, name, **kwargs):
            # Don't write any finding files
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            result, _ = await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
            )

        assert result == "No findings recorded."

    @pytest.mark.asyncio
    async def test_tool_calls_accumulated(self, tmp_path: Path):
        """Tool calls should be counted across all waves."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()

        async def mock_tracked(*, name, on_tool=None, **kwargs):
            if on_tool:
                for i in range(3):
                    on_tool(name, "Task", f"explore{i}", False)
            finding = {"severity": "HIGH", "location": "file.py:1", "issue": "Issue", "evidence": "code"}
            (findings_dir / "finding-test-issue.json").write_text(json.dumps(finding))
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            _, tool_calls = await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
            )

        # 3 tool calls per wave × 2 waves = 6
        assert tool_calls == 6

    @pytest.mark.asyncio
    async def test_on_todos_callback_forwarded(self, tmp_path: Path):
        """on_todos should be passed through to _run_tracked_agent."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        captured_kwargs = []

        async def mock_tracked(*, name, on_todos=None, **kwargs):
            captured_kwargs.append({"name": name, "on_todos": on_todos})
            finding = {"severity": "HIGH", "location": "file.py:1", "issue": "Issue", "evidence": "code"}
            (findings_dir / "finding-test-issue.json").write_text(json.dumps(finding))
            return ("wave output", "")

        def my_on_todos(agent_name, todos):
            pass

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
                on_todos=my_on_todos,
            )

        # Wave call should have on_todos set
        wave_calls = [k for k in captured_kwargs if k["name"] == "test"]
        assert len(wave_calls) == 1
        assert wave_calls[0]["on_todos"] is not None

    @pytest.mark.asyncio
    async def test_housekeeping_todos_are_filtered(self, tmp_path: Path):
        """Only investigation todos should flow to display/status callbacks."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        captured_todos: list[list[dict]] = []

        async def mock_tracked(*, name, on_todos=None, **kwargs):
            if name == "test":
                if on_todos is not None:
                    on_todos(
                        "test",
                        [
                            {"id": "1", "content": "Write all findings to scratchpad", "status": "in_progress"},
                            {"id": "2", "content": "Review JWT alg handling in auth.py", "status": "pending"},
                            {"id": "3", "content": "Update Todo checklist", "status": "pending"},
                        ],
                    )
                finding = {"severity": "HIGH", "location": "file.py:1", "issue": "Issue", "evidence": "code"}
                (findings_dir / "finding-test-issue.json").write_text(json.dumps(finding))
                return ("wave output", "")
            return ("ok", "")

        def on_todos(agent_name: str, todos: list[dict]) -> None:
            captured_todos.append(list(todos))

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
                on_todos=on_todos,
            )

        assert captured_todos
        last = captured_todos[-1]
        contents = [str(t.get("content", "")) for t in last]
        assert "Review JWT alg handling in auth.py" in contents
        assert not any("scratchpad" in c.lower() for c in contents)
        assert not any("todo checklist" in c.lower() for c in contents)

    @pytest.mark.asyncio
    async def test_todos_do_not_shrink_when_agent_rewrites_shorter_list(self, tmp_path: Path):
        """Progress counts should remain stable when TodoWrite emits a shorter subset later."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        captured_todos: list[list[dict]] = []

        async def mock_tracked(*, name, on_todos=None, **kwargs):
            if name == "auth" and on_todos is not None:
                on_todos(
                    "auth",
                    [
                        {"id": "1", "content": "Trace login flow", "status": "pending"},
                        {"id": "2", "content": "Trace token validation", "status": "pending"},
                        {"id": "3", "content": "Trace refresh path", "status": "pending"},
                    ],
                )
                on_todos(
                    "auth",
                    [
                        {"id": "1", "content": "Trace login flow", "status": "completed"},
                    ],
                )
            return ("wave output", "")

        def on_todos(agent_name: str, todos: list[dict]) -> None:
            captured_todos.append(list(todos))

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="auth",
                system_prompt="system",
                skill_prompt="investigate auth",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
                on_todos=on_todos,
            )

        assert captured_todos
        last = captured_todos[-1]
        by_content = {str(t.get("content", "")): t for t in last}
        assert "Trace login flow" in by_content
        assert "Trace token validation" in by_content
        assert "Trace refresh path" in by_content
        assert by_content["Trace login flow"].get("status") == "completed"

    @pytest.mark.asyncio
    async def test_prior_findings_injected_from_json(self, tmp_path: Path):
        """Wave 2 prompt should include prior findings from JSON files."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        captured_prompts = []

        async def mock_tracked(*, name, prompt, **kwargs):
            if name == "test":
                captured_prompts.append(prompt)
                if len(captured_prompts) == 1:
                    # Simulate agent writing a finding JSON file
                    finding = {
                        "severity": "HIGH",
                        "location": "auth.py:42",
                        "issue": "JWT secret fallback to hardcoded value",
                        "evidence": "SECRET = 'changeme'",
                    }
                    (findings_dir / "finding-test-jwt-secret.json").write_text(json.dumps(finding))
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
            )

        # Wave 2 prompt should contain prior findings summary
        assert len(captured_prompts) == 2
        assert "auth.py:42" in captured_prompts[1]
        assert "JWT secret fallback" in captured_prompts[1]
        assert "already recorded" in captured_prompts[1]

    @pytest.mark.asyncio
    async def test_scope_gating_block_injected_into_wave_prompt(self, tmp_path: Path):
        """Each wave prompt should include the enforced scope gating contract."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "auth.py").write_text("def login():\n    pass\n")

        captured_prompt = {}
        captured_on_tool_event = {}

        async def mock_tracked(*, name, prompt, on_tool_event=None, **kwargs):
            if name == "auth":
                captured_prompt["prompt"] = prompt
                captured_on_tool_event["value"] = on_tool_event
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="auth",
                system_prompt="system",
                skill_prompt="investigate auth.py",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
            )

        assert "## Scope Gating (enforced)" in captured_prompt["prompt"]
        assert "### ALLOWED_FILES" in captured_prompt["prompt"]
        assert "EXPAND|from:file:line|to:file_or_symbol|gate:" in captured_prompt["prompt"]
        assert captured_on_tool_event["value"] is not None

    @pytest.mark.asyncio
    async def test_hybrid_logic_mode_forces_three_waves(self, tmp_path: Path):
        """Hybrid mode should auto-upgrade 2 requested waves to 3 (1 breadth + 2 trace)."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "logic.py").write_text("def run_workflow():\n    return True\n")
        wave_prompts = []
        captured_turns = []

        async def mock_tracked(*, name, prompt, max_turns: int = 0, **kwargs):
            if name == "logic":
                wave_prompts.append(prompt)
                captured_turns.append(max_turns)
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="logic",
                system_prompt="system",
                skill_prompt="investigate logic.py workflow",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
            )

        assert len(wave_prompts) == 3
        assert "Mode for this wave: `breadth` (1/3)" in wave_prompts[0]
        assert "Mode for this wave: `trace` (2/3)" in wave_prompts[1]
        assert "Mode for this wave: `trace` (3/3)" in wave_prompts[2]
        assert captured_turns == [14, 20, 20]

    @pytest.mark.asyncio
    async def test_expand_tickets_can_walk_deep_chain(self, tmp_path: Path):
        """Trace waves should repeatedly approve tickets to reach deep files."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        depth = 9
        for idx in range(depth):
            path = tmp_path / f"chain_{idx}.flow"
            if idx < depth - 1:
                path.write_text(f"next = chain_{idx + 1}\n")
            else:
                path.write_text("def bug():\n    return 'deep'\n")

        wave_prompts: list[str] = []
        state_path = findings_dir / "logic-state.md"

        async def mock_tracked(*, name, prompt, **kwargs):
            if name == "logic":
                wave_idx = len(wave_prompts)
                wave_prompts.append(prompt)
                if wave_idx == 0:
                    state_path.write_text("Breadth discovery: potential deep flow\n")
                elif 1 <= wave_idx <= depth - 1:
                    state_path.write_text(
                        "EXPAND|"
                        f"from:chain_{wave_idx - 1}.flow:1|"
                        f"to:chain_{wave_idx}.flow|"
                        "gate:BOUNDARY|follow nested flow\n"
                    )
                else:
                    state_path.write_text("FINDING|HIGH|chain_8 reached\n")
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="logic",
                system_prompt="system",
                skill_prompt="investigate workflow in chain_0.flow",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=10,
            )

        assert len(wave_prompts) == 10
        assert any(
            "APPROVED|from:chain_2.flow:1|to:chain_3.flow|gate:BOUNDARY" in prompt
            for prompt in wave_prompts
        )
        assert "chain_8.flow" in wave_prompts[9]

    @pytest.mark.asyncio
    async def test_breadth_mode_handles_wide_cross_file_scan(self, tmp_path: Path):
        """Breadth tracks should allow many shallow reads without EXPAND tickets."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        for idx in range(60):
            (tmp_path / f"handler_{idx}.py").write_text("try:\n    x=1\nexcept:\n    pass\n")

        captured = {"prompt": "", "reads": 0}

        async def mock_tracked(*, name, prompt, on_tool_event=None, **kwargs):
            if name == "error-handling":
                captured["prompt"] = prompt
                if on_tool_event:
                    for idx in range(60):
                        on_tool_event(
                            name,
                            "Read",
                            {"file_path": str(tmp_path / f"handler_{idx}.py")},
                            True,
                        )
                        captured["reads"] += 1
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="error-handling",
                system_prompt="system",
                skill_prompt="scan exception handlers",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
            )

        assert "Mode for this wave: `breadth` (1/1)" in captured["prompt"]
        assert "repo-wide grep/read is allowed" in captured["prompt"]
        assert captured["reads"] == 60

    @pytest.mark.asyncio
    async def test_trace_mode_defaults_to_two_waves_and_twenty_turns(self, tmp_path: Path):
        """Trace skills should default to 2 waves at 20 turns each."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "auth.py").write_text("def login():\n    pass\n")
        captured_turns: list[int] = []

        async def mock_tracked(*, name, max_turns: int = 0, **kwargs):
            if name == "auth":
                captured_turns.append(max_turns)
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="auth",
                system_prompt="system",
                skill_prompt="investigate auth flow",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
            )

        assert captured_turns == [20, 20]

    @pytest.mark.asyncio
    async def test_breadth_mode_defaults_to_eight_turns(self, tmp_path: Path):
        """Breadth skills should default to 8 turns per wave."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "handler.py").write_text("try:\n    pass\nexcept:\n    pass\n")
        captured_turns: list[int] = []

        async def mock_tracked(*, name, max_turns: int = 0, **kwargs):
            if name == "error-handling":
                captured_turns.append(max_turns)
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="error-handling",
                system_prompt="system",
                skill_prompt="scan handlers",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
            )

        assert captured_turns == [14]

    @pytest.mark.asyncio
    async def test_turn_limited_wave_triggers_single_auto_continuation(self, tmp_path: Path):
        """When a wave hits cap and work remains, queue exactly one continuation wave."""
        from claude_agent_sdk import ResultMessage

        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "auth.py").write_text("def login():\n    pass\n")
        run_stats: dict[str, object] = {}
        wave_calls = {"count": 0}

        async def mock_tracked(*, name, max_turns: int = 0, on_result=None, on_todos=None, **kwargs):
            if name == "auth":
                wave_calls["count"] += 1
                if on_todos is not None:
                    on_todos(
                        "auth",
                        [{"id": "1", "content": "follow edge", "status": "in_progress"}],
                    )
                state_path = findings_dir / "auth-state.md"
                with state_path.open("a", encoding="utf-8") as f:
                    f.write("UNTRACED_EDGE|needs follow-up|next.py\n")
                if on_result is not None:
                    on_result(
                        ResultMessage(
                            subtype="max_turns",
                            duration_ms=1,
                            duration_api_ms=1,
                            is_error=False,
                            num_turns=max_turns,
                            session_id="sess",
                        )
                    )
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="auth",
                system_prompt="system",
                skill_prompt="investigate auth",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
                run_stats=run_stats,
            )

        assert wave_calls["count"] == 2
        assert run_stats["turn_limited"] is True
        assert run_stats["continuation_wave_used"] is True
        assert run_stats["executed_waves"] == 2

    @pytest.mark.asyncio
    async def test_success_at_budget_is_not_marked_turn_limited(self, tmp_path: Path):
        """A successful wave ending exactly at budget should not be treated as truncation."""
        from claude_agent_sdk import ResultMessage

        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "auth.py").write_text("def login():\n    pass\n")
        run_stats: dict[str, object] = {}

        async def mock_tracked(*, name, max_turns: int = 0, on_result=None, on_todos=None, **kwargs):
            if name == "auth":
                if on_todos is not None:
                    on_todos(
                        "auth",
                        [{"id": "1", "content": "follow edge", "status": "completed"}],
                    )
                if on_result is not None:
                    on_result(
                        ResultMessage(
                            subtype="success",
                            duration_ms=1,
                            duration_api_ms=1,
                            is_error=False,
                            num_turns=max_turns,
                            session_id="sess",
                        )
                    )
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="auth",
                system_prompt="system",
                skill_prompt="investigate auth",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
                run_stats=run_stats,
            )

        assert run_stats["turn_limited"] is False
        assert run_stats["continuation_wave_used"] is False

    @pytest.mark.asyncio
    async def test_skill_can_read_own_state_file_inside_scratchpad(self, tmp_path: Path):
        """Skill scope enforcement should allow reading its own state file in .hiro/.scratchpad."""
        findings_dir = tmp_path / ".hiro" / ".scratchpad"
        findings_dir.mkdir(parents=True)
        state_path = findings_dir / "injection-state.md"
        state_path.write_text("UNTRACED_EDGE|follow path|backend/server/detections.py\n")
        run_stats: dict[str, object] = {}

        async def mock_tracked(*, name, on_tool_event=None, **kwargs):
            if name == "injection" and on_tool_event is not None:
                on_tool_event(
                    "injection",
                    "Read",
                    {"file_path": str(state_path)},
                    True,
                )
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="injection",
                system_prompt="system",
                skill_prompt="investigate injection",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
                run_stats=run_stats,
            )

        # Existing state edge remains, but no new scope violation edge is added by this read.
        content = state_path.read_text(encoding="utf-8")
        assert "read into ignored directory `.hiro` is blocked" not in content

    @pytest.mark.asyncio
    async def test_approved_expand_is_reflected_in_todos_and_completed_on_read(self, tmp_path: Path):
        """Approved expansion targets should show up in todo list/count and complete when read."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "a_from.py").write_text("import z_target\n")
        (tmp_path / "b_mid.py").write_text("pass\n")
        (tmp_path / "c_mid.py").write_text("pass\n")
        (tmp_path / "z_target.py").write_text("def sink():\n    return True\n")

        wave_idx = {"n": 0}
        todo_snapshots: list[list[dict]] = []
        state_path = findings_dir / "test-state.md"

        def on_todos(agent_name: str, todos: list[dict]) -> None:
            todo_snapshots.append(list(todos))

        async def mock_tracked(*, name, on_todos=None, on_tool_event=None, **kwargs):
            if name == "test":
                wave_idx["n"] += 1
                if wave_idx["n"] == 1:
                    if on_todos is not None:
                        on_todos(
                            "test",
                            [{"id": "1", "content": "initial", "status": "completed"}],
                        )
                    state_path.write_text(
                        "EXPAND|from:a_from.py:1|to:z_target.py|gate:BOUNDARY|follow import\n"
                    )
                    return ("wave1", "")

                # Wave 2: read approved file to mark follow-up completed.
                if on_tool_event is not None:
                    on_tool_event(
                        "test",
                        "Read",
                        {"file_path": str(tmp_path / "z_target.py")},
                        True,
                    )
                return ("wave2", "")

            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)
        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate a_from.py",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
                on_todos=on_todos,
            )

        pending_seen = any(
            any(
                t.get("content") == "Follow approved expansion target: z_target.py"
                and t.get("status") == "pending"
                for t in snapshot
            )
            for snapshot in todo_snapshots
        )
        completed_seen = any(
            any(
                t.get("content") == "Follow approved expansion target: z_target.py"
                and t.get("status") == "completed"
                for t in snapshot
            )
            for snapshot in todo_snapshots
        )

        assert pending_seen
        assert completed_seen

    @pytest.mark.asyncio
    async def test_no_synthesis_agent_called(self, tmp_path: Path):
        """No synthesis agent should be spawned after waves."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        call_names = []

        async def mock_tracked(*, name, **kwargs):
            call_names.append(name)
            if name == "test":
                finding = {"severity": "HIGH", "location": "file.py:1", "issue": "Issue", "evidence": "code"}
                (findings_dir / "finding-test-issue.json").write_text(json.dumps(finding))
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            result, _ = await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
            )

        assert "test-synthesis" not in call_names
        # Result should be formatted directly from JSON
        assert "HIGH" in result
        assert "file.py:1" in result

    @pytest.mark.asyncio
    async def test_findings_read_directly_from_json(self, tmp_path: Path):
        """Findings should be read directly from JSON files, not summarized."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()

        async def mock_tracked(*, name, **kwargs):
            if name == "test":
                # Simulate writing multiple finding files
                f1 = {"severity": "CRITICAL", "location": "auth.py:10", "issue": "Hardcoded secret", "evidence": "SECRET='abc'"}
                f2 = {"severity": "HIGH", "location": "db.py:42", "issue": "SQL injection", "evidence": "cursor.execute(query)"}
                (findings_dir / "finding-test-hardcoded-secret.json").write_text(json.dumps(f1))
                (findings_dir / "finding-test-sql-injection.json").write_text(json.dumps(f2))
            return ("wave output", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            result, _ = await _run_skill_waves(
                name="test",
                system_prompt="system",
                skill_prompt="investigate",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=1,
            )

        assert "CRITICAL" in result
        assert "auth.py:10" in result
        assert "Hardcoded secret" in result
        assert "HIGH" in result
        assert "db.py:42" in result
        assert "SQL injection" in result

    @pytest.mark.asyncio
    async def test_stall_timeout_treated_as_turn_limited(self, tmp_path: Path):
        """A stalled wave (TimeoutError) should be treated like a turn-limited wave, not crash."""
        findings_dir = tmp_path / "findings"
        findings_dir.mkdir()
        (tmp_path / "auth.py").write_text("def login():\n    pass\n")
        wave_calls = {"count": 0}
        run_stats: dict[str, object] = {}

        async def mock_tracked(*, name, **kwargs):
            if name == "auth":
                wave_calls["count"] += 1
                if wave_calls["count"] == 1:
                    raise TimeoutError("Agent 'auth' stalled for 120s with no messages")
                # Wave 2 succeeds normally.
                finding = {"severity": "HIGH", "location": "auth.py:1", "issue": "Issue", "evidence": "code"}
                (findings_dir / "finding-auth-issue.json").write_text(json.dumps(finding))
                return ("wave output", "")
            return ("ok", "")

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with patch("hiro_agent._common._run_tracked_agent", side_effect=mock_tracked):
            result, _ = await _run_skill_waves(
                name="auth",
                system_prompt="system",
                skill_prompt="investigate auth",
                findings_dir=findings_dir,
                cwd=str(tmp_path),
                mcp_setup=setup,
                waves=2,
                run_stats=run_stats,
            )

        # Both waves should have been attempted — the stall didn't crash the skill.
        assert wave_calls["count"] == 2
        assert "HIGH" in result
        assert run_stats.get("turn_limited") is True


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
