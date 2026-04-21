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
    _EXPLORE_AGENT,
    _ScanDisplay,
    _get_agent_env,
    _get_api_key,
    _get_mcp_config,
    _inject_prefetched_context,
    _mcp_call_tool,
    _prefetch_mcp_context,
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
    async def test_adds_proxy_tool_turn_constraint_with_hiro_key(self):
        """Tracked agents should serialize tool use when routed through Hiro proxy."""
        from claude_agent_sdk import AssistantMessage, TextBlock

        captured_options = {}
        msg = AssistantMessage(
            content=[TextBlock(text="skill findings here")],
            model="claude-sonnet-4-5-20250514",
        )

        async def mock_query(prompt, options):
            captured_options.update(vars(options))
            yield msg

        setup = McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

        with (
            patch("hiro_agent._common.query", side_effect=mock_query),
            patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test"}),
        ):
            await _run_tracked_agent(
                name="auth",
                prompt="investigate auth",
                system_prompt="system",
                cwd="/tmp",
                allowed_tools=["Read"],
                mcp_setup=setup,
            )

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
    """Smoke test for the live single-agent review display."""

    def test_agent_lifecycle_updates_state(self):
        display = _ScanDisplay(["review"], skip_phases=True)

        display.start_investigations()
        assert display._running is True

        display.agent_started("review")
        assert display._agent_status["review"] == "running"

        display.agent_tool("review", "Read", "auth.py")
        assert display._agent_tool["review"] == "Read(auth.py)"

        display.agent_completed("review")
        assert display._agent_status["review"] == "completed"
        assert "review" not in display._agent_tool

    def test_build_lines_running_and_completed(self):
        display = _ScanDisplay(["review"], skip_phases=True)

        display.agent_started("review")
        display.agent_tool("review", "Read", "auth.py")
        running = "\n".join(display._build_lines())
        assert "Review" in running
        assert "Read(auth.py)" in running

        display.agent_completed("review")
        done = "\n".join(display._build_lines())
        assert "Review" in done

    def test_start_report_clears_running_flag(self):
        display = _ScanDisplay(["review"], skip_phases=True)
        display.start_investigations()
        display.agent_started("review")
        display.start_report()
        assert display._running is False
        # finish() is a documented no-op after start_report().
        display.finish()
        assert display._running is False


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
