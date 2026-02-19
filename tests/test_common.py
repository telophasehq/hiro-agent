"""Tests for hiro_agent._common — shared agent runner."""

import os
from unittest.mock import patch

import pytest

from hiro_agent._common import (
    HIRO_BACKEND_URL,
    HIRO_MCP_URL,
    _get_agent_env,
    _get_mcp_config,
    run_review_agent,
)


class TestGetMcpConfig:
    """Test _get_mcp_config() MCP server configuration."""

    def test_returns_empty_without_api_key(self):
        """Without HIRO_API_KEY, should return empty dict."""
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
        assert HIRO_MCP_URL == "https://api.hiro.is/mcp/architect"

    def test_hardcoded_backend_url(self):
        """Backend URL should be hardcoded constant."""
        assert HIRO_BACKEND_URL == "https://api.hiro.is"


class TestGetAgentEnv:
    """Test _get_agent_env() environment variable builder."""

    def test_always_clears_claudecode(self):
        """CLAUDECODE should always be empty string."""
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("HIRO_API_KEY", None)
            env = _get_agent_env()
            assert env["CLAUDECODE"] == ""

    def test_no_proxy_without_api_key(self):
        """Without HIRO_API_KEY, should not set ANTHROPIC_BASE_URL."""
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
    async def test_calls_query_with_options(self):
        """Should call claude-agent-sdk query with correct options."""
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
    async def test_returns_last_text_block(self):
        """Should return the text from the last AssistantMessage."""
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
        """When HIRO_API_KEY is set, MCP context tools should be in allowed_tools."""
        captured_options = {}

        async def mock_query(prompt, options):
            captured_options.update(vars(options))
            return
            yield  # make it an async generator

        with patch("hiro_agent._common.query", side_effect=mock_query):
            with patch.dict(os.environ, {"HIRO_API_KEY": "hiro_ak_test"}):
                await run_review_agent(
                    prompt="Review",
                    system_prompt="System",
                    allowed_tools=["Read"],
                )

        allowed = captured_options["allowed_tools"]
        assert "Read" in allowed
        assert "mcp__hiro__get_org_context" in allowed
        assert "mcp__hiro__recall" in allowed
        assert "mcp__hiro__get_security_policy" in allowed
        # Write tools should NOT be allowed
        assert "mcp__hiro__remember" not in allowed
        assert "mcp__hiro__set_org_context" not in allowed
        assert "mcp__hiro__forget" not in allowed

    @pytest.mark.asyncio
    async def test_no_mcp_tools_without_key(self):
        """Without HIRO_API_KEY, MCP tools should not be in allowed_tools."""
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
