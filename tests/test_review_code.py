"""Tests for hiro_agent.review_code — code review agent."""

from unittest.mock import patch

import pytest

from hiro_agent.review_code import ALLOWED_TOOLS, MAX_TURNS, review_code


class TestReviewCode:
    """Test review_code() function."""

    @pytest.mark.asyncio
    async def test_calls_agent_with_diff(self):
        """Should include diff in the prompt passed to run_review_agent."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["prompt"] = prompt
            captured["system_prompt"] = system_prompt
            captured.update(kwargs)
            return "## Findings\nNo issues."

        with patch("hiro_agent.review_code.run_review_agent", side_effect=mock_run):
            result = await review_code("diff --git a/foo.py\n+import os", cwd="/repo")

        assert "diff --git" in captured["prompt"]
        assert captured["cwd"] == "/repo"
        assert result == "## Findings\nNo issues."

    @pytest.mark.asyncio
    async def test_includes_context_in_prompt(self):
        """Context string should appear in the prompt."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["prompt"] = prompt
            return "ok"

        with patch("hiro_agent.review_code.run_review_agent", side_effect=mock_run):
            await review_code("some diff", context="This is an auth module")

        assert "This is an auth module" in captured["prompt"]

    @pytest.mark.asyncio
    async def test_allowed_tools(self):
        """Should pass Read, Grep, Glob as allowed tools."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)
            return "ok"

        with patch("hiro_agent.review_code.run_review_agent", side_effect=mock_run):
            await review_code("diff")

        assert captured["allowed_tools"] == ["Read", "Grep", "Glob"]

    @pytest.mark.asyncio
    async def test_max_turns(self):
        """Should use configured MAX_TURNS."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)
            return "ok"

        with patch("hiro_agent.review_code.run_review_agent", side_effect=mock_run):
            await review_code("diff")

        assert captured["max_turns"] == MAX_TURNS
        assert MAX_TURNS == 15

    @pytest.mark.asyncio
    async def test_system_prompt_is_code_review(self):
        """Should use CODE_REVIEW_SYSTEM_PROMPT."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["system_prompt"] = system_prompt
            return "ok"

        with patch("hiro_agent.review_code.run_review_agent", side_effect=mock_run):
            await review_code("diff")

        assert "OWASP Top 10" in captured["system_prompt"]
        assert "Read, Grep, and Glob" in captured["system_prompt"]
