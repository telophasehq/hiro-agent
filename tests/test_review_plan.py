"""Tests for hiro_agent.review_plan — plan review agent."""

from unittest.mock import patch

import pytest

from hiro_agent.review_plan import ALLOWED_TOOLS, MAX_TURNS, review_plan


class TestReviewPlan:
    """Test review_plan() function."""

    @pytest.mark.asyncio
    async def test_calls_agent_with_plan(self):
        """Should include plan text in the prompt."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["prompt"] = prompt
            captured["system_prompt"] = system_prompt
            captured.update(kwargs)

        with patch("hiro_agent.review_plan.run_streaming_agent", side_effect=mock_run):
            await review_plan("## Plan\nBuild a REST API")

        assert "Build a REST API" in captured["prompt"]

    @pytest.mark.asyncio
    async def test_includes_context(self):
        """Context should appear in the prompt."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["prompt"] = prompt

        with patch("hiro_agent.review_plan.run_streaming_agent", side_effect=mock_run):
            await review_plan("plan", context="Public-facing payment API")

        assert "Public-facing payment API" in captured["prompt"]

    @pytest.mark.asyncio
    async def test_has_file_tools(self):
        """Plan review should have Read, Grep, Glob tools."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)

        with patch("hiro_agent.review_plan.run_streaming_agent", side_effect=mock_run):
            await review_plan("plan")

        assert captured["allowed_tools"] == ["Read", "Grep", "Glob"]
        assert ALLOWED_TOOLS == ["Read", "Grep", "Glob"]

    @pytest.mark.asyncio
    async def test_max_turns(self):
        """Should use configured MAX_TURNS = 15."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)

        with patch("hiro_agent.review_plan.run_streaming_agent", side_effect=mock_run):
            await review_plan("plan")

        assert captured["max_turns"] == MAX_TURNS
        assert MAX_TURNS == 15

    @pytest.mark.asyncio
    async def test_system_prompt_is_stride(self):
        """Should use PLAN_REVIEW_SYSTEM_PROMPT with STRIDE references."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["system_prompt"] = system_prompt

        with patch("hiro_agent.review_plan.run_streaming_agent", side_effect=mock_run):
            await review_plan("plan")

        assert "STRIDE" in captured["system_prompt"]
        assert "poofing" in captured["system_prompt"]
        assert "levation of Privilege" in captured["system_prompt"]

    @pytest.mark.asyncio
    async def test_passes_cwd(self):
        """Should forward cwd to the streaming agent."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)

        with patch("hiro_agent.review_plan.run_streaming_agent", side_effect=mock_run):
            await review_plan("plan", cwd="/tmp/myproject")

        assert captured["cwd"] == "/tmp/myproject"
