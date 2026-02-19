"""Tests for hiro_agent.review_plan — plan review agent."""

from unittest.mock import patch

import pytest

from hiro_agent.review_plan import MAX_TURNS, review_plan


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
            return "### Threat Model\nNo critical threats."

        with patch("hiro_agent.review_plan.run_review_agent", side_effect=mock_run):
            result = await review_plan("## Plan\nBuild a REST API")

        assert "Build a REST API" in captured["prompt"]
        assert result == "### Threat Model\nNo critical threats."

    @pytest.mark.asyncio
    async def test_includes_context(self):
        """Context should appear in the prompt."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["prompt"] = prompt
            return "ok"

        with patch("hiro_agent.review_plan.run_review_agent", side_effect=mock_run):
            await review_plan("plan", context="Public-facing payment API")

        assert "Public-facing payment API" in captured["prompt"]

    @pytest.mark.asyncio
    async def test_no_file_tools(self):
        """Plan review should have empty allowed_tools (no filesystem access)."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)
            return "ok"

        with patch("hiro_agent.review_plan.run_review_agent", side_effect=mock_run):
            await review_plan("plan")

        assert captured["allowed_tools"] == []

    @pytest.mark.asyncio
    async def test_max_turns(self):
        """Should use configured MAX_TURNS = 10."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)
            return "ok"

        with patch("hiro_agent.review_plan.run_review_agent", side_effect=mock_run):
            await review_plan("plan")

        assert captured["max_turns"] == MAX_TURNS
        assert MAX_TURNS == 10

    @pytest.mark.asyncio
    async def test_system_prompt_is_stride(self):
        """Should use PLAN_REVIEW_SYSTEM_PROMPT with STRIDE references."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["system_prompt"] = system_prompt
            return "ok"

        with patch("hiro_agent.review_plan.run_review_agent", side_effect=mock_run):
            await review_plan("plan")

        assert "STRIDE" in captured["system_prompt"]
        assert "poofing" in captured["system_prompt"]
        assert "levation of Privilege" in captured["system_prompt"]
