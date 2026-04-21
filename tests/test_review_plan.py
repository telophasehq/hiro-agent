"""Tests for hiro_agent.review_plan — single-agent plan security review."""

from unittest.mock import AsyncMock, patch

import pytest

from hiro_agent._common import McpSetup, ToolPolicyViolationError
from hiro_agent.review_plan import review_plan
from hiro_agent.skills import SKILL_NAMES


class TestReviewPlan:
    """Test single-agent review_plan() flow."""

    @pytest.fixture
    def mock_mcp_setup(self):
        return McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

    @pytest.fixture
    def tmp_cwd(self, tmp_path):
        return str(tmp_path)

    @pytest.mark.asyncio
    async def test_plan_written_to_tempfile_and_path_in_prompt(self, mock_mcp_setup, tmp_cwd):
        """Plan is written to a temp .md file; the prompt references that path."""
        captured = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            captured["name"] = name
            captured["prompt"] = prompt
            return ("Stride report body", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("Proposed payment module design", cwd=tmp_cwd)

        assert captured["name"] == "review"
        assert "hiro-plan-" in captured["prompt"]
        assert ".md" in captured["prompt"]

    @pytest.mark.asyncio
    async def test_context_passed_through(self, mock_mcp_setup, tmp_cwd):
        """Context string should appear in the agent prompt."""
        captured = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            captured["prompt"] = prompt
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("plan", cwd=tmp_cwd, context="Public-facing payment API")

        assert "Public-facing payment API" in captured["prompt"]

    @pytest.mark.asyncio
    async def test_mcp_called_once(self, mock_mcp_setup, tmp_cwd):
        """prepare_mcp should be called exactly once."""
        mock_prepare = AsyncMock(return_value=mock_mcp_setup)

        async def mock_tracked(*, name, **kwargs):
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", mock_prepare),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        mock_prepare.assert_called_once()

    @pytest.mark.asyncio
    async def test_model_is_opus(self, mock_mcp_setup, tmp_cwd):
        """The review agent should use opus."""
        captured = {}

        async def mock_tracked(*, name, model, **kwargs):
            captured["model"] = model
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert captured["model"] == "opus"

    @pytest.mark.asyncio
    async def test_allowed_tools_read_grep(self, mock_mcp_setup, tmp_cwd):
        """Review agent should have Read and Grep available."""
        captured = {}

        async def mock_tracked(*, name, allowed_tools=None, **kwargs):
            captured["allowed_tools"] = allowed_tools
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert "Read" in captured["allowed_tools"]
        assert "Grep" in captured["allowed_tools"]

    @pytest.mark.asyncio
    async def test_system_prompt_has_all_playbooks(self, mock_mcp_setup, tmp_cwd):
        """System prompt should include a section title for every skill playbook."""
        captured = {}

        async def mock_tracked(*, name, system_prompt=None, **kwargs):
            captured["system_prompt"] = system_prompt
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        system = captured["system_prompt"]
        for skill_name in SKILL_NAMES:
            title = skill_name.replace("-", " ").title()
            assert title in system, f"Missing playbook section for {skill_name}"

    @pytest.mark.asyncio
    async def test_max_turns_is_30(self, mock_mcp_setup, tmp_cwd):
        """Review agent is given a 30-turn budget."""
        captured = {}

        async def mock_tracked(*, name, max_turns=None, **kwargs):
            captured["max_turns"] = max_turns
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert captured["max_turns"] == 30

    @pytest.mark.asyncio
    async def test_output_written_to_file(self, mock_mcp_setup, tmp_cwd, tmp_path):
        """When output_file is given, the report text is written there."""
        async def mock_tracked(*, name, **kwargs):
            return ("### Security Considerations\nLooks okay.", "sess")

        out = tmp_path / "plan_report.md"
        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("plan", cwd=tmp_cwd, output_file=str(out))

        assert out.exists()
        assert "Security Considerations" in out.read_text()

    @pytest.mark.asyncio
    async def test_policy_violation_retries(self, mock_mcp_setup, tmp_cwd):
        """A ToolPolicyViolationError should trigger a retry with a policy note."""
        calls = {"n": 0, "prompts": []}

        async def mock_tracked(*, name, prompt, **kwargs):
            calls["n"] += 1
            calls["prompts"].append(prompt)
            if calls["n"] == 1:
                raise ToolPolicyViolationError(
                    "**/*.py", "Glob must target a first-party subpath", tool_name="Glob"
                )
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert calls["n"] == 2
        assert "Enforced Tool Policy" in calls["prompts"][1]

    @pytest.mark.asyncio
    async def test_single_tracked_agent_call(self, mock_mcp_setup, tmp_cwd):
        """The refactored flow uses a single agent (no recon/investigation split)."""
        call_names = []

        async def mock_tracked(*, name, **kwargs):
            call_names.append(name)
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert call_names == ["review"]
