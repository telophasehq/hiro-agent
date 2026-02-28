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
    async def test_plan_passed_to_recon(self, mock_mcp_setup, tmp_cwd):
        """Plan text should appear in the recon agent prompt."""
        captured_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            captured_prompts[name] = prompt
            return ("recon output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("SECRET_PLAN_TEXT", cwd=tmp_cwd)

        assert "SECRET_PLAN_TEXT" in captured_prompts["recon"]

    @pytest.mark.asyncio
    async def test_plan_passed_to_investigation(self, mock_mcp_setup, tmp_cwd):
        """Plan text should appear in the investigation agent prompt."""
        captured_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            captured_prompts[name] = prompt
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("UNIQUE_PLAN_TOKEN", cwd=tmp_cwd)

        assert "UNIQUE_PLAN_TOKEN" in captured_prompts["investigation"]

    @pytest.mark.asyncio
    async def test_recon_passed_to_investigation(self, mock_mcp_setup, tmp_cwd):
        """Recon output should appear in the investigation agent prompt."""
        captured_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            captured_prompts[name] = prompt
            if name == "recon":
                return ("RECON_DATA_XYZ", "sess-recon")
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("some plan", cwd=tmp_cwd)

        assert "RECON_DATA_XYZ" in captured_prompts["investigation"]

    @pytest.mark.asyncio
    async def test_context_passed_through(self, mock_mcp_setup, tmp_cwd):
        """Context string should appear in recon and investigation prompts."""
        captured_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            captured_prompts[name] = prompt
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd, context="This is an auth module")

        assert "This is an auth module" in captured_prompts["recon"]
        assert "This is an auth module" in captured_prompts["investigation"]

    @pytest.mark.asyncio
    async def test_report_gets_investigation_output(self, mock_mcp_setup, tmp_cwd):
        """Report phase should receive investigation output."""
        captured_report = {}

        async def mock_tracked(*, name, **kwargs):
            if name == "investigation":
                return ("INVESTIGATION_FINDINGS_HERE", "sess")
            return ("recon", "sess")

        async def mock_report(*, prompt, **kwargs):
            captured_report["prompt"] = prompt

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", side_effect=mock_report),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert "INVESTIGATION_FINDINGS_HERE" in captured_report["prompt"]

    @pytest.mark.asyncio
    async def test_report_includes_plan(self, mock_mcp_setup, tmp_cwd):
        """Report prompt should include the original plan text."""
        captured_report = {}

        async def mock_tracked(*, name, **kwargs):
            return ("output", "sess")

        async def mock_report(*, prompt, **kwargs):
            captured_report["prompt"] = prompt

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", side_effect=mock_report),
        ):
            await review_plan("REPORT_PLAN_MARKER", cwd=tmp_cwd)

        assert "REPORT_PLAN_MARKER" in captured_report["prompt"]

    @pytest.mark.asyncio
    async def test_mcp_called_once(self, mock_mcp_setup, tmp_cwd):
        """prepare_mcp should be called exactly once."""
        mock_prepare = AsyncMock(return_value=mock_mcp_setup)

        async def mock_tracked(*, name, **kwargs):
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", mock_prepare),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        mock_prepare.assert_called_once()

    @pytest.mark.asyncio
    async def test_recon_uses_plan_prompt(self, mock_mcp_setup, tmp_cwd):
        """Recon should use PLAN_RECON_SYSTEM_PROMPT, not DIFF_RECON_SYSTEM_PROMPT."""
        captured_recon = {}

        async def mock_tracked(*, name, system_prompt, **kwargs):
            if name == "recon":
                captured_recon["system_prompt"] = system_prompt
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert "implementation plan" in captured_recon["system_prompt"]
        assert "Plan Overview" in captured_recon["system_prompt"]

    @pytest.mark.asyncio
    async def test_report_uses_plan_report_prompt(self, mock_mcp_setup, tmp_cwd):
        """Report should use PLAN_REPORT_SYSTEM_PROMPT with STRIDE framing."""
        captured_report = {}

        async def mock_tracked(*, name, **kwargs):
            return ("output", "sess")

        async def mock_report(*, system_prompt, **kwargs):
            captured_report["system_prompt"] = system_prompt

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", side_effect=mock_report),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert "STRIDE" in captured_report["system_prompt"]
        assert "Recommended Controls" in captured_report["system_prompt"]

    @pytest.mark.asyncio
    async def test_recon_model_is_sonnet(self, mock_mcp_setup, tmp_cwd):
        """Recon phase should use sonnet model."""
        captured = {}

        async def mock_tracked(*, name, model, **kwargs):
            if name == "recon":
                captured["model"] = model
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert captured["model"] == "sonnet"

    @pytest.mark.asyncio
    async def test_investigation_model_is_opus(self, mock_mcp_setup, tmp_cwd):
        """Investigation phase should use opus model."""
        captured = {}

        async def mock_tracked(*, name, model, **kwargs):
            if name == "investigation":
                captured["model"] = model
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert captured["model"] == "opus"

    @pytest.mark.asyncio
    async def test_investigation_has_read_grep(self, mock_mcp_setup, tmp_cwd):
        """Investigation agent should have Read and Grep tools."""
        captured = {}

        async def mock_tracked(*, name, allowed_tools=None, **kwargs):
            if name == "investigation":
                captured["allowed_tools"] = allowed_tools
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert "Read" in captured["allowed_tools"]
        assert "Grep" in captured["allowed_tools"]

    @pytest.mark.asyncio
    async def test_investigation_system_prompt_has_playbooks(self, mock_mcp_setup, tmp_cwd):
        """Investigation system prompt should include content from all skill playbooks."""
        captured = {}

        async def mock_tracked(*, name, system_prompt=None, **kwargs):
            if name == "investigation":
                captured["system_prompt"] = system_prompt
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        system = captured["system_prompt"]
        # Should contain section headers for all skills
        for name in SKILL_NAMES:
            title = name.replace("-", " ").title()
            assert title in system, f"Missing playbook section for {name}"

    @pytest.mark.asyncio
    async def test_investigation_max_turns_is_10(self, mock_mcp_setup, tmp_cwd):
        """Investigation agent should have 10 turns."""
        captured = {}

        async def mock_tracked(*, name, max_turns=None, system_prompt=None, **kwargs):
            if name == "investigation":
                captured["max_turns"] = max_turns
                captured["system_prompt"] = system_prompt
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert captured["max_turns"] == 10
        assert "10 turns" in captured["system_prompt"]

    @pytest.mark.asyncio
    async def test_recon_max_turns_is_5(self, mock_mcp_setup, tmp_cwd):
        """Recon should use 5 turn budget for plan review."""
        captured = {}

        async def mock_tracked(*, name, max_turns, system_prompt, **kwargs):
            if name == "recon":
                captured["max_turns"] = max_turns
                captured["system_prompt"] = system_prompt
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert captured["max_turns"] == 5
        assert "5 turns" in captured["system_prompt"]

    @pytest.mark.asyncio
    async def test_report_model_is_opus(self, mock_mcp_setup, tmp_cwd):
        """Report phase should use opus model."""
        captured = {}

        async def mock_tracked(*, name, **kwargs):
            return ("output", "sess")

        async def mock_report(*, model, **kwargs):
            captured["model"] = model

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", side_effect=mock_report),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert captured["model"] == "opus"

    @pytest.mark.asyncio
    async def test_plan_recon_policy_violation_retries(self, mock_mcp_setup, tmp_cwd):
        """Plan recon should retry when tool policy blocks an unscoped search."""
        calls = {"recon": 0}

        async def mock_tracked(*, name, **kwargs):
            if name == "recon":
                calls["recon"] += 1
                if calls["recon"] == 1:
                    raise ToolPolicyViolationError("**/*.py", "Glob must target a first-party subpath", tool_name="Glob")
                return ("recon summary", "sess-recon")
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert calls["recon"] == 2

    @pytest.mark.asyncio
    async def test_only_two_tracked_agent_calls(self, mock_mcp_setup, tmp_cwd):
        """Pipeline should call _run_tracked_agent exactly twice: recon + investigation."""
        call_names = []

        async def mock_tracked(*, name, **kwargs):
            call_names.append(name)
            return ("output", "sess")

        with (
            patch("hiro_agent.review_plan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_plan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_plan._run_report_stream", return_value=None),
        ):
            await review_plan("plan", cwd=tmp_cwd)

        assert call_names == ["recon", "investigation"]
