"""Tests for hiro_agent.review_code — multi-agent diff security review."""

from unittest.mock import AsyncMock, patch

import pytest

from hiro_agent._common import McpSetup, SKILL_TOOLS
from hiro_agent.review_code import review_code
from hiro_agent.skills import SKILL_NAMES


def _is_meta_agent(name: str) -> bool:
    """Return True for recon/compact (non-skill agents)."""
    return name in ("recon", "compact")


class TestReviewCode:
    """Test multi-agent review_code() flow."""

    @pytest.fixture
    def mock_mcp_setup(self):
        return McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

    @pytest.fixture
    def tmp_cwd(self, tmp_path):
        return str(tmp_path)

    @pytest.mark.asyncio
    async def test_all_skills_spawned(self, mock_mcp_setup, tmp_cwd):
        """All skill agents should be invoked during investigation phase."""
        tracked_names = []

        async def mock_tracked(*, name, **kwargs):
            tracked_names.append(name)
            return ("recon summary", "sess-recon")

        skill_names_called = []

        async def mock_skill_waves(*, name, **kwargs):
            skill_names_called.append(name)
            return (f"findings for {name}", 5)

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", return_value=None),
        ):
            await review_code("diff --git a/foo.py\n+import os", cwd=tmp_cwd)

        assert sorted(skill_names_called) == sorted(SKILL_NAMES)

    @pytest.mark.asyncio
    async def test_diff_passed_to_recon(self, mock_mcp_setup, tmp_cwd):
        """Diff should appear in the recon agent prompt."""
        captured_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            captured_prompts[name] = prompt
            return ("recon", "sess")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", return_value=None),
        ):
            await review_code("diff --git SECRET_DIFF", cwd=tmp_cwd)

        assert "SECRET_DIFF" in captured_prompts["recon"]

    @pytest.mark.asyncio
    async def test_diff_passed_to_skill_agents(self, mock_mcp_setup, tmp_cwd):
        """Diff should appear in each skill agent's prompt."""
        captured_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            return ("recon", "sess")

        async def mock_skill_waves(*, name, skill_prompt, **kwargs):
            captured_prompts[name] = skill_prompt
            return ("ok", 5)

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", return_value=None),
        ):
            await review_code("diff --git UNIQUE_DIFF_TOKEN", cwd=tmp_cwd)

        for name in SKILL_NAMES:
            assert "UNIQUE_DIFF_TOKEN" in captured_prompts[name]

    @pytest.mark.asyncio
    async def test_recon_output_passed_to_skills(self, mock_mcp_setup, tmp_cwd):
        """Compacted recon summary should appear in investigation agent prompts."""
        captured_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            if name == "recon":
                return ("RECON_DATA_XYZ", "sess-recon")
            if name == "compact":
                return ("COMPACT_RECON", "sess-compact")
            return ("ok", "sess")

        async def mock_skill_waves(*, name, skill_prompt, **kwargs):
            captured_prompts[name] = skill_prompt
            return ("ok", 5)

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", return_value=None),
        ):
            await review_code("some diff", cwd=tmp_cwd)

        for name in SKILL_NAMES:
            assert "COMPACT_RECON" in captured_prompts[name]

    @pytest.mark.asyncio
    async def test_context_passed_through(self, mock_mcp_setup, tmp_cwd):
        """Context string should appear in recon and skill agent prompts."""
        captured_recon_prompt = {}
        captured_skill_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            if name == "recon":
                captured_recon_prompt["prompt"] = prompt
            return ("recon", "sess")

        async def mock_skill_waves(*, name, skill_prompt, **kwargs):
            captured_skill_prompts[name] = skill_prompt
            return ("ok", 5)

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", return_value=None),
        ):
            await review_code("diff", cwd=tmp_cwd, context="This is an auth module")

        assert "This is an auth module" in captured_recon_prompt["prompt"]
        for name in SKILL_NAMES:
            assert "This is an auth module" in captured_skill_prompts[name]

    @pytest.mark.asyncio
    async def test_report_gets_skill_findings(self, mock_mcp_setup, tmp_cwd):
        """Report phase should receive synthesized findings from skill waves."""
        captured_report = {}

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, **kwargs):
            return (f"FINDINGS_{name.upper()}", 5)

        async def mock_report(*, prompt, **kwargs):
            captured_report["prompt"] = prompt

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", side_effect=mock_report),
        ):
            await review_code("diff", cwd=tmp_cwd)

        prompt = captured_report["prompt"]
        for name in SKILL_NAMES:
            assert f"FINDINGS_{name.upper()}" in prompt

    @pytest.mark.asyncio
    async def test_report_includes_diff(self, mock_mcp_setup, tmp_cwd):
        """Report prompt should include the original diff."""
        captured_report = {}

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        async def mock_report(*, prompt, **kwargs):
            captured_report["prompt"] = prompt

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", side_effect=mock_report),
        ):
            await review_code("REPORT_DIFF_MARKER", cwd=tmp_cwd)

        assert "REPORT_DIFF_MARKER" in captured_report["prompt"]

    @pytest.mark.asyncio
    async def test_one_agent_failure_doesnt_crash(self, mock_mcp_setup, tmp_cwd):
        """A single skill agent failure should not crash the review."""
        skill_count = 0

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, **kwargs):
            nonlocal skill_count
            skill_count += 1
            if name == "crypto":
                raise RuntimeError("crypto agent exploded")
            return (f"findings for {name}", 5)

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", return_value=None),
        ):
            await review_code("diff", cwd=tmp_cwd)  # Should not raise

        assert skill_count == len(SKILL_NAMES)

    @pytest.mark.asyncio
    async def test_mcp_called_once(self, mock_mcp_setup, tmp_cwd):
        """prepare_mcp should be called exactly once."""
        mock_prepare = AsyncMock(return_value=mock_mcp_setup)

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        with (
            patch("hiro_agent.review_code.prepare_mcp", mock_prepare),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", return_value=None),
        ):
            await review_code("diff", cwd=tmp_cwd)

        mock_prepare.assert_called_once()

    @pytest.mark.asyncio
    async def test_recon_uses_diff_prompt(self, mock_mcp_setup, tmp_cwd):
        """Recon should use DIFF_RECON_SYSTEM_PROMPT, not RECON_SYSTEM_PROMPT."""
        captured_recon = {}

        async def mock_tracked(*, name, system_prompt, **kwargs):
            if name == "recon":
                captured_recon["system_prompt"] = system_prompt
            return ("recon", "sess")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", return_value=None),
        ):
            await review_code("diff", cwd=tmp_cwd)

        # DIFF_RECON_SYSTEM_PROMPT has unique markers
        assert "Callers and consumers" in captured_recon["system_prompt"]
        assert "Diff Overview" in captured_recon["system_prompt"]

    @pytest.mark.asyncio
    async def test_on_todos_passed_to_skill_waves(self, mock_mcp_setup, tmp_cwd):
        """on_todos kwarg should be accepted by _run_skill_waves mock."""
        captured_kwargs = {}

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, on_todos=None, **kwargs):
            captured_kwargs[name] = {"on_todos": on_todos}
            return ("ok", 5)

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.review_code._run_report_stream", return_value=None),
        ):
            await review_code("diff --git a/foo.py", cwd=tmp_cwd)

        for name in SKILL_NAMES:
            assert name in captured_kwargs

    def test_skill_tools_includes_write(self):
        """SKILL_TOOLS should include Task and Write (imported from _common)."""
        from hiro_agent.review_code import SKILL_TOOLS as rc_tools
        assert "Task" in rc_tools
        assert "Write" in rc_tools
