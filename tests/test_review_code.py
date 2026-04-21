"""Tests for hiro_agent.review_code — single-agent diff security review."""

from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from hiro_agent._common import McpSetup, ToolPolicyViolationError
from hiro_agent.review_code import review_code
from hiro_agent.skills import SKILL_NAMES


class TestReviewCode:
    """Test single-agent review_code() flow."""

    @pytest.fixture
    def mock_mcp_setup(self):
        return McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

    @pytest.fixture
    def tmp_cwd(self, tmp_path):
        return str(tmp_path)

    @pytest.mark.asyncio
    async def test_diff_written_to_tempfile_and_path_in_prompt(self, mock_mcp_setup, tmp_cwd):
        """Diff is written to a temp .patch file; the prompt references that path."""
        captured = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            captured["name"] = name
            captured["prompt"] = prompt
            return ("Verdict: APPROVE\n\nClean.", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending") as mock_save,
        ):
            await review_code("diff --git SECRET_DIFF", cwd=tmp_cwd)

        assert captured["name"] == "review"
        # Prompt references a temp diff path, not the raw diff.
        assert "hiro-diff-" in captured["prompt"]
        assert ".patch" in captured["prompt"]
        # save_pending receives the raw diff for later upload.
        mock_save.assert_called_once()
        assert mock_save.call_args.kwargs["diff"] == "diff --git SECRET_DIFF"

    @pytest.mark.asyncio
    async def test_context_passed_through(self, mock_mcp_setup, tmp_cwd):
        """Context string should appear in the agent prompt."""
        captured = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            captured["prompt"] = prompt
            return ("Verdict: COMMENT\n", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff", cwd=tmp_cwd, context="This is an auth module")

        assert "This is an auth module" in captured["prompt"]

    @pytest.mark.asyncio
    async def test_mcp_called_once(self, mock_mcp_setup, tmp_cwd):
        """prepare_mcp should be called exactly once."""
        mock_prepare = AsyncMock(return_value=mock_mcp_setup)

        async def mock_tracked(*, name, **kwargs):
            return ("Verdict: APPROVE\n", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", mock_prepare),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff", cwd=tmp_cwd)

        mock_prepare.assert_called_once()

    @pytest.mark.asyncio
    async def test_model_is_opus(self, mock_mcp_setup, tmp_cwd):
        """The review agent should use opus."""
        captured = {}

        async def mock_tracked(*, name, model, **kwargs):
            captured["model"] = model
            return ("Verdict: APPROVE\n", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff", cwd=tmp_cwd)

        assert captured["model"] == "opus"

    @pytest.mark.asyncio
    async def test_allowed_tools_read_grep(self, mock_mcp_setup, tmp_cwd):
        """Review agent should have Read and Grep available."""
        captured = {}

        async def mock_tracked(*, name, allowed_tools=None, **kwargs):
            captured["allowed_tools"] = allowed_tools
            return ("Verdict: APPROVE\n", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff", cwd=tmp_cwd)

        assert "Read" in captured["allowed_tools"]
        assert "Grep" in captured["allowed_tools"]

    @pytest.mark.asyncio
    async def test_system_prompt_has_all_playbooks(self, mock_mcp_setup, tmp_cwd):
        """System prompt should include a section title for every skill playbook."""
        captured = {}

        async def mock_tracked(*, name, system_prompt=None, **kwargs):
            captured["system_prompt"] = system_prompt
            return ("Verdict: APPROVE\n", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff", cwd=tmp_cwd)

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
            return ("Verdict: APPROVE\n", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff", cwd=tmp_cwd)

        assert captured["max_turns"] == 30

    @pytest.mark.asyncio
    async def test_output_written_to_file(self, mock_mcp_setup, tmp_cwd, tmp_path):
        """When output_file is given, the report text is written there."""
        async def mock_tracked(*, name, **kwargs):
            return ("Verdict: APPROVE\n\n### Executive Summary\nClean.", "sess")

        out = tmp_path / "report.md"
        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff", cwd=tmp_cwd, output_file=str(out))

        assert out.exists()
        assert "Verdict: APPROVE" in out.read_text()

    @pytest.mark.asyncio
    async def test_save_pending_called_with_diff_and_report(self, mock_mcp_setup, tmp_cwd):
        """After review, save_pending is called with the raw diff + report so
        the post-commit hook can upload it to the backend."""
        async def mock_tracked(*, name, **kwargs):
            return ("Verdict: REQUEST_CHANGES\n\nFound SQLi.", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending") as mock_save,
            patch("hiro_agent.review_code._git_head_sha", return_value="abc123"),
        ):
            await review_code("diff --git a/x b/x", cwd=tmp_cwd)

        mock_save.assert_called_once()
        kwargs = mock_save.call_args.kwargs
        assert kwargs["diff"] == "diff --git a/x b/x"
        assert "Verdict: REQUEST_CHANGES" in kwargs["report_text"]
        assert kwargs["parent_sha"] == "abc123"

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
            return ("Verdict: APPROVE\n", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff --git a/foo.py", cwd=tmp_cwd)

        assert calls["n"] == 2
        # Retry prompt should contain the enforced-policy note.
        assert "Enforced Tool Policy" in calls["prompts"][1]

    @pytest.mark.asyncio
    async def test_single_tracked_agent_call(self, mock_mcp_setup, tmp_cwd):
        """The refactored flow uses a single agent (no recon/investigation split)."""
        call_names = []

        async def mock_tracked(*, name, **kwargs):
            call_names.append(name)
            return ("Verdict: APPROVE\n", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff", cwd=tmp_cwd)

        assert call_names == ["review"]

    @pytest.mark.asyncio
    async def test_clears_review_state_on_success(self, mock_mcp_setup, tmp_cwd):
        """Successful review clears the pre-commit state so git commit is unblocked."""
        import json
        import time

        state_dir = Path(tmp_cwd) / ".hiro" / ".state"
        state_dir.mkdir(parents=True)
        state_file = state_dir / "code_review_project.json"
        state_file.write_text(json.dumps({
            "needs_review": True,
            "modified_files": ["a.py"],
            "updated_at": int(time.time()),
        }))

        async def mock_tracked(*, name, **kwargs):
            return ("Verdict: APPROVE\n", "sess")

        with (
            patch("hiro_agent.review_code.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.review_code._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.review_code.save_pending"),
        ):
            await review_code("diff", cwd=tmp_cwd)

        state = json.loads(state_file.read_text())
        assert state["needs_review"] is False
        assert state["modified_files"] == []
