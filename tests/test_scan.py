"""Tests for hiro_agent.scan — multi-wave codebase security scanner."""

import asyncio
import json
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from hiro_agent._common import McpSetup, SKILL_TOOLS, ToolPolicyViolationError
from hiro_agent.scan import scan
from hiro_agent.skills import SKILL_NAMES


def _is_meta_agent(name: str) -> bool:
    """Return True for recon/compact (non-skill agents)."""
    return name in ("recon", "compact")


class TestScan:
    """Test multi-wave scan() flow."""

    @pytest.fixture
    def mock_mcp_setup(self):
        return McpSetup(mcp_config={}, mcp_tools=[], org_context=None, security_policy=None)

    @pytest.fixture
    def tmp_cwd(self, tmp_path):
        """Return a temporary directory to use as cwd."""
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
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)

        assert sorted(skill_names_called) == sorted(SKILL_NAMES)

    @pytest.mark.asyncio
    async def test_recon_output_passed_to_skills(self, mock_mcp_setup, tmp_cwd):
        """Compacted recon summary should appear in skill agent prompts."""
        captured_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            if name == "recon":
                return ("RECON_DATA_XYZ", "sess-recon")
            if name == "strategy":
                return (
                    "### Scan Strategy\nSTRATEGY_TEXT\n\n### Compressed Brief\nBRIEF_FOR_SKILLS",
                    "sess-strategy",
                )
            return ("ok", "sess")

        async def mock_skill_waves(*, name, skill_prompt, **kwargs):
            captured_prompts[name] = skill_prompt
            return ("ok", 5)

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)

        # Investigation agents get the compressed brief in their prompt
        for name in SKILL_NAMES:
            assert "BRIEF_FOR_SKILLS" in captured_prompts[name]

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
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", side_effect=mock_report),
        ):
            await scan(cwd=tmp_cwd)

        prompt = captured_report["prompt"]
        for name in SKILL_NAMES:
            assert f"FINDINGS_{name.upper()}" in prompt

    @pytest.mark.asyncio
    async def test_one_agent_failure_doesnt_crash(self, mock_mcp_setup, tmp_cwd):
        """A single skill agent failure should not crash the scan."""
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
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)  # Should not raise

        assert skill_count == len(SKILL_NAMES)

    @pytest.mark.asyncio
    async def test_skill_failure_logs_include_skill_name(self, mock_mcp_setup, tmp_cwd):
        """Skill failures should be logged with explicit skill identity and traceback."""

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, **kwargs):
            if name == "crypto":
                raise RuntimeError("crypto agent exploded")
            return ("ok", 5)

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
            patch("hiro_agent.scan.logger.error") as mock_error,
        ):
            await scan(cwd=tmp_cwd)

        matched = [
            c for c in mock_error.call_args_list
            if c.args
            and c.args[0] == "skill_agent_failed"
            and c.kwargs.get("skill") == "crypto"
        ]
        assert matched
        assert matched[0].kwargs.get("traceback")

    @pytest.mark.asyncio
    async def test_successful_scan_cleans_scratchpad(self, mock_mcp_setup, tmp_cwd):
        """Successful runs should delete .hiro/.scratchpad."""

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)

        assert not (Path(tmp_cwd) / ".hiro" / ".scratchpad").exists()

    @pytest.mark.asyncio
    async def test_failed_scan_preserves_scratchpad(self, mock_mcp_setup, tmp_cwd):
        """Aborted/failed runs should keep .hiro/.scratchpad for postmortem."""

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", side_effect=RuntimeError("report failed")),
        ):
            with pytest.raises(RuntimeError, match="report failed"):
                await scan(cwd=tmp_cwd)

        assert (Path(tmp_cwd) / ".hiro" / ".scratchpad").exists()

    @pytest.mark.asyncio
    async def test_mcp_called_once(self, mock_mcp_setup, tmp_cwd):
        """prepare_mcp should be called exactly once."""
        mock_prepare = AsyncMock(return_value=mock_mcp_setup)

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        with (
            patch("hiro_agent.scan.prepare_mcp", mock_prepare),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)

        mock_prepare.assert_called_once()

    @pytest.mark.asyncio
    async def test_focus_passed_through(self, mock_mcp_setup, tmp_cwd):
        """Focus area should appear in recon and investigation prompts."""
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
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd, focus="authentication")

        assert "authentication" in captured_recon_prompt["prompt"]
        for name in SKILL_NAMES:
            assert "authentication" in captured_skill_prompts[name]

    @pytest.mark.asyncio
    async def test_recon_uses_opus(self, mock_mcp_setup, tmp_cwd):
        """Recon uses sonnet for speed; strategy uses opus for reasoning."""
        captured = {}

        async def mock_tracked(*, name, model, **kwargs):
            captured[name] = model
            if name == "strategy":
                return (
                    "### Scan Strategy\nstrategy\n\n### Compressed Brief\nbrief",
                    "sess",
                )
            return ("recon", "sess")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)

        assert captured["recon"] == "sonnet"
        assert captured["strategy"] == "opus"

    @pytest.mark.asyncio
    async def test_report_uses_opus(self, mock_mcp_setup, tmp_cwd):
        """Report phase should use opus model."""
        captured = {}

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        async def mock_report(*, prompt, **kwargs):
            captured.update(kwargs)

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", side_effect=mock_report),
        ):
            await scan(cwd=tmp_cwd)

        assert captured["model"] == "opus"

    @pytest.mark.asyncio
    async def test_tool_call_count_tracked(self, mock_mcp_setup, tmp_cwd):
        """Investigation status should track tool call count."""
        captured_report = {}

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, **kwargs):
            return ("findings", 5)

        async def mock_report(*, prompt, **kwargs):
            captured_report["prompt"] = prompt

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", side_effect=mock_report),
        ):
            await scan(cwd=tmp_cwd)

        prompt = captured_report["prompt"]
        assert "5 tool calls" in prompt

    @pytest.mark.asyncio
    async def test_incomplete_investigation_flagged(self, mock_mcp_setup, tmp_cwd):
        """Skill with < 3 tool calls should be marked INCOMPLETE."""
        captured_report = {}

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, **kwargs):
            # First skill gets only 1 tool call
            if name == SKILL_NAMES[0]:
                return ("findings", 1)
            return ("findings", 5)

        async def mock_report(*, prompt, **kwargs):
            captured_report["prompt"] = prompt

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", side_effect=mock_report),
        ):
            await scan(cwd=tmp_cwd)

        prompt = captured_report["prompt"]
        assert "INCOMPLETE" in prompt

    @pytest.mark.asyncio
    async def test_turn_limited_investigation_flagged(self, mock_mcp_setup, tmp_cwd):
        """Skill hitting turn limit should be marked INCOMPLETE regardless of tool count."""
        captured_report = {}

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, run_stats=None, **kwargs):
            if run_stats is not None and name == SKILL_NAMES[0]:
                run_stats["turn_limited"] = True
                run_stats["continuation_wave_used"] = True
                run_stats["has_pending_todos"] = True
            return ("findings", 9)

        async def mock_report(*, prompt, **kwargs):
            captured_report["prompt"] = prompt

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", side_effect=mock_report),
        ):
            await scan(cwd=tmp_cwd)

        prompt = captured_report["prompt"]
        assert "turn-limited at cap" in prompt

    @pytest.mark.asyncio
    async def test_turn_limited_but_no_pending_work_not_flagged(self, mock_mcp_setup, tmp_cwd):
        """Turn-limited skills should be considered complete when no pending work remains."""
        captured_report = {}

        async def mock_tracked(*, name, **kwargs):
            return ("recon", "sess-recon")

        async def mock_skill_waves(*, name, run_stats=None, **kwargs):
            if run_stats is not None and name == SKILL_NAMES[0]:
                run_stats["turn_limited"] = True
                run_stats["has_pending_todos"] = False
                run_stats["has_untraced_edges"] = False
                run_stats["pending_expansion_followups"] = 0
            return ("findings", 9)

        async def mock_report(*, prompt, **kwargs):
            captured_report["prompt"] = prompt

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", side_effect=mock_report),
        ):
            await scan(cwd=tmp_cwd)

        prompt = captured_report["prompt"]
        assert "turn-limited at cap" not in prompt

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
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)

        # All skills should have on_todos passed (non-None since display is None in test)
        for name in SKILL_NAMES:
            assert name in captured_kwargs

    @pytest.mark.asyncio
    async def test_recon_policy_violation_retries(self, mock_mcp_setup, tmp_cwd):
        """Recon should retry when tool policy blocks an unscoped search."""
        calls = {"recon": 0}

        async def mock_tracked(*, name, **kwargs):
            if name == "recon":
                calls["recon"] += 1
                if calls["recon"] == 1:
                    raise ToolPolicyViolationError("**/*.py", "Grep must target a first-party subpath", tool_name="Grep")
                return ("recon summary", "sess-recon")
            return ("compact summary", "sess")

        async def mock_skill_waves(*, name, **kwargs):
            return ("ok", 5)

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)

        assert calls["recon"] == 2

    @pytest.mark.asyncio
    async def test_shared_index_written_and_injected(self, mock_mcp_setup, tmp_cwd):
        """Scan should write one shared index and inject it into skill prompts."""
        # Seed first-party files so the index has content.
        src_dir = Path(tmp_cwd) / "src"
        src_dir.mkdir(parents=True, exist_ok=True)
        (src_dir / "app.py").write_text("def main():\n    pass\n")

        captured_prompts = {}

        async def mock_tracked(*, name, prompt, **kwargs):
            if name == "recon":
                return ("Recon summary mentions src/app.py", "sess-recon")
            if name == "compact":
                return ("Compact recon with src/app.py", "sess-compact")
            return ("ok", "sess")

        async def mock_skill_waves(*, name, skill_prompt, **kwargs):
            captured_prompts[name] = skill_prompt
            return ("ok", 5)

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)

        index_path = Path(tmp_cwd) / ".hiro" / ".scan_index.json"
        assert index_path.exists()

        data = json.loads(index_path.read_text())
        assert data["file_count"] >= 1
        assert "skills" in data
        assert "logic" in data["skills"]

        for name in SKILL_NAMES:
            prompt = captured_prompts[name]
            assert "Shared Repository Index (authoritative)" in prompt
            assert "Index artifact path:" in prompt

    @pytest.mark.asyncio
    async def test_skill_concurrency_semaphore_passed(self, mock_mcp_setup, tmp_cwd, monkeypatch):
        """Skill waves should receive the concurrency semaphore."""
        monkeypatch.setenv("HIRO_SKILL_CONCURRENCY", "2")
        captured_semaphores = []

        async def mock_tracked(*, name, **kwargs):
            if name == "recon":
                return ("recon", "sess-recon")
            if name == "compact":
                return ("compact", "sess-compact")
            return ("ok", "sess")

        async def mock_skill_waves(*, name, semaphore=None, **kwargs):
            captured_semaphores.append(semaphore)
            return ("ok", 5)

        with (
            patch("hiro_agent.scan.prepare_mcp", return_value=mock_mcp_setup),
            patch("hiro_agent.scan._run_tracked_agent", side_effect=mock_tracked),
            patch("hiro_agent.scan._run_skill_waves", side_effect=mock_skill_waves),
            patch("hiro_agent.scan._run_report_stream", return_value=None),
        ):
            await scan(cwd=tmp_cwd)

        assert all(s is not None for s in captured_semaphores)
        assert all(isinstance(s, asyncio.Semaphore) for s in captured_semaphores)
        assert len(captured_semaphores) == len(SKILL_NAMES)

    def test_skill_tools_includes_write(self):
        """SKILL_TOOLS should include Task and Write (imported from _common)."""
        from hiro_agent.scan import SKILL_TOOLS as scan_tools
        assert "Task" in scan_tools
        assert "Write" in scan_tools

    def test_skill_tools_include_todo(self):
        """SKILL_TOOLS should include TodoWrite and TodoRead for self-planning."""
        assert "TodoWrite" in SKILL_TOOLS
        assert "TodoRead" in SKILL_TOOLS

    def test_recon_tools_include_todo(self):
        """RECON_TOOLS should include TodoWrite and TodoRead for self-planning."""
        from hiro_agent.scan import RECON_TOOLS
        assert "TodoWrite" in RECON_TOOLS
        assert "TodoRead" in RECON_TOOLS
        assert "Task" not in RECON_TOOLS
