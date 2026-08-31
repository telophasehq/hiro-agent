"""Tests for hiro_agent.cli command-level behavior."""

from click.testing import CliRunner
from unittest.mock import patch


class TestCliReviewCode:
    """`hiro review-code` should announce and persist report output."""

    def test_review_code_announces_output_path_and_passes_it_through(self):
        runner = CliRunner()
        captured = {}

        async def _noop_review(diff: str, **kwargs):
            captured["diff"] = diff
            captured["kwargs"] = kwargs
            return None

        with (
            patch("hiro_agent.review_code.review_code", side_effect=_noop_review),
            patch("hiro_agent.cli._configure_file_logging", return_value=".hiro/logs/test.log"),
            patch("hiro_agent.cli._default_review_output_path", return_value="/tmp/hiro-review-code-test.md"),
        ):
            from hiro_agent.cli import main

            result = runner.invoke(main, ["review-code", "--quiet"], input="diff --git a/foo.py b/foo.py\n")

        assert result.exit_code == 0
        assert "outputting review to /tmp/hiro-review-code-test.md" in result.output
        assert captured["diff"] == "diff --git a/foo.py b/foo.py\n"
        assert captured["kwargs"]["output_file"] == "/tmp/hiro-review-code-test.md"
        assert captured["kwargs"]["mirror_to_stdout"] is False


def test_review_code_rejected_key_exits_1_with_actionable_hint():
    """A rejected Hiro key fails fast with the env-shadow hint (exit 1 =
    config error, not the fail-closed exit 2 of a failed review)."""
    from hiro_agent._common import HiroAuthError

    runner = CliRunner()

    async def _auth_fail(diff: str, **kwargs):
        raise HiroAuthError("HTTP 401 Unauthorized")

    with (
        patch("hiro_agent.review_code.review_code", side_effect=_auth_fail),
        patch("hiro_agent.cli._configure_file_logging", return_value=".hiro/logs/test.log"),
        patch("hiro_agent.cli._default_review_output_path", return_value="/tmp/hiro-review-code-test.md"),
    ):
        from hiro_agent.cli import main

        result = runner.invoke(main, ["review-code", "--quiet"], input="diff --git a/foo b/foo\n")

    assert result.exit_code == 1
    assert "Hiro rejected your API key (HTTP 401 Unauthorized)" in result.output
    assert "env -u HIRO_API_KEY hiro review-code" in result.output
    assert "hiro setup" in result.output


def test_review_code_error_result_with_only_stderr_hint_surfaces_it():
    """When an error ResultMessage carries no result text (the 2026-08-31
    shape: is_error=True, subtype='success', empty result), the last
    meaningful CLI stderr line is the only cause signal — print it."""
    from hiro_agent._common import AgentResultError

    runner = CliRunner()

    async def _error_result(diff: str, **kwargs):
        raise AgentResultError(
            agent="review",
            subtype="success",
            partial_output="",
            session_id="sess",
            api_error_detail=None,
            result_text=None,
            stderr_hint='API Error: 401 {"detail":"Invalid API key"}',
        )

    with (
        patch("hiro_agent.review_code.review_code", side_effect=_error_result),
        patch("hiro_agent.cli._configure_file_logging", return_value=".hiro/logs/test.log"),
        patch("hiro_agent.cli._default_review_output_path", return_value="/tmp/hiro-review-code-test.md"),
    ):
        from hiro_agent.cli import main

        result = runner.invoke(main, ["review-code", "--quiet"], input="diff --git a/foo b/foo\n")

    assert result.exit_code == 2
    assert 'Agent stderr: API Error: 401 {"detail":"Invalid API key"}' in result.output
    assert "stopped without producing a verdict (success)" in result.output
