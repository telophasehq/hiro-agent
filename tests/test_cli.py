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
