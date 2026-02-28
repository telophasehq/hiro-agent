"""Tests for hiro_agent.cli command-level behavior."""

from click.testing import CliRunner
from unittest.mock import patch


class TestCliScan:
    """`hiro scan` should clearly communicate its experimental status."""

    def test_scan_prints_experimental_notice(self):
        runner = CliRunner()

        async def _noop_scan(**kwargs):
            return None

        with (
            patch("hiro_agent.scan.scan", side_effect=_noop_scan),
            patch("hiro_agent.cli._configure_file_logging", return_value=".hiro/logs/test.log"),
        ):
            from hiro_agent.cli import main

            result = runner.invoke(main, ["scan", "--quiet"])

        assert result.exit_code == 0
        assert "experimental" in result.output.lower()
        assert "review-code" in result.output
        assert "review-plan" in result.output
