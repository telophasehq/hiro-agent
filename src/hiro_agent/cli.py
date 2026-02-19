"""CLI entry point: hiro review-code, review-plan, review-infra, setup, verify."""

import asyncio
import os
import sys

import click
import structlog

logger = structlog.get_logger(__name__)

# 2 MB stdin cap to prevent accidental piping of huge files
MAX_STDIN_BYTES = 2 * 1024 * 1024


def _read_stdin(command_name: str) -> str:
    """Read stdin with a 2MB size cap."""
    if sys.stdin.isatty():
        click.echo(f"Error: No input on stdin. Pipe content to `hiro {command_name}`.", err=True)
        raise SystemExit(1)
    data = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    if len(data) > MAX_STDIN_BYTES:
        click.echo(
            f"Error: Input exceeds 2MB limit ({len(data)} bytes). "
            "Reduce the input size or review files individually.",
            err=True,
        )
        raise SystemExit(1)
    return data.decode("utf-8", errors="replace")


@click.group()
@click.version_option(package_name="hiro-agent")
def main() -> None:
    """Hiro — AI security review agent."""


@main.command("review-code")
@click.option("--context", "-c", default="", help="Additional context about the code.")
def review_code_cmd(context: str) -> None:
    """Review code changes for security issues. Reads diff from stdin."""
    from hiro_agent.review_code import review_code

    diff = _read_stdin("review-code")
    if not diff.strip():
        click.echo("Error: Empty input. Pipe a diff: git diff | hiro review-code", err=True)
        raise SystemExit(1)

    cwd = os.getcwd()
    result = asyncio.run(review_code(diff, cwd=cwd, context=context))
    click.echo(result)


@main.command("review-plan")
@click.option("--context", "-c", default="", help="Additional context about the plan.")
def review_plan_cmd(context: str) -> None:
    """Review an implementation plan for security concerns. Reads from stdin."""
    from hiro_agent.review_plan import review_plan

    plan = _read_stdin("review-plan")
    if not plan.strip():
        click.echo("Error: Empty input. Pipe a plan: cat plan.md | hiro review-plan", err=True)
        raise SystemExit(1)

    result = asyncio.run(review_plan(plan, context=context))
    click.echo(result)


@main.command("review-infra")
@click.argument("filepath", required=False)
def review_infra_cmd(filepath: str | None) -> None:
    """Review infrastructure config for security issues. File arg or stdin."""
    from hiro_agent.review_infra import review_infrastructure

    if filepath:
        filename = os.path.basename(filepath)
        filepath = os.path.abspath(filepath)
        cwd = os.path.dirname(filepath)
        result = asyncio.run(
            review_infrastructure(filepath, filename=filename, cwd=cwd)
        )
    else:
        config = _read_stdin("review-infra")
        if not config.strip():
            click.echo("Error: Empty input. Usage: hiro review-infra <file>", err=True)
            raise SystemExit(1)
        result = asyncio.run(
            review_infrastructure(config, filename="stdin")
        )

    click.echo(result)


@main.command()
@click.option("--claude-code", "tools", flag_value="claude-code", help="Claude Code only.")
@click.option("--cursor", "tools", flag_value="cursor", help="Cursor only.")
@click.option("--vscode", "tools", flag_value="vscode", help="VSCode Copilot only.")
@click.option("--codex", "tools", flag_value="codex", help="Codex CLI only.")
def setup(tools: str | None) -> None:
    """Configure AI coding tool hooks for security review enforcement."""
    from hiro_agent.setup_hooks import run_setup

    run_setup(tool_filter=tools)


@main.command()
def verify() -> None:
    """Verify hook integrity against installed package version."""
    from hiro_agent.setup_hooks import run_verify

    run_verify()
