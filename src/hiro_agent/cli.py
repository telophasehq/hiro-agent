"""CLI entry point: hiro review-code, review-plan, review-infra, setup, verify."""

import asyncio
import datetime
import logging
import os
import sys
from pathlib import Path

import click
import structlog


def _silence_logs() -> None:
    """Suppress structlog output in CLI mode."""
    structlog.configure(
        wrapper_class=structlog.make_filtering_bound_logger(logging.CRITICAL),
    )


def _configure_file_logging() -> str:
    """Route structlog to a timestamped log file. Returns the log file path.

    Stderr stays clean for the live display. All structlog.info/warning/error
    calls go to .hiro/logs/hiro-{timestamp}.log instead.
    """
    log_dir = Path(".hiro") / "logs"
    log_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.datetime.now().strftime("%Y%m%d-%H%M%S")
    log_path = log_dir / f"hiro-{ts}.log"

    log_file = open(log_path, "w")  # noqa: SIM115 — closed on process exit

    structlog.configure(
        processors=[
            structlog.processors.add_log_level,
            structlog.processors.TimeStamper(fmt="iso"),
            structlog.dev.ConsoleRenderer(),
        ],
        wrapper_class=structlog.make_filtering_bound_logger(logging.DEBUG),
        logger_factory=structlog.WriteLoggerFactory(file=log_file),
    )

    return str(log_path)

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
    _silence_logs()


@main.command("review-code")
@click.option("--context", "-c", default="", help="Additional context about the code.")
@click.option("--quiet", "-q", is_flag=True, help="Hide tool calls and agent reasoning.")
def review_code_cmd(context: str, quiet: bool) -> None:
    """Review code changes for security issues. Reads diff from stdin."""
    from hiro_agent.review_code import review_code

    log_path = _configure_file_logging()

    diff = _read_stdin("review-code")
    if not diff.strip():
        click.echo("Error: Empty input. Pipe a diff: git diff | hiro review-code", err=True)
        raise SystemExit(1)

    cwd = os.getcwd()
    asyncio.run(review_code(diff, cwd=cwd, context=context, verbose=not quiet))
    click.echo(f"\nLog: {log_path}", err=True)


@main.command("review-plan")
@click.option("--context", "-c", default="", help="Additional context about the plan.")
@click.option("--quiet", "-q", is_flag=True, help="Hide tool calls and agent reasoning.")
def review_plan_cmd(context: str, quiet: bool) -> None:
    """Review an implementation plan for security concerns. Reads from stdin."""
    from hiro_agent.review_plan import review_plan

    log_path = _configure_file_logging()

    plan = _read_stdin("review-plan")
    if not plan.strip():
        click.echo("Error: Empty input. Pipe a plan: cat plan.md | hiro review-plan", err=True)
        raise SystemExit(1)

    cwd = os.getcwd()
    click.echo("Reviewing plan...\n", err=True)
    asyncio.run(review_plan(plan, cwd=cwd, context=context, verbose=not quiet))
    click.echo(f"\nLog: {log_path}", err=True)


@main.command("review-infra")
@click.argument("filepath", required=False)
def review_infra_cmd(filepath: str | None) -> None:
    """Review infrastructure config for security issues. File arg or stdin."""
    from hiro_agent.review_infra import review_infrastructure

    _configure_file_logging()
    click.echo("Reviewing infrastructure...\n", err=True)
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
@click.option("--focus", "-f", default="", help="Focus area (e.g., 'auth', 'api', 'crypto').")
@click.option("--quiet", "-q", is_flag=True, help="Hide tool calls and agent reasoning.")
def scan(focus: str, quiet: bool) -> None:
    """Scan the codebase for security issues."""
    from hiro_agent.scan import scan as run_scan

    log_path = _configure_file_logging()

    cwd = os.getcwd()
    if focus:
        click.echo(f"Scanning {cwd} (focus: {focus})...\n", err=True)
    else:
        click.echo(f"Scanning {cwd}...\n", err=True)
    asyncio.run(run_scan(cwd=cwd, focus=focus, verbose=not quiet))
    click.echo(f"\nLog: {log_path}", err=True)


@main.command()
@click.option("--quiet", "-q", is_flag=True, help="Hide tool calls and agent reasoning.")
@click.argument("question", nargs=-1, required=True)
def chat(question: tuple[str, ...], quiet: bool) -> None:
    """Ask a security question about your codebase."""
    from hiro_agent.chat import chat as run_chat

    log_path = _configure_file_logging()

    cwd = os.getcwd()
    full_question = " ".join(question)
    click.echo("Thinking...\n", err=True)
    asyncio.run(run_chat(full_question, cwd=cwd, verbose=not quiet))
    click.echo(f"\nLog: {log_path}", err=True)


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
@click.option("--claude-code", "tools", flag_value="claude-code", help="Claude Code only.")
@click.option("--cursor", "tools", flag_value="cursor", help="Cursor only.")
@click.option("--vscode", "tools", flag_value="vscode", help="VSCode Copilot only.")
@click.option("--codex", "tools", flag_value="codex", help="Codex CLI only.")
def upgrade(tools: str | None) -> None:
    """Update hooks and tool configs to the latest version."""
    from hiro_agent.setup_hooks import run_upgrade

    run_upgrade(tool_filter=tools)


@main.command()
def verify() -> None:
    """Verify hook integrity against installed package version."""
    from hiro_agent.setup_hooks import run_verify

    run_verify()
