"""Code review — single-agent security audit of a diff."""

import asyncio
import json
import os
import sys
import tempfile
import time as _time
from pathlib import Path

import structlog

from hiro_agent._common import (
    ToolPolicyViolationError,
    _ScanDisplay,
    _get_api_key,
    _prefetch_review_context,
    _strip_post_report_text,
    get_tool_policy_violation,
    _run_tracked_agent,
    prepare_mcp,
)
from hiro_agent.prompts import (
    CONTEXT_PREAMBLE,
    REVIEW_CODE_SYSTEM_PROMPT,
)
from hiro_agent.review_store import save_pending
from hiro_agent.skills import SKILL_NAMES, load_skill

logger = structlog.get_logger(__name__)


def _git_head_sha(cwd: str | None) -> str | None:
    """Return current HEAD SHA, or None if not in a git repo / no commits yet."""
    import subprocess
    try:
        out = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=cwd or ".",
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode != 0:
            return None
        return out.stdout.strip() or None
    except Exception:
        return None


def _clear_review_state(cwd: str | None) -> None:
    """Clear all code_review state files so git commit is unblocked."""
    state_dir = Path(cwd or ".") / ".hiro" / ".state"
    if not state_dir.is_dir():
        return
    for state_file in state_dir.glob("code_review_*.json"):
        try:
            state = json.loads(state_file.read_text())
            state["needs_review"] = False
            state["modified_files"] = []
            state["updated_at"] = int(_time.time())
            state_file.write_text(json.dumps(state))
        except Exception:
            continue


async def review_code(
    diff: str,
    *,
    cwd: str | None = None,
    context: str = "",
    verbose: bool = False,
    output_file: str | None = None,
    mirror_to_stdout: bool = False,
) -> None:
    """Run a single-agent security review of a diff.

    One Opus agent reads the diff, explores surrounding code, investigates
    security issues, and writes the report as its final output.

    Args:
        diff: Git diff output to review.
        cwd: Working directory (repo root).
        context: Additional context about the code.
        verbose: Print tool use details to stderr.
    """
    repo_name = os.path.basename(cwd) if cwd else "this codebase"
    is_tty = sys.stderr.isatty()
    review_start = _time.monotonic()

    logger.info("review_code_started", cwd=cwd, diff_len=len(diff))

    # Write diff to a temp file so the agent can Read it instead of
    # embedding the entire diff in the prompt context window.
    diff_fd, diff_path = tempfile.mkstemp(suffix=".patch", prefix="hiro-diff-")
    try:
        os.write(diff_fd, diff.encode())
    finally:
        os.close(diff_fd)
    logger.info("diff_written", path=diff_path, size=len(diff))

    # Shared MCP setup — called once
    mcp_setup = await prepare_mcp(is_tty=is_tty)

    # Prefetch infrastructure context for this diff
    api_key = _get_api_key()
    if api_key and mcp_setup.mcp_config:
        mcp_setup.review_context = await _prefetch_review_context(api_key, diff)

    display = _ScanDisplay(["review"], skip_phases=True) if is_tty else None

    try:
        if display:
            display.start_investigations()
            display.agent_started("review")

        # Bundle all playbooks into the system prompt
        all_playbooks = "\n\n".join(
            f"### {name.replace('-', ' ').title()}\n\n{load_skill(name)}"
            for name in SKILL_NAMES
        )

        system = REVIEW_CODE_SYSTEM_PROMPT.format(
            context_preamble=CONTEXT_PREAMBLE,
            all_playbooks=all_playbooks,
        )

        prompt_parts = [
            f"Review the diff at `{diff_path}` from {repo_name}.",
        ]
        if context:
            prompt_parts.append(f"\nAdditional context: {context}")

        def _on_tool(agent_name: str, tool_name: str, summary: str, is_subagent: bool) -> None:
            if display:
                display.agent_tool(agent_name, tool_name, summary, is_subagent)

        def _on_tool_event(agent_name: str, tool_name: str, tool_input: dict, is_subagent: bool) -> None:
            violation = get_tool_policy_violation(
                tool_name=tool_name,
                tool_input=tool_input,
            )
            if violation is not None:
                blocked_path, reason = violation
                raise ToolPolicyViolationError(blocked_path, reason, tool_name=tool_name)

        policy_note = ""
        for attempt in range(3):
            try:
                output, _ = await _run_tracked_agent(
                    name="review",
                    prompt="\n".join(prompt_parts) + policy_note,
                    system_prompt=system,
                    cwd=cwd,
                    allowed_tools=["Read", "Grep"],
                    mcp_setup=mcp_setup,
                    max_turns=30,
                    model="opus",
                    thinking_budget=30_000,
                    on_tool=_on_tool,
                    on_tool_event=_on_tool_event,
                )
                break
            except ToolPolicyViolationError as exc:
                logger.warning(
                    "review_policy_violation",
                    attempt=attempt + 1,
                    tool=exc.tool_name,
                    path=exc.path,
                    reason=exc.reason,
                )
                if attempt == 2:
                    raise
                policy_note = (
                    "\n\n## Enforced Tool Policy\n"
                    "- Do not read or search inside `.git/` directories.\n"
                    "- Do not search `.venv`, `node_modules`, `vendor`, `dist`, or other ignored directories.\n"
                    "- For `Grep`/`Glob`, always scope to first-party paths (for example: `src`, `app`, "
                    "`backend`, `frontend`, `services`, `tests`).\n"
                    "- Repo-root recursive searches are blocked.\n"
                )

        if display:
            display.agent_completed("review")

        # Strip trailing narration (safety net)
        output = _strip_post_report_text(output)

        logger.info(
            "review_code_completed",
            total_s=round(_time.monotonic() - review_start, 1),
        )

        if display:
            display.start_report()

        # Write output
        if output.strip():
            out_fh = open(output_file, "w") if output_file else None  # noqa: SIM115
            if out_fh:
                out_fh.write(output + "\n")
                out_fh.flush()
                out_fh.close()
            if not out_fh or mirror_to_stdout:
                print(output, flush=True)

            # Persist for the post-commit hook to pick up and upload.
            try:
                save_pending(
                    cwd=cwd,
                    diff=diff,
                    report_text=output,
                    parent_sha=_git_head_sha(cwd),
                )
            except Exception:
                logger.warning("review_persist_failed", exc_info=True)

        # Clear pre-commit gate so `git commit` is unblocked.
        _clear_review_state(cwd)

    finally:
        # Clean up the temp diff file.
        try:
            os.unlink(diff_path)
        except OSError:
            pass


def main() -> None:
    """CLI entry point: reads diff from stdin."""
    diff = sys.stdin.read()
    if not diff.strip():
        print("No input provided. Pipe a diff: git diff | hiro review-code")
        sys.exit(1)

    cwd = os.getcwd()
    asyncio.run(review_code(diff, cwd=cwd))


if __name__ == "__main__":
    main()
