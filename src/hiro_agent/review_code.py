"""Code review — single-agent security audit of a diff."""

import asyncio
import json
import os
import sys
import time as _time
from pathlib import Path

import structlog

from hiro_agent._common import (
    ToolPolicyViolationError,
    _ScanDisplay,
    _get_api_key,
    _prefetch_review_context,
    get_tool_policy_violation,
    _run_report_stream,
    _run_tracked_agent,
    prepare_mcp,
)
from hiro_agent.prompts import (
    CONTEXT_PREAMBLE,
    DIFF_INVESTIGATION_SYSTEM_PROMPT,
    DIFF_RECON_SYSTEM_PROMPT,
    REPORT_SYSTEM_PROMPT,
)
from hiro_agent.skills import SKILL_NAMES, load_skill

logger = structlog.get_logger(__name__)

RECON_TOOLS = ["Read", "Grep", "TodoWrite", "TodoRead"]


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
) -> None:
    """Run a single-agent security review of a diff.

    Three phases:
      1. Reconnaissance — explore code surrounding the diff (Sonnet, 5 turns)
      2. Investigation — single Opus agent with all playbook knowledge (10 turns)
      3. Report — synthesize findings into a structured report

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

    # Shared MCP setup — called once, reused by all agents
    mcp_setup = await prepare_mcp(is_tty=is_tty)

    # Prefetch infrastructure context for this diff (runs in parallel with setup)
    api_key = _get_api_key()
    if api_key and mcp_setup.mcp_config:
        mcp_setup.review_context = await _prefetch_review_context(api_key, diff)

    display = _ScanDisplay(["investigation"]) if is_tty else None

    try:
        # -- Phase 1: Reconnaissance ------------------------------------------
        if display:
            display.start_recon()

        recon_prompt_parts = [
            f"Review the following diff from **{repo_name}** ({cwd or '.'}).",
            "Explore the surrounding code to understand the security context.",
            f"\n## Diff\n\n```diff\n{diff}\n```",
        ]
        if context:
            recon_prompt_parts.append(f"\nAdditional context: {context}")

        def _on_recon_tool(agent_name: str, tool_name: str, summary: str, is_subagent: bool) -> None:
            if display:
                display.recon_tool(tool_name, summary)

        def _on_recon_text(text: str) -> None:
            if display:
                display.recon_text(text)

        def _on_recon_tool_event(agent_name: str, tool_name: str, tool_input: dict, is_subagent: bool) -> None:
            violation = get_tool_policy_violation(
                tool_name=tool_name,
                tool_input=tool_input,
            )
            if violation is not None:
                blocked_path, reason = violation
                raise ToolPolicyViolationError(blocked_path, reason, tool_name=tool_name)

        t0 = _time.monotonic()
        recon = ""
        recon_prompt = "\n".join(recon_prompt_parts)
        recon_policy_note = ""
        for attempt in range(3):
            try:
                recon_max_turns = 5
                recon, _ = await _run_tracked_agent(
                    name="recon",
                    prompt=f"{recon_prompt}{recon_policy_note}",
                    system_prompt=DIFF_RECON_SYSTEM_PROMPT.replace("{max_turns}", str(recon_max_turns)),
                    cwd=cwd,
                    allowed_tools=RECON_TOOLS,
                    mcp_setup=mcp_setup,
                    max_turns=recon_max_turns,
                    model="sonnet",
                    effort="medium",
                    on_tool=_on_recon_tool,
                    on_tool_event=_on_recon_tool_event,
                    on_text=_on_recon_text,
                )
                break
            except ToolPolicyViolationError as exc:
                logger.warning(
                    "diff_recon_policy_violation",
                    attempt=attempt + 1,
                    tool=exc.tool_name,
                    path=exc.path,
                    reason=exc.reason,
                )
                if attempt == 2:
                    raise
                recon_policy_note = (
                    "\n\n## Enforced Tool Policy\n"
                    "- Do not search `.venv`, `node_modules`, `vendor`, `dist`, or other ignored directories.\n"
                    "- For `Grep`/`Glob`, always scope to first-party paths (for example: `src`, `app`, "
                    "`backend`, `frontend`, `services`, `tests`).\n"
                    "- Repo-root recursive searches are blocked.\n"
                )
        logger.info("phase_completed", phase="recon", duration_s=round(_time.monotonic() - t0, 1))

        # -- Phase 2: Investigation (single agent, bundled playbooks) ----------
        if display:
            display.start_investigations()
            display.agent_started("investigation")

        t0 = _time.monotonic()

        # Bundle all playbooks into the system prompt
        all_playbooks = "\n\n".join(
            f"### {name.replace('-', ' ').title()}\n\n{load_skill(name)}"
            for name in SKILL_NAMES
        )

        investigation_max_turns = 10
        investigation_system = DIFF_INVESTIGATION_SYSTEM_PROMPT.format(
            context_preamble=CONTEXT_PREAMBLE,
            all_playbooks=all_playbooks,
            max_turns=investigation_max_turns,
        )

        investigation_prompt_parts = [
            f"## Diff Under Review\n\n```diff\n{diff}\n```",
            f"\n## Codebase Context\n\n{recon}",
        ]
        if context:
            investigation_prompt_parts.append(f"\nAdditional context: {context}")

        def _on_investigation_tool(agent_name: str, tool_name: str, summary: str, is_subagent: bool) -> None:
            if display:
                display.agent_tool(agent_name, tool_name, summary, is_subagent)

        def _on_investigation_tool_event(agent_name: str, tool_name: str, tool_input: dict, is_subagent: bool) -> None:
            violation = get_tool_policy_violation(
                tool_name=tool_name,
                tool_input=tool_input,
            )
            if violation is not None:
                blocked_path, reason = violation
                raise ToolPolicyViolationError(blocked_path, reason, tool_name=tool_name)

        investigation_output, _ = await _run_tracked_agent(
            name="investigation",
            prompt="\n".join(investigation_prompt_parts),
            system_prompt=investigation_system,
            cwd=cwd,
            allowed_tools=["Read", "Grep"],
            mcp_setup=mcp_setup,
            max_turns=investigation_max_turns,
            model="opus",
            on_tool=_on_investigation_tool,
            on_tool_event=_on_investigation_tool_event,
        )

        if display:
            display.agent_completed("investigation")

        logger.info(
            "phase_completed",
            phase="investigation",
            duration_s=round(_time.monotonic() - t0, 1),
        )

        # -- Phase 3: Report (streaming) --------------------------------------
        if display:
            display.start_report()

        t0 = _time.monotonic()
        report_prompt = (
            f"## Diff Under Review\n\n```diff\n{diff}\n```\n\n"
            f"## Investigation Findings\n\n{investigation_output}\n\n"
            "Synthesize the above into a final security report for this diff."
        )

        await _run_report_stream(
            prompt=report_prompt,
            system_prompt=REPORT_SYSTEM_PROMPT,
            mcp_setup=mcp_setup,
            model="opus",
            is_tty=is_tty,
            output_file=output_file,
        )
        logger.info("phase_completed", phase="report", duration_s=round(_time.monotonic() - t0, 1))

        if display:
            display.finish()

        logger.info(
            "review_code_completed",
            total_s=round(_time.monotonic() - review_start, 1),
        )

        # Clear pre-commit gate so `git commit` is unblocked.
        _clear_review_state(cwd)

    finally:
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
