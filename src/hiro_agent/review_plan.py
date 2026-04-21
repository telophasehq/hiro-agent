"""Plan review agent — single-agent STRIDE threat modeling on design documents."""

import asyncio
import os
import sys
import tempfile
import time as _time

import structlog

from hiro_agent._common import (
    ToolPolicyViolationError,
    _ScanDisplay,
    _strip_post_report_text,
    get_tool_policy_violation,
    _run_tracked_agent,
    prepare_mcp,
)
from hiro_agent.prompts import (
    CONTEXT_PREAMBLE,
    REVIEW_PLAN_SYSTEM_PROMPT,
)
from hiro_agent.skills import SKILL_NAMES, load_skill

logger = structlog.get_logger(__name__)


async def review_plan(
    plan: str,
    *,
    cwd: str | None = None,
    context: str = "",
    verbose: bool = False,
    output_file: str | None = None,
    mirror_to_stdout: bool = False,
) -> None:
    """Run a single-agent STRIDE threat model review on an implementation plan.

    One Opus agent reads the plan, explores surrounding code, investigates
    security implications, and writes the STRIDE report as its final output.

    Args:
        plan: The plan text, architecture description, or design document.
        cwd: Working directory (repo root).
        context: Additional context (e.g., "Public-facing payment API").
        verbose: Print tool use details to stderr.
    """
    repo_name = os.path.basename(cwd) if cwd else "this codebase"
    is_tty = sys.stderr.isatty()
    review_start = _time.monotonic()

    logger.info("review_plan_started", cwd=cwd, plan_len=len(plan))

    # Write plan to a temp file so the agent can Read it instead of
    # embedding the entire plan in the prompt context window.
    plan_fd, plan_path = tempfile.mkstemp(suffix=".md", prefix="hiro-plan-")
    try:
        os.write(plan_fd, plan.encode())
    finally:
        os.close(plan_fd)
    logger.info("plan_written", path=plan_path, size=len(plan))

    # Shared MCP setup — called once
    mcp_setup = await prepare_mcp(is_tty=is_tty)

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

        system = REVIEW_PLAN_SYSTEM_PROMPT.format(
            context_preamble=CONTEXT_PREAMBLE,
            all_playbooks=all_playbooks,
        )

        prompt_parts = [
            f"Review the plan at `{plan_path}` from {repo_name}.",
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
                    "review_plan_policy_violation",
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
            "review_plan_completed",
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

    finally:
        # Clean up the temp plan file.
        try:
            os.unlink(plan_path)
        except OSError:
            pass


def main() -> None:
    """CLI entry point: reads plan from stdin."""
    plan = sys.stdin.read()
    if not plan.strip():
        print("No input provided. Pipe a plan: cat plan.md | hiro review-plan")
        sys.exit(1)

    cwd = os.getcwd()
    asyncio.run(review_plan(plan, cwd=cwd))


if __name__ == "__main__":
    main()
