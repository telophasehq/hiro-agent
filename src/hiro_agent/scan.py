"""Codebase security scan — three-phase audit with per-skill agents."""

import asyncio
import json
import os
import shutil
import sys
import traceback
import time as _time
from pathlib import Path

import structlog

from hiro_agent._common import (
    McpSetup,
    SKILL_TOOLS,
    ToolPolicyViolationError,
    _ScanDisplay,
    get_tool_policy_violation,
    _run_report_stream,
    _run_skill_waves,
    _run_tracked_agent,
    prepare_mcp,
)
from hiro_agent.prompts import (
    CONTEXT_PREAMBLE,
    RECON_STRATEGY_PROMPT,
    RECON_SYSTEM_PROMPT,
    REPORT_SYSTEM_PROMPT,
    SKILL_AGENT_SYSTEM_PROMPT,
)
from hiro_agent.scope_gating import build_shared_index, format_shared_index_for_prompt
from hiro_agent.skills import SKILL_NAMES, load_skill

logger = structlog.get_logger(__name__)

RECON_TOOLS = ["Read", "Grep", "TodoWrite", "TodoRead"]


async def scan(
    *,
    cwd: str | None = None,
    focus: str = "",
    verbose: bool = False,
    output_file: str | None = None,
) -> None:
    """Run a comprehensive security scan of the codebase.

    Four phases:
      1. Reconnaissance — explore the codebase, map structure
      2. Compact — compress recon into a concise brief for skill agents
      3. Skill agents — parallel investigations, one per skill
      4. Report — synthesize findings into a structured report

    Args:
        cwd: Working directory (repo root).
        focus: Optional focus area (e.g., "auth", "api endpoints", "crypto").
        verbose: Print tool use details to stderr.
    """
    repo_name = os.path.basename(cwd) if cwd else "this codebase"
    is_tty = sys.stderr.isatty()
    scan_start = _time.monotonic()

    logger.info("scan_started", cwd=cwd, focus=focus or "general")

    # Shared MCP setup — called once, reused by all agents
    mcp_setup = await prepare_mcp(is_tty=is_tty)

    display = _ScanDisplay(SKILL_NAMES) if is_tty else None
    scratchpad_dir = Path(cwd or ".") / ".hiro" / ".scratchpad"
    shared_index_path = Path(cwd or ".") / ".hiro" / ".scan_index.json"
    completed_successfully = False

    try:
        # -- Phase 1: Reconnaissance -----------------------------------------
        if display:
            display.start_recon()

        recon_prompt_parts = [
            f"Explore and map the codebase at **{repo_name}** ({cwd or '.'}).",
            "Produce a structured reconnaissance summary.",
        ]
        if focus:
            recon_prompt_parts.append(f"\nPay special attention to: {focus}")

        def _on_recon_tool(agent_name: str, tool_name: str, summary: str, is_subagent: bool) -> None:
            if display:
                display.recon_tool(tool_name, summary)

        def _on_recon_text(text: str) -> None:
            if display:
                display.recon_text(text)

        def _on_recon_todos(agent_name: str, todos: list[dict]) -> None:
            if display:
                display.recon_todos(todos)

        def _on_recon_tool_event(agent_name: str, tool_name: str, tool_input: dict, is_subagent: bool) -> None:
            violation = get_tool_policy_violation(
                tool_name=tool_name,
                tool_input=tool_input,
            )
            if violation is not None:
                blocked_path, reason = violation
                raise ToolPolicyViolationError(
                    blocked_path, reason, tool_name=tool_name)

        t0 = _time.monotonic()
        recon = ""
        recon_prompt = "\n".join(recon_prompt_parts)
        recon_policy_note = ""
        for attempt in range(3):
            attempt_start = _time.monotonic()
            logger.info(
                "recon_attempt_started",
                attempt=attempt + 1,
                max_attempts=3,
                has_policy_note=bool(recon_policy_note),
            )
            try:
                recon_max_turns = 10
                recon, _ = await _run_tracked_agent(
                    name="recon",
                    prompt=f"{recon_prompt}{recon_policy_note}",
                    system_prompt=RECON_SYSTEM_PROMPT.replace("{max_turns}", str(recon_max_turns)),
                    cwd=cwd,
                    allowed_tools=RECON_TOOLS,
                    mcp_setup=mcp_setup,
                    max_turns=recon_max_turns,
                    model="sonnet",
                    effort="medium",
                    on_tool=_on_recon_tool,
                    on_tool_event=_on_recon_tool_event,
                    on_text=_on_recon_text,
                    on_todos=_on_recon_todos,
                )
                logger.info(
                    "recon_attempt_finished",
                    attempt=attempt + 1,
                    status="success",
                    duration_s=round(_time.monotonic() - attempt_start, 1),
                )
                break
            except ToolPolicyViolationError as exc:
                logger.warning(
                    "recon_policy_violation",
                    attempt=attempt + 1,
                    tool=exc.tool_name,
                    path=exc.path,
                    reason=exc.reason,
                    duration_s=round(_time.monotonic() - attempt_start, 1),
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
            except BaseException as exc:
                logger.error(
                    "recon_attempt_failed",
                    attempt=attempt + 1,
                    duration_s=round(_time.monotonic() - attempt_start, 1),
                    error_type=type(exc).__name__,
                    error=str(exc),
                )
                raise
        logger.info("phase_completed", phase="recon",
                    duration_s=round(_time.monotonic() - t0, 1))

        # -- Phase 1b: Strategy + compressed brief (Opus) ---------------------
        t0 = _time.monotonic()
        compact_mcp = McpSetup(mcp_config={})
        strategy_output, _ = await _run_tracked_agent(
            name="strategy",
            prompt=f"## Raw Reconnaissance\n\n{recon}",
            system_prompt=RECON_STRATEGY_PROMPT,
            cwd=cwd,
            allowed_tools=[],
            mcp_setup=compact_mcp,
            max_turns=1,
            model="opus",
            effort="medium",
        )

        # Parse strategy vs brief from output.
        # Strategy goes to the user display + report; brief goes to skill agents.
        if "### Compressed Brief" in strategy_output:
            parts = strategy_output.split("### Compressed Brief", 1)
            scan_strategy = parts[0].strip()
            recon_brief = parts[1].strip()
        else:
            # Fallback: use full output as both
            scan_strategy = strategy_output
            recon_brief = strategy_output

        logger.info("phase_completed", phase="strategy",
                    duration_s=round(_time.monotonic() - t0, 1))

        # Show the scan strategy to the user
        if display:
            display.show_recon_summary(scan_strategy)

        # Build a shared first-party index once, then inject into each skill prompt.
        shared_index = build_shared_index(cwd=cwd, recon_summary=recon_brief)
        shared_index_path.parent.mkdir(parents=True, exist_ok=True)
        shared_index_path.write_text(
            json.dumps(shared_index, indent=2, sort_keys=True),
            encoding="utf-8",
        )
        logger.info(
            "shared_index_built",
            path=str(shared_index_path),
            file_count=shared_index.get("file_count", 0),
        )

        # -- Phase 2: Skill agents (parallel, multi-wave) --------------------
        if display:
            display.start_investigations()

        t_investigations = _time.monotonic()
        scratchpad_dir.mkdir(parents=True, exist_ok=True)
        skill_concurrency = min(
            len(SKILL_NAMES),
            max(1, int(os.environ.get("HIRO_SKILL_CONCURRENCY", "4"))),
        )
        sem = asyncio.Semaphore(skill_concurrency)
        logger.info("skill_concurrency_limit", limit=skill_concurrency)

        async def _run_skill(name: str) -> tuple[str, str]:
            t_skill = _time.monotonic()

            if display:
                display.agent_started(name)

            skill_content = load_skill(name)
            system = SKILL_AGENT_SYSTEM_PROMPT.format(
                context_preamble=CONTEXT_PREAMBLE,
                skill_content=skill_content,
                findings_dir=str(scratchpad_dir.resolve()),
                skill_name=name,
            )

            skill_prompt_parts = [
                f"## Reconnaissance Summary\n\n{recon_brief}",
                "\n"
                + format_shared_index_for_prompt(
                    index=shared_index,
                    skill_name=name,
                ),
                (
                    f"\nIndex artifact path: `{shared_index_path.resolve()}`. "
                    "Treat the shared index as authoritative; do not rediscover repo structure."
                ),
                f"\nInvestigate **{name}** security issues in this codebase.",
            ]
            if focus:
                skill_prompt_parts.append(f"\nFocus especially on: {focus}")

            def _on_tool(agent_name: str, tool_name: str, summary: str, is_subagent: bool) -> None:
                if display:
                    display.agent_tool(agent_name, tool_name,
                                       summary, is_subagent)

            def _on_todos(agent_name: str, todos: list[dict]) -> None:
                if display:
                    display.agent_todos(agent_name, todos)

            run_stats: dict[str, object] = {}
            result, tool_call_count = await _run_skill_waves(
                name=name,
                system_prompt=system,
                skill_prompt="\n".join(skill_prompt_parts),
                findings_dir=scratchpad_dir,
                cwd=cwd,
                mcp_setup=mcp_setup,
                on_tool=_on_tool,
                on_todos=_on_todos,
                run_stats=run_stats,
                semaphore=sem,
            )

            has_pending_work = (
                bool(run_stats.get("has_pending_todos"))
                or bool(run_stats.get("has_untraced_edges"))
                or int(run_stats.get("pending_expansion_followups", 0)) > 0
            )
            turn_limited_incomplete = bool(run_stats.get("turn_limited")) and has_pending_work

            if display:
                if turn_limited_incomplete:
                    display.agent_incomplete(name)
                else:
                    display.agent_completed(name)

            # Tag with investigation status so the report can flag incomplete runs
            if turn_limited_incomplete:
                if bool(run_stats.get("continuation_wave_used")):
                    status = (
                        "INCOMPLETE — turn-limited at cap "
                        f"(auto-continued +1 wave, {tool_call_count} tool calls)"
                    )
                else:
                    status = (
                        "INCOMPLETE — turn-limited at cap "
                        f"({tool_call_count} tool calls)"
                    )
            elif tool_call_count < 3:
                status = f"INCOMPLETE — only {tool_call_count} tool calls"
            else:
                status = f"{tool_call_count} tool calls"

            total_duration = round(_time.monotonic() - t_skill, 1)
            logger.info(
                "skill_completed",
                skill=name,
                tool_calls=tool_call_count,
                total_s=total_duration,
                findings_len=len(result),
            )

            return name, f"_Investigation status: {status}_\n\n{result}"

        raw_results = await asyncio.gather(
            *[_run_skill(n) for n in SKILL_NAMES],
            return_exceptions=True,
        )

        # Collect results, logging any exceptions
        findings: list[tuple[str, str]] = []
        for skill_name, r in zip(SKILL_NAMES, raw_results):
            if isinstance(r, BaseException):
                logger.error(
                    "skill_agent_failed",
                    skill=skill_name,
                    error_type=type(r).__name__,
                    error=str(r),
                    traceback="".join(
                        traceback.format_exception(type(r), r, r.__traceback__)
                    ),
                )
            else:
                findings.append(r)

        logger.info(
            "phase_completed",
            phase="investigations",
            duration_s=round(_time.monotonic() - t_investigations, 1),
            succeeded=len(findings),
            failed=len(raw_results) - len(findings),
        )

        # -- Phase 3: Report (streaming) -------------------------------------
        if display:
            display.start_report()

        t0 = _time.monotonic()
        combined = "\n\n".join(
            f"## {name}\n\n{text}" for name, text in findings)
        report_prompt = (
            f"## Reconnaissance Summary\n\n{scan_strategy}\n\n{recon_brief}\n\n"
            f"## Investigation Findings\n\n{combined}\n\n"
            "Synthesize the above into a final security report."
        )

        await _run_report_stream(
            prompt=report_prompt,
            system_prompt=REPORT_SYSTEM_PROMPT,
            mcp_setup=mcp_setup,
            model="opus",
            is_tty=is_tty,
            output_file=output_file,
        )
        logger.info("phase_completed", phase="report",
                    duration_s=round(_time.monotonic() - t0, 1))

        if display:
            display.finish()

        logger.info(
            "scan_completed",
            total_s=round(_time.monotonic() - scan_start, 1),
        )
        completed_successfully = True

    finally:
        if completed_successfully:
            shutil.rmtree(scratchpad_dir, ignore_errors=True)
        elif scratchpad_dir.exists():
            logger.warning(
                "scratchpad_preserved",
                path=str(scratchpad_dir),
                reason="scan_failed_or_aborted",
            )


def main() -> None:
    """CLI entry point."""
    cwd = os.getcwd()
    asyncio.run(scan(cwd=cwd))


if __name__ == "__main__":
    main()
