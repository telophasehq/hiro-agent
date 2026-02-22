"""Codebase security scan — three-phase audit with per-skill agents."""

import asyncio
import os
import shutil
import sys
import time as _time
from pathlib import Path

import structlog

from hiro_agent._common import (
    McpSetup,
    SKILL_TOOLS,
    _ScanDisplay,
    _run_report_stream,
    _run_skill_waves,
    _run_tracked_agent,
    prepare_mcp,
)
from hiro_agent.prompts import (
    CONTEXT_PREAMBLE,
    RECON_SYSTEM_PROMPT,
    REPORT_SYSTEM_PROMPT,
    SKILL_AGENT_SYSTEM_PROMPT,
)
from hiro_agent.skills import SKILL_NAMES, load_skill

logger = structlog.get_logger(__name__)

RECON_TOOLS = ["Read", "Grep", "Glob", "TodoWrite", "TodoRead"]


async def scan(
    *,
    cwd: str | None = None,
    focus: str = "",
    verbose: bool = False,
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

        t0 = _time.monotonic()
        recon, _ = await _run_tracked_agent(
            name="recon",
            prompt="\n".join(recon_prompt_parts),
            system_prompt=RECON_SYSTEM_PROMPT,
            cwd=cwd,
            allowed_tools=RECON_TOOLS,
            mcp_setup=mcp_setup,
            max_turns=15,
            model="opus",
            on_tool=_on_recon_tool,
            on_text=_on_recon_text,
            on_todos=_on_recon_todos,
        )
        logger.info("phase_completed", phase="recon", duration_s=round(_time.monotonic() - t0, 1))

        # Always show the recon summary (the "scan plan")
        if display:
            display.show_recon_summary(recon)

        # -- Phase 1b: Compact recon summary for downstream agents ------------
        t0 = _time.monotonic()
        compact_mcp = McpSetup(mcp_config={})
        recon_brief, _ = await _run_tracked_agent(
            name="compact",
            prompt=(
                "Compress the following reconnaissance summary into a concise "
                "brief (under 2000 words). Preserve ALL factual findings: tech "
                "stack, key file paths, entry points, auth mechanism, dependencies, "
                "infrastructure, and security-relevant observations. Drop verbose "
                "descriptions, redundant details, and filler. Output only the "
                "compressed summary — no preamble.\n\n"
                f"{recon}"
            ),
            system_prompt="You are a concise technical summarizer. Output only the compressed summary.",
            cwd=cwd,
            allowed_tools=[],
            mcp_setup=compact_mcp,
            max_turns=1,
            model="sonnet",
        )
        logger.info("phase_completed", phase="compact", duration_s=round(_time.monotonic() - t0, 1))

        # -- Phase 2: Skill agents (parallel, multi-wave) --------------------
        if display:
            display.start_investigations()

        t_investigations = _time.monotonic()
        scratchpad_dir.mkdir(parents=True, exist_ok=True)

        async def _run_skill(name: str) -> tuple[str, str]:
            t_skill = _time.monotonic()

            if display:
                display.agent_started(name)

            skill_content = load_skill(name)
            scratchpad_path = scratchpad_dir / f"{name}.md"
            system = SKILL_AGENT_SYSTEM_PROMPT.format(
                context_preamble=CONTEXT_PREAMBLE,
                skill_content=skill_content,
                scratchpad_path=str(scratchpad_path.resolve()),
            )

            skill_prompt_parts = [
                f"## Reconnaissance Summary\n\n{recon_brief}",
                f"\nInvestigate **{name}** security issues in this codebase.",
            ]
            if focus:
                skill_prompt_parts.append(f"\nFocus especially on: {focus}")

            def _on_tool(agent_name: str, tool_name: str, summary: str, is_subagent: bool) -> None:
                if display:
                    display.agent_tool(agent_name, tool_name, summary, is_subagent)

            def _on_todos(agent_name: str, todos: list[dict]) -> None:
                if display:
                    display.agent_todos(agent_name, todos)

            result, tool_call_count = await _run_skill_waves(
                name=name,
                system_prompt=system,
                skill_prompt="\n".join(skill_prompt_parts),
                scratchpad_path=scratchpad_path,
                cwd=cwd,
                mcp_setup=mcp_setup,
                on_tool=_on_tool,
                on_todos=_on_todos,
            )

            if display:
                display.agent_completed(name)

            # Tag with investigation status so the report can flag incomplete runs
            if tool_call_count < 3:
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
        for r in raw_results:
            if isinstance(r, BaseException):
                logger.error("skill_agent_failed", error=str(r))
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
        combined = "\n\n".join(f"## {name}\n\n{text}" for name, text in findings)
        report_prompt = (
            f"## Reconnaissance Summary\n\n{recon}\n\n"
            f"## Investigation Findings\n\n{combined}\n\n"
            "Synthesize the above into a final security report."
        )

        await _run_report_stream(
            prompt=report_prompt,
            system_prompt=REPORT_SYSTEM_PROMPT,
            mcp_setup=mcp_setup,
            model="opus",
            is_tty=is_tty,
        )
        logger.info("phase_completed", phase="report", duration_s=round(_time.monotonic() - t0, 1))

        if display:
            display.finish()

        logger.info(
            "scan_completed",
            total_s=round(_time.monotonic() - scan_start, 1),
        )

    finally:
        shutil.rmtree(scratchpad_dir, ignore_errors=True)


def main() -> None:
    """CLI entry point."""
    cwd = os.getcwd()
    asyncio.run(scan(cwd=cwd))


if __name__ == "__main__":
    main()
