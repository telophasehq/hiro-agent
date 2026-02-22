"""Plan review agent — STRIDE threat modeling on design documents."""

import asyncio
import os
import sys

import structlog

from hiro_agent._common import run_streaming_agent
from hiro_agent.prompts import PLAN_REVIEW_SYSTEM_PROMPT

logger = structlog.get_logger(__name__)

ALLOWED_TOOLS = ["Read", "Grep", "Glob"]
MAX_TURNS = 15


async def review_plan(
    plan: str,
    *,
    cwd: str | None = None,
    context: str = "",
    verbose: bool = False,
) -> None:
    """Run a STRIDE threat model review on an implementation plan.

    Args:
        plan: The plan text, architecture description, or design document.
        cwd: Working directory (repo root).
        context: Additional context (e.g., "Public-facing payment API").
        verbose: Print tool use details to stderr.
    """
    prompt_parts = ["Review this implementation plan for security concerns:\n"]
    if context:
        prompt_parts.append(f"Context: {context}\n")
    prompt_parts.append(plan)

    prompt = "\n".join(prompt_parts)

    logger.info("review_plan_started", plan_len=len(plan))

    await run_streaming_agent(
        prompt=prompt,
        system_prompt=PLAN_REVIEW_SYSTEM_PROMPT,
        cwd=cwd,
        allowed_tools=ALLOWED_TOOLS,
        max_turns=MAX_TURNS,
        verbose=verbose,
    )

    logger.info("review_plan_completed")


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
