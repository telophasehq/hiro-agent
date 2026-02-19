"""Plan review agent — STRIDE threat modeling on design documents."""

import asyncio
import sys

import structlog

from hiro_agent._common import run_review_agent
from hiro_agent.prompts import PLAN_REVIEW_SYSTEM_PROMPT

logger = structlog.get_logger(__name__)

MAX_TURNS = 10


async def review_plan(
    plan: str,
    *,
    context: str = "",
) -> str:
    """Run a STRIDE threat model review on an implementation plan.

    Args:
        plan: The plan text, architecture description, or design document.
        context: Additional context (e.g., "Public-facing payment API").
    """
    prompt_parts = ["Review this implementation plan for security concerns:\n"]
    if context:
        prompt_parts.append(f"Context: {context}\n")
    prompt_parts.append(plan)

    prompt = "\n".join(prompt_parts)

    logger.info("review_plan_started", plan_len=len(plan))

    result = await run_review_agent(
        prompt=prompt,
        system_prompt=PLAN_REVIEW_SYSTEM_PROMPT,
        allowed_tools=[],
        max_turns=MAX_TURNS,
    )

    logger.info("review_plan_completed", result_len=len(result))
    return result


def main() -> None:
    """CLI entry point: reads plan from stdin."""
    plan = sys.stdin.read()
    if not plan.strip():
        print("No input provided. Pipe a plan: cat plan.md | hiro review-plan")
        sys.exit(1)

    result = asyncio.run(review_plan(plan))
    print(result)


if __name__ == "__main__":
    main()
