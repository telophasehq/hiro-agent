"""Code review agent — analyzes diffs with filesystem access."""

import asyncio
import sys

import structlog

from hiro_agent._common import run_review_agent
from hiro_agent.prompts import CODE_REVIEW_SYSTEM_PROMPT

logger = structlog.get_logger(__name__)

ALLOWED_TOOLS = ["Read", "Grep", "Glob"]
MAX_TURNS = 15


async def review_code(
    diff_or_files: str,
    *,
    cwd: str | None = None,
    context: str = "",
) -> str:
    """Run a security code review on a diff or set of files.

    Args:
        diff_or_files: Git diff output or file contents to review.
        cwd: Working directory for filesystem access (repo root).
        context: Additional context about what the code does.
    """
    prompt_parts = ["Review the following code changes for security issues:\n"]
    if context:
        prompt_parts.append(f"Context: {context}\n")
    prompt_parts.append(f"```\n{diff_or_files}\n```")

    prompt = "\n".join(prompt_parts)

    logger.info("review_code_started", diff_len=len(diff_or_files), has_cwd=bool(cwd))

    result = await run_review_agent(
        prompt=prompt,
        system_prompt=CODE_REVIEW_SYSTEM_PROMPT,
        cwd=cwd,
        allowed_tools=ALLOWED_TOOLS,
        max_turns=MAX_TURNS,
    )

    logger.info("review_code_completed", result_len=len(result))
    return result


def main() -> None:
    """CLI entry point: reads diff from stdin."""
    diff = sys.stdin.read()
    if not diff.strip():
        print("No input provided. Pipe a diff: git diff | hiro review-code")
        sys.exit(1)

    result = asyncio.run(review_code(diff))
    print(result)


if __name__ == "__main__":
    main()
