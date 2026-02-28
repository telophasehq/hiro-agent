"""Interactive security chat — Q&A about the codebase."""

import asyncio
import os

import structlog

from hiro_agent._common import run_streaming_agent
from hiro_agent.prompts import CHAT_SYSTEM_PROMPT

logger = structlog.get_logger(__name__)

ALLOWED_TOOLS = ["Read", "Grep"]
MAX_TURNS = 15


async def chat(
    question: str,
    *,
    cwd: str | None = None,
    verbose: bool = False,
    output_file: str | None = None,
) -> None:
    """Ask a security question about the codebase.

    Args:
        question: The user's question.
        cwd: Working directory (repo root).
        verbose: Print tool use details to stderr.
    """
    logger.info("chat_started", question_len=len(question), cwd=cwd)

    await run_streaming_agent(
        prompt=question,
        system_prompt=CHAT_SYSTEM_PROMPT,
        cwd=cwd,
        allowed_tools=ALLOWED_TOOLS,
        max_turns=MAX_TURNS,
        verbose=verbose,
        model="sonnet",
        output_file=output_file,
    )

    logger.info("chat_completed")
