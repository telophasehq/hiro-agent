"""Infrastructure review agent — IaC security analysis with filesystem access."""

import asyncio
import sys

import structlog

from hiro_agent._common import run_review_agent
from hiro_agent.prompts import INFRA_REVIEW_SYSTEM_PROMPT

logger = structlog.get_logger(__name__)

ALLOWED_TOOLS = ["Read", "Grep"]
MAX_TURNS = 12

# Detect config type from filename extension/patterns
CONFIG_TYPE_MAP = {
    "dockerfile": "Dockerfile",
    "docker-compose": "Docker Compose",
    "values.yaml": "Helm Values",
    "values.yml": "Helm Values",
    ".helmfile": "Helm",
    ".tf": "Terraform",
    ".hcl": "Terraform",
    ".tfvars": "Terraform Variables",
    ".yaml": "Kubernetes/CloudFormation YAML",
    ".yml": "Kubernetes/CloudFormation YAML",
    ".json": "CloudFormation/ARM JSON",
}


def _detect_config_type(filename: str) -> str:
    """Detect IaC config type from filename."""
    filename_lower = filename.lower()
    for pattern, config_type in CONFIG_TYPE_MAP.items():
        if pattern in filename_lower:
            return config_type
    return "Infrastructure Configuration"


async def review_infrastructure(
    config_or_path: str,
    *,
    filename: str = "unknown",
    cwd: str | None = None,
) -> str:
    """Run a security review on infrastructure-as-code configuration.

    Args:
        config_or_path: Configuration file contents or a file path.
        filename: Filename used to detect config type.
        cwd: Working directory for filesystem access.
    """
    config_type = _detect_config_type(filename)

    prompt_parts = [
        f"Review this {config_type} configuration for security misconfigurations.",
        f"Filename: {filename}",
        "",
    ]

    # If it looks like a file path (no newlines, starts with / or ./), tell
    # the agent to read it.  Otherwise include inline.
    is_path = "\n" not in config_or_path and (
        config_or_path.startswith("/") or config_or_path.startswith("./")
    )
    if is_path:
        prompt_parts.append(f"Read the file at `{config_or_path}` and review it.")
        prompt_parts.append("Also check for related configuration files in the same directory.")
    else:
        prompt_parts.append(f"```\n{config_or_path}\n```")

    prompt = "\n".join(prompt_parts)

    logger.info(
        "review_infra_started",
        filename=filename,
        config_type=config_type,
        is_path=is_path,
    )

    result = await run_review_agent(
        prompt=prompt,
        system_prompt=INFRA_REVIEW_SYSTEM_PROMPT,
        cwd=cwd,
        allowed_tools=ALLOWED_TOOLS,
        max_turns=MAX_TURNS,
    )

    logger.info("review_infra_completed", result_len=len(result))
    return result


def main() -> None:
    """CLI entry point: reads config from stdin or file path argument."""
    if len(sys.argv) > 1:
        # Argument is a file path
        filepath = sys.argv[1]
        filename = filepath.rsplit("/", 1)[-1] if "/" in filepath else filepath
        result = asyncio.run(
            review_infrastructure(filepath, filename=filename)
        )
    else:
        config = sys.stdin.read()
        if not config.strip():
            print("No input. Usage: hiro review-infra <filepath>")
            print("   or: cat main.tf | hiro review-infra")
            sys.exit(1)
        result = asyncio.run(
            review_infrastructure(config, filename="stdin")
        )

    print(result)


if __name__ == "__main__":
    main()
