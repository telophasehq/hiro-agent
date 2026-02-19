"""Shared agent runner for local security review agents.

CLAUDECODE="" prevents claude-agent-sdk from detecting a nested Claude Code
session and rejecting the spawn. This is intentional — the review agent is
a separate subprocess, not a nested invocation of the caller's session.
"""

import json
import os
from pathlib import Path

import structlog
from claude_agent_sdk import (
    AssistantMessage,
    ClaudeAgentOptions,
    TextBlock,
    query,
)
from claude_agent_sdk.types import McpHttpServerConfig

logger = structlog.get_logger(__name__)

# Hardcoded — not configurable to prevent SSRF. HTTPS enforced.
HIRO_MCP_URL = "https://api.hiro.is/mcp/architect"
HIRO_BACKEND_URL = "https://api.hiro.is"


def _get_api_key() -> str:
    """Resolve Hiro API key: env var first, then .hiro/config.json."""
    key = os.environ.get("HIRO_API_KEY", "")
    if key:
        return key
    config_file = Path(".hiro/config.json")
    if config_file.exists():
        try:
            return json.loads(config_file.read_text()).get("api_key", "")
        except Exception:
            return ""
    return ""


def _get_mcp_config() -> dict[str, McpHttpServerConfig]:
    """Build MCP server config for connecting to Hiro.

    Returns an empty dict when no API key is available (MCP context
    tools will be unavailable but the review still runs).
    """
    key = _get_api_key()
    if not key:
        return {}
    return {
        "hiro": McpHttpServerConfig(
            url=HIRO_MCP_URL,
            headers={"Authorization": f"Bearer {key}"},
        ),
    }


def _get_agent_env() -> dict[str, str]:
    """Build env vars for the agent subprocess.

    When a Hiro API key is available, route LLM calls through the Hiro
    backend proxy to Bedrock (keeps source code within AWS infrastructure).
    Otherwise the agent uses the developer's ANTHROPIC_API_KEY directly.
    """
    env: dict[str, str] = {"CLAUDECODE": ""}
    api_key = _get_api_key()
    if api_key:
        env["ANTHROPIC_BASE_URL"] = f"{HIRO_BACKEND_URL}/api/llm-proxy"
        env["ANTHROPIC_API_KEY"] = api_key
    return env


async def run_review_agent(
    prompt: str,
    system_prompt: str,
    *,
    cwd: str | None = None,
    allowed_tools: list[str] | None = None,
    max_turns: int = 15,
) -> str:
    """Run a local review agent and return its final text output.

    The agent connects to the Hiro MCP server for organizational context
    (memories, security policy, org profile) and optionally has filesystem
    access via Read/Grep/Glob tools.

    Only read-only MCP tools are allowed — remember, set_org_context, and
    forget are explicitly excluded to prevent the review agent from
    modifying organizational state.
    """
    mcp_config = _get_mcp_config()

    # MCP context tools are only available when connected to Hiro
    mcp_tools = []
    if mcp_config:
        mcp_tools = [
            "mcp__hiro__get_org_context",
            "mcp__hiro__recall",
            "mcp__hiro__get_security_policy",
        ]

    options = ClaudeAgentOptions(
        cwd=cwd,
        allowed_tools=(allowed_tools or []) + mcp_tools,
        system_prompt=system_prompt,
        mcp_servers=mcp_config,
        permission_mode="acceptEdits",
        max_turns=max_turns,
        env=_get_agent_env(),
    )

    summary = ""
    async for message in query(prompt=prompt, options=options):
        if isinstance(message, AssistantMessage):
            for block in message.content:
                if isinstance(block, TextBlock):
                    summary = block.text

    return summary
