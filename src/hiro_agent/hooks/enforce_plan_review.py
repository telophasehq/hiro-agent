#!/usr/bin/env python3
"""Enforce Hiro plan review before allowing ExitPlanMode.

Tool-agnostic: works with Claude Code, Cursor, VSCode Copilot, and Codex.
Detects caller format automatically.

State stored in .hiro/.state/ (not tool-specific directories).
"""

from __future__ import annotations

import json
import os
import stat
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def _git_root() -> Path:
    """Resolve the git repo root so paths work from any CWD."""
    try:
        root = subprocess.check_output(
            ["git", "rev-parse", "--show-toplevel"],
            stderr=subprocess.DEVNULL,
            text=True,
        ).strip()
        return Path(root)
    except Exception:
        return Path(".")


STATE_DIR = _git_root() / ".hiro" / ".state"


def _state_path(session_id: str) -> Path:
    safe_session_id = session_id.replace("/", "_")
    return STATE_DIR / f"{safe_session_id}.json"


def _load_state(session_id: str) -> dict[str, Any]:
    path = _state_path(session_id)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save_state(session_id: str, state: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, stat.S_IRWXU)  # 0700
    path = _state_path(session_id)
    path.write_text(json.dumps(state))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600


def _allow() -> None:
    print("{}")


def _deny_pre_tool(message: str) -> None:
    print(
        json.dumps(
            {
                "hookSpecificOutput": {
                    "hookEventName": "PreToolUse",
                    "permissionDecision": "deny",
                },
                "systemMessage": message,
            }
        )
    )


def _is_plan_review(tool_name: str, tool_input: dict[str, Any]) -> bool:
    """Check if this is a plan review action (MCP tool or CLI command)."""
    if tool_name == "mcp__hiro__review_plan":
        return True
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        if "hiro review-plan" in cmd or "hiro_review.review_plan" in cmd:
            return True
    return False


def main() -> int:
    try:
        input_data = json.load(sys.stdin)
    except Exception:
        _allow()
        return 0

    event_name = input_data.get("hook_event_name", "")
    session_id = input_data.get("session_id", "default")
    tool_name = input_data.get("tool_name", "")

    if event_name == "PreToolUse":
        if tool_name in ("Plan", "EnterPlanMode"):
            # Reset requirement for each new planning cycle.
            _save_state(
                session_id,
                {
                    "hiro_plan_reviewed": False,
                    "updated_at": int(time.time()),
                },
            )
            _allow()
            return 0

        if tool_name == "ExitPlanMode":
            state = _load_state(session_id)
            if state.get("hiro_plan_reviewed"):
                # Consume the approval so each plan finalization requires
                # an explicit Hiro review in that same planning cycle.
                state["hiro_plan_reviewed"] = False
                state["updated_at"] = int(time.time())
                _save_state(session_id, state)
                _allow()
                return 0

            _deny_pre_tool(
                "Plan finalization blocked — Hiro security review required.\n\n"
                "Run this exact Bash command:\n"
                "  hiro review-plan --file /path/to/plan.md --output .hiro/.state/plan-review.md\n\n"
                "Replace /path/to/plan.md with the plan file you wrote. "
                "Do NOT use cat or pipes. Do NOT run in background.\n"
                "After the command exits (code 0), use the Read tool on "
                ".hiro/.state/plan-review.md to read the report.\n\n"
                "Then call ExitPlanMode again — it will be allowed."
            )
            return 0

    if event_name == "PostToolUse":
        tool_input = input_data.get("tool_input", {})
        if _is_plan_review(tool_name, tool_input):
            state = _load_state(session_id)
            state["hiro_plan_reviewed"] = True
            state["updated_at"] = int(time.time())
            _save_state(session_id, state)
            _allow()
            return 0

    _allow()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
