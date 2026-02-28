#!/usr/bin/env python3
"""Enforce Hiro code review before committing.

Tracks whether files have been modified since the last review_code call.
Blocks git commit until a code review has been run on the changes.

Tool-agnostic: works with Claude Code, Cursor, VSCode Copilot, and
as a git pre-commit hook. Detects caller format automatically.

State stored in .hiro/.state/ (not tool-specific directories).
"""

from __future__ import annotations

import json
import os
import stat
import sys
import time
from pathlib import Path
from typing import Any

STATE_DIR = Path(".hiro/.state")


def _state_path(session_id: str) -> Path:
    safe = session_id.replace("/", "_")
    return STATE_DIR / f"code_review_{safe}.json"


def _load(session_id: str) -> dict[str, Any]:
    path = _state_path(session_id)
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text())
    except Exception:
        return {}


def _save(session_id: str, state: dict[str, Any]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, stat.S_IRWXU)  # 0700
    state["updated_at"] = int(time.time())
    path = _state_path(session_id)
    path.write_text(json.dumps(state))
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR)  # 0600


def _allow() -> None:
    print("{}")


def _deny(message: str) -> None:
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


def _is_git_commit(command: str) -> bool:
    """Check if a bash command is a git commit."""
    stripped = command.strip()
    parts = stripped.split("&&")
    for part in parts:
        tokens = part.strip().split()
        if len(tokens) >= 2 and tokens[0] == "git" and tokens[1] == "commit":
            return True
    return False


def _is_review_command(tool_name: str, tool_input: dict[str, Any]) -> bool:
    """Check if this is a code review action (MCP tool or CLI command)."""
    if tool_name == "mcp__hiro__review_code":
        return True
    if tool_name == "Bash":
        cmd = tool_input.get("command", "")
        # Match both old (hiro_review.review_code) and new (hiro review-code) forms
        if "hiro_review.review_code" in cmd or "hiro review-code" in cmd:
            return True
    return False


def main() -> int:
    try:
        input_data = json.load(sys.stdin)
    except Exception:
        _allow()
        return 0

    event = input_data.get("hook_event_name", "")
    session_id = input_data.get("session_id", "default")
    tool_name = input_data.get("tool_name", "")
    tool_input = input_data.get("tool_input", {})

    # --- PostToolUse: track edits and reviews ---
    if event == "PostToolUse":
        if tool_name in ("Edit", "Write"):
            state = _load(session_id)
            files = state.get("modified_files", [])
            file_path = tool_input.get("file_path", "")
            if file_path and file_path not in files:
                files.append(file_path)
            state["modified_files"] = files
            state["needs_review"] = True
            _save(session_id, state)

        elif _is_review_command(tool_name, tool_input):
            # Review done — clear the flag
            state = _load(session_id)
            state["needs_review"] = False
            state["modified_files"] = []
            _save(session_id, state)

        _allow()
        return 0

    # --- PreToolUse: force hiro commands to write to file ---
    if event == "PreToolUse" and _is_review_command(tool_name, tool_input):
        if tool_input.get("run_in_background"):
            _deny(
                "Hiro commands must not run in the background. "
                "Re-run the same command with --output .hiro/.state/code-review.md "
                "in the foreground, then use the Read tool on "
                ".hiro/.state/code-review.md to read the report."
            )
            return 0

    # --- PreToolUse: block git commit if review is pending ---
    if event == "PreToolUse" and tool_name == "Bash":
        command = tool_input.get("command", "")
        if _is_git_commit(command):
            state = _load(session_id)
            if state.get("needs_review"):
                files = state.get("modified_files", [])
                file_list = ", ".join(files[-5:])
                if len(files) > 5:
                    file_list += f" and {len(files) - 5} more"
                _deny(
                    f"Commit blocked: {len(files)} file(s) modified since last "
                    f"security review ({file_list}).\n"
                    "Run: git diff --cached | hiro review-code --output .hiro/.state/code-review.md\n"
                    "Then use the Read tool on .hiro/.state/code-review.md to read the report."
                )
                return 0

        _allow()
        return 0

    _allow()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
