"""Setup and verify Hiro hooks for AI coding tools.

`hiro setup` copies hook scripts from the installed package into .hiro/hooks/
and configures the target tool(s) to invoke them. `hiro verify` checks that
the installed hooks match the package version (SHA-256 comparison).
"""

from __future__ import annotations

import hashlib
import importlib.resources
import json
import os
import stat
from pathlib import Path

import click
import structlog

logger = structlog.get_logger(__name__)

HOOK_FILES = [
    "enforce_code_review.py",
    "enforce_plan_review.py",
]


def _get_package_hook_content(filename: str) -> str:
    """Read hook file content from the installed package."""
    ref = importlib.resources.files("hiro_agent.hooks").joinpath(filename)
    return ref.read_text(encoding="utf-8")


def _sha256(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


def _write_hook(dest: Path, content: str) -> None:
    """Write a hook file with restrictive permissions."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    dest.write_text(content)
    dest.chmod(stat.S_IRUSR | stat.S_IWUSR)  # 0600


def _ensure_state_dir(project_root: Path) -> None:
    """Create .hiro/.state/ with restrictive permissions."""
    state_dir = project_root / ".hiro" / ".state"
    state_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(state_dir, stat.S_IRWXU)  # 0700


def _ensure_gitignore(project_root: Path) -> None:
    """Add .hiro/.state/ to .gitignore if not already present."""
    gitignore = project_root / ".gitignore"
    entry = ".hiro/.state/"

    if gitignore.exists():
        content = gitignore.read_text()
        if entry in content:
            return
        if not content.endswith("\n"):
            content += "\n"
        content += f"{entry}\n"
        gitignore.write_text(content)
    else:
        gitignore.write_text(f"{entry}\n")


def _install_hooks(project_root: Path) -> None:
    """Copy hook scripts from package to .hiro/hooks/."""
    hooks_dir = project_root / ".hiro" / "hooks"
    for filename in HOOK_FILES:
        content = _get_package_hook_content(filename)
        dest = hooks_dir / filename
        _write_hook(dest, content)
        click.echo(f"  Installed {dest}")


def _setup_claude_code(project_root: Path) -> None:
    """Configure Claude Code hooks in .claude/settings.local.json."""
    click.echo("Configuring Claude Code...")

    settings_dir = project_root / ".claude"
    settings_dir.mkdir(parents=True, exist_ok=True)
    settings_file = settings_dir / "settings.local.json"

    if settings_file.exists():
        try:
            settings = json.loads(settings_file.read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}
    else:
        settings = {}

    hooks_config = {
        "PreToolUse": [
            {
                "matcher": "Plan|EnterPlanMode|ExitPlanMode",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python3 .hiro/hooks/enforce_plan_review.py",
                        "timeout": 10,
                    }
                ],
            },
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python3 .hiro/hooks/enforce_code_review.py",
                        "timeout": 10,
                    }
                ],
            },
        ],
        "PostToolUse": [
            {
                "matcher": "Bash|mcp__hiro__review_plan",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python3 .hiro/hooks/enforce_plan_review.py",
                        "timeout": 10,
                    }
                ],
            },
            {
                "matcher": "Edit|Write|Bash|mcp__hiro__review_code",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python3 .hiro/hooks/enforce_code_review.py",
                        "timeout": 10,
                    }
                ],
            },
        ],
    }

    settings["hooks"] = hooks_config
    settings_file.write_text(json.dumps(settings, indent=2) + "\n")
    click.echo(f"  Wrote {settings_file}")


def _setup_cursor(project_root: Path) -> None:
    """Configure Cursor hooks in .cursor/hooks.json."""
    click.echo("Configuring Cursor...")

    cursor_dir = project_root / ".cursor"
    cursor_dir.mkdir(parents=True, exist_ok=True)
    hooks_file = cursor_dir / "hooks.json"

    config = {
        "version": 1,
        "hooks": {
            "beforeShellExecution": [
                {"command": "python3 .hiro/hooks/enforce_code_review.py"}
            ],
            "afterFileEdit": [
                {"command": "python3 .hiro/hooks/enforce_code_review.py"}
            ],
            "stop": [
                {"command": "python3 .hiro/hooks/enforce_plan_review.py"}
            ],
        },
    }

    hooks_file.write_text(json.dumps(config, indent=2) + "\n")
    click.echo(f"  Wrote {hooks_file}")


def _setup_vscode(project_root: Path) -> None:
    """Configure VSCode Copilot hooks in .vscode/settings.json."""
    click.echo("Configuring VSCode Copilot...")

    vscode_dir = project_root / ".vscode"
    vscode_dir.mkdir(parents=True, exist_ok=True)
    settings_file = vscode_dir / "settings.json"

    if settings_file.exists():
        try:
            settings = json.loads(settings_file.read_text())
        except (json.JSONDecodeError, OSError):
            settings = {}
    else:
        settings = {}

    settings["github.copilot.chat.agent.hooks"] = {
        "PreToolUse": [
            {
                "matcher": "Plan|EnterPlanMode|ExitPlanMode",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python3 .hiro/hooks/enforce_plan_review.py",
                    }
                ],
            },
            {
                "matcher": "Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python3 .hiro/hooks/enforce_code_review.py",
                    }
                ],
            },
        ],
        "PostToolUse": [
            {
                "matcher": "Edit|Write|Bash",
                "hooks": [
                    {
                        "type": "command",
                        "command": "python3 .hiro/hooks/enforce_code_review.py",
                    }
                ],
            },
        ],
    }

    settings_file.write_text(json.dumps(settings, indent=2) + "\n")
    click.echo(f"  Wrote {settings_file}")


def _setup_codex(project_root: Path) -> None:
    """Configure Codex CLI — limited hook support, uses git pre-commit."""
    click.echo("Configuring Codex CLI (via git pre-commit hook)...")
    _setup_git_precommit(project_root)


def _setup_git_precommit(project_root: Path) -> None:
    """Install git pre-commit hook that checks .hiro/.state/ for pending reviews."""
    git_dir = project_root / ".git"
    if not git_dir.is_dir():
        click.echo("  Skipping git pre-commit: not a git repository.")
        return

    hooks_dir = git_dir / "hooks"
    hooks_dir.mkdir(parents=True, exist_ok=True)
    precommit = hooks_dir / "pre-commit"

    script = """\
#!/usr/bin/env python3
\"\"\"Git pre-commit hook — blocks commits when Hiro review is pending.\"\"\"
import json
import sys
from pathlib import Path

state_dir = Path(".hiro/.state")
if not state_dir.is_dir():
    sys.exit(0)

for state_file in state_dir.glob("code_review_*.json"):
    try:
        state = json.loads(state_file.read_text())
    except Exception:
        continue
    if state.get("needs_review"):
        files = state.get("modified_files", [])
        print(f"Commit blocked: {len(files)} file(s) modified since last security review.")
        print("Run: git diff | hiro review-code")
        sys.exit(1)

sys.exit(0)
"""

    if precommit.exists():
        existing = precommit.read_text()
        if ".hiro/.state" in existing:
            click.echo("  Git pre-commit hook already contains Hiro check.")
            return
        click.echo("  Warning: existing pre-commit hook found. Adding Hiro check as wrapper.")
        # Prepend Hiro check, then chain to existing hook
        combined = script.rstrip() + f"\n\n# Original pre-commit hook follows:\nimport subprocess\nsys.exit(subprocess.call(['{precommit}.original']))\n"
        precommit.rename(precommit.with_suffix(".original"))
        precommit.write_text(combined)
    else:
        precommit.write_text(script)

    precommit.chmod(stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP | stat.S_IROTH | stat.S_IXOTH)  # 0755
    click.echo(f"  Installed {precommit}")


def _detect_tools(project_root: Path) -> list[str]:
    """Auto-detect which AI coding tools are in use."""
    tools = []
    if (project_root / ".claude").is_dir():
        tools.append("claude-code")
    if (project_root / ".cursor").is_dir() or (project_root / ".cursorrc").exists():
        tools.append("cursor")
    if (project_root / ".vscode").is_dir():
        tools.append("vscode")
    # Codex: check for codex config or just always install git hook
    if (project_root / ".codex").is_dir():
        tools.append("codex")
    return tools


TOOL_SETUP_MAP = {
    "claude-code": _setup_claude_code,
    "cursor": _setup_cursor,
    "vscode": _setup_vscode,
    "codex": _setup_codex,
}


def run_setup(tool_filter: str | None = None) -> None:
    """Main setup entry point."""
    project_root = Path.cwd()
    click.echo(f"Setting up Hiro in {project_root}\n")

    # Always install hooks and state dir
    _install_hooks(project_root)
    _ensure_state_dir(project_root)
    _ensure_gitignore(project_root)
    click.echo()

    if tool_filter:
        tools = [tool_filter]
    else:
        tools = _detect_tools(project_root)
        if not tools:
            click.echo("No AI coding tools detected. Installing git pre-commit hook only.")
            tools = []

    for tool in tools:
        setup_fn = TOOL_SETUP_MAP.get(tool)
        if setup_fn:
            setup_fn(project_root)
        else:
            click.echo(f"Unknown tool: {tool}", err=True)
    click.echo()

    # Always install git pre-commit as universal fallback
    if "codex" not in tools:  # codex setup already installs it
        _setup_git_precommit(project_root)

    click.echo("\nDone! Hiro security review hooks are active.")


def run_verify() -> None:
    """Verify installed hooks match the package version."""
    project_root = Path.cwd()
    hooks_dir = project_root / ".hiro" / "hooks"

    if not hooks_dir.is_dir():
        click.echo("No hooks installed. Run `hiro setup` first.", err=True)
        raise SystemExit(1)

    all_ok = True
    for filename in HOOK_FILES:
        installed = hooks_dir / filename
        if not installed.exists():
            click.echo(f"  MISSING: {installed}")
            all_ok = False
            continue

        expected = _sha256(_get_package_hook_content(filename))
        actual = _sha256(installed.read_text())

        if expected == actual:
            click.echo(f"  OK: {filename} (sha256: {actual[:12]}...)")
        else:
            click.echo(f"  MISMATCH: {filename}")
            click.echo(f"    Expected: {expected[:12]}...")
            click.echo(f"    Actual:   {actual[:12]}...")
            all_ok = False

    if all_ok:
        click.echo("\nAll hooks verified.")
    else:
        click.echo("\nHook integrity check failed. Run `hiro setup` to reinstall.", err=True)
        raise SystemExit(1)
