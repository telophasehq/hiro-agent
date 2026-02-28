"""Tests for hiro_agent.setup_hooks — hook installation and verification."""

import json
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from hiro_agent.setup_hooks import (
    HOOK_FILES,
    _detect_tools,
    _ensure_gitignore,
    _get_claude_desktop_config_path,
    _get_package_hook_content,
    _install_hooks,
    _resolve_api_key,
    _setup_claude_code,
    _setup_claude_desktop,
    _setup_cursor,
    _setup_git_precommit,
    _setup_vscode,
    run_verify,
)


class TestGetPackageHookContent:
    """Test reading hook files from the installed package."""

    def test_reads_code_review_hook(self):
        content = _get_package_hook_content("enforce_code_review.py")
        assert "enforce" in content.lower()
        assert "code_review" in content

    def test_reads_plan_review_hook(self):
        content = _get_package_hook_content("enforce_plan_review.py")
        assert "enforce" in content.lower()
        assert "plan_review" in content or "plan_reviewed" in content


class TestInstallHooks:
    """Test hook file installation."""

    def test_creates_hooks_directory(self, tmp_path: Path):
        _install_hooks(tmp_path)
        hooks_dir = tmp_path / ".hiro" / "hooks"
        assert hooks_dir.is_dir()

    def test_installs_all_hook_files(self, tmp_path: Path):
        _install_hooks(tmp_path)
        hooks_dir = tmp_path / ".hiro" / "hooks"
        for filename in HOOK_FILES:
            assert (hooks_dir / filename).exists()

    def test_hook_file_permissions(self, tmp_path: Path):
        _install_hooks(tmp_path)
        hooks_dir = tmp_path / ".hiro" / "hooks"
        for filename in HOOK_FILES:
            mode = (hooks_dir / filename).stat().st_mode
            # Owner read+write only (0600)
            assert mode & 0o777 == 0o600


class TestEnsureGitignore:
    """Test .gitignore management."""

    def test_creates_gitignore_if_missing(self, tmp_path: Path):
        _ensure_gitignore(tmp_path)
        gitignore = tmp_path / ".gitignore"
        assert gitignore.exists()
        content = gitignore.read_text()
        assert ".hiro/.state/" in content
        assert ".hiro/config.json" in content

    def test_appends_to_existing_gitignore(self, tmp_path: Path):
        gitignore = tmp_path / ".gitignore"
        gitignore.write_text("node_modules/\n")
        _ensure_gitignore(tmp_path)
        content = gitignore.read_text()
        assert "node_modules/" in content
        assert ".hiro/.state/" in content
        assert ".hiro/config.json" in content

    def test_idempotent(self, tmp_path: Path):
        _ensure_gitignore(tmp_path)
        _ensure_gitignore(tmp_path)
        content = (tmp_path / ".gitignore").read_text()
        assert content.count(".hiro/.state/") == 1
        assert content.count(".hiro/config.json") == 1


class TestDetectTools:
    """Test auto-detection of AI coding tools."""

    def test_detects_claude_code(self, tmp_path: Path):
        (tmp_path / ".claude").mkdir()
        assert "claude-code" in _detect_tools(tmp_path)

    def test_detects_cursor(self, tmp_path: Path):
        (tmp_path / ".cursor").mkdir()
        assert "cursor" in _detect_tools(tmp_path)

    def test_detects_vscode(self, tmp_path: Path):
        (tmp_path / ".vscode").mkdir()
        assert "vscode" in _detect_tools(tmp_path)

    def test_detects_codex(self, tmp_path: Path):
        (tmp_path / ".codex").mkdir()
        assert "codex" in _detect_tools(tmp_path)

    def test_detects_claude_desktop(self, tmp_path: Path):
        fake_config = tmp_path / "Claude" / "claude_desktop_config.json"
        fake_config.parent.mkdir(parents=True)
        with patch(
            "hiro_agent.setup_hooks._get_claude_desktop_config_path",
            return_value=fake_config,
        ):
            assert "claude-desktop" in _detect_tools(tmp_path)

    def test_no_claude_desktop_when_dir_missing(self, tmp_path: Path):
        fake_config = tmp_path / "Claude" / "claude_desktop_config.json"
        # Parent dir does NOT exist
        with patch(
            "hiro_agent.setup_hooks._get_claude_desktop_config_path",
            return_value=fake_config,
        ):
            assert "claude-desktop" not in _detect_tools(tmp_path)

    def test_empty_when_nothing_detected(self, tmp_path: Path):
        with patch("hiro_agent.setup_hooks._get_claude_desktop_config_path", return_value=None):
            assert _detect_tools(tmp_path) == []


class TestSetupClaudeCode:
    """Test Claude Code hook configuration."""

    def test_creates_settings_file(self, tmp_path: Path):
        _setup_claude_code(tmp_path)
        settings_file = tmp_path / ".claude" / "settings.local.json"
        assert settings_file.exists()

    def test_settings_contains_hooks(self, tmp_path: Path):
        _setup_claude_code(tmp_path)
        settings_file = tmp_path / ".claude" / "settings.local.json"
        settings = json.loads(settings_file.read_text())
        assert "hooks" in settings
        assert "PreToolUse" in settings["hooks"]
        assert "PostToolUse" in settings["hooks"]

    def test_preserves_existing_settings(self, tmp_path: Path):
        settings_dir = tmp_path / ".claude"
        settings_dir.mkdir()
        settings_file = settings_dir / "settings.local.json"
        settings_file.write_text(json.dumps({"permissions": {"allow": ["Bash"]}}))

        _setup_claude_code(tmp_path)

        settings = json.loads(settings_file.read_text())
        assert settings["permissions"]["allow"] == ["Bash"]
        assert "hooks" in settings


class TestSetupCursor:
    """Test Cursor hook configuration."""

    def test_creates_hooks_file(self, tmp_path: Path):
        _setup_cursor(tmp_path)
        hooks_file = tmp_path / ".cursor" / "hooks.json"
        assert hooks_file.exists()

    def test_hooks_file_structure(self, tmp_path: Path):
        _setup_cursor(tmp_path)
        hooks_file = tmp_path / ".cursor" / "hooks.json"
        config = json.loads(hooks_file.read_text())
        assert config["version"] == 1
        assert "beforeShellExecution" in config["hooks"]
        assert "afterFileEdit" in config["hooks"]
        assert "stop" in config["hooks"]


class TestSetupVscode:
    """Test VSCode Copilot hook configuration."""

    def test_creates_settings_file(self, tmp_path: Path):
        _setup_vscode(tmp_path)
        settings_file = tmp_path / ".vscode" / "settings.json"
        assert settings_file.exists()

    def test_settings_contains_copilot_hooks(self, tmp_path: Path):
        _setup_vscode(tmp_path)
        settings = json.loads((tmp_path / ".vscode" / "settings.json").read_text())
        assert "github.copilot.chat.agent.hooks" in settings


class TestSetupClaudeDesktop:
    """Test Claude Desktop MCP server configuration."""

    def test_writes_config_file(self, tmp_path: Path):
        config_path = tmp_path / "Claude" / "claude_desktop_config.json"
        config_path.parent.mkdir(parents=True)
        (tmp_path / ".hiro").mkdir()
        (tmp_path / ".hiro" / "config.json").write_text(json.dumps({"api_key": "test-key-123"}))

        with patch("hiro_agent.setup_hooks._get_claude_desktop_config_path", return_value=config_path):
            _setup_claude_desktop(tmp_path)

        assert config_path.exists()
        config = json.loads(config_path.read_text())
        assert "mcpServers" in config
        assert "hiro" in config["mcpServers"]
        assert config["mcpServers"]["hiro"]["url"] == "https://api.hiro.is/mcp/architect/mcp"
        assert config["mcpServers"]["hiro"]["headers"]["Authorization"] == "Bearer test-key-123"

    def test_preserves_existing_mcp_servers(self, tmp_path: Path):
        config_path = tmp_path / "Claude" / "claude_desktop_config.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(json.dumps({
            "mcpServers": {
                "other-tool": {"url": "https://other.example.com/mcp"},
            }
        }))
        (tmp_path / ".hiro").mkdir()
        (tmp_path / ".hiro" / "config.json").write_text(json.dumps({"api_key": "test-key"}))

        with patch("hiro_agent.setup_hooks._get_claude_desktop_config_path", return_value=config_path):
            _setup_claude_desktop(tmp_path)

        config = json.loads(config_path.read_text())
        assert "other-tool" in config["mcpServers"]
        assert "hiro" in config["mcpServers"]

    def test_skips_when_no_api_key(self, tmp_path: Path):
        config_path = tmp_path / "Claude" / "claude_desktop_config.json"
        config_path.parent.mkdir(parents=True)

        with patch("hiro_agent.setup_hooks._get_claude_desktop_config_path", return_value=config_path):
            with patch.dict(os.environ, {}, clear=False):
                # Ensure no HIRO_API_KEY in env
                os.environ.pop("HIRO_API_KEY", None)
                _setup_claude_desktop(tmp_path)

        assert not config_path.exists()

    def test_skips_on_unsupported_platform(self, tmp_path: Path):
        with patch("hiro_agent.setup_hooks._get_claude_desktop_config_path", return_value=None):
            _setup_claude_desktop(tmp_path)
        # No config written anywhere — just verifying no error

    def test_uses_env_var_key(self, tmp_path: Path):
        config_path = tmp_path / "Claude" / "claude_desktop_config.json"
        config_path.parent.mkdir(parents=True)

        with patch("hiro_agent.setup_hooks._get_claude_desktop_config_path", return_value=config_path):
            with patch.dict(os.environ, {"HIRO_API_KEY": "env-key-456"}):
                _setup_claude_desktop(tmp_path)

        config = json.loads(config_path.read_text())
        assert config["mcpServers"]["hiro"]["headers"]["Authorization"] == "Bearer env-key-456"

    def test_updates_existing_hiro_entry(self, tmp_path: Path):
        config_path = tmp_path / "Claude" / "claude_desktop_config.json"
        config_path.parent.mkdir(parents=True)
        config_path.write_text(json.dumps({
            "mcpServers": {
                "hiro": {"url": "https://old.example.com/mcp", "headers": {"Authorization": "Bearer old-key"}},
            }
        }))
        (tmp_path / ".hiro").mkdir()
        (tmp_path / ".hiro" / "config.json").write_text(json.dumps({"api_key": "new-key"}))

        with patch("hiro_agent.setup_hooks._get_claude_desktop_config_path", return_value=config_path):
            _setup_claude_desktop(tmp_path)

        config = json.loads(config_path.read_text())
        assert config["mcpServers"]["hiro"]["url"] == "https://api.hiro.is/mcp/architect/mcp"
        assert config["mcpServers"]["hiro"]["headers"]["Authorization"] == "Bearer new-key"


class TestSetupGitPrecommit:
    """Test git pre-commit hook installation."""

    def test_installs_precommit_hook(self, tmp_path: Path):
        (tmp_path / ".git").mkdir()
        _setup_git_precommit(tmp_path)
        precommit = tmp_path / ".git" / "hooks" / "pre-commit"
        assert precommit.exists()

    def test_precommit_is_executable(self, tmp_path: Path):
        (tmp_path / ".git").mkdir()
        _setup_git_precommit(tmp_path)
        precommit = tmp_path / ".git" / "hooks" / "pre-commit"
        assert os.access(precommit, os.X_OK)

    def test_skips_when_not_git_repo(self, tmp_path: Path):
        _setup_git_precommit(tmp_path)
        assert not (tmp_path / ".git" / "hooks" / "pre-commit").exists()

    def test_precommit_checks_hiro_state(self, tmp_path: Path):
        (tmp_path / ".git").mkdir()
        _setup_git_precommit(tmp_path)
        content = (tmp_path / ".git" / "hooks" / "pre-commit").read_text()
        assert ".hiro/.state" in content


class TestRunVerify:
    """Test hook integrity verification."""

    def test_fails_when_no_hooks_installed(self, tmp_path: Path):
        with patch("hiro_agent.setup_hooks.Path.cwd", return_value=tmp_path):
            with pytest.raises(SystemExit):
                run_verify()

    def test_passes_when_hooks_match(self, tmp_path: Path):
        _install_hooks(tmp_path)
        with patch("hiro_agent.setup_hooks.Path.cwd", return_value=tmp_path):
            run_verify()  # Should not raise

    def test_fails_when_hooks_tampered(self, tmp_path: Path):
        _install_hooks(tmp_path)
        # Tamper with a hook
        tampered = tmp_path / ".hiro" / "hooks" / "enforce_code_review.py"
        tampered.write_text("# tampered")
        with patch("hiro_agent.setup_hooks.Path.cwd", return_value=tmp_path):
            with pytest.raises(SystemExit):
                run_verify()
