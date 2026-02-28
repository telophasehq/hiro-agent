"""Tests for hiro_agent.chat — interactive security Q&A."""

from unittest.mock import patch

import pytest

from hiro_agent.chat import ALLOWED_TOOLS, MAX_TURNS, chat


class TestChat:
    """Test chat() function."""

    @pytest.mark.asyncio
    async def test_passes_question_as_prompt(self):
        """Should pass the user's question directly as the prompt."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["prompt"] = prompt
            captured.update(kwargs)

        with patch("hiro_agent.chat.run_streaming_agent", side_effect=mock_run):
            await chat("How does auth work in this codebase?", cwd="/repo")

        assert captured["prompt"] == "How does auth work in this codebase?"
        assert captured["cwd"] == "/repo"

    @pytest.mark.asyncio
    async def test_allowed_tools_read_only(self):
        """Chat should have Read/Grep/Glob but not Bash."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)

        with patch("hiro_agent.chat.run_streaming_agent", side_effect=mock_run):
            await chat("question")

        assert "Read" in captured["allowed_tools"]
        assert "Grep" in captured["allowed_tools"]
        assert "Glob" not in captured["allowed_tools"]
        assert "Bash" not in captured["allowed_tools"]

    @pytest.mark.asyncio
    async def test_system_prompt_is_chat(self):
        """Should use CHAT_SYSTEM_PROMPT."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["system_prompt"] = system_prompt

        with patch("hiro_agent.chat.run_streaming_agent", side_effect=mock_run):
            await chat("question")

        assert "interactive" in captured["system_prompt"].lower() or "Q&A" in captured["system_prompt"]
        assert "Read" in captured["system_prompt"]

    @pytest.mark.asyncio
    async def test_max_turns(self):
        """Should use moderate max_turns."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)

        with patch("hiro_agent.chat.run_streaming_agent", side_effect=mock_run):
            await chat("question")

        assert captured["max_turns"] == MAX_TURNS
        assert MAX_TURNS == 15

    @pytest.mark.asyncio
    async def test_uses_sonnet_model(self):
        """Chat should use sonnet model for faster responses."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)

        with patch("hiro_agent.chat.run_streaming_agent", side_effect=mock_run):
            await chat("question")

        assert captured["model"] == "sonnet"
