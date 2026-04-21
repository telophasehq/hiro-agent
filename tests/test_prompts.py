"""Tests for hiro_agent.prompts — system prompt content validation."""

from hiro_agent.prompts import (
    CHAT_SYSTEM_PROMPT,
    CONTEXT_PREAMBLE,
    INFRA_REVIEW_SYSTEM_PROMPT,
    REVIEW_CODE_SYSTEM_PROMPT,
    REVIEW_PLAN_SYSTEM_PROMPT,
)


class TestContextPreamble:
    """Shared org-context preamble."""

    def test_does_not_instruct_get_org_context(self):
        """Org context is pre-loaded — preamble should not tell the agent to call get_org_context."""
        assert "get_org_context" not in CONTEXT_PREAMBLE

    def test_does_not_instruct_get_security_policy(self):
        """Security policy is pre-loaded — preamble should not tell the agent to call get_security_policy."""
        assert "get_security_policy" not in CONTEXT_PREAMBLE

    def test_mentions_preloaded_context(self):
        assert "pre-loaded" in CONTEXT_PREAMBLE.lower()

    def test_includes_recall(self):
        assert "recall" in CONTEXT_PREAMBLE

    def test_graceful_degradation_note(self):
        assert "unavailable" in CONTEXT_PREAMBLE.lower() or "proceed" in CONTEXT_PREAMBLE.lower()


class TestReviewCodePrompt:
    """REVIEW_CODE_SYSTEM_PROMPT is a template rendered with preamble + playbooks."""

    def _render(self) -> str:
        return REVIEW_CODE_SYSTEM_PROMPT.format(
            context_preamble="PREAMBLE_HERE",
            all_playbooks="PLAYBOOKS_HERE",
        )

    def test_has_required_placeholders(self):
        assert "{context_preamble}" in REVIEW_CODE_SYSTEM_PROMPT
        assert "{all_playbooks}" in REVIEW_CODE_SYSTEM_PROMPT

    def test_format_interpolates(self):
        rendered = self._render()
        assert "PREAMBLE_HERE" in rendered
        assert "PLAYBOOKS_HERE" in rendered

    def test_single_agent_contract(self):
        """The prompt describes the single-agent workflow (read → investigate → report)."""
        rendered = self._render()
        assert "work alone" in rendered.lower() or "single" in rendered.lower()

    def test_severity_scale(self):
        rendered = self._render()
        for level in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            assert level in rendered

    def test_mentions_read_grep_discovery(self):
        rendered = self._render()
        assert "Read" in rendered
        assert "Grep" in rendered

    def test_has_verdict_line_format(self):
        """The report must start with a Verdict: line so downstream consumers can parse it."""
        rendered = self._render()
        assert "Verdict: APPROVE" in rendered
        assert "Verdict: REQUEST_CHANGES" in rendered
        assert "Verdict: COMMENT" in rendered

    def test_has_report_sections(self):
        rendered = self._render()
        assert "Executive Summary" in rendered
        assert "Findings" in rendered

    def test_scopes_to_diff_only(self):
        """Only issues introduced by the diff should be reported."""
        rendered = self._render()
        assert "INTRODUCED" in rendered or "introduced" in rendered


class TestReviewPlanPrompt:
    """REVIEW_PLAN_SYSTEM_PROMPT is a template rendered with preamble + playbooks."""

    def _render(self) -> str:
        return REVIEW_PLAN_SYSTEM_PROMPT.format(
            context_preamble="PREAMBLE_HERE",
            all_playbooks="PLAYBOOKS_HERE",
        )

    def test_has_required_placeholders(self):
        assert "{context_preamble}" in REVIEW_PLAN_SYSTEM_PROMPT
        assert "{all_playbooks}" in REVIEW_PLAN_SYSTEM_PROMPT

    def test_format_interpolates(self):
        rendered = self._render()
        assert "PREAMBLE_HERE" in rendered
        assert "PLAYBOOKS_HERE" in rendered

    def test_contains_stride(self):
        rendered = self._render()
        assert "STRIDE" in rendered
        for term in ("Spoofing", "Tampering", "Repudiation",
                     "Information Disclosure", "Denial of Service",
                     "Elevation of Privilege"):
            assert term in rendered

    def test_has_output_sections(self):
        rendered = self._render()
        for section in (
            "Security Considerations",
            "Recommended Controls",
            "Threat Model Highlights",
            "Missing from the Plan",
        ):
            assert section in rendered

    def test_mentions_read_grep_discovery(self):
        rendered = self._render()
        assert "Read" in rendered
        assert "Grep" in rendered


class TestInfraReviewPrompt:
    """INFRA_REVIEW_SYSTEM_PROMPT is pre-rendered (preamble already substituted)."""

    def test_contains_preamble(self):
        assert "recall" in INFRA_REVIEW_SYSTEM_PROMPT

    def test_contains_cis(self):
        assert "CIS Benchmarks" in INFRA_REVIEW_SYSTEM_PROMPT

    def test_contains_file_tool_instructions(self):
        assert "Read" in INFRA_REVIEW_SYSTEM_PROMPT
        assert "Grep" in INFRA_REVIEW_SYSTEM_PROMPT

    def test_contains_output_format(self):
        assert "Severity" in INFRA_REVIEW_SYSTEM_PROMPT
        assert "Resource" in INFRA_REVIEW_SYSTEM_PROMPT


class TestChatPrompt:
    """CHAT_SYSTEM_PROMPT is pre-rendered."""

    def test_contains_preamble(self):
        assert "recall" in CHAT_SYSTEM_PROMPT

    def test_mentions_read_grep(self):
        assert "Read" in CHAT_SYSTEM_PROMPT
        assert "Grep" in CHAT_SYSTEM_PROMPT
