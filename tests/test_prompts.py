"""Tests for hiro_agent.prompts — system prompt content validation."""

from hiro_agent.prompts import (
    CODE_REVIEW_SYSTEM_PROMPT,
    CONTEXT_PREAMBLE,
    INFRA_REVIEW_SYSTEM_PROMPT,
    PLAN_REVIEW_SYSTEM_PROMPT,
)


class TestContextPreamble:
    """Test shared context-loading instructions."""

    def test_includes_get_org_context(self):
        assert "get_org_context" in CONTEXT_PREAMBLE

    def test_includes_get_security_policy(self):
        assert "get_security_policy" in CONTEXT_PREAMBLE

    def test_includes_recall(self):
        assert "recall" in CONTEXT_PREAMBLE

    def test_graceful_degradation_note(self):
        """Should mention proceeding without context if tools unavailable."""
        assert "unavailable" in CONTEXT_PREAMBLE.lower() or "proceed" in CONTEXT_PREAMBLE.lower()


class TestCodeReviewPrompt:
    """Test CODE_REVIEW_SYSTEM_PROMPT content."""

    def test_contains_preamble(self):
        assert "get_org_context" in CODE_REVIEW_SYSTEM_PROMPT

    def test_contains_owasp(self):
        assert "OWASP" in CODE_REVIEW_SYSTEM_PROMPT

    def test_contains_file_tool_instructions(self):
        assert "Read" in CODE_REVIEW_SYSTEM_PROMPT
        assert "Grep" in CODE_REVIEW_SYSTEM_PROMPT
        assert "Glob" in CODE_REVIEW_SYSTEM_PROMPT

    def test_contains_output_format(self):
        assert "Severity" in CODE_REVIEW_SYSTEM_PROMPT
        assert "CRITICAL" in CODE_REVIEW_SYSTEM_PROMPT


class TestPlanReviewPrompt:
    """Test PLAN_REVIEW_SYSTEM_PROMPT content."""

    def test_contains_preamble(self):
        assert "get_org_context" in PLAN_REVIEW_SYSTEM_PROMPT

    def test_contains_stride(self):
        assert "STRIDE" in PLAN_REVIEW_SYSTEM_PROMPT
        assert "poofing" in PLAN_REVIEW_SYSTEM_PROMPT
        assert "ampering" in PLAN_REVIEW_SYSTEM_PROMPT
        assert "epudiation" in PLAN_REVIEW_SYSTEM_PROMPT
        assert "nformation Disclosure" in PLAN_REVIEW_SYSTEM_PROMPT
        assert "enial of Service" in PLAN_REVIEW_SYSTEM_PROMPT
        assert "levation of Privilege" in PLAN_REVIEW_SYSTEM_PROMPT

    def test_no_file_tool_instructions(self):
        """Plan review should not reference filesystem tools."""
        assert "Read" not in PLAN_REVIEW_SYSTEM_PROMPT or "Read the" not in PLAN_REVIEW_SYSTEM_PROMPT


class TestInfraReviewPrompt:
    """Test INFRA_REVIEW_SYSTEM_PROMPT content."""

    def test_contains_preamble(self):
        assert "get_org_context" in INFRA_REVIEW_SYSTEM_PROMPT

    def test_contains_cis(self):
        assert "CIS Benchmarks" in INFRA_REVIEW_SYSTEM_PROMPT

    def test_contains_file_tool_instructions(self):
        assert "Read" in INFRA_REVIEW_SYSTEM_PROMPT
        assert "Glob" in INFRA_REVIEW_SYSTEM_PROMPT

    def test_contains_output_format(self):
        assert "Severity" in INFRA_REVIEW_SYSTEM_PROMPT
        assert "Resource" in INFRA_REVIEW_SYSTEM_PROMPT
