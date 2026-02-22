"""Tests for hiro_agent.prompts — system prompt content validation."""

from hiro_agent.prompts import (
    CODE_REVIEW_SYSTEM_PROMPT,
    CONTEXT_PREAMBLE,
    INFRA_REVIEW_SYSTEM_PROMPT,
    PLAN_REVIEW_SYSTEM_PROMPT,
    RECON_SYSTEM_PROMPT,
    REPORT_SYSTEM_PROMPT,
    SKILL_AGENT_SYSTEM_PROMPT,
)


class TestContextPreamble:
    """Test shared context-loading instructions."""

    def test_does_not_instruct_get_org_context(self):
        """Org context is pre-loaded — preamble should not tell agent to call get_org_context."""
        assert "get_org_context" not in CONTEXT_PREAMBLE

    def test_does_not_instruct_get_security_policy(self):
        """Security policy is pre-loaded — preamble should not tell agent to call get_security_policy."""
        assert "get_security_policy" not in CONTEXT_PREAMBLE

    def test_mentions_preloaded_context(self):
        """Should mention that context is pre-loaded."""
        assert "pre-loaded" in CONTEXT_PREAMBLE.lower()

    def test_includes_recall(self):
        assert "recall" in CONTEXT_PREAMBLE

    def test_graceful_degradation_note(self):
        """Should mention proceeding without recall if unavailable."""
        assert "unavailable" in CONTEXT_PREAMBLE.lower() or "proceed" in CONTEXT_PREAMBLE.lower()


class TestCodeReviewPrompt:
    """Test CODE_REVIEW_SYSTEM_PROMPT content."""

    def test_contains_preamble(self):
        assert "recall" in CODE_REVIEW_SYSTEM_PROMPT

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
        assert "recall" in PLAN_REVIEW_SYSTEM_PROMPT

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
        assert "recall" in INFRA_REVIEW_SYSTEM_PROMPT

    def test_contains_cis(self):
        assert "CIS Benchmarks" in INFRA_REVIEW_SYSTEM_PROMPT

    def test_contains_file_tool_instructions(self):
        assert "Read" in INFRA_REVIEW_SYSTEM_PROMPT
        assert "Glob" in INFRA_REVIEW_SYSTEM_PROMPT

    def test_contains_output_format(self):
        assert "Severity" in INFRA_REVIEW_SYSTEM_PROMPT
        assert "Resource" in INFRA_REVIEW_SYSTEM_PROMPT


class TestReconPrompt:
    """Test RECON_SYSTEM_PROMPT content."""

    def test_contains_preamble(self):
        assert "recall" in RECON_SYSTEM_PROMPT

    def test_contains_exploration_instructions(self):
        assert "Glob" in RECON_SYSTEM_PROMPT
        assert "Read" in RECON_SYSTEM_PROMPT

    def test_contains_output_sections(self):
        assert "Organizational Context" in RECON_SYSTEM_PROMPT
        assert "Recall Findings" in RECON_SYSTEM_PROMPT
        assert "Codebase Overview" in RECON_SYSTEM_PROMPT
        assert "Scan Strategy" in RECON_SYSTEM_PROMPT


class TestSkillAgentPrompt:
    """Test SKILL_AGENT_SYSTEM_PROMPT template."""

    def test_is_template_with_placeholders(self):
        assert "{context_preamble}" in SKILL_AGENT_SYSTEM_PROMPT
        assert "{skill_content}" in SKILL_AGENT_SYSTEM_PROMPT
        assert "{scratchpad_path}" in SKILL_AGENT_SYSTEM_PROMPT

    def test_format_works(self):
        result = SKILL_AGENT_SYSTEM_PROMPT.format(
            context_preamble="PREAMBLE_HERE",
            skill_content="SKILL_CONTENT_HERE",
            scratchpad_path="/tmp/scratchpad.md",
        )
        assert "PREAMBLE_HERE" in result
        assert "SKILL_CONTENT_HERE" in result
        assert "/tmp/scratchpad.md" in result

    def test_contains_orchestrator_instructions(self):
        assert "Task" in SKILL_AGENT_SYSTEM_PROMPT
        assert "sub-agent" in SKILL_AGENT_SYSTEM_PROMPT
        assert "delegate" in SKILL_AGENT_SYSTEM_PROMPT.lower()

    def test_contains_scratchpad_instructions(self):
        assert "scratchpad" in SKILL_AGENT_SYSTEM_PROMPT.lower()
        assert "Write" in SKILL_AGENT_SYSTEM_PROMPT


class TestReportPrompt:
    """Test REPORT_SYSTEM_PROMPT content."""

    def test_contains_output_format(self):
        assert "Executive Summary" in REPORT_SYSTEM_PROMPT
        assert "Findings" in REPORT_SYSTEM_PROMPT
        assert "Incomplete Investigations" in REPORT_SYSTEM_PROMPT

    def test_no_tools_mentioned(self):
        """Report prompt should not reference filesystem tools."""
        assert "Grep" not in REPORT_SYSTEM_PROMPT
        assert "Glob" not in REPORT_SYSTEM_PROMPT
