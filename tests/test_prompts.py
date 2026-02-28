"""Tests for hiro_agent.prompts — system prompt content validation."""

from hiro_agent.prompts import (
    CODE_REVIEW_SYSTEM_PROMPT,
    CONTEXT_PREAMBLE,
    DIFF_INVESTIGATION_SYSTEM_PROMPT,
    INFRA_REVIEW_SYSTEM_PROMPT,
    PLAN_INVESTIGATION_SYSTEM_PROMPT,
    PLAN_RECON_SYSTEM_PROMPT,
    PLAN_REPORT_SYSTEM_PROMPT,
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

    def test_contains_output_format(self):
        assert "Severity" in CODE_REVIEW_SYSTEM_PROMPT
        assert "CRITICAL" in CODE_REVIEW_SYSTEM_PROMPT


class TestPlanReconPrompt:
    """Test PLAN_RECON_SYSTEM_PROMPT content."""

    def test_contains_preamble(self):
        assert "recall" in PLAN_RECON_SYSTEM_PROMPT

    def test_contains_plan_focus(self):
        assert "implementation plan" in PLAN_RECON_SYSTEM_PROMPT
        assert "Plan Overview" in PLAN_RECON_SYSTEM_PROMPT

    def test_contains_exploration_instructions(self):
        assert "Grep" in PLAN_RECON_SYSTEM_PROMPT
        assert "Read" in PLAN_RECON_SYSTEM_PROMPT

    def test_contains_output_sections(self):
        assert "Organizational Context" in PLAN_RECON_SYSTEM_PROMPT
        assert "Recall Findings" in PLAN_RECON_SYSTEM_PROMPT
        assert "Surrounding Context" in PLAN_RECON_SYSTEM_PROMPT

    def test_no_review_strategy_section(self):
        """Review Strategy is the strategy agent's job, not recon's."""
        assert "### Review Strategy" not in PLAN_RECON_SYSTEM_PROMPT


class TestPlanReportPrompt:
    """Test PLAN_REPORT_SYSTEM_PROMPT content."""

    def test_contains_stride(self):
        assert "STRIDE" in PLAN_REPORT_SYSTEM_PROMPT
        assert "poofing" in PLAN_REPORT_SYSTEM_PROMPT
        assert "ampering" in PLAN_REPORT_SYSTEM_PROMPT
        assert "epudiation" in PLAN_REPORT_SYSTEM_PROMPT
        assert "nformation Disclosure" in PLAN_REPORT_SYSTEM_PROMPT
        assert "enial of Service" in PLAN_REPORT_SYSTEM_PROMPT
        assert "levation of Privilege" in PLAN_REPORT_SYSTEM_PROMPT

    def test_contains_output_sections(self):
        assert "Security Considerations" in PLAN_REPORT_SYSTEM_PROMPT
        assert "Recommended Controls" in PLAN_REPORT_SYSTEM_PROMPT
        assert "Threat Model Highlights" in PLAN_REPORT_SYSTEM_PROMPT
        assert "Missing from the Plan" in PLAN_REPORT_SYSTEM_PROMPT
        assert "Incomplete Investigations" in PLAN_REPORT_SYSTEM_PROMPT


class TestInfraReviewPrompt:
    """Test INFRA_REVIEW_SYSTEM_PROMPT content."""

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


class TestReconPrompt:
    """Test RECON_SYSTEM_PROMPT content."""

    def test_contains_preamble(self):
        assert "recall" in RECON_SYSTEM_PROMPT

    def test_contains_exploration_instructions(self):
        assert "Grep" in RECON_SYSTEM_PROMPT
        assert "Read" in RECON_SYSTEM_PROMPT

    def test_contains_output_sections(self):
        assert "Organizational Context" in RECON_SYSTEM_PROMPT
        assert "Recall Findings" in RECON_SYSTEM_PROMPT
        assert "Codebase Overview" in RECON_SYSTEM_PROMPT

    def test_strategy_prompt_exists(self):
        from hiro_agent.prompts import RECON_STRATEGY_PROMPT
        assert "Scan Strategy" in RECON_STRATEGY_PROMPT
        assert "Compressed Brief" in RECON_STRATEGY_PROMPT

    def test_plan_strategy_prompt_is_plan_scoped(self):
        from hiro_agent.prompts import PLAN_STRATEGY_PROMPT
        assert "Scan Strategy" in PLAN_STRATEGY_PROMPT
        assert "Compressed Brief" in PLAN_STRATEGY_PROMPT
        assert "plan" in PLAN_STRATEGY_PROMPT.lower()
        # Must NOT read like a generic codebase scan
        assert "broad codebase audit" in PLAN_STRATEGY_PROMPT

    def test_plan_strategy_prompt_uses_plan_as_primary_input(self):
        """Strategy prompt should instruct using the plan as primary input."""
        from hiro_agent.prompts import PLAN_STRATEGY_PROMPT
        assert "PRIMARY input is the plan" in PLAN_STRATEGY_PROMPT
        # Should handle sparse/empty recon gracefully
        assert "sparse or empty" in PLAN_STRATEGY_PROMPT


class TestSkillAgentPrompt:
    """Test SKILL_AGENT_SYSTEM_PROMPT template."""

    def test_is_template_with_placeholders(self):
        assert "{context_preamble}" in SKILL_AGENT_SYSTEM_PROMPT
        assert "{skill_content}" in SKILL_AGENT_SYSTEM_PROMPT
        assert "{findings_dir}" in SKILL_AGENT_SYSTEM_PROMPT
        assert "{skill_name}" in SKILL_AGENT_SYSTEM_PROMPT

    def test_format_works(self):
        result = SKILL_AGENT_SYSTEM_PROMPT.format(
            context_preamble="PREAMBLE_HERE",
            skill_content="SKILL_CONTENT_HERE",
            findings_dir="/tmp/findings",
            skill_name="auth",
        )
        assert "PREAMBLE_HERE" in result
        assert "SKILL_CONTENT_HERE" in result
        assert "/tmp/findings" in result
        assert "auth" in result

    def test_contains_orchestrator_instructions(self):
        assert "Task" in SKILL_AGENT_SYSTEM_PROMPT
        assert "sub-agent" in SKILL_AGENT_SYSTEM_PROMPT
        assert "delegate" in SKILL_AGENT_SYSTEM_PROMPT.lower()

    def test_contains_json_finding_instructions(self):
        assert "finding-" in SKILL_AGENT_SYSTEM_PROMPT
        assert "JSON" in SKILL_AGENT_SYSTEM_PROMPT
        assert "Write" in SKILL_AGENT_SYSTEM_PROMPT

    def test_contains_scope_gating_contract(self):
        assert "Scope Expansion Gating" in SKILL_AGENT_SYSTEM_PROMPT
        assert "Current wave mode" in SKILL_AGENT_SYSTEM_PROMPT
        assert "EXPAND|from:file:line|to:file_or_symbol|gate:" in SKILL_AGENT_SYSTEM_PROMPT
        assert "UNTRACED_EDGE|why_it_matters|next_file_needed" in SKILL_AGENT_SYSTEM_PROMPT

    def test_high_critical_only_focus(self):
        assert "Severity Threshold (strict)" in SKILL_AGENT_SYSTEM_PROMPT
        assert "ONLY if severity is **CRITICAL** or **HIGH**" in SKILL_AGENT_SYSTEM_PROMPT

    def test_investigation_focus_section(self):
        """Should include investigation focus guidance."""
        assert "Investigation Focus" in SKILL_AGENT_SYSTEM_PROMPT
        assert "depth over breadth" in SKILL_AGENT_SYSTEM_PROMPT
        assert "3-5" in SKILL_AGENT_SYSTEM_PROMPT


class TestDiffInvestigationPrompt:
    """Test DIFF_INVESTIGATION_SYSTEM_PROMPT template."""

    def test_has_playbook_placeholder(self):
        assert "{all_playbooks}" in DIFF_INVESTIGATION_SYSTEM_PROMPT

    def test_has_preamble_placeholder(self):
        assert "{context_preamble}" in DIFF_INVESTIGATION_SYSTEM_PROMPT

    def test_has_max_turns_placeholder(self):
        assert "{max_turns}" in DIFF_INVESTIGATION_SYSTEM_PROMPT

    def test_diff_focused(self):
        assert "THIS DIFF" in DIFF_INVESTIGATION_SYSTEM_PROMPT
        assert "Do NOT audit the entire codebase" in DIFF_INVESTIGATION_SYSTEM_PROMPT

    def test_severity_format(self):
        assert "CRITICAL" in DIFF_INVESTIGATION_SYSTEM_PROMPT
        assert "HIGH" in DIFF_INVESTIGATION_SYSTEM_PROMPT
        assert "MEDIUM" in DIFF_INVESTIGATION_SYSTEM_PROMPT
        assert "LOW" in DIFF_INVESTIGATION_SYSTEM_PROMPT

    def test_format_works(self):
        result = DIFF_INVESTIGATION_SYSTEM_PROMPT.format(
            context_preamble="PREAMBLE_HERE",
            all_playbooks="PLAYBOOKS_HERE",
            max_turns=10,
        )
        assert "PREAMBLE_HERE" in result
        assert "PLAYBOOKS_HERE" in result
        assert "10 turns" in result

    def test_has_read_grep_instructions(self):
        assert "Read" in DIFF_INVESTIGATION_SYSTEM_PROMPT
        assert "Grep" in DIFF_INVESTIGATION_SYSTEM_PROMPT


class TestPlanInvestigationPrompt:
    """Test PLAN_INVESTIGATION_SYSTEM_PROMPT template."""

    def test_has_playbook_placeholder(self):
        assert "{all_playbooks}" in PLAN_INVESTIGATION_SYSTEM_PROMPT

    def test_has_preamble_placeholder(self):
        assert "{context_preamble}" in PLAN_INVESTIGATION_SYSTEM_PROMPT

    def test_has_max_turns_placeholder(self):
        assert "{max_turns}" in PLAN_INVESTIGATION_SYSTEM_PROMPT

    def test_plan_focused(self):
        """Should instruct focusing on the plan, not auditing the whole codebase."""
        assert "THIS PLAN" in PLAN_INVESTIGATION_SYSTEM_PROMPT
        assert "Do NOT audit the entire codebase" in PLAN_INVESTIGATION_SYSTEM_PROMPT

    def test_severity_format(self):
        assert "CRITICAL" in PLAN_INVESTIGATION_SYSTEM_PROMPT
        assert "HIGH" in PLAN_INVESTIGATION_SYSTEM_PROMPT
        assert "MEDIUM" in PLAN_INVESTIGATION_SYSTEM_PROMPT
        assert "LOW" in PLAN_INVESTIGATION_SYSTEM_PROMPT

    def test_format_works(self):
        result = PLAN_INVESTIGATION_SYSTEM_PROMPT.format(
            context_preamble="PREAMBLE_HERE",
            all_playbooks="PLAYBOOKS_HERE",
            max_turns=10,
        )
        assert "PREAMBLE_HERE" in result
        assert "PLAYBOOKS_HERE" in result
        assert "10 turns" in result

    def test_has_read_grep_instructions(self):
        assert "Read" in PLAN_INVESTIGATION_SYSTEM_PROMPT
        assert "Grep" in PLAN_INVESTIGATION_SYSTEM_PROMPT

    def test_has_output_format(self):
        assert "Severity" in PLAN_INVESTIGATION_SYSTEM_PROMPT
        assert "Category" in PLAN_INVESTIGATION_SYSTEM_PROMPT
        assert "Location" in PLAN_INVESTIGATION_SYSTEM_PROMPT
        assert "Evidence" in PLAN_INVESTIGATION_SYSTEM_PROMPT


class TestReportPrompt:
    """Test REPORT_SYSTEM_PROMPT content."""

    def test_contains_output_format(self):
        assert "Executive Summary" in REPORT_SYSTEM_PROMPT
        assert "Findings" in REPORT_SYSTEM_PROMPT
        assert "Incomplete Investigations" in REPORT_SYSTEM_PROMPT
        assert "Only include CRITICAL/HIGH findings" in REPORT_SYSTEM_PROMPT

    def test_no_tools_mentioned(self):
        """Report prompt should not reference filesystem tools."""
        assert "Grep" not in REPORT_SYSTEM_PROMPT
        assert "Glob" not in REPORT_SYSTEM_PROMPT
