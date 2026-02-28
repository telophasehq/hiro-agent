"""Tests for hiro_agent.review_infra — infrastructure review agent."""

from unittest.mock import patch

import pytest

from hiro_agent.review_infra import (
    ALLOWED_TOOLS,
    MAX_TURNS,
    _detect_config_type,
    review_infrastructure,
)


class TestDetectConfigType:
    """Test _detect_config_type() helper."""

    def test_terraform(self):
        assert _detect_config_type("main.tf") == "Terraform"

    def test_dockerfile(self):
        assert _detect_config_type("Dockerfile") == "Dockerfile"

    def test_docker_compose(self):
        assert _detect_config_type("docker-compose.yml") == "Docker Compose"

    def test_kubernetes_yaml(self):
        assert _detect_config_type("deployment.yaml") == "Kubernetes/CloudFormation YAML"

    def test_helm_values(self):
        assert _detect_config_type("values.yaml") == "Helm Values"

    def test_unknown(self):
        assert _detect_config_type("random.txt") == "Infrastructure Configuration"


class TestReviewInfrastructure:
    """Test review_infrastructure() function."""

    @pytest.mark.asyncio
    async def test_calls_agent_with_config(self):
        """Should include config content in the prompt."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["prompt"] = prompt
            captured.update(kwargs)
            return "## Findings\nPublic S3 bucket."

        config = 'resource "aws_s3_bucket" "data" { bucket = "test" }'

        with patch("hiro_agent.review_infra.run_review_agent", side_effect=mock_run):
            result = await review_infrastructure(config, filename="main.tf")

        assert "aws_s3_bucket" in captured["prompt"]
        assert "Terraform" in captured["prompt"]
        assert result == "## Findings\nPublic S3 bucket."

    @pytest.mark.asyncio
    async def test_file_path_detection(self):
        """When given a file path, should tell agent to read it."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["prompt"] = prompt
            return "ok"

        with patch("hiro_agent.review_infra.run_review_agent", side_effect=mock_run):
            await review_infrastructure(
                "/path/to/main.tf", filename="main.tf", cwd="/path/to"
            )

        assert "Read the file" in captured["prompt"]
        assert "/path/to/main.tf" in captured["prompt"]

    @pytest.mark.asyncio
    async def test_allowed_tools(self):
        """Should pass Read and Glob as allowed tools."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)
            return "ok"

        with patch("hiro_agent.review_infra.run_review_agent", side_effect=mock_run):
            await review_infrastructure("config content", filename="Dockerfile")

        assert captured["allowed_tools"] == ["Read", "Grep"]

    @pytest.mark.asyncio
    async def test_max_turns(self):
        """Should use configured MAX_TURNS = 12."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured.update(kwargs)
            return "ok"

        with patch("hiro_agent.review_infra.run_review_agent", side_effect=mock_run):
            await review_infrastructure("config", filename="main.tf")

        assert captured["max_turns"] == MAX_TURNS
        assert MAX_TURNS == 12

    @pytest.mark.asyncio
    async def test_system_prompt_is_infra_review(self):
        """Should use INFRA_REVIEW_SYSTEM_PROMPT."""
        captured = {}

        async def mock_run(prompt, system_prompt, **kwargs):
            captured["system_prompt"] = system_prompt
            return "ok"

        with patch("hiro_agent.review_infra.run_review_agent", side_effect=mock_run):
            await review_infrastructure("config", filename="main.tf")

        assert "CIS Benchmarks" in captured["system_prompt"]
        assert "Read" in captured["system_prompt"]
        assert "Grep" in captured["system_prompt"]
