"""Security investigation skill definitions (loaded from markdown)."""

import importlib.resources

SKILL_NAMES: list[str] = [
    "auth", "injection", "secrets", "crypto",
    "infra", "cicd", "logic", "sensitive-logging", "error-handling",
]


def load_skill(name: str) -> str:
    """Load a skill markdown file from the installed package."""
    ref = importlib.resources.files("hiro_agent.skills").joinpath(f"{name}.md")
    return ref.read_text(encoding="utf-8")
