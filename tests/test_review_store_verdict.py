"""Pin hiro-agent's binary-verdict contract.

The CLI emits APPROVE or REQUEST_CHANGES — never the legacy third tier
COMMENT. These tests guard ``parse_verdict`` against drift.
"""

from hiro_agent.review_store import parse_verdict


def test_parses_approve():
    assert parse_verdict("Verdict: APPROVE\n\nbody") == "APPROVE"


def test_parses_request_changes():
    assert parse_verdict("Verdict: REQUEST_CHANGES\n\nbody") == "REQUEST_CHANGES"


def test_parses_with_markdown_emphasis():
    assert parse_verdict("**Verdict:** **APPROVE**\n") == "APPROVE"
    assert parse_verdict("Verdict: ***REQUEST_CHANGES***\n") == "REQUEST_CHANGES"


def test_legacy_comment_coerces_to_approve():
    """Back-compat: a model still emitting COMMENT must not produce a
    non-approving review on GitHub."""
    assert parse_verdict("Verdict: COMMENT\n\nMedium-sev notes") == "APPROVE"


def test_missing_verdict_fails_closed():
    """Safety control: a missing / unparseable verdict line MUST default
    to REQUEST_CHANGES. The backend's auto-merge consumes this value
    and only fails closed on null risk/confidence — fail-open here
    would let a prompt-injection-induced verdict omission auto-merge."""
    assert parse_verdict("Hello, no verdict line\nat all") == "REQUEST_CHANGES"


def test_unrecognised_value_fails_closed():
    """Hallucinated verdict value (e.g. invented third tier) is also
    treated as parse failure: fail closed."""
    assert parse_verdict("Verdict: MAYBE\n\nbody") == "REQUEST_CHANGES"


def test_only_scans_first_ten_lines():
    """Stop scanning so a body that mentions 'Verdict:' deep in prose
    can't override the absent header. Combined with fail-closed default
    this means burying a fake Verdict line in commit messages also
    can't smuggle through an APPROVE."""
    text = "\n".join(["filler"] * 12) + "\nVerdict: REQUEST_CHANGES\n"
    assert parse_verdict(text) == "REQUEST_CHANGES"  # fail-closed on missing
