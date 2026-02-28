"""Tests for hiro_agent.scope_gating helpers."""

from pathlib import Path

from hiro_agent.scope_gating import (
    ExpansionRequest,
    SkillGatePolicy,
    evaluate_expansion_requests,
    get_skill_gate_policy,
    parse_expand_requests,
    render_scope_gate_block,
    resolve_wave_modes,
)


def test_parse_expand_requests_parses_valid_lines() -> None:
    text = """
    EXPAND|from:src/app/auth.py:42|to:src/app/tokens.py|gate:TOKEN|token verification path
    EXPAND|from:bad-no-line|to:x.py|gate:TOKEN|invalid
    """

    requests = parse_expand_requests(text)

    assert len(requests) == 1
    req = requests[0]
    assert req.from_file == "src/app/auth.py"
    assert req.from_line == 42
    assert req.to_target == "src/app/tokens.py"
    assert req.gate == "TOKEN"


def test_evaluate_expansion_requests_approves_valid_request(tmp_path: Path) -> None:
    seed = tmp_path / "seed.py"
    target = tmp_path / "new_mod.py"
    seed.write_text("import new_mod\n")
    target.write_text("VALUE = 1\n")

    policy = SkillGatePolicy(("AUTHZ",), max_new_files=3)
    request = ExpansionRequest(
        raw_line="EXPAND|from:seed.py:1|to:new_mod.py|gate:AUTHZ|needs auth check",
        from_file="seed.py",
        from_line=1,
        to_target="new_mod.py",
        gate="AUTHZ",
        why="needs auth check",
    )
    allowed_files = {"seed.py"}
    seen: set[str] = set()

    decisions, used = evaluate_expansion_requests(
        [request],
        policy=policy,
        allowed_files=allowed_files,
        seen_request_keys=seen,
        cwd=str(tmp_path),
        used_expansions=0,
    )

    assert len(decisions) == 1
    assert decisions[0].approved is True
    assert decisions[0].approved_path == "new_mod.py"
    assert "new_mod.py" in allowed_files
    assert used == 1


def test_evaluate_expansion_requests_denies_invalid_gate_and_budget(tmp_path: Path) -> None:
    seed = tmp_path / "seed.py"
    target = tmp_path / "next_file.py"
    seed.write_text("import next_file\n")
    target.write_text("VALUE = 1\n")

    policy = SkillGatePolicy(("AUTHZ",), max_new_files=1)
    invalid_gate = ExpansionRequest(
        raw_line="EXPAND|from:seed.py:1|to:next_file.py|gate:SINK|bad gate",
        from_file="seed.py",
        from_line=1,
        to_target="next_file.py",
        gate="SINK",
        why="bad gate",
    )
    budget_exhausted = ExpansionRequest(
        raw_line="EXPAND|from:seed.py:1|to:next_file.py|gate:AUTHZ|budget",
        from_file="seed.py",
        from_line=1,
        to_target="next_file.py",
        gate="AUTHZ",
        why="budget",
    )

    allowed_files = {"seed.py"}
    seen: set[str] = set()
    decisions, used = evaluate_expansion_requests(
        [invalid_gate, budget_exhausted],
        policy=policy,
        allowed_files=allowed_files,
        seen_request_keys=seen,
        cwd=str(tmp_path),
        used_expansions=1,
    )

    assert len(decisions) == 2
    assert decisions[0].approved is False
    assert "gate not allowed" in decisions[0].reason
    assert decisions[1].approved is False
    assert "budget exhausted" in decisions[1].reason
    assert used == 1
    assert "next_file.py" not in allowed_files


def test_render_scope_gate_block_includes_contract() -> None:
    policy = SkillGatePolicy(("BOUNDARY", "AUTHZ"), mode="trace", max_depth=4, max_new_files=8, max_minutes=12)
    block = render_scope_gate_block(
        skill_name="auth",
        policy=policy,
        mode="trace",
        wave_index=0,
        total_waves=2,
        allowed_files=["src/app/auth.py"],
        used_expansions=2,
        feedback="APPROVED|from:a.py:1|to:b.py|gate:AUTHZ",
    )

    assert "Scope Gating" in block
    assert "EXPAND|from:file:line|to:file_or_symbol|gate:(BOUNDARY|AUTHZ)" in block
    assert "src/app/auth.py" in block
    assert "Remaining expansion budget" in block
    assert "APPROVED|" in block


def test_render_scope_gate_block_breadth_mode() -> None:
    policy = SkillGatePolicy(("ERROR_PATH",), mode="breadth", max_breadth_files=100)
    block = render_scope_gate_block(
        skill_name="error-handling",
        policy=policy,
        mode="breadth",
        wave_index=0,
        total_waves=1,
        allowed_files=["src/a.py", "src/b.py"],
        used_expansions=0,
    )

    assert "Mode for this wave: `breadth`" in block
    assert "repo-wide grep/read is allowed" in block
    assert "STARTER_FILES" in block


def test_resolve_wave_modes_hybrid_forces_three_waves() -> None:
    policy = SkillGatePolicy(("BOUNDARY",), mode="hybrid")
    waves, modes = resolve_wave_modes(policy, 2)
    assert waves == 3
    assert modes == ["breadth", "trace", "trace"]


def test_skill_mode_mapping_matches_track_intent() -> None:
    assert get_skill_gate_policy("auth").mode == "trace"
    assert get_skill_gate_policy("injection").mode == "trace"
    assert get_skill_gate_policy("crypto").mode == "trace"
    assert get_skill_gate_policy("logic").mode == "hybrid"
    assert get_skill_gate_policy("infra").mode == "breadth"
    assert get_skill_gate_policy("cicd").mode == "breadth"
    assert get_skill_gate_policy("error-handling").mode == "breadth"
    assert get_skill_gate_policy("sensitive-logging").mode == "breadth"
    assert get_skill_gate_policy("secrets").mode == "breadth"
