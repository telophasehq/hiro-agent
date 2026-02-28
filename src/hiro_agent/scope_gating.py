"""Scope gating helpers for bounded multi-wave skill investigations."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import os
from pathlib import Path
import re
from typing import Literal

AuditMode = Literal["trace", "breadth", "hybrid"]

VALID_GATES: tuple[str, ...] = (
    "BOUNDARY",
    "AUTHZ",
    "SINK",
    "TOKEN",
    "ERROR_PATH",
)

_IGNORED_DIRS: set[str] = {
    ".cache",
    ".claude",
    ".git",
    ".mypy_cache",
    ".next",
    ".nuxt",
    ".npm",
    ".pnp",
    ".pytest_cache",
    ".ruff_cache",
    ".serverless",
    ".terraform",
    ".venv",
    ".yarn",
    "__pycache__",
    "build",
    "dist",
    "env",
    "external",
    "node_modules",
    "out",
    "site-packages",
    "target",
    "third_party",
    "vendor",
    "venv",
}

IGNORED_DIRS: frozenset[str] = frozenset(_IGNORED_DIRS)


@dataclass(frozen=True)
class SkillGatePolicy:
    """Per-track gating policy."""

    allowed_gates: tuple[str, ...]
    mode: AuditMode = "trace"
    max_depth: int = 4
    max_new_files: int = 8
    max_minutes: int = 12
    max_seed_files: int = 8
    max_breadth_files: int = 80


@dataclass(frozen=True)
class ExpansionRequest:
    """Parsed expansion ticket from scratchpad output."""

    raw_line: str
    from_file: str
    from_line: int
    to_target: str
    gate: str
    why: str

    @property
    def key(self) -> str:
        return (
            f"{self.from_file}:{self.from_line}|{self.to_target}|"
            f"{self.gate}|{self.why}"
        )


@dataclass(frozen=True)
class ExpansionDecision:
    """Approval/denial outcome for an expansion request."""

    request: ExpansionRequest
    approved: bool
    reason: str
    approved_path: str | None = None


_SKILL_POLICIES: dict[str, SkillGatePolicy] = {
    "auth": SkillGatePolicy(("BOUNDARY", "AUTHZ", "TOKEN", "ERROR_PATH"), mode="trace"),
    "injection": SkillGatePolicy(("BOUNDARY", "SINK", "AUTHZ", "ERROR_PATH"), mode="trace"),
    "secrets": SkillGatePolicy(
        ("BOUNDARY", "SINK", "TOKEN", "ERROR_PATH"),
        mode="breadth",
        max_seed_files=24,
        max_breadth_files=120,
    ),
    "crypto": SkillGatePolicy(("TOKEN", "SINK", "ERROR_PATH"), mode="trace"),
    "infra": SkillGatePolicy(
        ("AUTHZ", "BOUNDARY", "SINK"),
        mode="breadth",
        max_seed_files=20,
        max_breadth_files=120,
    ),
    "cicd": SkillGatePolicy(
        ("AUTHZ", "SINK", "BOUNDARY", "ERROR_PATH"),
        mode="breadth",
        max_seed_files=20,
        max_breadth_files=100,
    ),
    "logic": SkillGatePolicy(
        ("BOUNDARY", "AUTHZ", "SINK", "ERROR_PATH"),
        mode="hybrid",
        max_depth=5,
        max_new_files=12,
        max_minutes=15,
        max_seed_files=12,
        max_breadth_files=150,
    ),
    "sensitive-logging": SkillGatePolicy(
        ("BOUNDARY", "SINK", "TOKEN", "ERROR_PATH"),
        mode="breadth",
        max_seed_files=32,
        max_breadth_files=160,
    ),
    "error-handling": SkillGatePolicy(
        ("ERROR_PATH", "AUTHZ", "BOUNDARY", "TOKEN"),
        mode="breadth",
        max_seed_files=32,
        max_breadth_files=160,
    ),
}

_SKILL_KEYWORDS: dict[str, tuple[str, ...]] = {
    "auth": ("auth", "login", "session", "token", "jwt", "permission", "role", "middleware"),
    "injection": ("route", "api", "request", "input", "query", "sql", "exec", "command"),
    "secrets": ("env", "secret", "key", "token", "config", "settings", "credential"),
    "crypto": ("crypto", "hash", "encrypt", "decrypt", "jwt", "tls", "ssl", "password"),
    "infra": ("infra", "terraform", "docker", "compose", "k8s", "kubernetes", "deploy"),
    "cicd": ("workflow", "ci", "cd", "pipeline", "github", "gitlab", "jenkins", "build"),
    "logic": ("workflow", "state", "service", "transaction", "payment", "order", "inventory"),
    "sensitive-logging": ("log", "logger", "logging", "audit", "middleware", "exception"),
    "error-handling": ("error", "exception", "handler", "middleware", "main", "app"),
}

_EXTENSION_BONUS: dict[str, tuple[str, ...]] = {
    "auth": (".py", ".ts", ".js"),
    "injection": (".py", ".ts", ".js", ".sql"),
    "secrets": (".env", ".yaml", ".yml", ".toml", ".json", ".py"),
    "crypto": (".py", ".ts", ".js", ".go", ".java"),
    "infra": (".tf", ".yaml", ".yml", "dockerfile"),
    "cicd": (".yml", ".yaml", ".toml", ".json"),
    "logic": (".py", ".ts", ".js", ".go"),
    "sensitive-logging": (".py", ".ts", ".js"),
    "error-handling": (".py", ".ts", ".js"),
}

_PATH_TOKEN_RE = re.compile(
    r"(?:^|[\s`'\"(])([A-Za-z0-9_./-]+\.[A-Za-z0-9_]+)(?=$|[\s`'\"),\]])"
)

_EXPAND_RE = re.compile(
    r"^EXPAND\|from:(?P<from>[^|]+)\|to:(?P<to>[^|]+)\|gate:(?P<gate>[A-Z_]+)\|(?P<why>.+)$"
)


def get_skill_gate_policy(skill_name: str) -> SkillGatePolicy:
    """Return per-skill policy, defaulting to the strict baseline."""
    return _SKILL_POLICIES.get(skill_name, SkillGatePolicy(VALID_GATES, mode="trace"))


def list_first_party_files(cwd: str | None) -> list[str]:
    """List first-party files under cwd, excluding dependency/build directories."""
    root = Path(cwd or ".").resolve()
    if not root.exists():
        return []

    results: list[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in _IGNORED_DIRS]
        base = Path(dirpath)
        for filename in filenames:
            path = base / filename
            try:
                rel = path.relative_to(root).as_posix()
            except ValueError:
                continue
            if _is_ignored(rel):
                continue
            results.append(rel)
    results.sort()
    return results


def build_seed_scope(
    skill_name: str,
    *,
    cwd: str | None,
    context_text: str,
    max_seeds: int | None = None,
    all_files: list[str] | None = None,
) -> list[str]:
    """Select an initial seed scope for a skill using context + filename ranking."""
    policy = get_skill_gate_policy(skill_name)
    limit = max_seeds if max_seeds is not None else policy.max_seed_files
    files = all_files if all_files is not None else list_first_party_files(cwd)
    if not files:
        return []

    existing = set(files)
    context_paths: list[str] = []
    seen: set[str] = set()
    for token in _PATH_TOKEN_RE.findall(context_text or ""):
        normalized = normalize_repo_file(token, cwd, must_exist=True)
        if not normalized or normalized not in existing or normalized in seen:
            continue
        seen.add(normalized)
        context_paths.append(normalized)

    seeded: list[str] = []
    for path in sorted(context_paths, key=lambda p: _score_path(skill_name, p), reverse=True):
        if _score_path(skill_name, path) <= 0:
            continue
        seeded.append(path)
        if len(seeded) >= limit:
            return seeded

    for path in sorted(files, key=lambda p: _score_path(skill_name, p), reverse=True):
        if path in seeded:
            continue
        score = _score_path(skill_name, path)
        # Keep at least 3 starter files even if the heuristic score is weak.
        if score <= 0 and len(seeded) >= 3:
            continue
        seeded.append(path)
        if len(seeded) >= limit:
            break

    return seeded


def resolve_wave_modes(policy: SkillGatePolicy, requested_waves: int) -> tuple[int, list[AuditMode]]:
    """Return the effective wave count and per-wave audit mode plan."""
    if policy.mode == "hybrid":
        # Hybrid always starts broad, then requires enough trace waves
        # to process ticket approvals in subsequent iterations.
        effective = max(requested_waves, 3)
        return effective, ["breadth"] + (["trace"] * (effective - 1))
    if policy.mode == "breadth":
        return requested_waves, ["breadth"] * requested_waves
    return requested_waves, ["trace"] * requested_waves


def render_scope_gate_block(
    *,
    skill_name: str,
    policy: SkillGatePolicy,
    mode: AuditMode,
    wave_index: int,
    total_waves: int,
    allowed_files: list[str],
    used_expansions: int,
    feedback: str = "",
) -> str:
    """Render the per-wave gating contract injected into the skill prompt."""
    gates = "|".join(policy.allowed_gates)
    remaining = max(policy.max_new_files - used_expansions, 0)
    lines = [
        "## Scope Gating (enforced)",
        f"- Track: `{skill_name}`",
        f"- Mode for this wave: `{mode}` ({wave_index + 1}/{total_waves})",
        (
            f"- Budget: max_depth={policy.max_depth}, max_new_files={policy.max_new_files}, "
            f"max_time={policy.max_minutes}m"
        ),
    ]

    if mode == "breadth":
        lines.extend(
            [
                (
                    "- Breadth mode active: repo-wide grep/read is allowed for cross-cutting checks "
                    f"(up to {policy.max_breadth_files} unique files)."
                ),
                "- Keep tracing shallow in this wave; defer deep chains to trace waves.",
                "- If deeper tracing is required, record: `UNTRACED_EDGE|why_it_matters|next_file_needed`.",
                "",
                "### STARTER_FILES",
            ]
        )
        lines.extend(_format_allowed_files(allowed_files, max_items=24))
    else:
        lines.extend(
            [
                f"- Remaining expansion budget: {remaining}",
                f"- Allowed gates: `{', '.join(policy.allowed_gates)}`",
                "- Read only files listed in `ALLOWED_FILES`.",
                (
                    "- To request a new file, emit exactly: "
                    f"`EXPAND|from:file:line|to:file_or_symbol|gate:({gates})|why`"
                ),
                "- If blocked, emit: `UNTRACED_EDGE|why_it_matters|next_file_needed`.",
                "",
                "### ALLOWED_FILES",
            ]
        )
        lines.extend(_format_allowed_files(allowed_files, max_items=48))

    if feedback.strip():
        lines.extend(["", "### Previous Ticket Decisions", feedback.strip()])

    return "\n".join(lines)


def _format_allowed_files(paths: list[str], *, max_items: int) -> list[str]:
    """Format a bounded view of file scope for prompt injection."""
    if not paths:
        return ["- `<empty>`"]
    visible = paths[:max_items]
    lines = [f"- `{path}`" for path in visible]
    hidden = len(paths) - len(visible)
    if hidden > 0:
        lines.append(f"- `… +{hidden} more files`")
    return lines


def build_shared_index(
    *,
    cwd: str | None,
    recon_summary: str,
    max_skill_files: int = 24,
) -> dict:
    """Build a shared first-party index for all skill agents."""
    files = list_first_party_files(cwd)

    top_dirs: dict[str, int] = {}
    for rel in files:
        root = Path(rel).parts[0] if Path(rel).parts else rel
        top_dirs[root] = top_dirs.get(root, 0) + 1
    top_dirs = dict(sorted(top_dirs.items(), key=lambda kv: kv[1], reverse=True)[:20])

    skill_index: dict[str, dict] = {}
    for skill_name in sorted(_SKILL_POLICIES):
        policy = get_skill_gate_policy(skill_name)
        starters = build_seed_scope(
            skill_name,
            cwd=cwd,
            context_text=recon_summary,
            max_seeds=min(policy.max_seed_files, max_skill_files),
            all_files=files,
        )
        skill_index[skill_name] = {
            "mode": policy.mode,
            "starter_files": starters,
            "allowed_gates": list(policy.allowed_gates),
        }

    return {
        "version": 1,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "repo_root": str(Path(cwd or ".").resolve()),
        "file_count": len(files),
        "top_directories": top_dirs,
        "skills": skill_index,
    }


def format_shared_index_for_prompt(
    *,
    index: dict,
    skill_name: str,
    max_files: int = 24,
) -> str:
    """Render a compact, authoritative shared-index block for one skill."""
    skills = index.get("skills", {})
    skill_info = skills.get(skill_name, {})
    starters = list(skill_info.get("starter_files", []))[:max_files]
    mode = skill_info.get("mode", "trace")
    top_dirs = index.get("top_directories", {})
    top_dir_items = list(top_dirs.items())[:8]

    lines = [
        "## Shared Repository Index (authoritative)",
        "- This index was generated once after recon and shared across all skill agents.",
        "- Do NOT rediscover repository structure with broad globbing.",
        "- If the index is insufficient, request specific `EXPAND|...` tickets in trace mode.",
        f"- Index file count: {index.get('file_count', 0)}",
        f"- Skill mode: `{mode}`",
        "",
        "### Top Directories",
    ]
    if top_dir_items:
        lines.extend(f"- `{name}` ({count} files)" for name, count in top_dir_items)
    else:
        lines.append("- `<none>`")

    lines.extend(["", f"### {skill_name} Starter Files"])
    lines.extend(_format_allowed_files(starters, max_items=max_files))
    return "\n".join(lines)


def parse_expand_requests(text: str) -> list[ExpansionRequest]:
    """Extract structured EXPAND tickets from free-form notes/scratchpad text."""
    requests: list[ExpansionRequest] = []
    for raw_line in (text or "").splitlines():
        line = raw_line.strip()
        line = line.lstrip("-* ").strip()
        match = _EXPAND_RE.match(line)
        if not match:
            continue

        from_ref = match.group("from").strip()
        if ":" not in from_ref:
            continue
        from_file, line_s = from_ref.rsplit(":", 1)
        if not line_s.isdigit():
            continue
        from_line = int(line_s)
        if from_line <= 0:
            continue

        requests.append(
            ExpansionRequest(
                raw_line=line,
                from_file=from_file.strip(),
                from_line=from_line,
                to_target=match.group("to").strip(),
                gate=match.group("gate").strip(),
                why=match.group("why").strip(),
            )
        )
    return requests


def evaluate_expansion_requests(
    requests: list[ExpansionRequest],
    *,
    policy: SkillGatePolicy,
    allowed_files: set[str],
    seen_request_keys: set[str],
    cwd: str | None,
    used_expansions: int,
) -> tuple[list[ExpansionDecision], int]:
    """Approve/deny expansion requests and update scope set + budget count."""
    decisions: list[ExpansionDecision] = []

    for request in requests:
        if request.key in seen_request_keys:
            continue
        seen_request_keys.add(request.key)

        if request.gate not in VALID_GATES:
            decisions.append(ExpansionDecision(request, False, "invalid gate"))
            continue
        if request.gate not in policy.allowed_gates:
            decisions.append(ExpansionDecision(request, False, "gate not allowed for this track"))
            continue

        from_path = normalize_repo_file(request.from_file, cwd, must_exist=False)
        if not from_path:
            decisions.append(ExpansionDecision(request, False, "from path is invalid"))
            continue
        if from_path not in allowed_files:
            decisions.append(ExpansionDecision(request, False, "from path is out of scope"))
            continue
        if not _line_exists(cwd, from_path, request.from_line):
            decisions.append(ExpansionDecision(request, False, "from line does not exist"))
            continue

        if used_expansions >= policy.max_new_files:
            decisions.append(ExpansionDecision(request, False, "expansion budget exhausted"))
            continue

        to_path = normalize_repo_file(request.to_target, cwd, must_exist=True)
        if not to_path:
            decisions.append(ExpansionDecision(request, False, "target is not a readable file"))
            continue
        if to_path in allowed_files:
            decisions.append(ExpansionDecision(request, False, "target already in scope"))
            continue
        if not _has_direct_edge(cwd, from_path, to_path):
            decisions.append(ExpansionDecision(request, False, "no direct edge evidence"))
            continue

        allowed_files.add(to_path)
        used_expansions += 1
        decisions.append(ExpansionDecision(request, True, "approved", approved_path=to_path))

    return decisions, used_expansions


def format_expansion_feedback(
    *,
    decisions: list[ExpansionDecision],
    policy: SkillGatePolicy,
    used_expansions: int,
) -> str:
    """Compact feedback summary to feed into the next wave prompt."""
    if not decisions:
        remaining = max(policy.max_new_files - used_expansions, 0)
        return f"No new expansion tickets processed. Remaining budget: {remaining}."

    lines = []
    for decision in decisions:
        request = decision.request
        if decision.approved:
            lines.append(
                "APPROVED|"
                f"from:{request.from_file}:{request.from_line}|"
                f"to:{decision.approved_path}|"
                f"gate:{request.gate}"
            )
        else:
            lines.append(
                "DENIED|"
                f"from:{request.from_file}:{request.from_line}|"
                f"to:{request.to_target}|"
                f"gate:{request.gate}|"
                f"{decision.reason}"
            )

    remaining = max(policy.max_new_files - used_expansions, 0)
    lines.append(f"Remaining budget: {remaining}/{policy.max_new_files}")
    return "\n".join(lines)


def normalize_tool_read_path(path: str, *, cwd: str | None) -> str | None:
    """Normalize a tool-supplied file path for scope comparisons."""
    return normalize_repo_file(path, cwd, must_exist=False)


def normalize_repo_file(path: str, cwd: str | None, *, must_exist: bool) -> str | None:
    """Normalize to repo-relative POSIX path and enforce root/ignore rules."""
    raw = (path or "").strip().strip("`\"'")
    if not raw:
        return None
    raw = raw.split("#", 1)[0].strip()
    raw = raw.replace("\\", "/")

    root = Path(cwd or ".").resolve()
    candidate = Path(raw)
    if not candidate.is_absolute():
        candidate = root / candidate

    try:
        resolved = candidate.resolve(strict=must_exist)
    except FileNotFoundError:
        return None
    except OSError:
        return None

    try:
        rel = resolved.relative_to(root).as_posix()
    except ValueError:
        return None
    if _is_ignored(rel):
        return None
    if must_exist and not resolved.is_file():
        return None
    return rel


def _is_ignored(rel_path: str) -> bool:
    parts = Path(rel_path).parts
    return any(part in _IGNORED_DIRS for part in parts)


def _score_path(skill_name: str, rel_path: str) -> int:
    keywords = _SKILL_KEYWORDS.get(skill_name, ())
    lower_path = rel_path.lower()
    score = 0

    for keyword in keywords:
        if keyword in lower_path:
            score += 2

    name = Path(rel_path).name.lower()
    for keyword in keywords:
        if keyword in name:
            score += 3

    ext = Path(rel_path).suffix.lower()
    bonuses = _EXTENSION_BONUS.get(skill_name, ())
    for bonus in bonuses:
        if bonus.startswith(".") and ext == bonus:
            score += 1
        if bonus == "dockerfile" and name.startswith("dockerfile"):
            score += 2

    return score


def _line_exists(cwd: str | None, rel_path: str, line_no: int) -> bool:
    if line_no <= 0:
        return False
    root = Path(cwd or ".").resolve()
    path = root / rel_path
    try:
        with path.open("r", encoding="utf-8", errors="ignore") as handle:
            for idx, _ in enumerate(handle, start=1):
                if idx == line_no:
                    return True
    except OSError:
        return False
    return False


def _has_direct_edge(cwd: str | None, from_rel: str, to_rel: str) -> bool:
    """Heuristic check that the source file references the target path/module."""
    root = Path(cwd or ".").resolve()
    from_path = root / from_rel
    to_path = Path(to_rel)
    try:
        from_text = from_path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return False

    tokens = {
        to_path.name,
        to_path.stem,
        to_rel,
    }
    if to_rel.endswith(".py"):
        module = to_rel[:-3].replace("/", ".")
        tokens.add(module)
        tokens.add(module.split(".")[-1])

    return any(token and token in from_text for token in tokens)
