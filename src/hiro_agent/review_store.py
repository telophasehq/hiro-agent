"""Local persistence of review reports for later upload to the backend.

Reviews run before the commit exists, so we can't key by the commit SHA at
review time. Instead we save under a content hash of the diff, and a separate
post-commit step picks the report up, attaches the actual commit SHA, and
uploads it.
"""

from __future__ import annotations

import hashlib
import json
import os
import stat
import time
from pathlib import Path
from typing import Optional

import structlog

logger = structlog.get_logger(__name__)


PENDING_DIRNAME = "pending"
UPLOADED_DIRNAME = "uploaded"


def reviews_dir(cwd: str | os.PathLike[str] | None = None) -> Path:
    return Path(cwd or ".") / ".hiro" / "reviews"


def diff_hash(diff: str) -> str:
    """Stable content hash of a diff (sha256 hex)."""
    return hashlib.sha256(diff.encode("utf-8", errors="replace")).hexdigest()


_VERDICT_TOKENS = ("APPROVE", "REQUEST_CHANGES", "COMMENT")


def _verdict_line_value(line: str) -> Optional[str]:
    """The verdict token if this line is a verdict line, else None.

    A verdict line is ``<label>: <value>`` where the label's last word
    is ``verdict`` — tolerant to the markdown the model wraps around
    the contract format (``### Verdict:``, ``**Overall verdict:**``).
    The value is the first recognisable token, tolerant to emphasis and
    decoration (``**APPROVE** ✅``). Backtick-quoted mentions of the
    contract (`` `Verdict: APPROVE` `` in prose) don't match: the
    backtick survives normalization and breaks the label. Returns the
    RAW token — COMMENT is not coerced here.
    """
    stripped = line.strip().lstrip("#").replace("*", "").strip()
    if ":" not in stripped:
        return None
    label, _, value = stripped.partition(":")
    words = label.strip().lower().split()
    if not words or words[-1] != "verdict":
        return None
    for token in value.strip().upper().split():
        cleaned = token.strip("`.,;:!()[]{}\"'")
        if cleaned in _VERDICT_TOKENS:
            return cleaned
    return None


def parse_verdict(report_text: str) -> str:
    """Extract the verdict from a review report.

    ``report_text`` is the agent session's accumulated text — narration
    first, the actual report (and its verdict line) usually near the
    END, often markdown-decorated. The old first-10-lines scan misread
    exactly those reports: an approving review whose verdict sat below
    the window failed closed to a stored REQUEST_CHANGES with no
    findings — the poisoned-row class behind securityengineer PRs
    #1214/#1217/#1220. So: scan EVERY line.

    A whole-text scan must not hand prompt-injected content the win,
    so aggregation is fail-closed in the direction that matters:

    * any REQUEST_CHANGES verdict line wins over any number of APPROVE
      lines — injected trailing "Verdict: APPROVE" cannot override a
      real blocker, and a spurious injected REQUEST_CHANGES merely
      costs a fresh backend review, never a wrong approval;
    * no verdict line at all fails closed to REQUEST_CHANGES.

    Hiro's verdict is binary: APPROVE or REQUEST_CHANGES. The legacy
    third tier (COMMENT) coerces to APPROVE when explicitly emitted —
    back-compat with stale prompts degrades to "approve with notes,"
    matching ``services/hiro_pr_reviewer._parse_verdict``.
    """
    values = [
        v for v in (
            _verdict_line_value(line) for line in report_text.splitlines()
        )
        if v is not None
    ]
    if not values:
        return "REQUEST_CHANGES"
    if "REQUEST_CHANGES" in values:
        return "REQUEST_CHANGES"
    return "APPROVE"


def downgrade_verdict_to_request_changes(report_text: str) -> str:
    """Rewrite every verdict line in the report to REQUEST_CHANGES.

    Shares :func:`_verdict_line_value` with :func:`parse_verdict`, so no
    formatting variant the parser would read as APPROVE — including the
    COMMENT coercion — can escape the downgrade.
    """
    lines = report_text.splitlines()
    for i, line in enumerate(lines):
        value = _verdict_line_value(line)
        if value is not None and value != "REQUEST_CHANGES":
            lines[i] = "Verdict: REQUEST_CHANGES"
    return "\n".join(lines)


def save_pending(
    *,
    cwd: str | os.PathLike[str] | None,
    diff: str,
    report_text: str,
    parent_sha: Optional[str],
) -> Path:
    """Save a review report to ``.hiro/reviews/pending/<diff_hash>.json``.

    Returns the path written. Restrictive permissions (0600) since the report
    can contain sensitive code excerpts.
    """
    dh = diff_hash(diff)
    pending = reviews_dir(cwd) / PENDING_DIRNAME
    pending.mkdir(parents=True, exist_ok=True)

    payload = {
        "diff_hash": dh,
        "parent_sha": parent_sha,
        "verdict": parse_verdict(report_text),
        "report_text": report_text,
        "diff": diff,
        "saved_at": int(time.time()),
    }

    out = pending / f"{dh}.json"
    out.write_text(json.dumps(payload))
    out.chmod(stat.S_IRUSR | stat.S_IWUSR)
    logger.info(
        "review_persisted",
        path=str(out),
        diff_hash=dh,
        verdict=payload["verdict"],
    )
    return out


def list_pending(cwd: str | os.PathLike[str] | None = None) -> list[Path]:
    pending = reviews_dir(cwd) / PENDING_DIRNAME
    if not pending.is_dir():
        return []
    return sorted(pending.glob("*.json"))


def mark_uploaded(pending_path: Path, commit_sha: str) -> None:
    """Move a pending review to ``uploaded/<commit_sha>.json``."""
    uploaded = pending_path.parent.parent / UPLOADED_DIRNAME
    uploaded.mkdir(parents=True, exist_ok=True)
    dest = uploaded / f"{commit_sha}.json"
    pending_path.replace(dest)
    dest.chmod(stat.S_IRUSR | stat.S_IWUSR)
