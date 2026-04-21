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


def parse_verdict(report_text: str) -> str:
    """Extract the verdict from a review report.

    Defaults to ``COMMENT`` if no verdict line is present, which keeps the
    backend conservative — never auto-approve based on a missing/unparseable
    verdict.
    """
    for line in report_text.splitlines()[:10]:
        stripped = line.strip()
        if stripped.lower().startswith("verdict:"):
            value = stripped.split(":", 1)[1].strip().upper()
            if value in ("APPROVE", "REQUEST_CHANGES", "COMMENT"):
                return value
    return "COMMENT"


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
