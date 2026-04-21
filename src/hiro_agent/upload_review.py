"""Upload pending review reports to the Hiro backend.

Run from a ``post-commit`` git hook. Reads ``.hiro/reviews/pending/*.json``,
attaches the current HEAD SHA + repo info, POSTs to the backend, and moves
each successfully uploaded report to ``.hiro/reviews/uploaded/<sha>.json``.

Best-effort: failures are logged and the pending file is left in place so
the next commit retries it. Never blocks the commit.
"""

from __future__ import annotations

import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
from typing import Optional

import structlog

from hiro_agent._common import HIRO_BACKEND_URL, _get_api_key
from hiro_agent.review_store import list_pending, mark_uploaded

logger = structlog.get_logger(__name__)


UPLOAD_ENDPOINT = "/api/hiro-reviews"
UPLOAD_TIMEOUT_SECS = 15


def _git(cwd: Path, *args: str) -> Optional[str]:
    try:
        out = subprocess.run(
            ["git", *args],
            cwd=cwd,
            capture_output=True,
            text=True,
            timeout=5,
        )
        if out.returncode != 0:
            return None
        return out.stdout.strip()
    except Exception:
        return None


def _detect_repo_full_name(cwd: Path) -> Optional[str]:
    """Return ``owner/repo`` parsed from the ``origin`` remote, or None."""
    url = _git(cwd, "config", "--get", "remote.origin.url")
    if not url:
        return None
    # git@github.com:owner/repo.git  or  https://github.com/owner/repo(.git)
    url = url.rstrip("/")
    if url.endswith(".git"):
        url = url[:-4]
    if url.startswith("git@"):
        _, _, path = url.partition(":")
        return path or None
    if "://" in url:
        path = url.split("/", 3)[-1] if url.count("/") >= 3 else None
        return path
    return None


def _post_review(*, api_key: str, payload: dict) -> tuple[int, str]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        url=f"{HIRO_BACKEND_URL}{UPLOAD_ENDPOINT}",
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=UPLOAD_TIMEOUT_SECS) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as exc:
        return exc.code, exc.read().decode("utf-8", errors="replace")


def upload_pending(cwd: Optional[str] = None) -> int:
    """Upload all pending reviews. Returns count uploaded."""
    root = Path(cwd or ".").resolve()

    api_key = _get_api_key()
    if not api_key:
        logger.info("upload_skipped_no_api_key")
        return 0

    head_sha = _git(root, "rev-parse", "HEAD")
    if not head_sha:
        logger.info("upload_skipped_no_head_sha")
        return 0

    repo_full_name = _detect_repo_full_name(root)
    if not repo_full_name:
        logger.info("upload_skipped_no_remote")
        return 0

    pending = list_pending(root)
    if not pending:
        return 0

    uploaded = 0
    for path in pending:
        try:
            data = json.loads(path.read_text())
        except Exception:
            logger.warning("upload_skip_unreadable", path=str(path))
            continue

        payload = {
            "repo_full_name": repo_full_name,
            "commit_sha": head_sha,
            "parent_sha": data.get("parent_sha"),
            "diff_hash": data.get("diff_hash"),
            "verdict": data.get("verdict", "COMMENT"),
            "report_text": data.get("report_text", ""),
            "diff": data.get("diff", ""),
        }

        status, body = _post_review(api_key=api_key, payload=payload)
        if 200 <= status < 300:
            mark_uploaded(path, head_sha)
            uploaded += 1
            logger.info(
                "upload_ok",
                repo=repo_full_name,
                commit_sha=head_sha,
                diff_hash=payload["diff_hash"],
            )
        else:
            logger.warning(
                "upload_failed",
                status=status,
                body=body[:300],
                repo=repo_full_name,
                commit_sha=head_sha,
            )
            # Leave the pending file in place for retry on the next commit.

    return uploaded


def main() -> None:
    """Entry point for the ``hiro upload-review`` command and the git hook.

    Always exits 0 — never block a commit because of an upload problem.
    """
    try:
        upload_pending()
    except Exception:
        logger.warning("upload_review_unhandled", exc_info=True)
    sys.exit(0)


if __name__ == "__main__":
    main()
