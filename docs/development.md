# Development

## Requirements

- Python 3.11+
- `uv` (recommended) or virtualenv + pip

## Setup

```bash
uv sync --dev
```

## Run Tests

```bash
uv run pytest -q
```

Release-gating tests (primary):

```bash
uv run pytest tests/test_review_code.py tests/test_review_plan.py tests/test_cli.py -q
```

Experimental scan tests (non-blocking by policy):

```bash
uv run pytest tests/test_scan.py tests/test_common.py -q
```

## Local CLI

```bash
uv run hiro --help
uv run hiro scan
```

## Code Organization Rules

- Keep orchestration code in command modules (`scan.py`, `review_code.py`, etc).
- Keep terminal rendering logic in `scan_display.py`.
- Keep scope policies in `scope_gating.py`.
- Add tests for behavior changes before merging.

## PR Expectations

- include tests for logic changes
- keep patches focused and reviewable
- avoid mixing refactors with behavior changes unless necessary
