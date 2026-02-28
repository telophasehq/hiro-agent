# Architecture

This project is a CLI-driven security review engine for repositories and plans.

## Runtime Flow

The `hiro` CLI command routes into one of these entry points:

- `hiro review-code` -> `src/hiro_agent/review_code.py`
- `hiro review-plan` -> `src/hiro_agent/review_plan.py`
- `hiro review-infra` -> `src/hiro_agent/review_infra.py`
- `hiro scan` -> `src/hiro_agent/scan.py`
- `hiro chat` -> `src/hiro_agent/chat.py`

Shared runtime machinery lives in `src/hiro_agent/_common.py`.

## Scan Pipeline

`hiro scan` runs four phases:

1. Reconnaissance
2. Strategy (compress recon into a brief)
3. Skill investigations (parallel, wave-based)
4. Report synthesis

Key files:

- Orchestration: `src/hiro_agent/scan.py`
- Shared agent loop + wave execution: `src/hiro_agent/_common.py`
- Scope gating: `src/hiro_agent/scope_gating.py`
- Live TTY UI: `src/hiro_agent/scan_display.py`
- Skill prompts: `src/hiro_agent/skills/*.md`

## Stability Policy

- **Primary (release-gated):** `review-code`, `review-plan`
- **Secondary:** `review-infra`
- **Experimental:** `scan`

CI is split to keep primary workflows strict while allowing scan iteration.

## Core Concepts

- **Skill**: A focused security topic (`auth`, `injection`, `crypto`, etc).
- **Wave**: One full run of a skill agent with a fresh model session.
- **Turn**: Model turn budget inside a single wave.
- **Todo**: Agent-provided investigation checklist item.
- **Expand ticket**: Request to trace beyond current allowed files (`EXPAND|...`).

## Module Boundaries

- `cli.py` handles argument parsing, logging setup, and command dispatch.
- `scan.py` / `review_code.py` handle phase orchestration and report assembly.
- `_common.py` handles agent execution, tool callbacks, and wave control.
- `scan_display.py` handles terminal rendering and progress state only.
- `scope_gating.py` handles file-scope policy and expansion ticket evaluation.

## Data Artifacts

- Run logs: `.hiro/logs/hiro-YYYYMMDD-HHMMSS.log`
- Skill findings: `.hiro/.scratchpad/finding-<skill>-*.json`
- Skill state: `.hiro/.scratchpad/<skill>-state.md`
- Shared index: `.hiro/.scan_index.json`

## Extending the System

To add a new skill:

1. Add a skill markdown file under `src/hiro_agent/skills/`.
2. Register it in `src/hiro_agent/skills/__init__.py`.
3. Add/adjust tests in `tests/test_scan.py` and `tests/test_common.py`.
