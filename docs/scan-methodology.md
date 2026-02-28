# Scan Methodology

This document explains how `hiro scan` balances breadth and deep tracing.

## Stability Status

`hiro scan` is currently **experimental**. It is valuable for exploratory audits,
but should not be the only release gate.

Primary enforcement should continue to rely on:

- `hiro review-code`
- `hiro review-plan`

## Execution Modes

Each skill uses one of these modes:

- `breadth`: wide shallow checks (for distributed patterns like logging, exception handling)
- `trace`: deeper path-following checks (for auth flows, logic bugs)
- `hybrid`: one breadth wave, then trace waves

Mode and default wave counts are selected by policy in `src/hiro_agent/scope_gating.py`.

## Waves and Turns

- A **wave** is one skill-agent run.
- A **turn** is the model conversation step budget in that run.

Current defaults:

- breadth: 8 turns per wave
- trace: 12 turns per wave
- hybrid: at least 1 breadth + 3 trace waves

## Scope Gating

Each wave includes a scope contract:

- skill starts with a seeded allow-list (`ALLOWED_FILES`)
- out-of-scope reads are blocked in trace waves
- agent can request `EXPAND` tickets when tracing requires new files

Approved expansion targets are carried to later waves.

## Todo Semantics

Skill todo lists are investigation-only and monotonic:

- housekeeping/plumbing todos are filtered
- checklist state is merged across updates to avoid count regressions

This keeps progress indicators stable while agents refine plans.

## Failure and Continuation

If a wave ends due to turn limit and work remains:

- run is marked turn-limited
- one guarded continuation wave can be queued automatically

This prevents silent truncation while avoiding runaway loops.

## What to Measure When Slow

Use both CLI and logs:

- CLI indicates the slowest active step in real time
- logs include `agent_run_started/finished`, `agent_tool_started/finished`, and `skill_wave_started/finished`

Primary bottleneck categories:

1. model latency
2. provider throttling/retries
3. excessive scope violations causing rework
4. too many concurrent skills for available model throughput
