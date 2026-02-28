# Configuration

## Environment Variables

- `HIRO_API_KEY`: Optional. If set, requests route through Hiro proxy and MCP context is enabled.
- `ANTHROPIC_API_KEY`: Required when `HIRO_API_KEY` is not set.
- `HIRO_SKILL_CONCURRENCY`: Max concurrent skill agents for scan/review-code (default: 4).
- `HIRO_AGENT_STALL_TIMEOUT`: Seconds with no agent messages before forced close (default: 300).
- `HIRO_AGENT_IDLE_LOG_INTERVAL`: Seconds between idle heartbeat log lines (default: 30).

## Model Routing

Model calls are configured in `src/hiro_agent/_common.py`:

- with `HIRO_API_KEY`: uses `ANTHROPIC_BASE_URL=<hiro_backend>/api/llm-proxy`
- without `HIRO_API_KEY`: uses direct Anthropic API key

## Logging

CLI commands write structured logs to:

- `.hiro/logs/hiro-YYYYMMDD-HHMMSS.log`

Useful events:

- `phase_completed`
- `agent_run_started` / `agent_run_finished`
- `agent_waiting_for_messages`
- `agent_tool_started` / `agent_tool_finished`
- `skill_wave_started` / `skill_wave_finished`

## Scope Gating Policies

Skill mode and expansion behavior are controlled by `src/hiro_agent/scope_gating.py`.

When tuning, prefer:

1. reduce unnecessary breadth
2. keep trace budgets high enough to finish real paths
3. constrain expansions to evidence-backed edges only
