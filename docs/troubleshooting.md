# Troubleshooting

## Scan Feels Slow

1. Check live CLI "Slowest active" hint.
2. Inspect `.hiro/logs/*.log` for:
   - `agent_waiting_for_messages`
   - large `agent_run_finished.total_s`
   - large `skill_wave_finished.duration_s`
3. Verify provider throttling/latency in your model backend metrics.

## Todos Seem Inconsistent

The display keeps investigation todos only and merges updates to keep progress monotonic.
If counts look wrong, inspect log events around `on_todos` and `skill_wave_finished`.

## Recon Keeps Repeating Structure Discovery

Check that shared index is built and injected:

- `.hiro/.scan_index.json` exists
- prompts include the index artifact path

## Frequent Turn-Limited Outcomes

Review:

- wave mode (`breadth` vs `trace`)
- turn budgets
- pending untraced edges and expansion follow-ups

If work is truly deep, allow additional trace waves.

## MCP Context Not Available

Look for `mcp_preflight_failed` in logs.
Common causes:

- missing/invalid `HIRO_API_KEY`
- network/auth issues to Hiro MCP endpoint
