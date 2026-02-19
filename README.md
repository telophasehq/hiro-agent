# hiro-agent

AI security review agent for code, plans, and infrastructure. Integrates with Claude Code, Cursor, VSCode Copilot, and Codex CLI to enforce security reviews before commits and plan finalization.

## Install

```bash
pip install hiro-agent
```

## Quick Start

```bash
# Set up hooks for your AI coding tools
hiro setup

# Review code changes
git diff | hiro review-code

# Review an implementation plan
cat plan.md | hiro review-plan

# Review infrastructure configuration
hiro review-infra main.tf
```

## Commands

| Command | Description |
|---------|-------------|
| `hiro review-code` | Security review of code changes (stdin: git diff) |
| `hiro review-plan` | STRIDE threat model review of a plan (stdin) |
| `hiro review-infra` | IaC security review (file arg or stdin) |
| `hiro setup` | Auto-detect and configure all AI coding tools |
| `hiro verify` | Verify hook integrity against installed version |

### Setup Options

```bash
hiro setup                # Auto-detect all tools
hiro setup --claude-code  # Claude Code only
hiro setup --cursor       # Cursor only
hiro setup --vscode       # VSCode Copilot only
hiro setup --codex        # Codex CLI only
```

## Configuration

Set `HIRO_API_KEY` to connect to the Hiro platform for organizational context (security policies, memories, org profile). Without it, reviews still run using your `ANTHROPIC_API_KEY` directly.

```bash
export HIRO_API_KEY=hiro_ak_...     # Optional: Hiro platform context
export ANTHROPIC_API_KEY=sk-ant-... # Required if HIRO_API_KEY not set
```

## How It Works

1. **`hiro setup`** installs hook scripts in `.hiro/hooks/` and configures your AI coding tool to call them
2. Hooks track file modifications and block commits until `hiro review-code` has run
3. Hooks track plan creation and block finalization until `hiro review-plan` has run
4. Review agents use `claude-agent-sdk` to spawn a Claude instance that performs the security review
5. When connected to Hiro (`HIRO_API_KEY`), reviews are enriched with your org's security policy, accepted risks, and architecture context

## License

MIT
