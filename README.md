# hiro-agent

AI security review agent for code, plans, and infrastructure.

## What this project does

- Reviews code diffs for security issues
- Reviews implementation plans with threat-modeling prompts
- Reviews infrastructure configs for security misconfigurations
- Scans repositories with multi-skill, wave-based security investigations (experimental)

It integrates with Claude Code, Cursor, VSCode Copilot, and Codex CLI to enforce review workflows before commits and plan finalization.

## Install

```bash
# Recommended (isolated environment, works on macOS/Linux)
pipx install hiro-agent

# Or with pip in a virtual environment
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

# Experimental: full-repo scan
hiro scan
```

## Commands

| Command | Description |
|---------|-------------|
| `hiro review-code` | Security review of code changes (stdin: git diff) |
| `hiro review-plan` | STRIDE threat model review of a plan (stdin) |
| `hiro review-infra` | IaC security review (file arg or stdin) |
| `hiro scan` | Full-repo multi-skill security scan (experimental/beta) |
| `hiro chat "<question>"` | Ask security questions about current repo |
| `hiro setup` | Auto-detect and configure all AI coding tools |
| `hiro upgrade` | Update installed hooks/configs to latest package behavior |
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

More details: `docs/configuration.md`

## How It Works

1. **`hiro setup`** installs hook scripts in `.hiro/hooks/` and configures your AI coding tool to call them
2. Hooks track file modifications and block commits until `hiro review-code` has run
3. Hooks track plan creation and block finalization until `hiro review-plan` has run
4. Review agents use `claude-agent-sdk` to spawn a Claude instance that performs the security review
5. When connected to Hiro (`HIRO_API_KEY`), reviews are enriched with your org's security policy, accepted risks, and architecture context

## Stability

- Primary/release-gated workflows: `review-code`, `review-plan`
- Secondary workflow: `review-infra`
- Experimental workflow: `scan`

## Architecture and Methodology

- Architecture: `docs/architecture.md`
- Scan methodology: `docs/scan-methodology.md`
- Troubleshooting: `docs/troubleshooting.md`
- Development: `docs/development.md`

## Contributing

- Contribution guide: `CONTRIBUTING.md`
- Code of conduct: `CODE_OF_CONDUCT.md`
- Security reporting: `SECURITY.md`

## License

MIT
