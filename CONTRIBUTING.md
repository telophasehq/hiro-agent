# Contributing

Thanks for contributing.

## Getting Started

1. Fork and clone the repo.
2. Install dev dependencies:

```bash
uv sync --dev
```

3. Run tests before opening a PR:

```bash
uv run pytest -q
```

## How to Contribute

- Bug fixes
- Reliability/performance improvements
- Documentation improvements
- Tests and tooling improvements

For substantial changes, open an issue first so design can be aligned.

## Coding Guidelines

- Keep changes focused to one concern.
- Prefer clear, explicit names over clever shortcuts.
- Add tests for behavior changes.
- Do not include secrets or customer data in code/tests/logs.

## Commit and PR Guidelines

- Use descriptive commit messages.
- In PR description, include:
  - problem statement
  - change summary
  - test evidence
  - risk/rollback notes (if applicable)

## Local Verification Checklist

- [ ] Core gate passes: `uv run pytest -q tests/test_review_code.py tests/test_review_plan.py tests/test_cli.py`
- [ ] Experimental scan tests checked when scan-related code changed
- [ ] docs updated if behavior changed
- [ ] no new warnings/errors in `.hiro/logs` during manual runs

## Reporting Security Issues

Please do not open public issues for exploitable vulnerabilities.
Use the process in `SECURITY.md`.
