# CI/CD & Supply Chain

## What to investigate

- Read all CI/CD config files (`.github/workflows/`, `.gitlab-ci.yml`, `Jenkinsfile`, etc.)
- Read dependency files and lockfiles for all package managers
- Check `.npmrc`, `.pypirc`, `pip.conf` for registry configuration
- Read `Makefile`, build scripts, and deployment scripts
- Check if lockfiles are committed and used in CI (`npm ci` vs `npm install`)

## What to grep for in CI/CD workflows

```
# GitHub Actions injection — user-controlled input in run: blocks
github\.event\.issue\.title|github\.event\.issue\.body
github\.event\.pull_request\.title|github\.event\.pull_request\.body
github\.event\.comment\.body|github\.event\.review\.body
github\.event\.head_commit\.message|github\.head_ref
# These are injectable when used in ${{ }} inside run: blocks

# Dangerous trigger + checkout combos
pull_request_target            # Runs with repo secrets on PR from fork
workflow_run                   # Runs in privileged context
actions/checkout.*ref.*head    # Checking out untrusted PR code

# Overprivileged permissions
permissions:\s*write-all       # Full write access
contents:\s*write              # Can modify repo
id-token:\s*write              # Can mint OIDC tokens

# Unpinned actions (mutable tags)
uses:.*@master|uses:.*@main    # Branch reference (mutable)
uses:.*@v\d+$                  # Major version only (mutable)
# Safe: uses: actions/checkout@a5ac7e51b41... (SHA pinned)

# Secrets in CI
password:|token:.*ghp_         # Hardcoded secrets
aws-access-key-id:.*AKIA      # Hardcoded AWS key
curl.*\|.*sh|wget.*\|.*bash   # Remote script execution
allow_failure:\s*true          # Security checks that can be skipped
```

## What to grep for in dependency management

```
# npm/yarn
"dependencies".*"\*"|"dependencies".*"latest"  # Unpinned versions
"preinstall"|"postinstall"                      # Install hooks (supply chain vector)
"resolved":.*"http://"                          # Non-HTTPS registry
--extra-index-url                               # Dependency confusion vector
--trusted-host                                  # TLS verification disabled

# Python
^[a-z].*(?!==[0-9])             # requirements.txt without pinned versions
allow_prereleases.*true         # Pre-release versions accepted

# General lockfile
# Check that lockfile exists and has integrity hashes
# Check that CI uses frozen install (npm ci, pip install --require-hashes)
```

## What to look for

- **Injection in CI**: user-controlled GitHub event data used in `run:` blocks without env var indirection
- **Privilege escalation**: `pull_request_target` trigger checking out attacker-controlled code with repo secrets
- **Unpinned actions**: third-party actions referenced by branch or major version tag, not SHA
- **Missing lockfile**: no `package-lock.json`, `yarn.lock`, `Pipfile.lock`, `go.sum` committed
- **Lockfile not enforced**: CI uses `npm install` instead of `npm ci`
- **Dependency confusion**: `--extra-index-url` pointing to both public and private registries
- **Install hooks**: packages with `preinstall`/`postinstall` scripts that execute arbitrary code
- **Outdated dependencies**: known CVEs in pinned dependency versions
- **Build pipeline secrets**: credentials in CI config as plaintext instead of the platform's secrets store
- **Security checks skippable**: security scan jobs marked `allow_failure` or `continue-on-error`
- **Remote script execution**: `curl | sh` or `wget | bash` in CI or build scripts

## Cross-reference with application code

- Check if dependency versions in lockfiles match what `import` statements actually use
- Check if build outputs are signed or verified before deployment
- Check if the deploy pipeline can be triggered by untrusted contributors (PR authors)
- Check if CI environment variables leak into build artifacts or Docker images
