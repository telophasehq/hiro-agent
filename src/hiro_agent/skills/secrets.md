# Secrets & Credentials

## What to investigate

- Grep for hardcoded secrets, API keys, and credentials in all source files
- Check every `.env*` file, config loader, and `settings.*` for hardcoded values
- Read `.gitignore` — are secret files excluded?
- Check logging config — are credentials filtered from log output?
- Check API responses — do any endpoints return secrets to the client?
- Read secret management code — how are secrets loaded at runtime?

## What to grep for

```
# Credential patterns
password\s*=\s*["']|passwd\s*=\s*["']
api_key\s*=\s*["']|apikey\s*=\s*["']
secret\s*=\s*["']|secret_key\s*=\s*["']
token\s*=\s*["']|auth_token\s*=\s*["']
private_key\s*=\s*["']

# Cloud provider keys
AKIA[0-9A-Z]{16}                          # AWS Access Key ID
-----BEGIN (RSA |DSA |EC )?PRIVATE KEY-----
AIza[0-9A-Za-z\-_]{35}                    # Google API key
"type":\s*"service_account"               # GCP service account JSON

# Service-specific tokens
sk_live_[0-9a-zA-Z]{24}                   # Stripe live key
ghp_[A-Za-z0-9]{36}                       # GitHub PAT
gho_[A-Za-z0-9]{36}                       # GitHub OAuth token
xox[pobra]-[0-9]{10,13}-                  # Slack token
SG\.[a-zA-Z0-9]{22}\.[a-zA-Z0-9]{43}      # SendGrid API key
sk-[a-zA-Z0-9]{48}                        # OpenAI API key

# Connection strings with embedded credentials
postgres://.*:.*@|mysql://.*:.*@|mongodb(\+srv)?://.*:.*@
redis://.*:.*@|amqp://.*:.*@

# Logging of secrets
log.*(password|secret|token|key|credential)
console.log.*(password|secret|token|key)
print.*(password|secret|api_key)
logger.*(password|secret|token|key)
```

## What to look for

- Hardcoded secrets in source code, config files, or test fixtures
- Credentials in `.env` files that are committed (not in `.gitignore`)
- Secrets passed as URL query parameters (visible in logs, browser history, referrer headers)
- API keys with overly broad permissions or no rotation policy
- Default credentials in config files, database seeds, or docker-compose
- Private keys or certificates checked into the repo
- Secrets in CI/CD workflow files (should use secrets store)
- Credentials logged in application output — grep for password/token/key near log statements
- Secrets returned in API responses (e.g., user profile endpoint returning API keys)
- Secrets in Dockerfile `ARG`/`ENV` instructions (visible in image history)
- `.env.example` or similar files containing real credentials instead of placeholders
- Test files with real credentials instead of mocked values

## Cross-reference with infrastructure

- Check if the app uses a secrets manager (Vault, AWS Secrets Manager, GCP Secret Manager) or just env vars
- Check Dockerfile — does it `COPY .env` or `COPY . .` without `.dockerignore`?
- Check CI/CD configs — are secrets passed as env vars in plaintext or via the platform's secrets store?
- Check if database connection strings in code use SSL (`sslmode=require` / `useSSL=true`)
