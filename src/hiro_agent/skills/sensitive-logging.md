# Sensitive Data in Logs & Audit Trails

## What to investigate

- Read logging configuration — what level, what format, where do logs go?
- Grep for log statements near sensitive data (passwords, tokens, PII)
- Look for audit trail implementation — are security events recorded?

## What to grep for

```
# Logging of sensitive data
log.*(password|secret|token|key|credential|ssn|credit_card)
console.log.*(password|secret|token|key|authorization)
print.*(password|secret|api_key|private)
logger.*(password|secret|token|auth|bearer)
logging.*(password|secret|token|key)
console.log.*process\.env             # Logging all env vars
console.log.*req\.(body|headers)      # Logging entire request
log.*request|log.*response            # Check if bodies are logged

# Audit events (should exist)
audit|security_event|access_log
failed_login|unauthorized|forbidden
permission_denied|access_denied
```

## What to look for

- **Sensitive data in logs**: passwords, tokens, API keys, PII, credit card numbers in log output
- **Log injection**: unsanitized user input written to logs (can forge log entries, inject ANSI escape codes)
- **Missing audit trail**: failed login attempts, authorization failures, and admin actions not logged
- **Insufficient logging**: no log entries for security-critical operations (password changes, privilege grants, data exports)
- **Log tampering**: can users influence log content to create misleading entries?
- **Missing monitoring**: no alerting on repeated auth failures, unusual data access patterns, or error rate spikes

## Cross-reference with infrastructure

- Check where logs are stored — are they encrypted? Who has access?
- Check if log aggregation exists (CloudWatch, ELK, Datadog) or just local files
