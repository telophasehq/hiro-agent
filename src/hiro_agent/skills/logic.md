# Business Logic & Concurrency

## What to investigate

- Map state machines and multi-step workflows (checkout, onboarding, approval flows)
- Read financial/transactional code — balance checks, transfers, inventory management
- Check for atomic operations where consistency matters
- Look for check-then-act patterns without proper synchronization
- Read rate limiting implementation — is it applied consistently?

## What to grep for

```
# State and workflow
state|status|step|phase|stage|workflow
transition|approve|reject|cancel|complete
next_step|current_step|set_status

# Financial/transactional
balance|credit|debit|transfer|withdraw|deposit
price|amount|quantity|discount|coupon|promo
checkout|payment|charge|refund|invoice
inventory|stock|available|reserve

# Concurrency primitives (or lack thereof)
lock|mutex|semaphore|synchronized
atomic|transaction|begin|commit|rollback
select_for_update|FOR UPDATE|SERIALIZABLE
asyncio.Lock|threading.Lock|multiprocessing.Lock

# Rate limiting
rate_limit|throttle|cooldown|retry_after
max_attempts|login_attempts|lockout

# Time-based
sleep|delay|timeout|expire|ttl
time.time|datetime.now|Date.now
schedule|cron|periodic|interval
```

## What to look for

- **Workflow bypass**: can steps in a multi-step process be skipped by calling later endpoints directly?
- **Price/discount manipulation**: can the client send a different price than what the server calculates?
- **Double-spend / double-submit**: can a financial operation be executed twice by concurrent requests before the balance check catches it?
- **TOCTOU (Time-of-Check-Time-of-Use)**: is there a gap between checking a condition and acting on it? Example: check balance → debit, without holding a lock
- **Race conditions in auth**: concurrent session creation, parallel password resets, simultaneous token refreshes
- **Inventory overselling**: concurrent purchases that each pass the stock check before decrementing
- **Negative values**: are negative quantities, amounts, or prices accepted where only positive values make sense?
- **Integer overflow/underflow**: large values that wrap around or cause unexpected behavior
- **Fail-open patterns**: `try/except: pass` or empty catch blocks around security-critical operations
- **Missing rate limiting**: no throttling on login, password reset, OTP verification, or expensive API endpoints
- **Client trust**: server trusts client-provided values (prices, roles, permissions, feature flags) without validation
- **Unbounded operations**: user can trigger operations that process unlimited data (ReDoS, algorithmic complexity attacks, zip bombs)

## Cross-reference with infrastructure

- Check if rate limiting is enforced at the application level, API gateway, or not at all
- Check if database transactions use appropriate isolation levels for financial operations
- Check if the deployment uses horizontal scaling (multiple instances) — race conditions are more likely
- Check if background job queues have idempotency guarantees
