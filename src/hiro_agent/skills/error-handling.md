# Error Handling & Debug Exposure

## What to investigate

- Read error handling code — what happens in catch/except blocks?
- Check API error responses — what information is returned to the client?

## What to grep for

```
# Error handling patterns
except:|catch\s*\(|catch\s*\{
except:\s*pass|catch.*\{\s*\}         # Empty catch blocks
except Exception|catch \(Exception    # Overly broad exception handling
rescue\s*=>|on.*catch                 # Ruby/Dart patterns
raise|throw|Error\(                   # Error creation

# Error response patterns
traceback|stack_trace|stacktrace
exc_info|format_exc|print_exc
debug=True|DEBUG.*True                # Debug mode (verbose errors)
res.status.*500.*send|res.json.*error # Check what's included in error responses
```

## What to look for

- **Empty catch blocks**: `except: pass` or `catch(e) {}` that silently swallow errors, including security failures
- **Fail-open error handling**: catch blocks that default to "allow" on exception — the security check fails and access is granted
- **Overly broad exception handling**: `except Exception` that masks specific security errors
- **Verbose error responses**: stack traces, internal file paths, database errors, or SQL queries returned to the client in production
- **Missing error responses**: security failures that return 200 OK instead of appropriate 401/403/500
- **Debug mode in production**: `DEBUG=True` or equivalent that enables verbose error pages
- **PII in error messages**: user data included in error responses or exception messages

## Cross-reference with infrastructure

- Check if error pages are configured at the reverse proxy level (nginx, CloudFront) to mask app errors
- Check if the deployment overrides `DEBUG` to `False`/`0` in production environment
- Check if health/status endpoints expose internal details publicly
