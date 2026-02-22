# Auth & Access Control

## What to investigate

- Grep for login/signup/register/reset handlers, session creation, token generation
- Read auth middleware — check if every protected route enforces it
- Trace the full auth flow: credential input → validation → session/token → route guard
- Check role/permission checks — are they enforced server-side or only in the UI?
- Read password reset and account recovery flows end-to-end
- Check OAuth/OIDC implementation if present — redirect URI validation, state parameter, PKCE

## What to grep for

```
login|signin|sign_in|authenticate|authorize
session|jwt|token|bearer|cookie
role|permission|is_admin|is_staff|has_role
password_reset|forgot_password|reset_token
@login_required|@auth|@protect|@guard
middleware.*auth|before_action.*auth
csrf|xsrf|_token|anti_forgery
oauth|oidc|openid|saml|redirect_uri|callback
```

## What to look for

- Missing auth on sensitive endpoints — map all routes and check which lack auth middleware
- Broken access control (IDOR/BOLA) — can user A access user B's resources by changing an ID?
- Privilege escalation — role checks that compare strings instead of enums, missing role validation on admin endpoints
- Session fixation — is the session ID rotated after login?
- Token expiry/revocation gaps — JWTs with no expiry, no token blacklist on logout
- Password reset flows — is the token single-use, time-limited, and tied to the user?
- Brute force protection — is there rate limiting on login/reset/OTP endpoints?
- User enumeration — do error messages or response timing differ between valid and invalid usernames?
- MFA bypass — can password reset or recovery flows skip MFA?
- OAuth misconfig — redirect_uri not strictly validated, state parameter missing or not checked
- CSRF — missing tokens on state-changing operations, SameSite cookie attribute not set
- Client-side-only access control — hidden UI elements with no backend enforcement

## Cross-reference with infrastructure

- Check deployment configs — is auth middleware applied at the gateway/ingress level too?
- Check CORS config — does `Access-Control-Allow-Origin: *` combined with credentials undermine auth?
- Check if admin endpoints are network-restricted or exposed publicly
