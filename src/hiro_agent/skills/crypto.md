# Cryptography & Data Protection

## What to investigate

- Grep for all crypto usage: hashing, encryption/decryption, signing, random generation
- Check how passwords are stored — hashing algorithm, salt strategy, iteration count
- Trace sensitive data (PII, passwords, tokens, financial data) from input to storage
- Check TLS configuration in HTTP clients — certificate validation, protocol versions
- Read data serialization boundaries — what gets sent to the client vs kept server-side?

## What to grep for

```
# Password hashing (check for weak algorithms)
md5(|MD5|hashlib.md5|MessageDigest.*MD5
sha1(|SHA1|hashlib.sha1|MessageDigest.*SHA-1
sha256|sha512                                    # OK for signatures, not for passwords
bcrypt|argon2|scrypt|pbkdf2|PBKDF2               # These are correct for passwords

# Encryption
AES|DES|3DES|Blowfish|RC4|RC2
ECB|CBC|GCM|CTR                                  # ECB is insecure
encrypt(|decrypt(|Cipher|CryptoJS
Fernet|AES.new|createCipheriv

# Random number generation
random.random|random.randint|Math.random          # Insecure for security purposes
random.choice|random.sample                       # Insecure for tokens/IDs
secrets.|crypto.getRandomValues|SecureRandom      # These are correct
os.urandom|/dev/urandom|RNGCryptoServiceProvider  # These are correct

# TLS/SSL configuration
verify=False|VERIFY_NONE|InsecureSkipVerify
verify_ssl=False|check_hostname=False
TLSv1|SSLv3|TLS_RSA_|ssl.PROTOCOL_TLSv1
NODE_TLS_REJECT_UNAUTHORIZED.*0
rejectUnauthorized.*false

# Key/IV management
hardcoded|static.*key|static.*iv|static.*salt
key\s*=\s*b"|iv\s*=\s*b"|salt\s*=\s*b"
```

## What to look for

- MD5/SHA1 for password hashing — should be bcrypt, argon2, or scrypt with proper work factor
- Insufficient PBKDF2 iterations (should be 600,000+ for SHA-256 per OWASP 2023)
- `Math.random`/`random.random` for security tokens, session IDs, or OTP generation
- ECB mode for block ciphers — reveals patterns in encrypted data
- Hardcoded encryption keys, IVs, or salts in source code
- Static/reused IVs or nonces — each encryption must use a unique IV
- Missing encryption at rest for sensitive data in databases or file storage
- Sensitive data in URL params or GET requests (logged by proxies, in browser history)
- PII stored without encryption or pseudonymization
- Over-fetching — API responses include sensitive fields the client doesn't need
- Disabled TLS certificate validation (`verify=False`) — check if "temporary" dev code reached production
- Weak TLS versions allowed (TLS 1.0, 1.1, SSLv3)
- Timing side channels — string comparison (`==`) for secrets/tokens instead of constant-time comparison (`hmac.compare_digest`, `crypto.timingSafeEqual`)
- Missing HSTS header (`Strict-Transport-Security`)

## Cross-reference with infrastructure

- Check if databases have encryption at rest enabled (Terraform: `storage_encrypted`, `kms_key_id`)
- Check TLS termination at load balancer — is backend traffic also encrypted?
- Check if the app uses HTTPS everywhere or falls back to HTTP in some paths
- Check deployment configs — do they set `NODE_TLS_REJECT_UNAUTHORIZED=0` or similar?
