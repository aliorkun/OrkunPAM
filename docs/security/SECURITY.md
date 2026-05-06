# Orkun PAM - Security Architecture

## Encryption

### At Rest
- **Database:** SQL Server TDE (Transparent Data Encryption)
- **Sensitive Columns:** Always Encrypted (MFA secrets, LDAP passwords)
- **Vault Data:** Custom AES-256-GCM with 3-tier key hierarchy (KEK → MK → DEK)
- **Session Recordings:** Encrypted with per-session DEK
- **Config Secrets:** DPAPI-encrypted sections in appsettings.json

### In Transit
- **External:** TLS 1.3 (HTTPS for API/UI, TLS for gRPC)
- **Internal:** gRPC with mTLS between proxy services and core
- **Database:** Encrypted connection (Encrypt=True;TrustServerCertificate=False)

### Key Management
- KEK derived from passphrase (PBKDF2, 600K iterations) + DPAPI
- Master Key rotatable without downtime
- DEK per-purpose, independently rotatable
- Zero plaintext keys on disk
- Memory zeroing after use (`CryptographicOperations.ZeroMemory`)

## Authentication Security

### Password Storage
- Argon2id (memory=64MB, iterations=3, parallelism=4)
- Unique salt per user
- Password history enforcement

### Session Tokens
- JWT with RS256 (RSA-2048 keypair)
- Short-lived access tokens (15 min)
- One-time-use refresh tokens (8 hr)
- Token revocation via JTI blacklist
- Signing key protected by DPAPI

### Brute Force Protection
- Account lockout: 5 failures in 5 minutes → 30 min lock
- Rate limiting: 5 auth requests/min per IP (sliding window)
- Progressive delay on failed attempts
- CAPTCHA after 3 failures (optional)

### MFA
- TOTP (RFC 6238) with ±1 window tolerance
- SMS OTP (6 digits, 5 min expiry)
- Push notification approval
- Enforced per policy (user/group/global level)

## Session Proxy Security

### Credential Isolation
- User NEVER sees target credential
- Credential decrypted only in proxy process memory
- Injected into target connection server-side
- Zeroed immediately after connection establishment

### Session Integrity
- One-time session tokens (non-replayable)
- Token tied to client IP
- Session timeout enforcement (idle + absolute)
- Admin termination capability
- All I/O recorded and hash-chained

## Audit Security

### Tamper-Proof Logs
- Append-only tables (separate DB principal, no DELETE)
- Hash chain: each entry includes SHA-256 of previous entry
- Integrity verification endpoint
- Log export with cryptographic proof

### Audit Coverage
- Every authentication attempt (success + failure)
- Every credential access (view, checkout, checkin, rotate)
- Every session (start, end, terminate, command)
- Every admin action (config change, user modify, policy change)
- Every approval decision
- Every API client access

## Network Security
- All proxy services listen on configurable ports
- Firewall rules configured during installation
- IP allowlisting for admin access
- IP allowlisting per AAPM API client
- No direct target access required from user endpoint (jump server architecture)
- CSP, HSTS, X-Frame-Options, anti-CSRF on web UI

## Input Validation
- FluentValidation on every API command
- Parameterized queries only (EF Core)
- HTML encoding in Blazor (XSS prevention by default)
- File upload validation (size, type, content)
- Path traversal prevention

## Secrets in Code
- No hardcoded secrets
- All sensitive config in DPAPI-encrypted sections
- Git pre-commit hook to scan for secrets
- .gitignore for development secrets
