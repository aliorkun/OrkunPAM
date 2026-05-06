# Orkun PAM - Architecture Document

## 1. Overview

Orkun PAM follows **Clean Architecture** with **modular vertical slices**. Each module is self-contained with its own domain entities, application logic, and UI components, while sharing core infrastructure (encryption, persistence, identity).

### Design Principles
- **API-First:** Every UI action backed by a REST endpoint
- **Event-Driven:** Internal event bus feeds SIEM, webhooks, analytics
- **Security-by-Default:** All data encrypted at rest, all comms over TLS
- **Modular:** Each module can be enabled/disabled per customer license
- **Minimal Dependencies:** Prefer built-in .NET/Windows APIs over third-party libraries

---

## 2. Layer Architecture

```
┌─────────────────────────────────────────┐
│           Presentation Layer             │
│  WebAPI │ Blazor Web │ gRPC │ Installer  │
├─────────────────────────────────────────┤
│              Module Layer                │
│  UserMgmt │ Vault │ Session │ Analytics  │
│  Workflow │ AAPM │ Compliance │ Report   │
├─────────────────────────────────────────┤
│           Application Layer              │
│    CQRS (MediatR) │ DTOs │ Validators   │
├─────────────────────────────────────────┤
│              Domain Layer                │
│   Entities │ Value Objects │ Interfaces  │
├─────────────────────────────────────────┤
│          Infrastructure Layer            │
│  Persistence │ Crypto │ Identity │ AD    │
│  Messaging │ WindowsServices             │
└─────────────────────────────────────────┘
```

### Dependency Rules (strict)
```
Domain        → Zero external dependencies
Application   → Domain only
Infrastructure → Application + Domain
Modules       → Application + Domain + Infrastructure interfaces
Presentation  → All layers (DI composition root)
```

---

## 3. Encryption Architecture (3-Tier Key Hierarchy)

```
┌─────────────────────────────────────────┐
│  Tier 1: Key Encryption Key (KEK)       │
│  ─────────────────────────────────────  │
│  • Derived from passphrase (PBKDF2,     │
│    600K iterations) set during install   │
│  • Protected by Windows DPAPI           │
│  • Optional HSM support (PKCS#11)       │
│  • NEVER stored in plaintext            │
│  • Only used to encrypt/decrypt MK      │
├─────────────────────────────────────────┤
│  Tier 2: Master Key (MK)               │
│  ─────────────────────────────────────  │
│  • AES-256 random key, generated at     │
│    install time                          │
│  • Encrypted at rest by KEK             │
│  • Stored in [crypto].[MasterKeys]      │
│  • Supports versioned rotation           │
│  • Used to encrypt/decrypt DEKs         │
├─────────────────────────────────────────┤
│  Tier 3: Data Encryption Keys (DEK)    │
│  ─────────────────────────────────────  │
│  • Per-purpose: VaultCredentials,        │
│    SessionRecordings, ConfigSecrets      │
│  • Encrypted by MK                      │
│  • Stored in [crypto].[DataEncKeys]     │
│  • AES-256-GCM for actual encryption    │
└─────────────────────────────────────────┘

Encrypted Blob Format:
┌──────────────┬──────────┬────────────┬──────────┐
│ DEK_Version  │    IV    │ Ciphertext │ GCM_Tag  │
│  (4 bytes)   │(12 bytes)│ (variable) │(16 bytes)│
└──────────────┴──────────┴────────────┴──────────┘
```

### Key Operations
- **Encrypt:** Lookup active DEK → decrypt DEK with MK → encrypt data with DEK (AES-256-GCM) → prepend metadata
- **Decrypt:** Read DEK version from blob → decrypt DEK with MK → decrypt data with DEK → zero memory
- **Rotate MK:** Generate new MK → re-encrypt all DEKs with new MK → mark old MK as decrypt-only
- **Rotate DEK:** Generate new DEK → encrypt with active MK → new data uses new DEK → old DEK kept for decryption

### Memory Protection
- Decrypted credentials held in `Span<byte>` and `SecureString` where possible
- `CryptographicOperations.ZeroMemory()` after use
- No plaintext credentials in logs, exceptions, or error messages

---

## 4. Authentication Flow

### Local Login
```
Client → POST /auth/login {username, password}
Server → Validate Argon2id hash
Server → If MFA enabled → return challenge token
Client → POST /auth/mfa/verify {challengeToken, totpCode}
Server → Issue JWT (access: 15min, refresh: 8hr)
```

### Active Directory Login
```
Client → POST /auth/login/ad {username, password, domain}
Server → LDAP bind (System.DirectoryServices.Protocols)
Server → Map AD groups → PAM groups
Server → Issue JWT
```

### SAML 2.0 SSO
```
Client → GET /auth/saml/initiate?provider=xyz
Server → Generate AuthnRequest → redirect to IdP
IdP    → POST /auth/saml/acs with SAMLResponse
Server → Validate XML signature → extract attributes
Server → JIT provision user → map groups → Issue JWT
```

### JWT Structure
```json
{
  "sub": "<user-id>",
  "name": "<display-name>",
  "auth_source": "local|ad|saml",
  "roles": ["VaultAdmin", "SessionViewer"],
  "permissions": ["vault.credential.checkout", "session.ssh.connect"],
  "modules": ["vault", "session", "device"],
  "mfa_verified": true,
  "tenant_id": "<tenant-id>",
  "iat": "...", "exp": "...", "jti": "<unique-token-id>"
}
```

---

## 5. Session Proxy Architecture

```
┌──────────┐     ┌─────────────────┐     ┌──────────────┐
│ SSH      │     │                 │     │              │
│ Client   │────→│  SSH Proxy      │────→│ Target       │
│          │     │  (:2222)        │     │ Server       │
└──────────┘     │                 │     │              │
                 │  ┌───────────┐  │     └──────────────┘
┌──────────┐     │  │ Recording │  │
│ RDP      │     │  │ Middleware│  │     ┌──────────────┐
│ Client   │────→│  ├───────────┤  │────→│ Target       │
│          │     │  │ Keystroke │  │     │ Server       │
└──────────┘     │  │ Logger    │  │     │              │
                 │  ├───────────┤  │     └──────────────┘
┌──────────┐     │  │ Command   │  │
│ Browser  │     │  │ Filter    │  │     ┌──────────────┐
│ (HTML5)  │────→│  ├───────────┤  │────→│ Target       │
│          │     │  │ UBA       │  │     │ Server       │
└──────────┘     │  │ Scorer    │  │     │              │
                 │  └───────────┘  │     └──────────────┘
                 │                 │
                 │    gRPC ↕       │
                 │  ┌───────────┐  │
                 │  │ Core API  │  │
                 │  │ (Auth +   │  │
                 │  │  Vault)   │  │
                 │  └───────────┘  │
                 └─────────────────┘

Proxy Pipeline:
  Client → [Auth] → [Policy Check] → [Credential Inject] → [I/O Pipe] → Target
                                                              ↓
                                                    [Recording] + [Keystroke] + [UBA]
```

### Session Token Flow
1. User authenticates to PAM via JWT → clicks "Connect"
2. PAM validates permissions, checks device access, retrieves credential from vault
3. PAM generates one-time session token
4. For SSH: token sent as SSH username (`token:<session-token>`)
5. For RDP: embedded in .rdp file / RD Gateway cookie
6. Proxy validates token via gRPC → establishes connection to target
7. **Credential NEVER sent to user's client**

### Recording Storage
- SSH: asciinema format (JSON lines with timestamp + data)
- RDP/VNC: Custom binary format (timestamp + bitmap deltas), converted to video on demand
- Encrypted at rest with session-specific DEK
- Configurable retention policies
- Playback via web (xterm.js for SSH, custom player for RDP)

---

## 6. Event Bus Architecture

```
┌──────────┐  ┌──────────┐  ┌──────────┐
│ UserMgmt │  │  Vault   │  │ Session  │  ... All Modules
└────┬─────┘  └────┬─────┘  └────┬─────┘
     │             │             │
     └─────────────┼─────────────┘
                   ↓
          ┌────────────────┐
          │   Event Bus    │
          │  (In-Process)  │
          └───────┬────────┘
                  │
     ┌────────────┼────────────┬──────────────┐
     ↓            ↓            ↓              ↓
┌─────────┐ ┌──────────┐ ┌──────────┐ ┌───────────┐
│  SIEM   │ │ Webhook  │ │ Threat   │ │ Audit Log │
│ (Syslog │ │ Delivery │ │ Analytics│ │  Writer   │
│  / CEF) │ │          │ │ Engine   │ │           │
└─────────┘ └──────────┘ └──────────┘ └───────────┘
```

Every significant action publishes a domain event:
- `UserLoggedIn`, `UserLockedOut`, `MfaFailed`
- `CredentialCheckedOut`, `PasswordRotated`, `CredentialDiscovered`
- `SessionStarted`, `CommandBlocked`, `SessionTerminated`
- `PolicyViolation`, `ApprovalRequested`, `ApprovalGranted`

---

## 7. Database Schema Map

```
[identity]   → Users, Groups, Roles, Permissions, Policies, SAML/LDAP configs
[vault]      → Credentials, Folders, RotationPolicies, Discovery, Shares, CheckOutHistory
[device]     → Devices, DeviceGroups, Platforms, DeviceCredentials
[session]    → ProxySessions, KeystrokeLogs, SessionPolicies, Recordings
[aapm]       → ApiClients, CredentialAccess, RequestLogs
[workflow]   → ApprovalWorkflows, ApprovalRequests, ApprovalSteps
[analytics]  → BehaviorBaselines, RiskScores, Anomalies, Alerts
[compliance] → ComplianceTemplates, AttestationCampaigns, PolicyMappings
[reporting]  → ReportDefinitions, Schedules, DashboardWidgets
[crypto]     → MasterKeys, DataEncryptionKeys
[system]     → SystemConfig, Jobs, AuditLog, Tenants, Licenses
```

---

## 8. NuGet Dependencies (Minimal)

### Required
| Package | Purpose |
|---------|---------|
| Microsoft.EntityFrameworkCore.SqlServer | ORM + SQL Server |
| Renci.SshNet | SSH proxy (client + server) |
| System.IdentityModel.Tokens.Jwt | JWT handling |
| Grpc.AspNetCore | gRPC services |
| MediatR | CQRS pattern |
| FluentValidation | Input validation |
| Serilog + Serilog.Sinks.* | Structured logging |

### Optional
| Package | Purpose |
|---------|---------|
| QuestPDF | PDF report generation |
| ClosedXML | Excel export |
| Konscious.Security.Cryptography.Argon2 | Argon2id hashing |

### Built-in (No External Dependency)
- LDAP: `System.DirectoryServices.Protocols`
- SAML: `System.Security.Cryptography.Xml`
- TOTP: `System.Security.Cryptography.HMACSHA1`
- AES-256-GCM: `System.Security.Cryptography.AesGcm`
- DPAPI: `System.Security.Cryptography.ProtectedData`
- JWT Signing: `System.Security.Cryptography.RSA`
