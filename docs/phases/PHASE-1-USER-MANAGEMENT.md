# Phase 1 - User Management & Workflow Engine

**Duration:** Week 4-7
**Depends On:** Phase 0
**Goal:** Complete identity management with multi-source auth, RBAC, MFA, and workflow engine

---

## Module 1A: User Management

### 1.1 Local User Management
- [ ] User CRUD (create, read, update, soft-delete)
- [ ] Argon2id password hashing (`Konscious.Security.Cryptography` or native interop)
- [ ] Password policy enforcement (min length, complexity, history, max age)
- [ ] Account lockout (configurable: N failures within M minutes → lock for K minutes)
- [ ] Password reset (admin-initiated, self-service)
- [ ] User status lifecycle: Active → Disabled → Locked → Deleted
- [ ] User properties / custom attributes
- [ ] API: `/api/v1/users/*`

### 1.2 Group Management
- [ ] Group CRUD (local groups)
- [ ] Group membership management (add/remove users)
- [ ] Nested groups (group within group)
- [ ] Group-based configuration inheritance
- [ ] API: `/api/v1/groups/*`

### 1.3 Role-Based Access Control (RBAC)
- [ ] Role definitions with permission codes
- [ ] Built-in roles: GlobalAdmin, VaultAdmin, SessionAdmin, DeviceAdmin, Auditor, ReadOnly, HelpDesk
- [ ] Custom role creation
- [ ] Permission codes: `module.resource.action` (e.g., `vault.credential.checkout`)
- [ ] User-Role and Group-Role assignments
- [ ] Effective permission resolution (user direct + group inherited)
- [ ] Module-level access control (user sees only licensed/permitted modules)
- [ ] API: `/api/v1/roles/*`, `/api/v1/permissions/*`

### 1.4 Policy Engine
- [ ] JSON-based policy documents
- [ ] Policy types: PasswordPolicy, SessionPolicy, VaultPolicy, AccessPolicy
- [ ] Policy scoping: User < Group < Global (inheritance with override)
- [ ] Policy evaluation service
- [ ] API: `/api/v1/policies/*`

### 1.5 Active Directory / LDAP Integration
- [ ] LDAP configuration CRUD (multiple AD domains)
- [ ] LDAP authentication (bind test)
- [ ] User sync: map AD attributes → PAM user fields
- [ ] Group sync: map AD groups → PAM groups (configurable mapping)
- [ ] Scheduled sync (IHostedService, configurable interval)
- [ ] On-demand sync trigger
- [ ] AD computer object discovery (reused in Phase 2)
- [ ] SSL/STARTTLS support
- [ ] API: `/api/v1/ldap-configs/*`

### 1.6 SAML 2.0 SSO
- [ ] SAML provider configuration CRUD (multiple IdPs)
- [ ] AuthnRequest generation (XML signing)
- [ ] Assertion Consumer Service (ACS): signature validation, attribute extraction
- [ ] Just-in-Time (JIT) user provisioning from SAML assertions
- [ ] Group mapping from SAML attributes
- [ ] Metadata endpoint (`/saml/metadata`)
- [ ] Single Logout (SLO) support
- [ ] API: `/api/v1/saml-providers/*`

### 1.7 Multi-Factor Authentication
- [ ] TOTP implementation (RFC 6238, built-in crypto)
- [ ] QR code generation for authenticator app setup
- [ ] SMS-based OTP (configurable SMS gateway via HTTP)
- [ ] Push notification MFA (mobile app integration)
- [ ] MFA enforcement policies (per-user, per-group, global)
- [ ] MFA bypass for break-glass accounts
- [ ] Remember device option (configurable duration)
- [ ] API: `/api/v1/auth/mfa/*`

### 1.8 Session (Auth) Management
- [ ] JWT issuance (RS256, access + refresh tokens)
- [ ] Refresh token rotation (one-time use)
- [ ] Concurrent session limits (configurable)
- [ ] Session listing and forced logout
- [ ] Session timeout (idle + absolute)
- [ ] Token revocation via JTI blacklist
- [ ] API: `/api/v1/auth/*`

### 1.9 Temporary / JIT Users
- [ ] Create time-limited user accounts
- [ ] Auto-disable after expiry
- [ ] Link to approval workflow
- [ ] Vendor/contractor access profiles

### 1.10 User Delegation
- [ ] Delegate approval authority to another user
- [ ] Time-limited delegation
- [ ] Delegation audit trail

---

## Module 1B: Workflow Engine

### 1.11 Approval Workflows
- [ ] Workflow definition CRUD (name, steps, conditions)
- [ ] Single-level approval (one approver)
- [ ] Multi-level approval chain (manager → CISO → SOC)
- [ ] Parallel approval (any one of N approvers)
- [ ] Conditional routing (based on risk score, device type, etc.)
- [ ] API: `/api/v1/workflows/*`

### 1.12 Approval Requests
- [ ] Request creation (manual or system-triggered)
- [ ] Approve / Deny / Escalate actions
- [ ] Auto-escalation (no response within N minutes → next approver)
- [ ] Request expiry
- [ ] Email / SMS / Push notifications for pending approvals
- [ ] API: `/api/v1/approval-requests/*`

### 1.13 Emergency / Break-Glass Access
- [ ] Break-glass account designation
- [ ] Bypass approval workflows for break-glass
- [ ] Enhanced audit logging for break-glass usage
- [ ] Post-usage notification to all admins
- [ ] Auto-expire break-glass sessions

### 1.14 Dual Authorization (Four-Eyes)
- [ ] Two-approver requirement for sensitive operations
- [ ] Configurable per-device, per-credential, or per-user-group

### 1.15 ITSM Integration
- [ ] ServiceNow ticket validation before access
- [ ] Jira ticket linking
- [ ] Ticket number required for session/checkout
- [ ] API: `/api/v1/itsm/*`

### 1.16 Access Scheduling
- [ ] Recurring time windows (e.g., "every Tuesday 09-17")
- [ ] One-time scheduled access
- [ ] Calendar view of scheduled access

---

## UI (Blazor)

### Pages
- [ ] Login page (Local / AD / SAML tabs)
- [ ] User list (searchable, filterable by source, status, group)
- [ ] User detail / edit page (properties, roles, groups, policies, MFA status)
- [ ] Group management (tree view, members, roles)
- [ ] Role management (permissions matrix)
- [ ] LDAP configuration page (connection test)
- [ ] SAML configuration page (metadata import/export)
- [ ] MFA setup wizard
- [ ] Approval workflows list and designer
- [ ] Approval requests inbox (pending, approved, denied)
- [ ] Audit log viewer (identity events)
- [ ] My Profile page (change password, MFA, active sessions)

---

## Audit Events
- User.Created, User.Updated, User.Disabled, User.Deleted
- User.Login.Success, User.Login.Failed, User.Login.Locked
- User.MFA.Enabled, User.MFA.Disabled, User.MFA.Failed
- User.Password.Changed, User.Password.Reset
- Group.Created, Group.MemberAdded, Group.MemberRemoved
- Role.Assigned, Role.Removed
- Workflow.Created, Approval.Requested, Approval.Granted, Approval.Denied
- BreakGlass.Activated, BreakGlass.Deactivated

---

## Deliverables
- Full local + AD + SAML authentication working
- MFA (TOTP + SMS) working
- Complete RBAC with permission resolution
- Workflow engine processing approvals
- All Blazor UI pages functional
- 90%+ test coverage on auth flows
