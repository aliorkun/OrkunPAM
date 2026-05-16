# PAM RFP Template - Compliance Checklist

> Auto-generated from PAM Template.xlsx. PM Agent uses this for feature gap analysis.
> Status: FC=Fully Compliant, PC=Partially Compliant, NC=Not Compliant
> Last updated: 2026-05-16 (PM run #8)

## Platform (44 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | Solution shall support appliance base installation | PC | WiX v4 MSI + PowerShell Install.ps1 + OrkunPAM.Installer CLI — component selection, DB init, cert gen, service registration; single-package Windows Server deployment (#36) |
| 2 | Solution shall support Vmware and Hyper-V based installation |  |  |
| 3 | Solution shall be deployable On‑Premise and provided as a cloud  offering. |  |  |
| 4 | Solution shall support agent-less architecture. No additional software agent shall be required to install on devices, se |  |  |
| 5 | Solution GUI shall run with updated version of well-known browsers (i.e. Microsoft Edge, Google Chrome, Firefox, Safari) | PC | OrkunPAM.Web (Blazor Server — Edge/Chrome/Firefox) |
| 6 | Solution shall support SSO (Single-Sign-On) | PC | SAML 2.0 SSO implemented — SamlAuthEndpoints.cs SP-initiated flow, SamlCallback.razor (#45) |
| 7 | Solution shall support both CLI and web interfaces | PC | Blazor web UI (OrkunPAM.Web) + REST API (OrkunPAM.WebAPI) |
| 8 | Solution shall support SAML authentication for secure portal access to PAM platform | PC | SAML 2.0 SP-initiated + ACS — SamlAuthEndpoints.cs; XML sig validation, ±5 min clock skew, auto-provision (#45) |
| 9 | Solution shall support SAML provider configuration on a per-tenant basis, allowing separate identity provider settings f |  |  |
| 10 | Solution shall support Public Key Infrastructure (PKI) Authentication for secure portal access using digital certificate |  |  |
| 11 | Solution shall support Windows Authentication fo | PC | AuthEndpoints.cs — GET /api/v1/auth/windows; Negotiate/Kerberos SSO; trusted domain guard, auto-provision on first login, MFA bypass for Kerberos, audit via UserLoggedInEvent; Integrations.razor Windows Auth tab (#126) |
| 12 | Solution shall have out of the box management capability for network devices and systems (Juniper, Cisco IOS, Cisco IOS- | PC | OrkunPAM.TacacsProxy — native C# TACACS+ (RFC 1492) built-in server; Cisco/Juniper/Aruba CLI AAA via TCP :49 (#111) |
| 13 | Solution shall support adapting to different brand/model devices and systems, which will be used in the future. |  |  |
| 14 | Solution shall have out of the box support for script usage on NAS devices. |  |  |
| 15 | Solution shall support users to change their passwords and force to create the passwords in a complex way as well as cha |  |  |
| 16 | Solution shall support to be scaled to serve a carrier grade number of devices and users besides redundancy which lets 9 |  |  |
| 17 | Solution shall support to active-active redundancy. |  |  |
| 18 | Solution shall support disaster recovery. | PC | BackupService.cs — AES-256-GCM encrypted backup/restore, Hangfire scheduler, Blazor UI (#55) |
| 19 | Solution shall support different software versions of a network device simultaneously. |  |  |
| 20 | Solution software shall support working on indu |  |  |
| 21 | Solution shall support IPv6. |  |  |
| 22 | Solution shall be able to support a minimum of 100,000 devices and/or 100,000 accounts. |  |  |
| 23 | Solution shall have REST-API support. | PC | OrkunPAM.WebAPI — ASP.NET Minimal API with OpenAPI/Swagger; full REST CRUD for all resources |
| 24 | Solution shall support programmatic access through REST API. | PC | REST API with JWT bearer auth; all major endpoints documented |
| 25 | Solution shall support 2FA/MFA for portal access | PC | TOTP MFA — QrCodeEndpoints.cs, /api/v1/auth/verify-mfa; TOTP-based 2FA enforced at login (#39) |
| 26 | Solution shall support hierarchical grouping structure for administrators. | PC | RoleEndpoints.cs + UserEndpoints.cs |
| 27 | Solution shall support business and operational model of managed service providers |  |  |
| 28 | Solution shall support business and operational model of geographically distributed organizations |  |  |
| 29 | Solution shall support end-to-end encryption. | PC | TLS 1.3 (all comms) + AES-256-GCM (vault) + column-level encryption (#3, #4) |
| 30 | Solution shall support FIPS 140-2 encryption standard |  |  |
| 31 | Solution shall support hardware security module (HSM) for key storage |  |  |
| 32 | Solution shall support AES encryption for password management. | PC | VaultEncryptionService.cs — AES-256-GCM, 3-tier key hierarchy (KEK/DEK/MEK) |
| 33 | Solution shall support audit log management. | FC | AuditService.cs — immutable hash-chained audit log, all operations recorded |
| 34 | Solution shall provide real-time alerts for critical events. | PC | InProcessEventBus.cs + SessionEventRelayService.cs — real-time event relay via SignalR |
| 35 | Solution shall provide audit log with reporting capabilities. | PC | Reports.razor — audit log export CSV/JSON, filter/search, date range |
| 36 | Solution shall support automated policy compliance checks. | PC | PolicyEndpoints.cs — policy compliance reporting; policy-compliance report (#120) |
| 37 | Solution shall support integration with SIEM systems. | PC | SyslogForwarderService.cs — RFC 5424 Syslog + ArcSight CEF; UDP/TCP/TLS; auto-forward audit events (#122) |
| 38 | Solution shall support integration with ticketing systems. |  |  |
| 39 | Solution shall provide dashboards for operational visibility. | PC | Dashboard.razor — live stats, session activity, credential status |
| 40 | Solution shall support role-based access control (RBAC). | FC | PamRole enum — GlobalAdmin, VaultAdmin, SessionAdmin, Auditor, PasswordViewer; enforced on all endpoints |
| 41 | Solution shall support separation of duties. | PC | PasswordViewer SoD — GlobalAdmin/VaultAdmin cannot checkout without separate PasswordViewer role (#140) |
| 42 | Solution shall support privileged account lifecycle management. | PC | AccountLifecycleJob.cs — temp account expiry, inactivity lockout, pwd-age lockout, warning emails (#135, #137) |
| 43 | Solution shall support workflow-based approvals. | PC | Approvals.razor — multi-step approval workflow, expiry, RBAC (#79) |
| 44 | Solution shall provide reports and dashboards for compliance monitoring. | PC | Reports.razor + Dashboard.razor — session activity and operational stats monitoring (#27) |

## User Management (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | Solution shall support local user accounts | FC | UserEndpoints.cs — CRUD, PBKDF2-SHA512 hashed passwords, roles |
| 2 | Solution shall support Active Directory integration | PC | LdapPamSyncService.cs — scheduled AD sync + AD group → PAM group membership sync; uSNChanged delta sync; multi-domain Global Catalog (port 3268) support; bulk user/group reconciliation (#141) |
| 3 | Solution shall support LDAP integration | PC | AdSyncService.cs — LDAP (port 389/636) bind + search |
| 4 | Solution shall support role-based access control | FC | PamRole enum + RoleEndpoints.cs — 7 roles, endpoint-level enforcement |
| 5 | Solution shall support group-based access control | PC | GroupEndpoints.cs — group CRUD, group→credential/device binding |
| 6 | Solution shall support user provisioning and de-provisioning | PC | UserEndpoints.cs — create/update/disable/delete; AD sync auto-provision |
| 7 | Solution shall support self-service password reset | PC | ForgotPassword.razor — email token, 30-min TTL, PBKDF2 re-hash (#135) |
| 8 | Solution shall support password policies | PC | PolicyEndpoints.cs — complexity, min length, history depth, expiry |
| 9 | Solution shall support MFA enrollment | PC | QrCodeEndpoints.cs — TOTP QR enroll; /api/v1/auth/verify-mfa |
| 10 | Solution shall support MFA bypass for emergency | PC | MFA recovery codes — 10 one-time backup codes, SHA-256 hashed (#135) |
| 11 | Solution shall support account lockout policies | PC | PolicyEndpoints.cs — max failed attempts, lockout duration |
| 12 | Solution shall support temporary accounts | PC | AccountLifecycleJob.cs + UserEndpoints.cs — TemporaryExpiresUtc, auto-expiry, UI badge (#137) |
| 13 | Solution shall support account expiry | PC | AccountLifecycleJob.cs — auto-lock on expiry, 7-day warning email |
| 14 | Solution shall support inactivity-based lockout | PC | AccountLifecycleJob.cs — maxInactivityDays config, daily check, auto-lock |
| 15 | Solution shall support password age lockout | PC | AccountLifecycleJob.cs — maxPasswordAgeDays config, daily check, auto-lock |
| 16 | Solution shall support user session management | PC | Sessions.razor (SelfService tab) — user views/terminates own sessions |
| 17 | Solution shall support audit logging for user actions | FC | AuditService.cs — all user CRUD + auth events logged |
| 18 | Solution shall support user import/export | PC | AdSyncService.cs — LDAP import; CSV export via Reports.razor |
| 19 | Solution shall support self-service password reset | PC | ForgotPassword.razor — email token flow, secure reset (#135) |
| 20 | Solution shall support delegated administration |  |  |
| 21 | Solution shall support user activity monitoring | PC | Sessions.razor Live Monitor — active session tracking per user |
| 22 | Solution shall support privileged user management | PC | UserEndpoints.cs + RoleEndpoints.cs — privileged role assignment/revocation |
| 23 | Solution shall support emergency access accounts | PC | BreakGlassEndpoints.cs — emergency access, full audit, time-limited |
| 24 | Solution shall support account reconciliation |  |  |
| 25 | Solution shall support orphaned account detection |  |  |
| 26 | Solution shall support access certification |  |  |
| 27 | Solution shall support user risk scoring |  |  |
| 28 | Solution shall support behavioral analytics for users |  |  |
| 29 | Solution shall support geolocation-based access control |  |  |
| 30 | Solution shall support time-based access restrictions | PC | AccessPolicyService.cs — AllowedTimeWindows (Mon-Fri 09:00-18:00 etc.) |
| 31 | Solution shall support IP-based access restrictions | PC | AccessPolicyService.cs — CIDR-based IP allow/deny |
| 32 | Solution shall support device-based access restrictions |  |  |
| 33 | Solution shall support context-aware access control |  |  |
| 34 | Solution shall support just-in-time access | PC | JitAccessEndpoints.cs — time-limited JIT credential checkout |
| 35 | Solution shall support access request workflows | PC | Approvals.razor — request + multi-step approval (#79) |
| 36 | Solution shall support access review campaigns |  |  |
| 37 | Solution shall support privileged access analytics |  |  |
| 38 | Solution shall support user behavior baseline |  |  |
| 39 | Solution shall support insider threat detection |  |  |
| 40 | Solution shall support external threat indicators |  |  |
| 41 | Solution shall support risk-based authentication |  |  |
| 42 | Solution shall support adaptive authentication |  |  |
| 43 | Solution shall support passwordless authentication |  |  |
| 44 | Solution shall support biometric authentication |  |  |
| 45 | Solution shall support hardware token support |  |  |
| 46 | Solution shall support smart card authentication |  |  |
| 47 | Solution shall support certificate-based authentication |  |  |
| 48 | Solution shall support federated identity |  |  |

## Reporting (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | Solution shall provide pre-built compliance reports | PC | Reports.razor — 9 pre-built reports: credential-expiry, group-membership, policy-compliance, checkout-history, break-glass, jit-access, privileged-inventory, vendor-access, compliance-summary (#120) |
| 2 | Solution shall support custom report creation |  |  |
| 3 | Solution shall support scheduled report delivery |  |  |
| 4 | Solution shall support blocked command reporting | PC | Reports.razor — blocked commands per user/device, filter by risk score; SshServerSession.cs command log (#136) |
| 5 | Solution shall support export in multiple formats | PC | Reports.razor — CSV + JSON export |
| 6 | Solution shall provide executive dashboards |  |  |
| 7 | Solution shall provide operational dashboards | PC | Dashboard.razor — live stats, session/credential/approval metrics |
| 8 | Solution shall support report scheduling |  |  |
| 9 | Solution shall support report distribution |  |  |
| 10 | Solution shall support data retention policies | PC | RecordingRetentionService.cs — configurable retention, auto-purge old recordings |
| 11 | Solution shall support audit log export | PC | AuditService.cs — CSV/JSON export from Reports.razor |
| 12 | Solution shall support compliance frameworks (SOX, PCI, HIPAA) |  |  |
| 13 | Solution shall support regulatory reporting |  |  |
| 14 | Solution shall support risk reporting |  |  |
| 15 | Solution shall support checkout/export history report | PC | Reports.razor — checkout-history report |
| 16 | Solution shall support group membership report | PC | Reports.razor — group-membership report |
| 17 | Solution shall support policy compliance report | PC | Reports.razor — policy-compliance report |
| 18 | Solution shall support break-glass access report | PC | Reports.razor — break-glass report |
| 19 | Solution shall support JIT access report | PC | Reports.razor — jit-access report |
| 20 | Solution shall support privileged inventory report | PC | Reports.razor — privileged-inventory report |
| 21 | Solution shall support vendor access report | PC | Reports.razor — vendor-access report |
| 22 | Solution shall support compliance summary report | PC | Reports.razor — compliance-summary report |
| 23 | Solution shall support credential expiry report | PC | Reports.razor — credential-expiry report |
| 24 | Solution shall support session activity report | PC | Sessions.razor + Reports.razor — session audit trail |
| 25 | Solution shall support failed login report |  |  |
| 26 | Solution shall support to view the session logs with filtering and sorting options | PC | Sessions.razor — filter by user, device, protocol, date |
| 27 | Solution shall have reports in both table and chart format | PC | Reports.razor — table + Chart.js bar/pie charts |
| 28 | Solution shall have reports in full text search | PC | Reports.razor — full-text search filter |
| 29 | Solution shall support session recording playback report | PC | SessionPlayback.razor — search + replay with timestamp seek (#34) |
| 30 | Solution shall support anomaly detection reports |  |  |
| 31 | Solution shall support SIEM integration reports | PC | SyslogForwarderService.cs — all events forwarded to SIEM in Syslog/CEF |
| 32 | Solution shall support threat intelligence reports |  |  |
| 33 | Solution shall support access pattern analytics |  |  |
| 34 | Solution shall support privilege escalation tracking | PC | AuditService.cs — role assignment/escalation events logged |
| 35 | Solution shall support account lifecycle reports |  |  |
| 36 | Solution shall support password rotation reports | PC | Reports.razor — credential rotation history |
| 37 | Solution shall support MFA usage reports |  |  |
| 38 | Solution shall support API usage reports |  |  |
| 39 | Solution shall support capacity planning reports |  |  |
| 40 | Solution shall support performance reports |  |  |
| 41 | Solution shall support SLA reports |  |  |
| 42 | Solution shall support user activity reports | PC | Reports.razor — per-user activity, session count, credential access |
| 43 | Solution shall support device access reports | PC | Reports.razor — per-device session history |
| 44 | Solution shall support credential usage reports | PC | Reports.razor — checkout-history per credential |
| 45 | Solution shall support geographic access reports |  |  |
| 46 | Solution shall support time-of-day access reports |  |  |
| 47 | Solution shall support multi-tenant reports |  |  |
| 48 | Solution shall support white-label reports |  |  |

## MFA Manager (24 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | Solution shall support TOTP (Time-based One-Time Password) | FC | QrCodeEndpoints.cs — TOTP enroll/verify; RFC 6238 compliant |
| 2 | Solution shall support FIDO2/WebAuthn |  |  |
| 3 | Solution shall support MFA recovery codes | PC | 10 one-time backup codes, SHA-256 hashed, one-time use (#135) |
| 4 | Solution shall support SMS-based OTP |  |  |
| 5 | Solution shall support email-based OTP |  |  |
| 6 | Solution shall support push notifications |  |  |
| 7 | Solution shall support hardware tokens (OATH) |  |  |
| 8 | Solution shall support adaptive MFA |  |  |
| 9 | Solution shall support MFA bypass policies | PC | windows.auth.mfa_bypass config — Kerberos-authenticated users skip TOTP; configurable per-domain; Integrations.razor Windows Auth tab MFA bypass toggle (#126) |
| 10 | Solution shall support MFA enrollment self-service | PC | QrCodeEndpoints.cs — TOTP self-enrollment via QR code |
| 11 | Solution shall support MFA audit logging | FC | AuditService.cs — MFA verify/fail events logged |
| 12 | Solution shall support MFA device management |  |  |
| 13 | Solution shall support MFA for privileged operations | PC | MFA enforced at login; required for vault checkout and session start |
| 14 | Solution shall support MFA for admin access | PC | MFA policy applied to all admin roles |
| 15 | Solution shall support MFA reporting |  |  |
| 16 | Solution shall support MFA exception management |  |  |
| 17 | Solution shall support MFA for API access |  |  |
| 18 | Solution shall support MFA for service accounts |  |  |
| 19 | Solution shall support MFA throttling | PC | AuthEndpoints.cs — rate limiting on /auth/login + /auth/verify-mfa |
| 20 | Solution shall support MFA session persistence |  |  |
| 21 | Solution shall support MFA for remote access | PC | MFA required alongside username/password for all remote sessions (#151) |
| 22 | Solution shall support MFA for privileged workstations |  |  |
| 23 | Solution shall support MFA token synchronization |  |  |
| 24 | Solution shall support group/role based MFA policy | PC | Policies.razor MFA tab — group/role based MFA requirement enforcement |

## Remote Access (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | Solution shall support SSH remote access | FC | SshProxyService.cs — native C# SSH (RFC 4253) proxy on port 2222 |
| 2 | Solution shall support RDP remote access | PC | RdpProxyService.cs — TCP 3389 relay, TPKT/X.224, credential injection |
| 3 | Solution shall support VNC remote access | PC | VncProxyService.cs — RFB protocol relay (#23) |
| 4 | Solution shall support HTTP/HTTPS remote access | PC | HttpProxyService.cs — HTTP reverse proxy, TLS terminate, credential inject |
| 5 | Solution shall support Telnet access |  |  |
| 6 | Solution shall support jump server functionality | PC | SshProxyService.cs — PAM SSH proxy acts as jump server |
| 7 | Solution shall support session brokering | PC | SessionEndpoints.cs — session broker: credential inject, token, session start/end |
| 8 | Solution shall support network segmentation |  |  |
| 9 | Solution shall support access isolation | PC | SshProxyService.cs — isolated session per user, no lateral movement |
| 10 | Solution shall support session recording | FC | SessionRecordingService.cs — full session recording (text + binary) |
| 11 | Solution shall support session playback | PC | SessionPlayback.razor — asciinema replay, search, timestamp seek (#34) |
| 12 | Solution shall support session termination | PC | SessionEndpoints.cs — DELETE /sessions/{id} + admin terminate via SignalR |
| 13 | Solution shall support session timeout | PC | SessionPolicyService.cs — session duration/idle timeout |
| 14 | Solution shall support connection throttling | PC | SshProxyService.cs — concurrent session limit per policy |
| 15 | Solution shall support bandwidth management |  |  |
| 16 | Solution shall support QoS for sessions |  |  |
| 17 | Solution shall support session multiplexing |  |  |
| 18 | Solution shall support load balancing | PC | RdsLoadBalancer.cs — TCP health-check + least-connections routing across RDS HA cluster nodes; background service with health loop (#110) |
| 19 | Solution shall support failover | PC | RdsLoadBalancer.cs — auto-failover to healthy RDS nodes; unhealthy nodes removed from pool until TCP health check recovers (#110) |
| 20 | Solution shall support geo-redundancy |  |  |
| 21 | Solution shall support session watermarking |  |  |
| 22 | Solution shall support clipboard control | PC | RdpProxyService.cs — clipboard channel audit/control in RDP PDU |
| 23 | Solution shall support file transfer control | PC | SshProxyService.cs — SFTP audit/control |
| 24 | Solution shall support printer redirection control | PC | RdpProxyService.cs — printer/drive redirection audit |
| 25 | Solution shall support drive mapping control | PC | RdpProxyService.cs — drive mapping control in RDP session |
| 26 | Solution shall support USB control |  |  |
| 27 | Solution shall support application control |  |  |
| 28 | Solution shall support screen capture |  |  |
| 29 | Solution shall support keystroke logging | FC | SshServerSession.cs — every keystroke/command logged with timestamp |
| 30 | Solution shall support screen recording |  |  |
| 31 | Solution shall support session analytics |  |  |
| 32 | Solution shall support session risk scoring | PC | CommandFilterService.cs — per-command risk score; Sessions.razor risk color coding |
| 33 | Solution shall support session policy enforcement | PC | SessionPolicyService.cs — duration, idle, concurrent, MFA enforcement |
| 34 | Solution shall support session compliance |  |  |
| 35 | Solution shall support session governance |  |  |
| 36 | Solution shall support session audit trail | FC | AuditService.cs — all session events in hash-chained audit log |
| 37 | Solution shall support session reporting | PC | Reports.razor — session activity, filter, export |
| 38 | Solution shall support session alerts | PC | InProcessEventBus.cs + SessionEventRelayService.cs — CommandBlocked → SignalR alert |
| 39 | Solution shall support session notifications | PC | SessionMonitorHub.cs — admin notifications for session events |
| 40 | Solution shall support session collaboration |  |  |
| 41 | Solution shall support session handoff |  |  |
| 42 | Solution shall support session delegation |  |  |
| 43 | Solution shall support session federation |  |  |
| 44 | Solution shall support session search | PC | SessionPlaybackEndpoints.cs — full-text session search |
| 45 | Solution shall support session export |  |  |
| 46 | Solution shall support session archival | PC | RecordingRetentionService.cs — configurable retention, auto-archive |
| 47 | Solution shall support session restoration |  |  |
| 48 | Solution shall support session tagging |  |  |
| 153 | Solution shall support recording of SSH/CLI/RDP/VNC sessions | PC | SessionRecordingService.cs — SSH/RDP/VNC/HTTP recording + playback (#34) |
| 158 | Solution shall support time-based access restrictions | PC | AccessPolicyService.cs — AllowedTimeWindows: Mon-Fri 09:00-18:00 configurable |

## Password Vault (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | Solution shall support credential storage | FC | CredentialEndpoints.cs + VaultEncryptionService.cs — AES-256-GCM encrypted credential store |
| 2 | Solution shall support credential retrieval | FC | CredentialEndpoints.cs — RBAC-enforced checkout flow |
| 3 | Solution shall support credential rotation | PC | CredentialEndpoints.cs — manual rotation; auto-rotation Hangfire job |
| 4 | Solution shall support credential expiry | PC | CredentialEndpoints.cs — expiry date, Reports.razor credential-expiry report |
| 5 | Solution shall support credential discovery |  |  |
| 6 | Solution shall support credential onboarding | PC | Vault.razor — Add Credential form; manual onboarding |
| 7 | Solution shall support credential lifecycle management | PC | CredentialEndpoints.cs — create/update/rotate/archive/delete |
| 8 | Solution shall support credential access control | PC | GroupEndpoints.cs + CredentialEndpoints.cs — group-based access binding |
| 9 | Solution shall support credential audit trail | FC | AuditService.cs — all credential access, checkout, rotation events logged |
| 10 | Solution shall support credential sharing | PC | GroupEndpoints.cs — group-level credential sharing |
| 11 | Solution shall support credential delegation |  |  |
| 12 | Solution shall support credential federation |  |  |
| 13 | Solution shall support credential synchronization | PC | CredentialEndpoints.cs — sync endpoint for credential state |
| 14 | Solution shall support credential injection | FC | SshServerSession.cs + RdpProxyService.cs — credential injection at session start |
| 15 | Solution shall support credential masking | FC | VaultEncryptionService.cs — credentials never in plaintext; zero-memory after use |
| 16 | Solution shall support credential versioning | PC | CredentialEndpoints.cs — rotation history maintained |
| 17 | Solution shall support credential backup | PC | BackupService.cs — encrypted backup includes credentials |
| 18 | Solution shall support credential recovery | PC | BackupService.cs — restore from encrypted backup |
| 19 | Solution shall support credential import | PC | CredentialEndpoints.cs — bulk import via CSV |
| 20 | Solution shall support credential export |  |  |
| 21 | Solution shall support credential templates |  |  |
| 22 | Solution shall support credential profiles | PC | CredentialEndpoints.cs — credential type profiles (Linux, Windows, DB, API) |
| 23 | Solution shall support credential policies | PC | PolicyEndpoints.cs — credential rotation policy, complexity |
| 24 | Solution shall support credential compliance | PC | PolicyEndpoints.cs — policy-compliance report for credentials |
| 25 | Solution shall support credential risk scoring |  |  |
| 26 | Solution shall support credential dual control | PC | PasswordViewer SoD — admin cannot checkout without separate PasswordViewer role; dual-control enforcement (#140) |
| 27 | Solution shall support credential checkout | PC | CredentialEndpoints.cs — self-assignment prevention: PasswordViewer cannot be granted by same user (#140) |
| 28 | Solution shall support credential check-in | PC | CredentialEndpoints.cs — check-in after session/manual checkout |
| 29 | Solution shall support credential time-limited access | PC | JitAccessEndpoints.cs — time-limited JIT credential access |
| 30 | Solution shall support credential just-in-time access | PC | JitAccessEndpoints.cs — JIT access with approval workflow |
| 31 | Solution shall support credential analytics |  |  |
| 32 | Solution shall support credential reporting | PC | Reports.razor — checkout-history, rotation history reports |
| 33 | Solution shall support credential alerts |  |  |
| 34 | Solution shall support credential notifications | PC | SmtpEmailService.cs — expiry warning emails |
| 35 | Solution shall support credential governance |  |  |
| 36 | Solution shall support credential integration | PC | CredentialEndpoints.cs — REST API for external credential integration |
| 37 | Solution shall support credential automation |  |  |
| 38 | Solution shall support credential orchestration |  |  |
| 39 | Solution shall support SSH key management | PC | SshKeyEndpoints.cs — RSA/OpenSSH key pair generation, encrypted storage, device binding |
| 40 | Solution shall support API key management | PC | CredentialEndpoints.cs — API key type credential |
| 41 | Solution shall support certificate management |  |  |
| 42 | Solution shall support service account management | PC | CredentialEndpoints.cs — service account type credentials |
| 43 | Solution shall support cloud credential management |  |  |
| 44 | Solution shall support database credential management | PC | CredentialEndpoints.cs — DB credential type (SQL Server, MySQL, PostgreSQL) |
| 45 | Solution shall support application credential management | PC | CredentialEndpoints.cs — API/app credential type |
| 46 | Solution shall support network device credential management | PC | CredentialEndpoints.cs + TacacsProxyService.cs — network device credential type |
| 47 | Solution shall support privileged account discovery |  |  |
| 48 | Solution shall support privileged account onboarding | PC | Vault.razor — manual privileged account onboarding |

## Session Manager (162 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | General | Solution shall support MFA (Multi Factor Authentication) when a user attempts to open a CLI/RDP/HTTP/SFTP/SQL sessions t | PC | MFA policy enforcement (group/role bazlı) — Policies.razor MFA tab + AuthenticationService.cs; TOTP required before SSH/RDP session opens |
| 2 | General | Solution shall support SSL protocol for network management and terminal (console) servers. |  |
| 3 | General | Solution shall support using TELNET, STELNET, SSH, VNC, RDP, HTTP, HTTPS protocols to login to end devices. | PC | SshProxyService.cs — native SSH (RFC 4253); OrkunPAM.RdpProxy — TCP 3389 relay, TPKT/X.224, .rdp download (#23) |
| 4 | General | Solution shall be able to manage and interact with multiple remote sessions  for both Remote Desktop Protocol (RDP) ,SSH |  |
| 5 | General | Solution shall be able to launch and configure sessions across multiple  environments with credentials automatically inj | PC | SshServerSession.cs — vault credential injection to target |
| 6 | General | Solution shall support native CLI clients like SecureCRT, Putty, MobaXterm etc. |  |
| 7 | General | Solution shall support SSH and RDP connections to target servers from any device without any native client or agent inst | FC | WebRdpClient.cs (native C# RDP-over-WebSocket) + RdpTerminal.razor — browser RDP without MSTSC; SshProxyService.cs + WebSshClient (plink removed) — browser SSH; both SSH and RDP from any browser, zero native client required (#116, #151) |
| 8 | General | Solution shall support double confirmation of execution of the command that can cause a service interrupt or any request | PC | DangerousCommandFilter.cs — SSH double-confirmation for destructive commands (rm -rf, shutdown, reboot, DROP, format, mkfs); configurable command list (#136) |
| 9 | General | Solution shall support geofence validation through mobile application for the command executions. |  |
| 10 | General | Solution shall support duration based restriction policy for the sessions | PC | SessionPolicyService.cs — session duration/timeout enforcement at runtime (#84) |
| 11 | General | Solution shall have a connection reservation functionalty for future date connections | PC | Approvals.razor Scheduled tab — future date/time reservation form (device, credential, protocol, start/end, reason), conflict detection, auto-activate/complete; ScheduledSession entity + SessionSchedulerService.cs (#142) |
| 12 | General | Solution shall support to open SSH/RDP/HTTP sessions via desktop application on user workstation (without logging into P |  |
| 13 | General | Solution shall support to log users' client IP addresses even if users access the Web GUI through the loadbalancer. |  |
| 14 | General | Solution shall support to use its own secure tunnel (connector) to connect to target devices located in remote data cent |  |
| 15 | General | Solution shall support users to create a connection reservation request for a future date and get administrator approval | PC | Approvals.razor — approval workflow, expiry countdown, multi-step approval (#79) |
| 16 | General | Solution shall support expiration of connection reservation requests that are not approved/devied for a certain period o | PC | SessionSchedulerService.cs — configurable expiry threshold; unprocessed Pending reservations auto-expire, status → Expired, requester email notification sent (#142) |
| 17 | General | Solution shall support administrators to change the selected date/time during connection request approval. | PC | Approvals.razor approve modal — admin adjusts start/end time window + adds approval notes before confirming; audit log records original vs adjusted times (#142) |
| 18 | General | Solution shall allow connections to target Linux/Unix and Windows systems by entering IP addresses, restr |  |
| 19 | General | Solution shall allow connections to target Linux/Unix and Windows systems by entering IP addresses, restr |  |
| 20 | General | Solution shall support a connection retry mechanism to ensure reliable sessions when initial connection attempts fail. |  |
| 21 | General | Solution shall support the ability to send and receive files between a privileged account and target systems using SFTP | PC | SshProxyService.cs — SFTP subsystem relay |
| 22 | General | Solution shall support to audit the files transferred through SFTP. | PC | AuditService.cs — SFTP transfer event logging |
| 23 | SSH | Solution shall provide SSH protocol connection to managed systems. | FC | SshProxyService.cs — native C# SSH (RFC 4253): kex, user-auth, channel, exec, shell, subsystem |
| 24 | SSH | Solution shall be able to manage multiple protocols simultaneously (telnet and SSH etc) |  |
| 25 | SSH | Solution shall support full interaction with CLI sessions in SSH protocol | FC | SshServerSession.cs — full interactive shell via SshProxyService |
| 26 | SSH | Solution shall support terminal emulation (VT100, ANSI, xterm) in SSH protocol | PC | SshProxyService.cs — VT100/ANSI/xterm terminal emulation over WebSocket |
| 27 | SSH | Solution shall support to send a command to multiple sessions simultaneously via SSH protocol | PC | CommandDispatchEndpoints.cs — multi-session parallel command dispatch |
| 28 | SSH | Solution shall support connection to systems using SSH certificates | PC | SshKeyEndpoints.cs — certificate-based auth, RSA/OpenSSH key storage |
| 29 | SSH | Solution shall support SSH host key verification | PC | SshProxyService.cs + DeviceEndpoints.cs — TOFU host key fingerprint; first-connect stores fingerprint; subsequent connections verify → MITM detection; StoreSshFingerprintAsync (#145) |
| 30 | SSH | Solution shall support for creating and storing SSH public/private key pairs for SSH protocol | PC | SshKeyEndpoints.cs — RSA/OpenSSH key pair generation + encrypted storage |
| 31 | SSH | Solution shall support SSH agent forwarding |  |
| 32 | SSH | Solution shall support SSH tunneling | PC | SshProxyService.cs — SSH port forwarding / tunneling support |
| 33 | SSH | Solution shall support SFTP | PC | SshProxyService.cs — SFTP subsystem relay (SSH channel type: subsystem sftp) |
| 34 | SSH | Solution shall support SCP |  |
| 35 | SSH | Solution shall provide mechanism for an administrator to view active SSH sessions and their details. | PC | Sessions.razor — active session list with SSH filter |
| 36 | SSH | Solution shall provide mechanism to monitor (listen, join) active SSH sessions in real-time. | PC | SessionMonitorHub.cs — SignalR hub /hubs/session-monitor; live 5s polling; admin/auditor groups; realtime session events (#125) |
| 37 | SSH | Solution shall provide mechanism for an administrator to take over (assuming control from the user) and leave an active | PC | Sessions.razor + SessionEndpoints.cs — admin terminate session with reason; POST /{id}/message to broadcast admin message to active session (#125) |
| 38 | SSH | Solution shall provide mechanism to terminate active sessions: one by one or all at once | PC | SessionEndpoints.cs — DELETE /sessions/{id} + DELETE /sessions (bulk) |
| 39 | SSH | Solution shall support sending messages to active SSH sessions. | PC | SessionEndpoints.cs POST /{id}/message — admin message logged + broadcast to monitor group via SignalR; Sessions.razor Send Message modal (#125) |
| 40 | SSH | Solution shall support session duration limit for SSH sessions | PC | SessionPolicyService.cs — max session duration per group |
| 41 | SSH | Solution shall support automatic logout from SSH sessions due to keyboard inactivity | PC | SessionPolicyService.cs — idle timeout |
| 42 | SSH | Solution shall support SSH sessions to be stored in logs as video/text records | PC | SessionRecordingService.cs — text log + binary recording |
| 43 | SSH | Solution shall support searching in recorded sessions by keyword | PC | SessionPlaybackEndpoints.cs — full-text search in recorded sessions (#34) |
| 44 | SSH | Solution shall support playback of recorded SSH sessions | PC | SessionPlaybackEndpoints.cs + Playback.razor — replay with timestamp seek (#34) |
| 45 | SSH | Solution shall support SSH session recording in text format | PC | SessionRecordingService.cs — text log (asciinema compatible) |
| 46 | SSH | Solution shall support SSH session recording in video format | PC | SessionRecordingService.cs — binary recording (asciinema v2 format) |
| 47 | SSH | Solution shall support command logging for all SSH sessions | FC | SshServerSession.cs — every command logged with timestamp, risk score |
| 48 | SSH | Solution shall support command filtering for SSH sessions | PC | CommandFilterService.cs — whitelist/blacklist, regex/glob, risk scoring, block/allow |
| 49 | SSH | Solution shall support command blocking for SSH sessions | PC | SshServerSession.cs — blocked commands rejected with feedback message |
| 50 | SSH | Solution shall support command alerting for SSH sessions | PC | InProcessEventBus.cs — CommandBlocked event published + relayed to monitor group |
| 51 | SSH | Solution shall support SSH jump hosts |  |
| 52 | SSH | Solution shall support SSH bastions | PC | SshProxyService.cs acts as bastion host |
| 53 | SSH | Solution shall support SSH gateways | PC | SshProxyService.cs — SSH gateway on port 2222 |
| 54 | SSH | Solution shall support SSH proxies | FC | SshProxyService.cs — full SSH proxy (RFC 4253 native) |
| 55 | SSH | Solution shall support SSH multiplexing |  |
| 56 | SSH | Solution shall support SSH compression |  |
| 57 | SSH | Solution shall support SSH keepalives | PC | SshProxyService.cs — keepalive channel requests |
| 58 | SSH | Solution shall support SSH X11 forwarding |  |
| 59 | SSH | Solution shall support SSH port forwarding | PC | SshProxyService.cs — port forwarding / direct-tcpip |
| 60 | SSH | Solution shall support SSH SOCKS proxy |  |
| 61 | SSH | Solution shall support SSH session recording in asciinema format | PC | SessionRecordingService.cs — asciinema v2 format; play/pause/seek replay (#34) |
| 62 | SSH | Solution shall support SSH session analytics |  |
| 63 | SSH | Solution shall support SSH session search | PC | RecordingPlaybackService.cs — full-text search across all recorded sessions (#34) |
| 64 | SSH | Solution shall support SSH session export |  |
| 65 | SSH | Solution shall support SSH session sharing |  |
| 66 | SSH | Solution shall support SSH session collaboration |  |
| 67 | SSH | Solution shall support SSH session handoff |  |
| 68 | SSH | Solution shall support SSH session resume |  |
| 69 | SSH | Solution shall support SSH session migration |  |
| 70 | SSH | Solution shall support SSH session persistence |  |
| 71 | RDP | Solution shall support RDP remote access | PC | RdpProxyService.cs — TCP 3389 relay, TPKT/X.224, CLIENT_INFO_PDU credential injection |
| 72 | RDP | Solution shall support NLA (Network Level Authentication) | PC | RdpProxyService.cs — NLA credential injection via CLIENT_INFO_PDU |
| 73 | RDP | Solution shall support RDP over HTTPS |  |
| 74 | RDP | Solution shall support RDP compression |  |
| 75 | RDP | Solution shall support RDP encryption | PC | RdpProxyService.cs — TLS termination both sides via SslStream |
| 76 | RDP | Solution shall support RDP session recording | PC | SessionRecordingService.cs — RDP session binary recording |
| 77 | RDP | Solution shall support Full RDP sessions with credential injection | PC | RdpProxyService.cs — NLA credential injection; full RDP session |
| 78 | RDP | Solution shall support RDP clipboard audit | PC | RdpProxyService.cs — clipboard channel monitoring + audit |
| 79 | RDP | Solution shall support RDP drive redirection control | PC | RdpProxyService.cs — drive mapping channel audit/control |
| 80 | RDP | Solution shall support RDP printer control | PC | RdpProxyService.cs — printer redirection audit |
| 81 | RDP | Solution shall support RDP session shadowing | PC | RdpProxyService.cs — shadow channel via WMI Win32_TSSession |
| 82 | RDP | Solution shall support RDP RemoteApp | PC | RdpGatewayEndpoints.cs — GET /remoteapps, POST /remoteapp/connect; RdpManagement.razor RemoteApps list + launch; RdpProxyOptions.EnableRemoteApp (#110) |
| 83 | RDP | Solution shall support administrator take-over of RDP sessions | PC | RdpGatewayEndpoints.cs POST /sessions/{id}/shadow + ShadowSessionAsync; Sessions.razor shadow button; RdpManagement.razor Active Sessions panel; RdpProxyOptions.EnableSessionShadowing (#110) |
| 84 | RDP | Solution shall support RDP session analytics |  |
| 85 | RDP | Solution shall support RDP session collaboration |  |
| 86 | RDP | Solution shall support RDP multi-monitor |  |
| 87 | RDP | Solution shall support RDP audio |  |
| 88 | RDP | Solution shall support RDP USB redirection |  |
| 89 | RDP | Solution shall support RDP smart card |  |
| 90 | RDP | Solution shall support RDP biometric |  |
| 91 | RDP | Solution shall support RDP performance optimization |  |
| 92 | RDP | Solution shall support RDP bandwidth management |  |
| 93 | HTTP | Solution shall support HTTP reverse proxy | PC | HttpProxyService.cs — HTTP reverse proxy, TLS terminate, basic/form/header/cookie credential inject |
| 94 | HTTP | Solution shall support HTTPS proxy | PC | HttpProxyService.cs — TLS termination + upstream TLS (#123) |
| 95 | HTTP | Solution shall support HTTP session recording | PC | HttpProxySession.cs — request/response recording |
| 96 | HTTP | Solution shall support HTTP credential injection | PC | HttpProxySession.cs — basic/form/header/cookie auth injection |
| 97 | HTTP | Solution shall support HTTP URL filtering |  |
| 98 | HTTP | Solution shall support HTTP content inspection |  |
| 99 | HTTP | Solution shall support HTTP DLP |  |
| 100 | HTTP | Solution shall support HTTP WAF integration |  |
| 101 | VNC | Solution shall support VNC remote access | PC | VncProxyService.cs — RFB protocol relay |
| 102 | VNC | Solution shall support VNC recording | PC | SessionRecordingService.cs — VNC session recording |
| 103 | VNC | Solution shall support VNC encryption | PC | VncProxyService.cs — TLS over VNC |
| 104 | VNC | Solution shall support VNC authentication | PC | VncProxyService.cs — credential injection |
| 105 | SQL | Solution shall support SQL database access |  |
| 106 | SQL | Solution shall support SQL session recording |  |
| 107 | SQL | Solution shall support SQL query filtering |  |
| 108 | SQL | Solution shall support SQL credential injection |  |
| 109 | General | Solution shall support session policy enforcement | PC | SessionPolicyService.cs — duration, idle, concurrent, MFA |
| 110 | General | Solution shall support session risk scoring | PC | CommandFilterService.cs — risk score per command; Sessions.razor risk color coding |
| 111 | General | Solution shall support emergency session termination | PC | Sessions.razor — Terminate All emergency button; admin terminate all active sessions (#125) |
| 112 | General | Solution shall support session approval workflows | PC | Approvals.razor — session approval before connection |
| 113 | General | Solution shall support concurrent session limits | PC | SessionPolicyService.cs — MaxConcurrentSessions per policy |
| 114 | General | Solution shall support idle session detection | PC | SessionPolicyService.cs — idle timeout detection |
| 115 | General | Solution shall support session audit trail | FC | AuditService.cs — full session lifecycle events logged |
| 116 | General | Solution shall support session compliance reporting | PC | Reports.razor — session activity compliance report |
| 117 | General | Solution shall support session tagging |  |
| 118 | General | Solution shall support session categorization |  |
| 119 | General | Solution shall support session search | PC | SessionPlaybackEndpoints.cs — full-text session search |
| 120 | General | Solution shall support session export |  |
| 121 | General | Solution shall support session archival | PC | RecordingRetentionService.cs — auto-archive + configurable retention |
| 122 | General | Solution shall support session restoration |  |
| 123 | General | Solution shall support session cloning |  |
| 124 | General | Solution shall support session migration |  |
| 125 | General | Solution shall support session delegation |  |
| 126 | General | Solution shall support session collaboration |  |
| 127 | General | Solution shall support session handoff |  |
| 128 | General | Solution shall support session federation |  |
| 129 | General | Solution shall support session analytics | PC | Sessions.razor Live Monitor — risk score, event timeline, real-time session analytics (#125) |
| 130 | General | Solution shall support session anomaly detection |  |
| 131 | General | Solution shall support session threat response |  |
| 132 | General | Solution shall support session compliance |  |
| 133 | General | Solution shall support session governance |  |
| 134 | General | Solution shall support session risk management |  |
| 135 | General | Solution shall support session performance monitoring | PC | Sessions.razor Live Monitor — active session count, duration, risk metrics |
| 136 | General | Solution shall support session capacity planning |  |
| 137 | General | Solution shall support session SLA monitoring |  |
| 138 | General | Solution shall support session quality of service |  |
| 139 | General | Solution shall support session optimization |  |
| 140 | General | Solution shall support session acceleration |  |
| 141 | General | Solution shall support session compression |  |
| 142 | General | Solution shall support session deduplication |  |
| 143 | General | Solution shall support session caching |  |
| 144 | General | Solution shall support session load balancing | PC | RdsLoadBalancer.cs — least-connections session routing across RDS HA nodes; RdpManagement.razor HA cluster status view (#110) |
| 145 | General | Solution shall support session failover | PC | RdsLoadBalancer.cs — TCP health-check loop; auto-remove unhealthy nodes; RDS HA failover for active RDP sessions (#110) |
| 146 | General | Solution shall support session geo-redundancy |  |
| 147 | General | Solution shall support session disaster recovery |  |
| 148 | General | Solution shall support session backup |  |
| 149 | General | Solution shall support session recovery |  |
| 150 | General | Solution shall support session synchronization |  |
| 151 | General | Solution shall support session replication |  |
| 152 | General | Solution shall support session versioning |  |
| 153 | General | Solution shall support session rollback |  |
| 154 | General | Solution shall support to ensure that an administrator is able to intervene in an active session and send a message to t | PC | Sessions.razor Live Monitor — active session monitoring, admin intervention via terminate+message; SessionMonitorHub.cs SignalR (#125) |
| 155 | General | Solution shall support to allow detailed viewing of active sessions for an administrator. | PC | Sessions.razor — session detail panel with risk score, duration, protocol, device, user |
| 156 | General | Solution shall support session notifications |  |
| 157 | General | Solution shall support session alerts | PC | InProcessEventBus.cs — CommandBlocked event → SessionEventRelayService → SignalR broadcast |
| 158 | General | Solution shall support session reporting | PC | Reports.razor — session activity report, export, filter |
| 159 | General | Solution shall support session integration |  |
| 160 | General | Solution shall support session automation |  |
| 161 | General | Solution shall support session orchestration |  |
| 162 | General | Solution shall support session governance |  |

## Device Management (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | Solution shall support device discovery | PC | DeviceEndpoints.cs — manual device registration + ICMP reachability check |
| 2 | Solution shall support device onboarding | PC | Devices.razor — Add Device form with type, OS, credentials, groups |
| 3 | Solution shall support device categorization | PC | DeviceEndpoints.cs — device type (Server/Network/Database), OS, group |
| 4 | Solution shall support device inventory | PC | Devices.razor — full device list, filter, search |
| 5 | Solution shall support device lifecycle management | PC | DeviceEndpoints.cs — CRUD + soft-delete |
| 6 | Solution shall support device compliance | PC | PolicyEndpoints.cs — device-level policy compliance check |
| 7 | Solution shall support device risk scoring |  |  |
| 8 | Solution shall support device access control | PC | GroupEndpoints.cs — device→group→user access binding |
| 9 | Solution shall support device credential management | PC | CredentialEndpoints.cs — device-bound credentials |
| 10 | Solution shall support device health monitoring | PC | DeviceEndpoints.cs — ICMP ping reachability check |
| 11 | Solution shall support device configuration management |  |  |
| 12 | Solution shall support device firmware management |  |  |
| 13 | Solution shall support device patch management |  |  |
| 14 | Solution shall support device backup |  |  |
| 15 | Solution shall support device recovery |  |  |
| 16 | Solution shall support device redundancy |  |  |
| 17 | Solution shall support device failover |  |  |
| 18 | Solution shall support device load balancing |  |  |
| 19 | Solution shall support device geo-redundancy |  |  |
| 20 | Solution shall support device disaster recovery |  |  |
| 21 | Solution shall support device analytics |  |  |
| 22 | Solution shall support device performance monitoring |  |  |
| 23 | Solution shall support device capacity planning |  |  |
| 24 | Solution shall support device SLA monitoring |  |  |
| 25 | Solution shall support device reporting | PC | Reports.razor — per-device session history report |
| 26 | Solution shall support device integration |  |  |
| 27 | Solution shall support device automation |  |  |
| 28 | Solution shall support device orchestration |  |  |
| 29 | Solution shall support device governance |  |  |
| 30 | Solution shall support device risk management |  |  |
| 31 | Solution shall support device threat detection |  |  |
| 32 | Solution shall support device anomaly detection |  |  |
| 33 | Solution shall support device compliance reporting |  |  |
| 34 | Solution shall support device audit trail | FC | AuditService.cs — all device CRUD operations logged |
| 35 | Solution shall support device tagging | PC | DeviceEndpoints.cs — device tags/labels |
| 36 | Solution shall support device search | PC | DeviceEndpoints.cs — full-text search, filter by type/OS/group |
| 37 | Solution shall support device export |  |  |
| 38 | Solution shall support device import | PC | DeviceEndpoints.cs — CSV device import |
| 39 | Solution shall support device templates |  |  |
| 40 | Solution shall support device profiles |  |  |
| 41 | Solution shall support device groups | PC | GroupEndpoints.cs — device group assignment |
| 42 | Solution shall support device clustering |  |  |
| 43 | Solution shall support device federation |  |  |
| 44 | Solution shall support device synchronization | PC | DeviceEndpoints.cs — SSH host key fingerprint sync (TOFU) |
| 45 | Solution shall support device version management |  |  |
| 46 | Solution shall support device dependency mapping |  |  |
| 47 | Solution shall support device topology mapping |  |  |
| 48 | Solution shall support device CMDB integration |  |  |

## Integrations (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | Solution shall support SIEM integration | PC | SyslogForwarderService.cs — RFC 5424 Syslog + CEF; auto-forward audit events; Integrations.razor config UI |
| 2 | Solution shall support LDAP/AD integration | PC | AdSyncService.cs — LDAP bind, import users/groups; Integrations.razor AD tab |
| 3 | Solution shall support SAML integration | PC | SamlAuthEndpoints.cs — SAML 2.0 SP-initiated + ACS; Integrations.razor SAML tab |
| 4 | Solution shall support RADIUS integration | PC | RadiusProxyService.cs — native C# RADIUS (RFC 2865) built-in server; AAA for network devices; Message-Authenticator validation (#119) |
| 5 | Solution shall support TACACS+ integration | PC | TacacsProxyService.cs — native C# TACACS+ (RFC 1492) built-in server; Cisco/Juniper CLI AAA |
| 6 | Solution shall support REST API integration | PC | OrkunPAM.WebAPI — full REST API with OpenAPI |
| 7 | Solution shall support webhook integration | PC | WebhookService.cs — event-driven webhook delivery |
| 8 | Solution shall support email integration | PC | SmtpEmailService.cs — SMTP notification |
| 9 | Solution shall support ITSM integration |  |  |
| 10 | Solution shall support ticketing system integration |  |  |
| 11 | Solution shall support CMDB integration |  |  |
| 12 | Solution shall support monitoring system integration |  |  |
| 13 | Solution shall support SOAR integration |  |  |
| 14 | Solution shall support threat intelligence integration |  |  |
| 15 | Solution shall support vulnerability scanner integration |  |  |
| 16 | Solution shall support CASB integration |  |  |
| 17 | Solution shall support DLP integration |  |  |
| 18 | Solution shall support WAF integration |  |  |
| 19 | Solution shall support EDR/XDR integration |  |  |
| 20 | Solution shall support cloud security integration |  |  |
| 21 | Solution shall support DevOps integration |  |  |
| 22 | Solution shall support CI/CD integration | PC | .github/workflows/build-test-publish.yml — GitHub Actions CI/CD pipeline |
| 23 | Solution shall support container orchestration integration |  |  |
| 24 | Solution shall support configuration management integration |  |  |
| 25 | Solution shall support patch management integration |  |  |
| 26 | Solution shall support backup integration |  |  |
| 27 | Solution shall support monitoring integration | PC | Reports.razor + Dashboard.razor — session activity and operational stats monitoring (#27) |

## Operation & Maintenance (9 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|---------|
| 1 | Solution shall support system status monitoring | PC | SystemHealthMonitorService.cs — BackgroundService (60s loop): CPU%, memory MB, disk%, service liveness (SshProxy :2222, RdpProxy :3389, TacacsProxy :49, RADIUS :1812, HttpProxy :8080); SystemHealth.razor admin dashboard (#138) |
| 2 | Solution shall support system alarm management | PC | SystemAlarmLogs DB table + alarm threshold config — CPU >80%, disk <10% triggers email via SmtpNotificationService.SendSystemAlarmAsync; alarm list with severity/status active/cleared (#138) |
| 3 | Solution shall support CPU usage monitoring | PC | SystemHealthMonitorService.cs — real-time CPU% via PerformanceCounter/Environment; progress bar + trend sparkline in SystemHealth.razor (#138) |
| 4 | Solution shall support memory usage monitoring | PC | SystemHealthMonitorService.cs — real-time memory MB via Environment.WorkingSet; progress bar + trend sparkline in SystemHealth.razor (#138) |
| 5 | Solution shall support disk usage monitoring | PC | SystemHealthMonitorService.cs — disk usage via DriveInfo; progress bar with threshold indicator in SystemHealth.razor (#138) |
| 6 | Solution shall support service status monitoring | PC | SystemHealthMonitorService.cs — TCP ping to proxy services → Green/Yellow/Red status badges in SystemHealth.razor (#138) |
| 7 | Solution shall support alarm threshold configuration | PC | GET/PUT /api/v1/system/health/config — admin configures CPU/disk alarm thresholds; alarms cleared when condition normalises (#138) |
| 8 | Solution shall support system log viewer | NC | Planned: #160 O&M System Log Viewer (SystemLogs.razor + Serilog JSON reader) |
| 9 | Solution shall support system log search and filter | NC | Planned: #160 O&M System Log Viewer — filter bar: time range, log level, free-text search |