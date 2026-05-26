# PAM RFP Template - Compliance Checklist

> Auto-generated from PAM Template.xlsx. PM Agent uses this to track which RFP items are implemented.
> Last updated: 2026-05-25 (PM Run #30 backfill: Platform #41 + UM #12 + RA #3 + RA #4 + RA #5 + RA #21 + MFA #5 + MFA #9 + MFA #10 + MFA #19 → PC; Sprint 60 RA #8 → PC #283; Sprint 59 Platform #44 → PC #282; Sprint 57 R #39+40+41 → PC #278; Sprint 56 MFA #23 → PC #277; Sprint 55 MFA #22 → PC #270; Sprint 54 UM #48 → PC #271; Platform #21 → PC #262; Sprint 52 RA #41 → PC #263; Sprint 51 MFA #7 → PC #261; Sprint 50 RA #40 → PC #258; Sprint 49 MFA #20 → PC #257; Sprint 48 PV #38 → PC #251; Sprint 47 MFA #16 → PC #252; Sprint 46 MFA #17+#18 → PC #250; Sprint 45 RA #26 → PC #249; Sprint 44 PV #21 → PC #248; Sprint 43 RA #28+#30 → PC #240; Sprint 42 PV #37 → PC #241; Sprint 41 RA #45 → PC #239)

**Legend:** PC = Partially Complete, C = Complete, NS = Not Started, N/A = Not Applicable

---

## Section 1: Platform / General Requirements

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall be a web-based PAM platform | PC | Blazor Server UI + REST API |
| 2 | Solution shall support Windows Server 2019/2022 deployment | PC | .NET 8 Windows Service |
| 3 | Solution shall support high availability (HA) clustering | NS | - |
| 4 | Solution shall support disaster recovery (DR) | PC | Backup/restore endpoints (#55) |
| 5 | Solution shall provide role-based access control (RBAC) | PC | Roles + Permissions + RBAC UI |
| 6 | Solution shall support multi-factor authentication (MFA) | PC | TOTP, Email OTP, SMS OTP, FIDO2, PKI, OATH hardware tokens |
| 7 | Solution shall have a self-service portal for end users | PC | /portal page (SelfService.razor) |
| 8 | Solution shall provide REST API for integration | PC | /api/v1/* endpoints |
| 9 | Solution shall support audit logging | PC | AuditLogEntry + tamper-proof hash chain |
| 10 | Solution shall encrypt data at rest | PC | AES-256-GCM vault engine |
| 11 | Solution shall encrypt data in transit (TLS 1.3) | PC | Configured in Program.cs |
| 12 | Solution shall support Active Directory / LDAP integration | PC | LdapAuthService |
| 13 | Solution shall support SAML 2.0 SSO | PC | SamlController |
| 14 | Solution shall support OIDC / OAuth 2.0 SSO | PC | OIDC provider management + login flow (#274) |
| 15 | Solution shall have dashboard with KPIs | PC | Dashboard.razor |
| 16 | Solution shall support session recording | PC | SessionRecorder + playback |
| 17 | Solution shall support session termination by admin | PC | Session admin controls |
| 18 | Solution shall support IP whitelisting / access control | PC | IP restriction in policies |
| 19 | Solution shall have alert/notification system | PC | AlertRules + email notifications |
| 20 | Solution shall support scheduled reports | PC | ReportSchedules (#159) |
| 21 | Solution shall support API keys for service accounts | PC | ApiKey entity + management UI (#250) |
| 22 | Solution shall support custom branding / theming | NS | - |
| 23 | Solution shall provide SLA monitoring | PC | SLA report endpoint (#278) |
| 24 | Solution shall support backup and restore | PC | BackupRecord + endpoints (#55) |
| 25 | Solution shall have installer / deployment package | PC | MSI installer project |
| 26 | Solution shall log all admin actions | PC | Audit log on all write endpoints |
| 27 | Solution shall support password complexity policies | PC | PasswordPolicy entity |
| 28 | Solution shall support account lockout | PC | FailedLoginCount + lockout logic |
| 29 | Solution shall have session timeout controls | PC | SessionPolicy.IdleTimeoutMinutes |
| 30 | Solution shall support concurrent session limits | PC | SessionPolicy.MaxConcurrentSessions |
| 31 | Solution shall have real-time monitoring dashboard | PC | Live session monitoring |
| 32 | Solution shall support email notifications | PC | SMTP service (#54) |
| 33 | Solution shall support webhook integrations | PC | WebhookService |
| 34 | Solution shall provide compliance reports | PC | ComplianceFramework + reports |
| 35 | Solution shall support custom report builder | PC | CustomReportDefinition (#169) |
| 36 | Solution shall have mobile-responsive UI | PC | Blazor responsive layout |
| 37 | Solution shall support cloud PAM (AWS/Azure/GCP) | PC | CloudAccount + CloudResource + JIT (#37) |
| 38 | Solution shall support privileged task automation | NS | Deferred to v3+ |
| 39 | Solution shall support data classification | NS | - |
| 40 | Solution shall have risk scoring | PC | RiskScore in LoginData |
| 41 | Solution shall support geolocation-based access control | PC | GeolocationAccessRule entity + IP geolocation lookup + Sprint 18 #208 |
| 42 | Solution shall support time-based access control | PC | ScheduledSession + time windows in policies |
| 43 | Solution shall support just-in-time (JIT) access | PC | JitAccessRequest (#38) |
| 44 | Solution shall support biometric authentication | PC | Fido2Endpoints.cs — platform authenticator (Windows Hello / Touch ID) via WebAuthn authenticatorAttachment=platform (#282) |
| 45 | Solution shall support hardware security keys (FIDO2) | PC | Fido2Endpoints.cs + Fido2Credential entity |
| 46 | Solution shall support certificate-based authentication | PC | PKI / Smart Card auth (#115) |
| 47 | Solution shall support zero-trust network access | NS | - |
| 48 | Solution shall integrate with SIEM systems | PC | SiemTarget + Syslog/CEF (#63) |
| 49 | Solution shall support secrets management | PC | Vault engine + credential management |
| 50 | Solution shall support container/Kubernetes secrets | NS | - |

---

## Section 2: User Management (UM)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| UM 1 | Create/edit/delete local users | PC | UserEndpoints CRUD |
| UM 2 | Import users from AD/LDAP | PC | LdapAuthService + sync |
| UM 3 | Assign roles to users | PC | UserRole + RoleEndpoints |
| UM 4 | User groups management | PC | GroupEndpoints |
| UM 5 | Temporary/time-limited accounts | PC | IsTemporary + ExpiresAt |
| UM 6 | Service accounts | PC | IsServiceAccount flag |
| UM 7 | Password history enforcement | PC | UserPasswordHistory |
| UM 8 | Force password change on next login | PC | MustChangePassword flag |
| UM 9 | Account expiry notifications | PC | Email notification on expiry |
| UM 10 | Self-service password reset | PC | /portal reset flow |
| UM 11 | User activity reports | PC | Audit log queries |
| UM 12 | Bulk user import (CSV) | PC | CsvUserImportJob + Sprint 5 #85 |
| UM 13 | User provisioning via SCIM | NS | - |
| UM 14 | Delegated administration | NS | - |
| UM 15 | User profile management | PC | /portal profile tab |
| UM 16 | Multi-tenancy user isolation | NS | Deferred to v3+ |
| UM 17 | User risk scoring | PC | RiskScore in user analytics |
| UM 18 | Inactive account detection | PC | LastLoginAtUtc monitoring |
| UM 19 | Account federation (SAML/OIDC) | PC | SAML + OIDC SSO |
| UM 20 | Emergency account unlock | PC | /unlock endpoint |
| UM 21 | User onboarding workflow | PC | ApprovalRequest flow |
| UM 22 | User offboarding (access revocation) | PC | Status=Disabled + session kill |
| UM 23 | Guest/vendor accounts | PC | VendorAccess (#127) |
| UM 24 | Privileged user identification | PC | IsServiceAccount + Role flags |
| UM 25 | Separation of duties (SoD) | PC | SodRule entity |
| UM 26 | User behavior analytics (UBA) | PC | UserBehaviorBaseline + Anomaly |
| UM 27 | Privileged Identity Management (PIM) | PC | Role + JIT access flow |
| UM 28 | Access certification / attestation | PC | AttestationCampaign (#compliance) |
| UM 29 | User access review | PC | Attestation workflow |
| UM 30 | Password manager integration | NS | - |
| UM 31 | SSH key management | PC | PrivateKey field in Credential |
| UM 32 | API token management | PC | ApiKey entity (#250) |
| UM 33 | Passwordless authentication | PC | FIDO2 WebAuthn |
| UM 34 | Adaptive authentication | NS | - |
| UM 35 | Privileged Access Workstation (PAW) | NS | - |
| UM 36 | Just-Enough-Administration (JEA) | NS | - |
| UM 37 | Access request portal | PC | /portal JIT tab |
| UM 38 | Manager approval workflow | PC | ApprovalRequest + email |
| UM 39 | Time-limited access grants | PC | JIT + ScheduledSession |
| UM 40 | Access extension requests | NS | - |
| UM 41 | Emergency break-glass accounts | PC | BreakGlassEvent |
| UM 42 | User impersonation for support | NS | - |
| UM 43 | Account cloning | NS | - |
| UM 44 | Password sharing (controlled) | PC | CredentialShare |
| UM 45 | Shared account management | PC | Credential + CheckOutHistory |
| UM 46 | Named account mapping | PC | DeviceCredential |
| UM 47 | Access policy templates | PC | Policy entity |
| UM 48 | User notification preferences | PC | NotificationPreference entity (#271) |

---

## Section 3: Vault / Password Vault (PV)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| PV 1 | Store passwords in encrypted vault | PC | AES-256-GCM + DEK hierarchy |
| PV 2 | Automatic password rotation | PC | RotationPolicy + scheduler |
| PV 3 | Password checkout / check-in | PC | CheckoutCredentialAsync |
| PV 4 | Password history | PC | PasswordHistory entity |
| PV 5 | Folder/group organization | PC | VaultFolder hierarchy |
| PV 6 | Credential sharing | PC | CredentialShare |
| PV 7 | Credential templates | PC | CredentialTemplate (#248) |
| PV 8 | SSH key storage | PC | PrivateKey in Credential |
| PV 9 | Certificate storage | PC | ManagedCertificate (#191) |
| PV 10 | Secret rotation scripts | PC | RotationScript entity |
| PV 11 | Vault access audit | PC | Audit log on checkout |
| PV 12 | Credential federation | NS | #284 queued — Sprint 61 |
| PV 13 | BYOK (Bring Your Own Key) | PC | MasterKey management |
| PV 14 | HSM integration | NS | - |
| PV 15 | Vault backup | PC | BackupRecord (#55) |
| PV 16 | Dual control for sensitive creds | NS | - |
| PV 17 | Credential expiry tracking | PC | NextRotationAt field |
| PV 18 | Password strength enforcement | PC | PasswordPolicy |
| PV 19 | Auto-fill for web apps | NS | - |
| PV 20 | Credential discovery | PC | DiscoveryJob + DiscoveredAccount |
| PV 21 | Credential orchestration | PC | CredentialOrchestrationSet/Member/Run (#248) |
| PV 22 | Vault search | PC | Search param on credentials endpoint |
| PV 23 | Credential tagging | NS | - |
| PV 24 | Vault import/export | NS | - |
| PV 25 | Credential health dashboard | PC | Rotation status in reports |
| PV 26 | Secret versioning | PC | PasswordHistory |
| PV 27 | Automatic secret injection | PC | SSH proxy credential injection |
| PV 28 | Secret zero / bootstrap secret | PC | MasterKey init flow |
| PV 29 | Vault access policies | PC | CredentialPermission |
| PV 30 | Dynamic secrets | NS | - |
| PV 31 | One-time passwords (OTP) | PC | TOTP MFA |
| PV 32 | Credential checkout duration | PC | durationMinutes in checkout |
| PV 33 | Concurrent checkout prevention | PC | IsCheckedOut flag |
| PV 34 | Credential rotation on checkout | NS | - |
| PV 35 | Vault API access | PC | /api/v1/vault/* endpoints |
| PV 36 | Vault encryption key rotation | PC | KeyRotation endpoint |
| PV 37 | Credential request/approval workflow | PC | ApprovalRequest for credential access (#241) |
| PV 38 | Credential access assignment | PC | AssignedCredential (Kron PAM model) — direct or group-based (#251) |

---

## Section 4: Remote Access (RA)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| RA 1 | SSH proxy | PC | SshProxy Windows Service |
| RA 2 | RDP proxy | PC | RDP TCP relay |
| RA 3 | VNC proxy | PC | Native C# RFC 6143 + Sprint 6 #101 |
| RA 4 | Telnet proxy | PC | Native C# RFC 854 + Sprint 19 |
| RA 5 | HTTP/HTTPS proxy | PC | Native C# reverse proxy + Sprint 6 #102 |
| RA 6 | Database proxy | NS | Deferred to v3+ |
| RA 7 | Web-based SSH terminal | PC | XTerm.js terminal |
| RA 8 | Network segmentation support | PC | NetworkZone entity + jump host ProxyJump (SSH direct-tcpip) + /network-zones UI (#283) |
| RA 9 | Jump server / bastion | PC | SSH proxy as bastion |
| RA 10 | Session recording (SSH) | PC | SessionRecorder |
| RA 11 | Session recording (RDP) | NS | RDP recording not yet implemented |
| RA 12 | Session playback | PC | Recording playback endpoint |
| RA 13 | Live session monitoring | PC | /api/v1/sessions/live/* |
| RA 14 | Session termination | PC | Admin kill endpoint |
| RA 15 | Command logging (SSH) | PC | CommandLog entity |
| RA 16 | Keystroke logging | PC | CommandLog via SSH proxy |
| RA 17 | Screen capture | PC | ScreenCaptureFrame |
| RA 18 | File transfer logging | NS | - |
| RA 19 | Session shadowing | PC | SessionShadow (#214) |
| RA 20 | Session sharing | PC | SessionHandoff + ShareSession |
| RA 21 | Multi-hop sessions | PC | ProxyJump SSH direct-tcpip via SshJumpTunnel.cs (Sprint 60 #283) |
| RA 22 | Session time limits | PC | SessionPolicy.MaxDurationMinutes |
| RA 23 | Idle session detection | PC | IdleTimeoutMinutes |
| RA 24 | Session token management | PC | SessionTokenHash |
| RA 25 | Connection scheduling | PC | ScheduledSession (#142) |
| RA 26 | Protocol detection | PC | SessionType enum + proxy routing (#249) |
| RA 27 | Port forwarding control | NS | - |
| RA 28 | X11 forwarding control | NS | - |
| RA 29 | SCP/SFTP control | NS | - |
| RA 30 | RDP clipboard control | NS | - |
| RA 31 | RDP drive redirection control | NS | - |
| RA 32 | RDP printer redirection control | NS | - |
| RA 33 | RDP USB redirection control | NS | - |
| RA 34 | Session audit trail | PC | AuditLogEntry on session events |
| RA 35 | Connection health monitoring | PC | SystemAlarmLog (#138) |
| RA 36 | Proxy load balancing | NS | - |
| RA 37 | Proxy failover | NS | - |
| RA 38 | Command filtering / blocking | PC | CommandFilterPolicy (#231) |
| RA 39 | Command risk scoring | PC | CommandRiskRule + risk scoring |
| RA 40 | Session tagging and annotation | PC | SessionAnnotation (#216) + #258 |
| RA 41 | Session search and filter | PC | Session search/filter endpoints + UI (#263) |
| RA 42 | Session delegation | PC | SessionDelegation entity + endpoints (#269) |
| RA 43 | Session handoff | PC | SessionHandoff entity + UI |
| RA 44 | Remote app launching | PC | LaunchToken + native client SSO (#170) |
| RA 45 | Privileged remote desktop groups | PC | DeviceGroup + DeviceRealm (#239) |
| RA 46 | SSH host key verification (TOFU) | PC | SshHostKeyFingerprint field + TOFU |
| RA 47 | Session restore after disconnect | PC | SessionRestoreToken + endpoints (#279) |

---

## Section 5: Multi-Factor Authentication (MFA)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| MFA 1 | TOTP authenticator app | PC | TotpService |
| MFA 2 | SMS OTP | PC | SmsOtpToken (#215) |
| MFA 3 | Email OTP | PC | EmailOtpToken (#178) |
| MFA 4 | Hardware FIDO2 security keys | PC | Fido2Credential + WebAuthn |
| MFA 5 | Push notification MFA | PC | PushMfaChallenge entity + Sprint 15 #196 |
| MFA 6 | Voice call MFA | NS | - |
| MFA 7 | OATH HOTP hardware tokens | PC | HardwareToken entity (#261) |
| MFA 8 | PKI / smart card authentication | PC | TrustedCaCertificate + PkiUserCertificate (#115) |
| MFA 9 | Risk-based MFA | PC | AdaptiveMfa — anomaly risk score triggers step-up (Sprint 17 #205) |
| MFA 10 | Step-up authentication | PC | AdaptiveMfa step-up on risk threshold + Sprint 17 #205 |
| MFA 11 | MFA bypass for service accounts | NS | - |
| MFA 12 | MFA enrollment self-service | PC | /portal security tab |
| MFA 13 | MFA reset by admin | PC | Admin reset endpoint |
| MFA 14 | MFA audit logging | PC | Audit events on MFA actions |
| MFA 15 | MFA grace period | NS | - |
| MFA 16 | MFA exception management | PC | MfaException entity + UI (#252) |
| MFA 17 | Trusted devices | PC | TrustedDevice entity (#207) |
| MFA 18 | Remember device (trusted sessions) | PC | MfaTrustedSession (#257) |
| MFA 19 | Adaptive MFA based on risk | PC | AdaptiveMfa entity + anomaly score routing (Sprint 17 #205) |
| MFA 20 | MFA for privileged operations | PC | mfaVerified claim in JWT (#258) |
| MFA 21 | Backup codes | PC | UserBackupCode generate/status/revoke endpoints + SelfService UI (#289) |
| MFA 22 | Device-based MFA policy | PC | DeviceMfaPolicy entity + endpoint (#270) |
| MFA 23 | OATH token drift/resync report | PC | TokenDriftReport endpoint (#277) |

---

## Section 6: Reporting (R)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| R 1 | Access reports | PC | Audit log queries |
| R 2 | Session reports | PC | Session list + stats |
| R 3 | Password rotation reports | PC | RotationPolicy audit |
| R 4 | Compliance reports | PC | ComplianceFramework |
| R 5 | User activity reports | PC | Audit log by user |
| R 6 | Failed login reports | PC | FailedLoginCount + audit |
| R 7 | Anomaly / threat reports | PC | Anomaly entity |
| R 8 | SLA reports | PC | SLA report endpoint |
| R 9 | Executive dashboard | PC | Dashboard.razor KPIs |
| R 10 | Scheduled report delivery | PC | ReportSchedule (#159) |
| R 11 | Custom report builder | PC | CustomReportDefinition (#169) |
| R 12 | Export to PDF/Excel | NS | - |
| R 13 | Real-time alerts | PC | AlertRule + AlertHistory |
| R 14 | Trend analysis | PC | Behavior baseline + anomaly detection |
| R 15 | Capacity planning reports | PC | Capacity trend report |
| R 16 | Audit trail reports | PC | AuditLogEntry + tamper-proof chain |
| R 17 | Privileged access reports | PC | CheckOutHistory reports |
| R 18 | Vendor access reports | PC | VendorAccess audit |
| R 19 | Cloud access reports | PC | CloudJitRequest audit |
| R 20 | Certificate expiry reports | PC | ManagedCertificate expiry |
| R 21 | Risk reports | PC | RiskScore + Anomaly |
| R 22 | SoD violation reports | PC | SodRule + violations |
| R 23 | Attestation reports | PC | AttestationCampaign results |
| R 24 | SIEM export | PC | SiemTarget + event forwarding |
| R 25 | API access reports | PC | ApiAccessLog |
| R 26 | Device health reports | PC | SystemAlarmLog |
| R 27 | Session recording reports | PC | ScreenCaptureFrame stats |
| R 28 | Command frequency reports | PC | CommandLog analytics |
| R 29 | Geographic access reports | NS | - |
| R 30 | Time-of-day access reports | PC | Audit timestamp analysis |
| R 31 | Unusual access pattern reports | PC | Anomaly detection |
| R 32 | Break-glass event reports | PC | BreakGlassEvent entity |
| R 33 | JIT access reports | PC | JitAccessRequest stats |
| R 34 | Rotation failure reports | PC | RotationScript error logging |
| R 35 | Credential age reports | PC | LastRotatedAt + policy |
| R 36 | Orphaned credential reports | NS | - |
| R 37 | License usage reports | NS | - |
| R 38 | Backup status reports | PC | BackupRecord status |
| R 39 | Capacity trend report | PC | CapacityReport endpoint (#278) |
| R 40 | Performance/SLA report | PC | PerformanceReport endpoint (#278) |
| R 41 | SLA compliance report | PC | SlaReport endpoint (#278) |

---

## Compliance Summary

| Section | Total | PC | C | NS | N/A |
|---------|-------|----|----|-----|-----|
| Platform | 50 | 44 | 0 | 6 | 0 |
| User Mgmt | 48 | 38 | 0 | 10 | 0 |
| Vault | 38 | 30 | 0 | 8 | 0 |
| Remote Access | 47 | 35 | 0 | 12 | 0 |
| MFA | 23 | 19 | 0 | 4 | 0 |
| Reporting | 41 | 37 | 0 | 4 | 0 |
| **TOTAL** | **247** | **203** | **0** | **44** | **0** |

> **Overall compliance rate: 82% (203/247 items partially or fully implemented)**

---

*This checklist is maintained by the PM Agent and updated after each sprint.*
*Last full review: 2026-05-25 (PM Run #30 — Sprint 60 backfill complete)*

---

## Recently Completed (Last 5 Sprints + PM Backfill)

| Sprint / Run | Issues Closed | RFP Items |
|--------|--------------|----------|
| PM Run #30 | — | Platform #41 (geolocation), UM #12 (bulk CSV import), RA #3 (VNC proxy), RA #4 (Telnet proxy), RA #5 (HTTP/HTTPS proxy), RA #21 (multi-hop via ProxyJump), MFA #5 (push notification), MFA #9 (risk-based), MFA #10 (step-up auth), MFA #19 (adaptive MFA) — backfill from sprints 5–19 |
| Sprint 60 | #283 | RA #8 (network segmentation + SSH ProxyJump) |
| Sprint 59 | #282, #286, #287, #288 | Platform #44 (biometric auth) |
| Sprint 58 | #279 | RA #47 (session restore) |
| Sprint 57 | #278 | R #39, R #40, R #41 (operational reports) |
| Sprint 56 | #277 | MFA #23 (OATH token drift report) |

---

## Open Items (Not Started)

High priority NS items based on RFP weight:
1. PV #12 — Credential federation (#284 queued — Sprint 61)
2. Platform #3 — HA clustering (v2/v3+)
3. Platform #47 — Zero-trust network access (v3+)
4. UM #13 — SCIM provisioning (enterprise IdP sync)
5. ~~MFA #21 — Backup codes~~ ✅ PC (#289)
6. R #12 — PDF/Excel export (compliance audit download)
7. RA #11 — RDP session recording
8. RA #6 — Database proxy (deferred v3+)
9. PV #14 — HSM integration (v3+)

---

## Deferred Items (v3+)

| Item | Section | Reason |
|------|---------|--------|
| Multitenancy | Platform #39 / UM #16 | Single tenant sufficient now |
| DB Proxy | RA #6 | SQL proxy deferred |
| Privileged Task Automation | Platform #38 | Automation deferred |
| Container secrets | Platform #50 | Out of scope v1 |

---

*Generated by PM Agent — do not edit manually. Use GitHub Issues for gap tracking.*

## Additional Notes for Tracking

- Platform #44 biometric auth implemented via WebAuthn platform authenticator (Windows Hello / Touch ID) in Fido2Endpoints.cs
- All FIDO2 credentials now carry `AuthenticatorType` field ("platform" or "cross-platform")
- Session restore (#279) implements RA #47 with CWE-285/208/316 security fixes
- Operational reports (#278) cover capacity trends, performance metrics, SLA compliance
- Device MFA policy (#270) maps to MFA #22, allowing per-device MFA enforcement
- OATH token drift report (#277) maps to MFA #23
- OIDC SSO (#274) maps to Platform #14
- Credential orchestration (#248) maps to PV #21
- Assigned credentials (#251) maps to PV #38 using Kron PAM model
- Session delegation (#269) maps to RA #42
- Session annotation + search (#258, #263) map to RA #40, RA #41
- VNC proxy (#101) = Sprint 6 native C# RFC 6143 → RA #3
- Telnet proxy (Sprint 19) = native C# RFC 854 → RA #4
- HTTP/HTTPS proxy (#102) = Sprint 6 native C# reverse proxy → RA #5
- Multi-hop sessions = ProxyJump SSH direct-tcpip SshJumpTunnel.cs (#283) → RA #21
- Push notification MFA (#196) = Sprint 15 → MFA #5
- Adaptive MFA (#205) = Sprint 17 → MFA #9 (risk-based) + MFA #10 (step-up) + MFA #19 (adaptive)
- Geolocation access control (#208) = Sprint 18 → Platform #41
- Bulk user CSV import (#85) = Sprint 5 → UM #12

| Item | Section | Status | Implementation |
|------|---------|--------|----------------|
| Privileged account onboarding | PV misc | PC | Vault.razor — manual privileged account onboarding |
