# PAM RFP Template - Compliance Checklist

> Auto-generated from PAM Template.xlsx. PM Agent uses this for feature gap analysis.
> Status: FC=Fully Compliant, PC=Partially Compliant, NC=Not Compliant
> Last updated: 2026-05-25 (Sprint 56 MFA #23 → PC #277; Sprint 55 MFA #22 → PC #270; Sprint 54 UM #48 → PC #271; Sprint 53 RA #42 → PC #269; Platform #21 → PC #262; Sprint 52 RA #41 → PC #263; Sprint 51 MFA #7 → PC #261; Sprint 50 RA #40 → PC #258; Sprint 49 MFA #20 → PC #257; Sprint 48 PV #38 → PC #251; Sprint 47 MFA #16 → PC #252; Sprint 46 MFA #17+#18 → PC #250; Sprint 45 RA #26 → PC #249; Sprint 44 PV #21 → PC #248; Sprint 43 RA #28+#30 → PC #240; Sprint 42 PV #37 → PC #241; Sprint 41 RA #45 → PC #239)

## Platform (44 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|------|
| 1 | Solution shall support appliance base installation | PC | WiX v4 MSI + PowerShell Install.ps1 + OrkunPAM.Installer CLI — component selection, DB init, cert gen, service registration; single-package Windows Server deployment (#36) |
| 2 | Solution shall support Vmware and Hyper-V based installation |  |  |
| 3 | Solution shall be deployable On‑Premise and provided as a cloud  offering. | PC | MSI installer (WiX v4) + PowerShell Install.ps1 — single-package Windows Server on-prem deployment (#36); Cloud PAM module — AWS/Azure/GCP cloud resource privileged access, JIT cloud credentials, multi-cloud dashboard (CloudPam.razor + CloudEndpoints.cs, #37) |
| 4 | Solution shall support agent-less architecture. No additional software agent shall be required to install on devices, se | PC | All session proxies (SSH :2222, RDP :3389, VNC, HTTP, TACACS+ :49, RADIUS :1812) connect to target systems via standard protocols — no agent installation on managed devices; credential injection via SshServerSession.cs / RdpProxyService.cs / VncProxyService.cs |
| 5 | Solution GUI shall run with updated version of well-known browsers (i.e. Microsoft Edge, Google Chrome, Firefox, Safari) | PC | OrkunPAM.Web (Blazor Server — Edge/Chrome/Firefox) |
| 6 | Solution shall support SSO (Single-Sign-On) | PC | SAML 2.0 SSO implemented — SamlAuthEndpoints.cs SP-initiated flow, SamlCallback.razor (#45) |
| 7 | Solution shall support both CLI and web interfaces | PC | Blazor web UI (OrkunPAM.Web) + REST API (OrkunPAM.WebAPI) |
| 8 | Solution shall support SAML authentication for secure portal access to PAM platform | PC | SAML 2.0 SP-initiated + ACS — SamlAuthEndpoints.cs; XML sig validation, ±5 min clock skew, auto-provision (#45) |
| 9 | Solution shall support SAML provider configuration on a per-tenant basis, allowing separate identity provider settings f |  |  |
| 10 | Solution shall support Public Key Infrastructure (PKI) Authentication for secure portal access using digital certificate | PC | PkiEndpoints.cs — Trusted CA CRUD (AdminPolicy), user cert mapping CRUD, POST /api/v1/auth/pki/login; X.509 chain validation + expiry check; X-Client-Cert header or body; JWT with mfaVerified=true; Integrations.razor PKI tab (#115) |
| 11 | Solution shall support Windows Authentication fo | PC | AuthEndpoints.cs — GET /api/v1/auth/windows; Negotiate/Kerberos SSO; trusted domain guard, auto-provision on first login, MFA bypass for Kerberos, audit via UserLoggedInEvent; Integrations.razor Windows Auth tab (#126) |
| 12 | Solution shall have out of the box management capability for network devices and systems (Juniper, Cisco IOS, Cisco IOS- | PC | OrkunPAM.TacacsProxy — native C# TACACS+ (RFC 1492) built-in server; Cisco/Juniper/Aruba CLI AAA via TCP :49 (#111) |
| 13 | Solution shall support adapting to different brand/model devices and systems, which will be used in the future. |  |  |
| 14 | Solution shall have out of the box support for script usage on NAS devices. |  |  |
| 15 | Solution shall support users to change their passwords and force to create the passwords in a complex way as well as cha | PC | AuthEndpoints.cs — POST /api/v1/auth/change-password (current pw + policy validation + history check + MustChangePassword flag reset); SelfService.razor "My Profile" tab — Change Password form with complexity hint; GET /api/v1/auth/me profile endpoint; PamApiService.ChangePasswordAsync + GetMyProfileAsync (Sprint 31) |
| 16 | Solution shall support to be scaled to serve a carrier grade number of devices and users besides redundancy which lets 9 |  |  |
| 17 | Solution shall support to active-active redundancy. |  |  |
| 18 | Solution shall support disaster recovery. | PC | BackupService.cs — AES-256-GCM encrypted backup/restore, Hangfire scheduler, Blazor UI (#55) |
| 19 | Solution shall support different software versions of a network device simultaneously. |  |  |
| 20 | Solution software shall support working on indu |  |  |
| 21 | Solution shall support IPv6. | PC | All 8 proxy services updated to IPv6 dual-stack: IPAddress.IPv6Any + DualMode=true for TCP proxies (SSH :2222, RDP :3389, SQL, VNC, HTTP, Telnet, TACACS+); RADIUS UdpClient dual-stack factory — UdpClient(IPv6) + DualMode=true before Bind; single socket accepts both IPv4 and IPv6 connections (#262) |
| 22 | Solution shall be able to support a minimum of 100,000 devices and/or 100,000 accounts. |  |  |
| 23 | Solution shall have REST-API support. | PC | OrkunPAM.WebAPI — ASP.NET Minimal API with OpenAPI/Swagger; full REST CRUD for all resources |
| 24 | Solution shall support programmatic access through REST API. | PC | REST API with JWT bearer auth; all major endpoints documented |
| 25 | Solution shall support 2FA/MFA for portal access | PC | TOTP MFA — QrCodeEndpoints.cs, /api/v1/auth/verify-mfa; TOTP-based 2FA enforced at login (#39) |
| 26 | Solution shall support hierarchical grouping structure for administrators. | PC | RoleEndpoints.cs + UserEndpoints.cs |
| 27 | Solution shall support business and operational model of managed service providers |  |  |
| 28 | Solution shall support business and operational model of geographically distributed organizations |  |  |
| 29 | Solution shall support end-to-end encryption. | PC | TLS 1.3 (all comms) + AES-256-GCM (vault) + column-level encryption (#3, #4) |
| 30 | Solution shall support FIPS 140-2 encryption standard | PC | FipsUtils.cs + VaultEncryptionService.cs — OS FIPS registry + appsettings Security.FipsMode override; AesCng when FIPS active; startup compliance validator; admin FIPS status badge (Integrations.razor); TLS 1.3 enforced; PBKDF2-SHA256 for passwords (#180) |
| 31 | Solution shall support hardware security module (HSM) for key storage | PC | HsmKeyStore.cs — IHsmProvider abstraction; SoftHsmProvider (dev/test), Pkcs11HsmProvider (Thales Luna/nCipher/SafeNet/AWS CloudHSM), AzureKeyVaultHsmProvider (Azure Managed HSM), AwsCloudHsmProvider (AWS KMS); MEK never leaves HSM (WrapKeyAsync/UnwrapKeyAsync); GET /api/v1/system/hsm/status + POST /api/v1/system/hsm/rotate (AdminPolicy); Security:HsmMode appsettings config (#187) |
| 32 | Solution shall support AES encryption for password management. | PC | VaultEncryptionService.cs — AES-256-GCM, 3-tier key hierarchy (KEK/DEK/MEK) |
| 33 | Solution shall support audit log management. | FC | AuditService.cs — immutable hash-chained audit log, all operations recorded |
| 34 | Solution shall provide real-time alerts for critical events. | PC | InProcessEventBus.cs + SessionEventRelayService.cs — real-time event relay via SignalR |
| 35 | Solution shall provide audit log with reporting capabilities. | PC | Reports.razor — audit log export CSV/JSON, filter/search, date range |
| 36 | Solution shall support automated policy compliance checks. | PC | PolicyEndpoints.cs — policy compliance reporting; policy-compliance report (#120) |
| 37 | Solution shall support integration with SIEM systems. | PC | SyslogForwarderService.cs — RFC 5424 Syslog + ArcSight CEF; UDP/TCP/TLS; auto-forward audit events (#122); SoarIntegration.cs — bi-directional Splunk SOAR / Palo Alto XSOAR playbook connector: PAM alert → SOAR trigger, SOAR action → PAM response (block/rotate/terminate), webhook ingest; Integrations.razor SOAR tab (#197) |
| 38 | Solution shall support integration with ticketing systems. | PC | IntegrationEndpoints.cs — ServiceNow/OneDesk/Jira/BMC/Generic ITSM config CRUD, toggle, test; HMAC-SHA256 inbound webhook; ticket state → ApprovalStatus.Approved/Denied; Integrations.razor ITSM tab (#114) |
| 39 | Solution shall provide dashboards for operational visibility. | PC | Dashboard.razor — live stats, session activity, credential status; Home.razor: High Risk Credentials stat card + top-5 high-risk credentials table widget (Sprint 34, #232) |
| 40 | Solution shall support role-based access control (RBAC). | FC | PamRole enum — GlobalAdmin, VaultAdmin, SessionAdmin, Auditor, PasswordViewer; enforced on all endpoints |
| 41 | Solution shall support separation of duties. | PC | PasswordViewer SoD — GlobalAdmin/VaultAdmin cannot checkout without separate PasswordViewer role (#140) |
| 42 | Solution shall support privileged account lifecycle management. | PC | AccountLifecycleJob.cs — temp account expiry, inactivity lockout, pwd-age lockout, warning emails (#135, #137) |
| 43 | Solution shall support workflow-based approvals. | PC | Approvals.razor — multi-step approval workflow, expiry, RBAC (#79) |
| 44 | Solution shall provide reports and dashboards for compliance monitoring. | PC | Reports.razor + Dashboard.razor — session activity and operational stats monitoring (#27) |

## User Management (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|------|
| 1 | Solution shall support local user accounts | FC | UserEndpoints.cs — CRUD, PBKDF2-SHA512 hashed passwords, roles |
| 2 | Solution shall support Active Directory integration | PC | LdapPamSyncService.cs — scheduled AD sync + AD group → PAM group membership sync; uSNChanged delta sync; multi-domain Global Catalog (port 3268) support; bulk user/group reconciliation (#141) |
| 3 | Solution shall support LDAP integration | PC | AdSyncService.cs — LDAP (port 389/636) bind + search |
| 4 | Solution shall support role-based access control | FC | PamRole enum + RoleEndpoints.cs — 7 roles, endpoint-level enforcement |
| 5 | Solution shall support group-based access control | PC | GroupEndpoints.cs — group CRUD, group→credential/device binding; DeviceRealm entity — access matrix: UserGroups × DeviceGroups (Kron PAM model); DeviceRealmEndpoints.cs + DeviceRealms.razor (Sprint 23); Sprint 27: realm-first access check enforced at session creation (CreateSession/CreateRdpSession/WebSSH) — DeviceRealmEndpoints.IsDeviceCoveredByRealmAsync + HasRealmAccessAsync; GetMyAccessibleDevicesAsync for device dropdown (realm-filtered for non-admins) |
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
| 20 | Solution shall support delegated administration | PC | VendorEndpoints.cs — sponsor users delegated control over vendor accounts: onboard, extend access (PUT /{id}/extend), revoke (PUT /{id}/revoke), view sessions; scoped delegation via VendorSponsorUserId without GlobalAdmin rights (#186) |
| 21 | Solution shall support user activity monitoring | PC | Sessions.razor Live Monitor — active session tracking per user |
| 22 | Solution shall support privileged user management | PC | UserEndpoints.cs + RoleEndpoints.cs — privileged role assignment/revocation |
| 23 | Solution shall support emergency access accounts | PC | BreakGlassEndpoints.cs — emergency access, full audit, time-limited |
| 24 | Solution shall support account reconciliation | PC | ReconciliationEndpoints.cs + ReconciliationService.cs — PAM vault vs AD/LDAP entitlement drift detection: daily scheduled reconciliation, per-user drift report (missing from PAM, extra in PAM, role mismatch), Compliance.razor Reconciliation tab, audit logged (#195) |
| 25 | Solution shall support orphaned account detection | PC | GET /api/v1/users/orphaned + Users.razor orphaned badge; accounts inactive >90 days or removed from AD marked IsOrphaned; OrphanedDetectedAtUtc field; daily background check (#153) |
| 26 | Solution shall support access certification | PC | AttestationCampaign entity + Compliance.razor — access certification campaigns; reviewer assignments, Approve/Revoke decisions, campaign progress tracking, audit trail (#154) |
| 27 | Solution shall support user risk scoring | PC | AnomalyDetectionService.cs — per-session risk score 0-100 (OffHours +25, UnusualIP +50, FrequencySpike +50, HighRiskCommand ×10); ProxySession.RiskScore field; SOC Dashboard risk-map per user; ThreatAnalytics.razor (#35) |
| 28 | Solution shall support behavioral analytics for users | PC | BehaviorBaselineService.cs — 30-day rolling session history; TypicalHours, KnownIPs (≥3 seen), KnownDevices (≥2 seen); UserBehaviorBaseline entity; baseline rebuild API; ThreatAnalytics.razor Baselines tab (#35) |
| 29 | Solution shall support geolocation-based access control | PC | GeoLocationHelper.cs — ip-api.com lookup; allowed/blocked country codes; ViolationAction (Block/StepUpAuth); private IP RFC 1918 bypass; login flow enforcement; GET/PUT /api/v1/policy/geo-access (AdminPolicy); Policies.razor Geo Access tab (#208) |
| 30 | Solution shall support time-based access restrictions | PC | AccessPolicyService.cs — AllowedTimeWindows (Mon-Fri 09:00-18:00 etc.) |
| 31 | Solution shall support IP-based access restrictions | PC | AccessPolicyService.cs — CIDR-based IP allow/deny |
| 32 | Solution shall support device-based access restrictions | PC | TrustedDevice entity — SHA-256 UA fingerprint, TrustLevel (Unknown/UserRegistered/AdminApproved); login block for Unknown; Integrations.razor Device Trust tab + Policies.razor Device Trust entry; POST /api/v1/auth/device-trust/register (self-service); admin approve/revoke; adaptive MFA step-up for UserRegistered (#207) |
| 33 | Solution shall support context-aware access control | PC | AdaptiveMfaService.cs + AnomalyDetectionService.cs — context: time, IP, device, risk score → MFA step-up decisions (#205) |
| 34 | Solution shall support privileged session management | PC | Sessions.razor — session list, termination, recording access |
| 35 | Solution shall support just-in-time access | PC | JitEndpoints.cs — time-limited privilege elevation, auto-revoke, audit (#38) |
| 36 | Solution shall support access request workflows | PC | Approvals.razor + ApprovalsEndpoints.cs — request, approval, denial, ITSM integration |
| 37 | Solution shall support access reviews | PC | Compliance.razor Certification tab — periodic access reviews |
| 38 | Solution shall support access analytics | PC | ThreatAnalytics.razor — anomaly patterns, access trends, peer comparison |
| 39 | Solution shall support privileged access governance | PC | DeviceRealm entity — Kron PAM access matrix: UserGroups × DeviceGroups; realm-based access check at session creation |
| 40 | Solution shall support insider threat detection | PC | AnomalyDetectionService.cs — behavioral baseline comparison; OffHours/UnusualIP/FrequencySpike detection; SOC ThreatAnalytics.razor (#35) |
| 41 | Solution shall support vendor access management | PC | VendorEndpoints.cs — vendor account lifecycle: onboard, sponsor-based access, automatic expiry, revocation (#186) |
| 42 | Solution shall support third-party access | PC | AssignedCredential + DeviceRealm — external user scoped to specific device/credential assignments |
| 43 | Solution shall support access federation | PC | SAML 2.0 + FIDO2 + PKI + Windows Auth — federated identity support |
| 44 | Solution shall support biometric authentication |  |  |
| 45 | Solution shall support certificate-based authentication | PC | PKI auth — X.509 client certificates via /api/v1/auth/pki/login (#115) |
| 46 | Solution shall support smart card authentication | PC | PKI auth supports smart card certificates (X.509 via PkiEndpoints.cs) |
| 47 | Solution shall support passwordless authentication | PC | FIDO2/WebAuthn — passwordless login via hardware security keys (#158) |
| 48 | Solution shall support federated identity | PC | OIDC Federation — Azure AD / Okta / Auth0 via OidcAuthEndpoints.cs (PKCE + auto-provision, Sprint 54) |

## Reporting (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|------|
| 1 | Solution shall support audit reports | FC | Reports.razor — comprehensive audit log with export |
| 2 | Solution shall support session reports | PC | Reports.razor + Sessions.razor — session activity, duration, user/device breakdown |
| 3 | Solution shall support compliance reports | PC | Reports.razor + Compliance.razor — SOX/PCI-DSS/ISO 27001 report templates (#179) |
| 4 | Solution shall support user activity reports | PC | Reports.razor — user action audit trail |
| 5 | Solution shall support credential reports | PC | Reports.razor + Vault.razor — credential usage, risk, rotation history |
| 6 | Solution shall support security reports | PC | Reports.razor — security event export; ThreatAnalytics.razor SOC |
| 7 | Solution shall support executive dashboards | PC | Home.razor — CISO KPIs, risk summary, top threats, compliance score, stat cards (#168) |
| 8 | Solution shall support scheduled reports | PC | ReportScheduleEndpoints.cs + Hangfire — CRON-based scheduled report delivery via email (#159) |
| 9 | Solution shall support custom report builder | PC | CustomReportEndpoints.cs — SQL-safe query builder, report definitions CRUD, on-demand generate/export CSV; Reports.razor Custom tab (#169) |
| 10 | Solution shall support report export (PDF/CSV) | PC | Reports.razor + ReportScheduleEndpoints.cs — CSV/JSON export, PDF via HTML render |
| 11 | Solution shall support real-time dashboards | PC | Dashboard.razor + SignalR session events — real-time session monitoring |
| 12 | Solution shall support access pattern reports | PC | AccessPatternEndpoints.cs — hourly/daily heatmap, per-user/device breakdowns, peer comparison, top-N rankings (#209) |
| 13 | Solution shall support privilege escalation reports | PC | Reports.razor — privilege events logged + reportable |
| 14 | Solution shall support risk reports | PC | ThreatAnalytics.razor + CredentialRiskEndpoints.cs — risk scoring, high-risk credentials (#35, #232) |
| 15 | Solution shall support SOX compliance reports | PC | SOX report template — user access certifications, separation of duties, privileged account reviews (#179) |
| 16 | Solution shall support PCI-DSS compliance reports | PC | PCI-DSS report template — cardholder data system access, MFA compliance, session recording coverage (#179) |
| 17 | Solution shall support ISO 27001 compliance reports | PC | ISO 27001 report template — asset access control, incident log, cryptographic compliance (#179) |
| 18 | Solution shall support GDPR compliance reports | PC | Compliance.razor + Reports.razor — GDPR data access log, consent tracking |
| 19 | Solution shall support HIPAA compliance reports | PC | Reports.razor — HIPAA audit trail, user access to sensitive systems |
| 20 | Solution shall support NIST framework alignment | PC | FIPS 140-2 compliance (FipsUtils.cs), audit chain (AuditService.cs), MFA enforcement — NIST SP 800-53 aligned |
| 21 | Solution shall support report templates | PC | SOX/PCI-DSS/ISO 27001 built-in templates via ComplianceReportEndpoints.cs (#179) |
| 22 | Solution shall support report scheduling | PC | ReportScheduleEndpoints.cs — CRON-based scheduling, email delivery, Hangfire BackgroundService (#159) |
| 23 | Solution shall support report notifications | PC | Email notification on report ready via EmailService.cs |
| 24 | Solution shall support report sharing | PC | Scheduled reports delivered via email to configured recipients |
| 25 | Solution shall support report archiving | PC | Reports stored in DB; audit log entries retained per retention policy |
| 26 | Solution shall support report access control | PC | Reports.razor + ReportScheduleEndpoints.cs — RBAC enforced; Auditor/GlobalAdmin roles required |
| 27 | Solution shall support report versioning | PC | Each report run stored separately with timestamp |
| 28 | Solution shall support report audit trail | PC | AuditService.cs — report generation/download events logged |
| 29 | Solution shall support report API | PC | REST API — GET /api/v1/reports/*, /api/v1/compliance/*, /api/v1/analytics/* |
| 30 | Solution shall support report localization | PC | Multi-language UI (TR/EN) — i18n.json; reports in selected language (#143) |
| 31 | Solution shall support failed login reports | PC | Reports.razor + AuthEndpoints.cs — failed login audit events (#172) |
| 32 | Solution shall support brute force detection reports | PC | SecurityReportEndpoints.cs — brute force detection patterns, lockout events (#172) |
| 33 | Solution shall support account lifecycle reports | PC | AccountLifecycleReportEndpoints.cs — account creation/modification/deletion/expiry events (#173) |
| 34 | Solution shall support privilege change reports | PC | PrivilegeChangeReportEndpoints.cs — role assignment/revocation events (#173) |
| 35 | Solution shall support MFA enrollment reports | PC | MfaReportEndpoints.cs — enrollment status per user/group, MFA method distribution, recent activity (#174) |
| 36 | Solution shall support MFA usage reports | PC | MfaReportEndpoints.cs — MFA usage breakdown, success/failure rates (#174) |
| 37 | Solution shall support session recording reports | PC | Sessions.razor — session recording status per session; Reports.razor session export |
| 38 | Solution shall support session playback reports | PC | SessionPlayback.razor — timeline, command log, risk events, screen captures |
| 39 | Solution shall support capacity planning reports |  |  |
| 40 | Solution shall support performance reports |  |  |
| 41 | Solution shall support SLA reports |  |  |
| 42 | Solution shall support trend analysis reports | PC | ThreatAnalytics.razor — behavioral trends, anomaly rate over time |
| 43 | Solution shall support predictive analytics | PC | AnomalyDetectionService.cs — risk scoring; ThreatAnalytics.razor forward-looking metrics |
| 44 | Solution shall support benchmark reports | PC | docs/perf-baseline.md — AES-256-GCM < 0.1 ms/op |
| 45 | Solution shall support comparative reports | PC | AccessPatternEndpoints.cs — peer comparison, top-N rankings (#209) |
| 46 | Solution shall support historical reports | PC | Reports.razor — date-range filtering; all data retained |
| 47 | Solution shall support multi-tenant reports |  |  |
| 48 | Solution shall support white-label reports |  |  |

## MFA Manager (24 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|------|
| 1 | Solution shall support TOTP (Time-based One-Time Password) | FC | QrCodeEndpoints.cs — TOTP enrollment + verification; RFC 6238 compliant |
| 2 | Solution shall support FIDO2/WebAuthn | PC | Fido2Endpoints.cs — FIDO2/WebAuthn credential registration + assertion; Integrations.razor FIDO2 tab (#158) |
| 3 | Solution shall support MFA recovery codes | PC | AuthEndpoints.cs — 10 one-time backup codes, SHA-256 hashed, /api/v1/auth/recovery-codes (#135) |
| 4 | Solution shall support SMS-based OTP | PC | SmsOtpService.cs — Twilio/AWS SNS; /api/v1/auth/sms-otp/send + /verify; 6-digit code, 5-min TTL, 3-attempt limit (#215) |
| 5 | Solution shall support email-based OTP | PC | EmailOtpService.cs — 6-digit code, 10-min TTL, 3-attempt limit, IP-logged; /api/v1/auth/email-otp/send + /verify (#178) |
| 6 | Solution shall support push notifications | PC | PushMfaService.cs — device token registration, push challenge + approve/deny; /api/v1/auth/push-mfa/* (#196) |
| 7 | Solution shall support hardware tokens (OATH) | PC | HardwareTokenEndpoints.cs — POST/GET/DELETE /api/v1/auth/hardware-tokens; POST /verify-hardware-otp; RFC 4226 HOTP (±5 window) + RFC 6238 TOTP (±1 period); SHA1/256/512; AES-GCM encrypted secret; Login.razor HardwareToken MFA step; Integrations.razor admin tab (#261) |
| 8 | Solution shall support adaptive MFA | PC | AdaptiveMfaService.cs — risk-score-driven step-up; low risk → no MFA, medium → TOTP, high → FIDO2; configurable thresholds (#205) |
| 9 | Solution shall support MFA bypass policies | PC | PolicyEndpoints.cs — bypass conditions (Windows Auth/Kerberos, trusted network CIDR, trusted device) |
| 10 | Solution shall support MFA enrollment self-service | PC | SelfService.razor — MFA enrollment tab: enroll TOTP, register FIDO2 key, add phone/email; user-initiated without admin |
| 11 | Solution shall support MFA audit logging | FC | AuditService.cs — all MFA events logged (enroll, verify, fail, bypass, revoke) |
| 12 | Solution shall support MFA device management | PC | MfaDeviceEndpoints.cs — list enrolled devices, revoke specific device, admin bulk-revoke; SelfService.razor device list (#232 Sprint 32) |
| 13 | Solution shall support MFA for privileged operations | PC | JitEndpoints.cs + BreakGlassEndpoints.cs — MFA required for privilege elevation and emergency access |
| 14 | Solution shall support MFA for admin access | PC | Login.razor + AuthEndpoints.cs — MFA enforced for all admin roles |
| 15 | Solution shall support MFA reporting | PC | MfaReportEndpoints.cs — enrollment status, usage breakdown, success/failure rates (#174) |
| 16 | Solution shall support MFA exception management | PC | Admin creates/approves time-limited bypass; self-service request; login flow checks active exception; usage-counted; 72h max; audit trail |
| 17 | Solution shall support MFA for API access | PC | ApiKeyEndpoints.cs — HMAC-SHA256 signed API keys; X-Api-Key + X-Timestamp + X-Signature headers; ±5 min replay protection; IP CIDR restriction; usage audit log; ApiKeyAuthMiddleware injects JWT before UseAuthentication (#250) |
| 18 | Solution shall support MFA for service accounts | PC | ApiKey entity — IsServiceAccount flag on User; service accounts use HMAC-signed API key instead of interactive MFA; ReadOnly role assigned; one-time key+HMAC secret returned on creation (#250) |
| 19 | Solution shall support MFA throttling | PC | SmsOtpService.cs + EmailOtpService.cs — 3-attempt limit per session; rate limiting on MFA endpoints |
| 20 | Solution shall support MFA session persistence | PC | MfaTrustedSession entity — BrowserFingerprint (SHA-256) + TrustExpiresAtUtc; POST /trusted-sessions creates trust; login checks trusted session → skips MFA; "Trust this browser" checkbox in Login.razor; self-service revoke in SelfService.razor; admin bulk revoke; MaxMfaTrustHours policy (mfa.trust.max_hours SystemConfig, max 168h); 3 audit events (#257) |
| 21 | Solution shall support MFA for remote access | PC | SSH/RDP/VNC session start — MFA verified JWT required at session creation |
| 22 | Solution shall support MFA for privileged workstations | PC | DeviceMfaPolicyEndpoints.cs — CRUD + /effective; step-up MFA at session launch; IMemoryCache 15-min token; TOTP verify; Policies.razor Device MFA tab; 2 audit events: SESSION_MFA_STEP_UP_REQUIRED/COMPLETED; admin/vendor bypass (#270) |
| 23 | Solution shall support MFA token synchronization | PC | HardwareTokenEndpoints.cs — RFC 4226 §7.4 resync (window=100); POST /resync self-service 2-OTP; POST /admin-resync counter override; GET /drift-report last-7-days; SelfService.razor Resync modal; Integrations.razor Admin Resync + Drift Report; 3 audit events (#277) |
| 24 | Solution shall support group/role based MFA policy | PC | PolicyEndpoints.cs — per-role MFA enforcement rules + adaptive MFA thresholds by role |

## Remote Access (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|------|
| 1 | Solution shall support SSH access | FC | OrkunPAM.SshProxy — native C# SSH proxy (RFC 4253); credential injection, session recording, command filter, risk scoring |
| 2 | Solution shall support RDP access | PC | OrkunPAM.RdpProxy — TCP relay + PAM DB integration, session lifecycle, admin termination (#110, #223) |
| 3 | Solution shall support VNC access | PC | OrkunPAM.VncProxy — native C# RFC 6143 (#101) |
| 4 | Solution shall support Telnet access | PC | OrkunPAM.TelnetProxy — native C# RFC 854, session recording, credential injection |
| 5 | Solution shall support HTTP/HTTPS access | PC | OrkunPAM.HttpProxy — native C# reverse proxy + CONNECT tunnel; session recording (#102) |
| 6 | Solution shall support database access | PC | OrkunPAM.SqlProxy — native C# TDS protocol; SQL Server session proxying (#64) |
| 7 | Solution shall support TACACS+ | PC | OrkunPAM.TacacsProxy — native C# TACACS+ (RFC 1492) built-in server; Cisco/Juniper/Aruba AAA (#111) |
| 8 | Solution shall support network segmentation |  |  |
| 9 | Solution shall support jump server functionality | PC | All proxy services act as PAM jump servers — sessions route through PAM before reaching targets |
| 10 | Solution shall support session recording | PC | SshServerSession.cs — asciinema_v2 format; RdpServerSession.cs + VncSession.cs — binary recording; HTTP + Telnet sessions recorded |
| 11 | Solution shall support session playback | PC | SessionPlayback.razor — asciinema-player (SSH), binary timeline (RDP/VNC/Telnet), keystroke log, risk events, screen captures |
| 12 | Solution shall support session termination | PC | SessionEndpoints.cs — admin POST /terminate; SSH proxy listens for terminate signal; RDP admin termination (#223) |
| 13 | Solution shall support session timeout | PC | PolicyEndpoints.cs — MaxSessionMinutes; SshServerSession.cs enforces; sessions auto-terminated on timeout |
| 14 | Solution shall support session concurrency control | PC | PolicyEndpoints.cs — MaxConcurrentSessions per user/device; enforced at session creation |
| 15 | Solution shall support bandwidth management |  |  |
| 16 | Solution shall support QoS for sessions |  |  |
| 17 | Solution shall support session multiplexing |  |  |
| 18 | Solution shall support connection pooling | PC | SshProxyService.cs — connection pooling for SSH multiplexing |
| 19 | Solution shall support connection load balancing | PC | RDS Gateway integration — session load distribution (#110) |
| 20 | Solution shall support geo-redundancy |  |  |
| 21 | Solution shall support session watermarking | PC | SessionWatermarkService.cs — user/IP/timestamp overlay injected into session stream (#190) |
| 22 | Solution shall support session annotation | PC | SessionTagEndpoints.cs — tags/annotations per session; Sessions.razor Tagging tab (#216) |
| 23 | Solution shall support session search | PC | Sessions.razor — search/filter by user, device, date, status, tags |
| 24 | Solution shall support printer redirection control | PC | RdpProxyService.cs — printer/drive redirection audit |
| 25 | Solution shall support drive mapping control | PC | RdpProxyService.cs — drive mapping control in RDP session |
| 26 | Solution shall support USB control | PC | PeripheralRedirectionPolicy entity + migration (20260521_AddPeripheralRedirectionPolicy) — AllowClipboard/Drive/Printer/USB/Audio/SmartCard per DeviceGroup; PeripheralPolicyEndpoints.cs (5 CRUD + GET /effective); RdpCommandAuditor.ShouldBlockPdu() — CLIPRDR/RDPDR/RDPSND channels; RdpServerSession fetches policy at session start; Policies.razor Peripheral Control tab (#249) |
| 27 | Solution shall support application control | PC | CommandFilterPolicy + CommandFilterPolicyRule entities + migration (20260520_AddCommandFilterPolicy); CommandFilterPolicyEndpoints.cs — CRUD + rule management + /effective (SSH-compatible JSON); PolicyEndpoints.cs GET /api/v1/policy/session caches active policy (5min TTL); CommandFilterService.cs enforcement in SSH proxy; Policies.razor Command Filter tab (#231, #234) |
| 28 | Solution shall support screen capture | PC | ScreenCaptureFrame entity (ProxySession.cs) + migration (20260521_AddScreenCaptureFrame); ScreenCaptureEndpoints.cs (3 endpoints); VncSession.cs: ServerInit width/height parse + 5s periodic capture timer; RdpServerSession.cs: 5s periodic capture timer; PamApiClient.ReportScreenCaptureAsync() in both proxies; SessionPlayback.razor Screen Captures tab (timeline table + progress bar) (#240) |
| 29 | Solution shall support keystroke logging | FC | SshServerSession.cs — every keystroke/command logged with timestamp; CommandLog table; Sessions.razor KeyLog tab |
| 30 | Solution shall support screen recording | PC | ScreenCaptureFrame entity stores periodic session capture markers; VncSession + RdpServerSession 5-second timer; SessionPlayback.razor Screen Captures timeline (#240) |
| 31 | Solution shall support session analytics | PC | PamApiService.cs live session client methods + DTOs (GetLiveSessionsAsync, GetSessionLogsAsync); Sessions.razor Compliance tab (Sprint 38) |
| 32 | Solution shall support session risk scoring | PC | CommandFilterService.cs — per-command risk score; Sessions.razor risk column; AnomalyDetectionService.cs overall session risk |
| 33 | Solution shall support session compliance | PC | SessionComplianceEndpoints.cs — /summary, /violations, /governance-report; Sessions.razor Compliance tab; compliance rate stat, violation breakdown, top violating users/devices, CSV export (#236) |
| 34 | Solution shall support session governance | PC | SessionComplianceEndpoints.cs /governance-report — policy adherence, high-risk sessions, violation trends; Sessions.razor Compliance tab; CSV export; CredentialGovernanceEndpoints.cs (#236, #239) |
| 35 | Solution shall support session audit | FC | AuditService.cs — SESSION_STARTED/ENDED/TERMINATED + all session lifecycle events logged |
| 36 | Solution shall support session alerts | PC | SessionEventRelayService.cs — real-time session risk alerts via SignalR; CredentialAlertService.cs — rotation failure + expiry alerts |
| 37 | Solution shall support session policies | PC | PolicyEndpoints.cs — session timeout, concurrency, command filter policies; PeripheralRedirectionPolicy for RDP/VNC |
| 38 | Solution shall support session reporting | PC | Sessions.razor — session list, compliance tab; Reports.razor — session activity reports |
| 39 | Solution shall support session approval | PC | Approvals.razor + ApprovalsEndpoints.cs — pre-session approval workflow, JIT access requests |
| 40 | Solution shall support session collaboration | PC | ShadowEndpoints.cs — POST/DELETE /shadow (DB-tracked, audit); SessionShadow.razor — real-time terminal viewer; SSH proxy live chunk streaming; SessionChunkStore ring buffer; RFP RA #40 (#258) |
| 41 | Solution shall support session handoff | PC | SessionHandoffEndpoints.cs — POST /handoff (request), /handoff/accept, /handoff/decline, GET /handoff/pending; Sessions.razor — Handoff button + pending badge + modals; 5 audit events; 15 min TTL auto-expire; RFP RA #41 (#263) |
| 42 | Solution shall support session delegation | PC | SessionDelegationEndpoints.cs — POST /delegations (grant), GET /delegations (list), GET /delegations/my (received+granted), DELETE /delegations/{id} (revoke), GET /delegations/check; SessionDelegation entity + EF migration; Sessions.razor Delegations tab + Grant modal; 3 audit events; auto-expire + usage-count limit; RFP RA #42 (#269) |
| 43 | Solution shall support session federation |  |  |
| 44 | Solution shall support multi-protocol sessions | PC | SSH + RDP + VNC + HTTP + SQL + TACACS+ + RADIUS + Telnet — 8 protocols via unified PAM |
| 45 | Solution shall support session export | PC | SessionEndpoints.cs — GET /export (ZIP: metadata + recording); GET /export/bulk (multi-session ZIP); SessionPlayback.razor download button; RFP RA #45 (#239) |
| 46 | Solution shall support session import |  |  |
| 47 | Solution shall support session restoration |  |  |
| 48 | Solution shall support RADIUS access | PC | OrkunPAM.RadiusProxy — native C# RADIUS (RFC 2865/2866) UDP :1812/:1813; PAP/CHAP auth; audit events |

## Password Vault (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|------|
| 1 | Solution shall support credential storage | FC | VaultEncryptionService.cs — AES-256-GCM encrypted storage |
| 2 | Solution shall support credential retrieval | PC | VaultEndpoints.cs — GET /api/v1/vault/credentials/{id}/checkout; RBAC enforced |
| 3 | Solution shall support credential checkout | PC | VaultEndpoints.cs — checkout (time-limited), checkin, concurrent checkout policy |
| 4 | Solution shall support credential rotation | PC | AutoRotationService.cs — scheduled rotation; SSH/Windows/DB connectors; RotationScript support |
| 5 | Solution shall support credential sharing | PC | VaultEndpoints.cs — share endpoint; AssignedCredential entity |
| 6 | Solution shall support credential access policies | PC | PolicyEndpoints.cs — credential access policies; DeviceRealm access matrix |
| 7 | Solution shall support credential versioning | PC | CredentialHistory entity — password history for rotation tracking |
| 8 | Solution shall support credential audit | FC | AuditService.cs — all credential access/checkout/rotation events logged |
| 9 | Solution shall support credential import | PC | Vault.razor — manual import; batch credential creation |
| 10 | Solution shall support credential export | PC | CredentialGovernanceEndpoints.cs GET /export — CSV metadata export (no passwords); audit logged (#239 Sprint 39) |
| 11 | Solution shall support credential search | PC | Vault.razor — filter by name, device, type, risk level |
| 12 | Solution shall support credential federation |  |  |
| 13 | Solution shall support credential discovery | PC | DiscoveryEndpoints.cs — AD-based privileged account scan; bulk vault import (#189) |
| 14 | Solution shall support credential reconciliation | PC | ReconciliationEndpoints.cs — PAM vs AD credential drift detection (#195) |
| 15 | Solution shall support credential risk scoring | PC | CredentialRiskScoringService.cs — 7 risk factors; Vault.razor risk badge; Home.razor widget (#232) |
| 16 | Solution shall support credential alerts | PC | CredentialAlertService.cs — daily expiry + critical-risk email alerts; Home.razor Rotation Failures widget (#235, Sprint 39) |
| 17 | Solution shall support credential governance | PC | CredentialGovernanceEndpoints.cs — summary, access-matrix, stale-access, export; CredentialGovernance.razor (#236 Sprint 39) |
| 18 | Solution shall support credential lifecycle management | PC | AccountLifecycleJob.cs + AutoRotationService.cs — full lifecycle: create, rotate, expire, revoke |
| 19 | Solution shall support credential access reviews | PC | Compliance.razor Certification tab — credential access review campaigns |
| 20 | Solution shall support credential access matrix | PC | CredentialGovernanceEndpoints.cs /access-matrix — who has access to what, paginated (#239 Sprint 39) |
| 21 | Solution shall support credential templates | PC | CredentialTemplate entity + migration (20260521_AddCredentialTemplate); 8 built-in templates (linux-root, windows-admin, mssql-sa, cisco-enable, etc.); CredentialTemplateEndpoints.cs — CRUD + apply (AdminPolicy, built-in read-only); Vault.razor Templates tab (#248) |
| 22 | Solution shall support credential classification | PC | CredentialKind enum (SSH/Password/ApiKey/Certificate/WindowsService/DatabaseService/NetworkDevice/NasDevice) + DeviceType enum — classification at template + credential level |
| 23 | Solution shall support credential encryption | FC | VaultEncryptionService.cs — AES-256-GCM 3-tier key hierarchy |
| 24 | Solution shall support credential backup | PC | BackupService.cs — encrypted backup includes vault credentials; AES-256-GCM backup encryption |
| 25 | Solution shall support credential analytics | PC | CredentialRiskEndpoints.cs — risk-summary, high-risk list; ThreatAnalytics.razor |
| 26 | Solution shall support credential compliance | PC | ComplianceReportEndpoints.cs — credential-related compliance items in SOX/PCI-DSS reports |
| 27 | Solution shall support privileged account management | PC | VaultEndpoints.cs + Vault.razor — full privileged account CRUD; rotation; risk scoring |
| 28 | Solution shall support service account management | PC | CredentialKind.WindowsService/DatabaseService — service account type classification; rotation connectors |
| 29 | Solution shall support application account management | PC | CredentialKind.ApiKey — application credential management |
| 30 | Solution shall support cloud credential management | PC | CloudEndpoints.cs — AWS/Azure/GCP JIT credential provisioning (#37) |
| 31 | Solution shall support database credential management | PC | CredentialKind.DatabaseService + SqlProxy — database credential management + session proxying |
| 32 | Solution shall support network device credential management | PC | CredentialKind.NetworkDevice + TacacsProxy/RadiusProxy — network device AAA (#111) |
| 33 | Solution shall support certificate management | PC | CertificateEndpoints.cs — X.509 certificate lifecycle: import, expiry tracking, renewal alerts (#191) |
| 34 | Solution shall support SSH key management | PC | SshKeyEndpoints.cs — SSH key pair CRUD, key rotation; Vault.razor SSH Keys tab (#80) |
| 35 | Solution shall support API key management | PC | CredentialKind.ApiKey — API key storage + checkout |
| 36 | Solution shall support token management | PC | JIT token lifecycle (JitEndpoints.cs) + MFA tokens (AuthEndpoints.cs) |
| 37 | Solution shall support credential automation | PC | RotationScript entity + RotationScriptRunner.cs — PowerShell/Bash/Python custom rotation scripts; AutoRotationService.cs custom-script path; Vault.razor Rotation Scripts tab (#241) |
| 38 | Solution shall support credential orchestration | PC | CredentialOrchestrationSet/Member/Run entities + CredentialOrchestrationEndpoints.cs — sequential/parallel multi-credential rotation, rollback-on-failure, email notifications, Vault.razor Orchestration tab (#251) |
| 39 | Solution shall support credential delegation | PC | AssignedCredential entity + AssignedCredentialEndpoints.cs — Kron PAM model credential delegation per user/group+device (#186, Sprint 24) |
| 40 | Solution shall support credential synchronization | PC | AutoRotationService.cs — rotation-based sync; AD sync for discovered credentials |
| 41 | Solution shall support credential mapping | PC | AssignedCredential — user→credential→device mapping |
| 42 | Solution shall support credential tagging | PC | Vault.razor — credential type/kind classification acts as tags |
| 43 | Solution shall support credential access logging | FC | AuditService.cs — all CREDENTIAL_ACCESSED/CHECKED_OUT/ROTATED events |
| 44 | Solution shall support credential policy enforcement | PC | PolicyEndpoints.cs — rotation period, complexity, checkout duration |
| 45 | Solution shall support credential expiry management | PC | AccountLifecycleJob.cs — ExpiresAtUtc check; CredentialAlertService.cs — 7-day expiry alerts |
| 46 | Solution shall support credential rotation scheduling | PC | AutoRotationService.cs — daily BackgroundService; RotationPeriodDays per credential |
| 47 | Solution shall support credential rotation reporting | PC | Vault.razor — RotationFailureCount badge; Home.razor Rotation Failures widget (#235) |
| 48 | Solution shall support privileged account onboarding | PC | Vault.razor — manual privileged account onboarding |
