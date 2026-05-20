# PAM RFP Template - Compliance Checklist

> Auto-generated from PAM Template.xlsx. PM Agent uses this for feature gap analysis.
> Status: FC=Fully Compliant, PC=Partially Compliant, NC=Not Compliant
> Last updated: 2026-05-20 (Sprint 32 ✅ MFA Device Management — MfaDeviceEndpoints.cs: GET /api/v1/my/mfa-devices unified list (TOTP/EmailOTP/SMS/FIDO2/Push), DELETE by-type/fido2/push; admin: GET+DELETE /api/v1/admin/users/{id}/mfa-devices/* (AdminPolicy); SelfService.razor Security tab; full audit trail; **RFP MFA #12 → PC**)

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
| 21 | Solution shall support IPv6. |  |  |
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
| 39 | Solution shall provide dashboards for operational visibility. | PC | Dashboard.razor — live stats, session activity, credential status |
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
| 32 | Solution shall support device-based access restrictions | PC | TrustedDevice entity — SHA-256 UA fingerprint, TrustLevel (Unknown/UserRegistered/AdminApproved/ManagedDevice), IsRevoked; DeviceTrustPolicySettings: RequireTrustedDevice, UnknownDeviceAction (Allow/StepUpAuth/Block), MaxTrustAgeDays; login flow enforcement; GET/PUT /api/v1/policy/device-trust + admin device management endpoints; MyDevices.razor user self-service; Policies.razor Device Trust tab (#207) |
| 33 | Solution shall support context-aware access control | PC | Combined policy chain: Adaptive MFA (risk score) + Device Trust + Geolocation + Time-Window + IP allow/deny — all evaluated at login in sequence; access decisions logged to audit trail; GET /api/v1/auth/risk-score; Policies.razor unified policy management (#205, #207, #208) |
| 34 | Solution shall support just-in-time access | PC | JitAccessEndpoints.cs — time-limited JIT credential checkout |
| 35 | Solution shall support access request workflows | PC | Approvals.razor — request + multi-step approval (#79) |
| 36 | Solution shall support access review campaigns | PC | Compliance.razor — attestation campaign manager; campaign creation, reviewer assignments, Approve/Revoke decisions, completion % tracking (#154) |
| 37 | Solution shall support privileged access analytics | PC | AnomalyDetectionService.cs + SocDashboardEndpoints.cs — GET /soc/dashboard: 24h anomaly summary, type breakdown, top risky users; GET /soc/risk-map: per-user risk breakdown; ThreatAnalytics.razor Overview + Risk Map tabs (#35) |
| 38 | Solution shall support user behavior baseline | PC | BehaviorBaselineService.cs — daily background rebuild; TypicalHours/KnownIPs/KnownDevices per user; GET /api/v1/analytics/baselines/{userId}; POST /api/v1/analytics/baselines/rebuild; ThreatAnalytics.razor Baselines tab (#35) |
| 39 | Solution shall support insider threat detection | PC | AnomalyDetectionService.cs — anomaly types: OffHours, UnusualIP, UnusualDevice, FrequencySpike, HighRiskCommand; AlertRule cooldown-gated alerts; alert history; SOC Dashboard anomaly feed; ThreatAnalytics.razor Anomalies tab (#35) |
| 40 | Solution shall support external threat indicators | PC | ThreatFeedService.cs (BackgroundService, saatlik) — AbuseIPDB/Emerging Threats/AlienVault OTX feed entegrasyonu; ThreatIndicator entity (IP/Domain/Hash, Severity, Source, ExpiresAtUtc); AnomalyDetectionService session başlatmada IOC lookup (KnownMaliciousIP +80 risk skoru); feed config CRUD AdminPolicy; ThreatAnalytics.razor Threat Intelligence sekmesi; feed API key AES-256-GCM şifreli; otomatik süresi dolmuş IOC temizliği (#206) |
| 41 | Solution shall support risk-based authentication | PC | AdaptiveMfaHelper.cs — login risk skoru hesaplama (IP baseline, off-hours, frequency faktörleri); risk seviyesine göre MFA zorlama: Low (<25) atlama, Medium (25-50) TOTP, High (50-75) Push MFA, Critical (>90) blok; GET /api/v1/auth/risk-score; Login.razor risk banner; Policies.razor Adaptive MFA sekmesi (#205) |
| 42 | Solution shall support adaptive authentication | PC | AdaptiveMfaHelper.cs — risk skoruna göre dinamik MFA yöntemi seçimi (0-100 skor); AnomalyDetectionService entegrasyonu; GET/PUT /api/v1/policy/adaptive-mfa yapılandırılabilir eşikler; session başlatmada anlık risk kontrol; mid-session step-up auth (#205) |
| 43 | Solution shall support passwordless authentication | PC | Fido2Endpoints.cs — FIDO2/WebAuthn passkey authentication; passwordless portal login with hardware security keys or platform authenticators; user self-enrollment UI (#158) |
| 44 | Solution shall support biometric authentication |  |  |
| 45 | Solution shall support hardware token support | PC | Fido2Endpoints.cs — YubiKey (roaming authenticator) + Windows Hello (platform); FIDO2.NET library; hardware-bound credential; PkiEndpoints.cs — physical smart card via X.509 cert (#115, #158) |
| 46 | Solution shall support smart card authentication | PC | PkiEndpoints.cs — POST /api/v1/auth/pki/login; X.509 cert from request body or X-Client-Cert header; TrustedCaCertificate chain validation; User.RequirePkiAuth flag; JWT issuance with mfaVerified=true (#115) |
| 47 | Solution shall support certificate-based authentication | PC | PkiEndpoints.cs — TrustedCaCertificate + PkiUserCertificate entities; AdminPolicy CRUD; X.509 chain + expiry validation; rate-limited PKI login; Integrations.razor PKI tab (Trusted CAs + User Certificates sub-tabs) (#115) |
| 48 | Solution shall support federated identity |  |  |

## Reporting (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|------|
| 1 | Solution shall provide pre-built compliance reports | PC | Reports.razor — 9 pre-built reports: credential-expiry, group-membership, policy-compliance, checkout-history, break-glass, jit-access, privileged-inventory, vendor-access, compliance-summary (#120) |
| 2 | Solution shall support custom report creation | PC | CustomReportEndpoints.cs + CustomReportDefinition entity — ad-hoc query builder: data source (AuditLogs/Sessions/Credentials/Users), date range, per-source filters, column selection, preview table, save/run/delete, CSV export; Reports.razor Custom tab (#169) |
| 3 | Solution shall support scheduled report delivery | PC | ReportScheduleEndpoints.cs + ReportSchedulerService.cs — cron-based schedule (daily/weekly/monthly), SMTP email delivery, RBAC-enforced (AdminPolicy); Reports.razor Scheduled Delivery tab (#159) |
| 4 | Solution shall support blocked command reporting | PC | Reports.razor — blocked commands per user/device, filter by risk score; SshServerSession.cs command log (#136) |
| 5 | Solution shall support export in multiple formats | PC | Reports.razor — CSV + JSON export |
| 6 | Solution shall provide executive dashboards | PC | Reports.razor Executive tab — CISO KPI widgets: active sessions, credential rotation rate, policy compliance %, MFA adoption %, failed login count, top risky users, risk trend chart (Chart.js); ReportEndpoints executive-dashboard endpoint (#168) |
| 7 | Solution shall provide operational dashboards | PC | Dashboard.razor — live stats, session/credential/approval metrics |
| 8 | Solution shall support report scheduling | PC | ReportSchedulerService.cs — Hangfire cron scheduler; daily/weekly/monthly cadence; auto-run + email dispatch; schedule CRUD via UI (#159) |
| 9 | Solution shall support report distribution | PC | ReportSchedulerService.cs — SMTP email distribution to configured recipients; HTML-safe email body (HTML-encoded, #176); run-now + scheduled delivery; audit logged (#159, #177) |
| 10 | Solution shall support data retention policies | PC | RecordingRetentionService.cs — configurable retention, auto-purge old recordings |
| 11 | Solution shall support audit log export | PC | AuditService.cs — CSV/JSON export from Reports.razor |
| 12 | Solution shall support compliance frameworks (SOX, PCI, HIPAA) | PC | ComplianceReportEndpoints.cs + ComplianceEndpoints.cs — SOX/PCI-DSS/ISO 27001 pre-built control sets; per-framework pass/fail/partial scoring; control-level evidence drill-down; Reports.razor Compliance tab with framework selector (#179) |
| 13 | Solution shall support regulatory reporting | PC | ComplianceReportEndpoints.cs — POST /api/v1/compliance/report/generate per framework; HTML print-friendly output for auditors; scheduled delivery via ReportSchedulerService.cs; SOX/PCI-DSS/ISO 27001 templates (#179) |
| 14 | Solution shall support risk reporting | PC | SocDashboardEndpoints.cs — GET /soc/risk-map: per-user risk score with anomaly type breakdown; GET /soc/dashboard: top risky users + risk trend; ThreatAnalytics.razor Risk Map tab; session RiskScore in Sessions.razor (#35) |
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
| 25 | Solution shall support failed login report | PC | ReportEndpoints.cs — failed login & brute-force security report: AuditLogs analysis, by-user & by-IP grouping, top-5 attacker summaries, currently locked accounts list (#172) |
| 26 | Solution shall support to view the session logs with filtering and sorting options | PC | Sessions.razor — filter by user, device, protocol, date |
| 27 | Solution shall have reports in both table and chart format | PC | Reports.razor — table + Chart.js bar/pie charts |
| 28 | Solution shall have reports in full text search | PC | Reports.razor — full-text search filter |
| 29 | Solution shall support session recording playback report | PC | SessionPlayback.razor — search + replay with timestamp seek (#34) |
| 30 | Solution shall support anomaly detection reports | PC | SocDashboardEndpoints.cs — GET /soc/timeline?hours=N: hourly anomaly count timeline; GET /soc/alert-history: paginated alert trigger log; GET /api/v1/analytics/anomalies: filterable anomaly list; ThreatAnalytics.razor Overview + Anomalies tabs; Ack button for SOC analysts (#35) |
| 31 | Solution shall support SIEM integration reports | PC | SyslogForwarderService.cs — all events forwarded to SIEM in Syslog/CEF |
| 32 | Solution shall support threat intelligence reports | PC | ThreatFeedService.cs + GET /api/v1/analytics/threat-feed/reports — IOC kaynak dağılımı, hit sayıları, top-5 IOC, aktif feed durumu; ThreatAnalytics.razor Threat Intelligence sekmesi: IOC tablosu, feed konfigürasyonu, son 24h hit listesi; CSV/JSON export; POST /api/v1/analytics/threat-feed/refresh manuel güncelleme (#206) |
| 33 | Solution shall support access pattern analytics | PC | AccessPatternEndpoints.cs — GET /api/v1/reports/access-patterns/summary (top users, targets, peak hours, weekday dist), /time-of-day (24h histogram), /user/{userId} (per-user profile: login hours, top targets, protocol usage, anomalies); AuditLog + ProxySession aggregation; Reports.razor Access Patterns tab; CSV export (#209) |
| 34 | Solution shall support privilege escalation tracking | PC | AuditService.cs — role assignment/escalation events logged |
| 35 | Solution shall support account lifecycle reports | PC | ReportEndpoints.cs — account lifecycle & privilege change history: user/role/password/lock events from AuditLogs, summary counters, per-user event timeline; RFP Reporting #35 (#173) |
| 36 | Solution shall support password rotation reports | PC | Reports.razor — credential rotation history |
| 37 | Solution shall support MFA usage reports | PC | ReportEndpoints.cs — MFA enrollment & usage report: per-user MFA status, MFA event log from AuditLogs, enrollment %, unenrolled users list; RFP Reporting #37 (#174) |
| 38 | Solution shall support API usage reports | PC | AccessPatternEndpoints.cs — GET /api/v1/reports/api-usage/summary (total calls, granted/denied/rate-limited, top clients, hourly trend), /by-client/{id} (per-client endpoint usage, daily trend, source IPs), /anomalies (high denial rate >20%, rate-limit hits); ApiAccessLog aggregation; Reports.razor API Usage tab (#209) |
| 39 | Solution shall support capacity planning reports |  |  |
| 40 | Solution shall support performance reports |  |  |
| 41 | Solution shall support SLA reports |  |  |
| 42 | Solution shall support user activity reports | PC | Reports.razor — per-user activity, session count, credential access |
| 43 | Solution shall support device access reports | PC | Reports.razor — per-device session history |
| 44 | Solution shall support credential usage reports | PC | Reports.razor — checkout-history per credential |
| 45 | Solution shall support geographic access reports | PC | GeoLocationHelper.cs — country-based access control logging; AuditLog GEO_BLOCKED events with country code and IP; Reports.razor Access Patterns tab includes geolocation dimension; geo policy audit in ComplianceReportEndpoints.cs (#208) |
| 46 | Solution shall support time-of-day access reports | PC | AccessPatternEndpoints.cs — GET /api/v1/reports/access-patterns/time-of-day: 24-hour session histogram (hour, sessionCount, uniqueUsers, blockedCount); Reports.razor Access Patterns tab peak-hours chart (#209) |
| 47 | Solution shall support multi-tenant reports |  |  |
| 48 | Solution shall support white-label reports |  |  |

## MFA Manager (24 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|------|
| 1 | Solution shall support TOTP (Time-based One-Time Password) | FC | QrCodeEndpoints.cs — TOTP enroll/verify; RFC 6238 compliant |
| 2 | Solution shall support FIDO2/WebAuthn | PC | Fido2Endpoints.cs — WebAuthn credential registration & assertion; hardware security key (YubiKey/Touch ID) support; FIDO2.NET library; passwordless + MFA second factor; user self-enrollment UI (#158) |
| 3 | Solution shall support MFA recovery codes | PC | 10 one-time backup codes, SHA-256 hashed, one-time use (#135) |
| 4 | Solution shall support SMS-based OTP | PC | SmsGatewayService.cs (Twilio/NetGSM/Webhook, native HttpClient); SmsOtpEndpoints.cs (send/verify, CSPRNG 6-digit, SHA-256 hash, 10-min TTL, 5-fail lockout); SmsOtpTokens migration; Login.razor SMS OTP step; Policies.razor SmsOtpEnabled; Integrations.razor SMS Gateway tab (#215) |
| 5 | Solution shall support email-based OTP | PC | EmailOtpEndpoints.cs — CSPRNG 6-digit OTP; SHA-256 hashed storage; 10-min TTL; single-use; 5-fail lockout; rate-limit 3/15 min; user enumeration prevention; Login.razor Email OTP step; Policies.razor EmailOtpEnabled toggle; audit events (#178) |
| 6 | Solution shall support push notifications | PC | PushMfaEndpoints.cs — device enrollment (POST /auth/push/enroll), challenge creation (POST /auth/push/challenge), mobile app polling (GET /auth/push/challenge/{id}/status), approve/deny (PUT /{id}/approve|deny); 5-min TTL, 1 pending challenge/user; Microsoft Authenticator / Duo-style flow; Login.razor Push step; audit logged (#196) |
| 7 | Solution shall support hardware tokens (OATH) |  |  |
| 8 | Solution shall support adaptive MFA | PC | AdaptiveMfaHelper.cs — risk skoruna göre adaptif MFA seçimi: 0-25 bypass, 25-50 TOTP zorunlu, 50-75 Push MFA zorunlu, >75 çift faktör, >90 blok; yapılandırılabilir eşikler (AdminPolicy); Login.razor adaptif MFA akışı; Policies.razor Adaptive MFA sekmesi; AnomalyDetectionService ile entegre (#205) |
| 9 | Solution shall support MFA bypass policies | PC | windows.auth.mfa_bypass config — Kerberos-authenticated users skip TOTP; configurable per-domain; Integrations.razor Windows Auth tab MFA bypass toggle (#126) |
| 10 | Solution shall support MFA enrollment self-service | PC | QrCodeEndpoints.cs — TOTP self-enrollment via QR code |
| 11 | Solution shall support MFA audit logging | FC | AuditService.cs — MFA verify/fail events logged |
| 12 | Solution shall support MFA device management | PC | MfaDeviceEndpoints.cs — GET /api/v1/my/mfa-devices (unified list: TOTP/EmailOTP/SMS/FIDO2/Push); DELETE by-type/{totp|email_otp|sms}; DELETE fido2/{credId}; DELETE push/{deviceId}; admin: GET+DELETE /api/v1/admin/users/{id}/mfa-devices/* (AdminPolicy); SelfService.razor "Security" tab — enrolled MFA methods table with type badges + inline revoke; full audit trail (Sprint 32) |
| 13 | Solution shall support MFA for privileged operations | PC | MFA enforced at login; required for vault checkout and session start |
| 14 | Solution shall support MFA for admin access | PC | MFA policy applied to all admin roles |
| 15 | Solution shall support MFA reporting | PC | ReportEndpoints.cs — MFA enrollment & usage report: enrollment %, per-user MFA method, unenrolled list, MFA event history from AuditLogs; Reports.razor MFA tab (#174) |
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
|---|-------------|--------|------|
| 1 | Solution shall support SSH remote access | FC | SshProxyService.cs — native C# SSH (RFC 4253) proxy on port 2222; Sprint 29: full PAM-DB session lifecycle — POST /api/v1/ssh/proxy/session-start|session-end|session-status; SshServerSession: StartSessionAsync after credential inject, EndSessionAsync in finally block; SshTargetClient: 15s TCP connect timeout; LoginData.UserId field; GetTargetCredentialAsync returns credentialId |
| 2 | Solution shall support RDP remote access | PC | RdpProxyService.cs — TCP 3389 relay, TPKT/X.224, credential injection |
| 3 | Solution shall support VNC remote access | PC | VncProxyService.cs — RFB protocol relay (#23) |
| 4 | Solution shall support HTTP/HTTPS remote access | PC | HttpProxyService.cs — HTTP reverse proxy, TLS terminate, credential inject |
| 5 | Solution shall support Telnet access | PC | OrkunPAM.TelnetProxy — native C# Telnet proxy (TCP :2323); RFC 854 option negotiation (ECHO, SGA, LINEMODE); PAM credential injection (pamuser@host[:port] login format); bidirectional relay with session recording; TelnetEndpoints.cs admin session management + proxy lifecycle API; SessionType.Telnet = 6 (Sprint 19) |
| 6 | Solution shall support jump server functionality | PC | SshProxyService.cs — PAM SSH proxy acts as jump server |
| 7 | Solution shall support session brokering | PC | SessionEndpoints.cs — session broker: credential inject, token, session start/end; Sprint 27: realm-first brokering — CreateSession/CreateRdpSession/WebSshEndpoints check DeviceRealm coverage before credential injection; accessible-devices filtered by realm membership (GET /api/v1/device-realms/accessible-devices) |
| 8 | Solution shall support network segmentation |  |  |
| 9 | Solution shall support access isolation | PC | SshProxyService.cs — isolated session per user, no lateral movement |
| 10 | Solution shall support session recording | FC | SessionRecordingService.cs — full session recording (text + binary) |
| 11 | Solution shall support session playback | PC | SessionPlayback.razor — asciinema replay, search, timestamp seek (#34) |
| 12 | Solution shall support session termination | PC | SessionEndpoints.cs — DELETE /sessions/{id} + admin terminate via SignalR; Sprint 29: SSH proxy IdleWatchAsync polls PamApiClient.IsTerminatedAsync every 60s — admin session termination propagates to proxy relay; TelnetSession: same pattern (Sprint 21) |
| 13 | Solution shall support session timeout | PC | SessionPolicyService.cs — session duration/idle timeout |
| 14 | Solution shall support connection throttling | PC | SshProxyService.cs — concurrent session limit per policy |
| 15 | Solution shall support bandwidth management |  |  |
| 16 | Solution shall support QoS for sessions |  |  |
| 17 | Solution shall support session multiplexing |  |  |
| 18 | Solution shall support load balancing | PC | RdsLoadBalancer.cs — TCP health-check + least-connections routing across RDS HA cluster nodes; background service with health loop (#110) |
| 19 | Solution shall support failover | PC | RdsLoadBalancer.cs — auto-failover to healthy RDS nodes; unhealthy nodes removed from pool until TCP health check recovers (#110) |
| 20 | Solution shall support geo-redundancy |  |  |
| 21 | Solution shall support session watermarking | PC | WatermarkPolicy entity + WatermarkEndpoints.cs — configurable watermark text (username/IP/timestamp), applied to SSH/RDP/VNC session recordings and metadata; Policies.razor Watermarking tab; CRUD + enable/disable toggle; SessionWatermarkService.cs; audit logged (#190) |
| 22 | Solution shall support clipboard control | PC | RdpProxyService.cs — clipboard channel audit/control in RDP PDU |
| 23 | Solution shall support file transfer control | PC | SshProxyService.cs — SFTP audit/control |
| 24 | Solution shall support printer redirection control | PC | RdpProxyService.cs — printer/drive redirection audit |
| 25 | Solution shall support drive mapping control | PC | RdpProxyService.cs — drive mapping control in RDP session |
| 26 | Solution shall support USB control |  |  |
| 27 | Solution shall support application control |  |  |
| 28 | Solution shall support screen capture |  |  |
| 29 | Solution shall support keystroke logging | FC | SshServerSession.cs — every keystroke/command logged with timestamp |
| 30 | Solution shall support screen recording |  |  |
| 31 | Solution shall support session analytics | PC | PamApiService.cs live session client methods + DTOs (GetLiveSessionsAsync, GetSessionMetricsAsync, TerminateSessionAsync); Sessions.razor Live Monitor tab — active session grid, protocol/user/device filter, admin terminate action (#214); Sprint 28: role-based scope — GET /api/v1/sessions + /active: privileged roles (GlobalAdmin/Auditor/SessionAdmin) see all sessions; regular users see only own sessions (CWE-200/284 fix, closes #221) |
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
| 48 | Solution shall support session tagging | PC | SessionTag + SessionAnnotation entities + migration; SessionTagEndpoints.cs (add/remove tag, add annotation, GET by-tag search); Sessions.razor tag badge column + Add Tag/Add Note modals; SessionPlayback.razor annotation panel; audit events: SessionTagAdded/Removed/AnnotationAdded (#216) |
| 153 | Solution shall support recording of SSH/CLI/RDP/VNC sessions | PC | SessionRecordingService.cs — SSH/RDP/VNC/HTTP recording + playback (#34) |
| 158 | Solution shall support time-based access restrictions | PC | AccessPolicyService.cs — AllowedTimeWindows: Mon-Fri 09:00-18:00 configurable |

## Password Vault (48 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|------|
| 1 | Solution shall support credential storage | FC | CredentialEndpoints.cs + VaultEncryptionService.cs — AES-256-GCM encrypted credential store |
| 2 | Solution shall support credential retrieval | FC | CredentialEndpoints.cs — RBAC-enforced checkout flow |
| 3 | Solution shall support credential rotation | PC | CredentialEndpoints.cs — manual rotation; auto-rotation Hangfire job |
| 4 | Solution shall support credential expiry | PC | CredentialEndpoints.cs — expiry date, Reports.razor credential-expiry report |
| 5 | Solution shall support credential discovery | PC | DiscoveryEndpoints.cs — POST /api/v1/vault/discovery (create scan config), POST /{id}/run (trigger AD scan); AD group-based privileged account discovery + bulk import to vault; DiscoveredCredential entity with status lifecycle; audit logged (#189) |
| 6 | Solution shall support credential onboarding | PC | Vault.razor — Add Credential form; manual onboarding |
| 7 | Solution shall support credential lifecycle management | PC | CredentialEndpoints.cs — create/update/rotate/archive/delete |
| 8 | Solution shall support credential access control | PC | GroupEndpoints.cs + CredentialEndpoints.cs — group-based access binding |
| 9 | Solution shall support credential audit trail | FC | AuditService.cs — all credential access, checkout, rotation events logged |
| 10 | Solution shall support credential sharing | PC | GroupEndpoints.cs — group-level credential sharing |
| 11 | Solution shall support credential delegation | PC | AssignedCredential entity — maps Credential → User/Group with optional DeviceGroup scope (Kron PAM assigned_credential model); AssignedCredentialEndpoints.cs (CRUD admin + /my-credentials user endpoint + toggle); CredentialAssignments.razor UI; FK cascade delete + SetNull on DeviceGroup (Sprint 24); full audit trail via AuditService.cs (assign/revoke events logged); unique constraint prevents duplicate assignments (Sprint 25, fixes #217 #218) |
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
| 27 | Solution shall support credential checkout | PC | CredentialEndpoints.cs — self-assignment prevention: PasswordViewer cannot be granted by same user (#140); POST /api/v1/vault/credentials/{id}/request-access — approval-gated checkout: reason + ticket, 48h TTL, duplicate detection, admin group notification; Vault.razor Request Access modal (Sprint 14) |
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
| 41 | Solution shall support certificate management | PC | CertificateEndpoints.cs + Certificates.razor — X.509 certificate inventory: import PEM/PFX, expiry tracking (Subject/Issuer/Thumbprint/NotAfter), expiry alert emails; Vault.razor Certificates tab; Certificate entity + DB migration; audit logged (#191) |
| 42 | Solution shall support service account management | PC | CredentialEndpoints.cs — service account type credentials |
| 43 | Solution shall support cloud credential management | PC | CloudEndpoints.cs + CloudPam.razor — AWS IAM/EC2/S3, Azure VM/KeyVault/SPN, GCP CE/SA/GCS credential management; cloud account CRUD; resource sync; multi-cloud dashboard (#37) |
| 44 | Solution shall support database credential management | PC | CredentialEndpoints.cs — DB credential type (SQL Server, MySQL, PostgreSQL) |
| 45 | Solution shall support application credential management | PC | CredentialEndpoints.cs — API/app credential type |
| 46 | Solution shall support network device credential management | PC | CredentialEndpoints.cs + TacacsProxyService.cs — network device credential type |
| 47 | Solution shall support privileged account discovery | PC | GET /api/v1/users/orphaned — orphaned privileged accounts flagged with IsOrphaned + OrphanedDetectedAtUtc; Users.razor orphaned badge + filter; UserDto includes IsOrphaned field (#153); DiscoveryEndpoints.cs — AD group-based privileged account scanning + bulk vault import (#189) |
| 48 | Solution shall support privileged account onboarding | PC | Vault.razor — manual privileged account onboarding |

## Session Manager (162 items)