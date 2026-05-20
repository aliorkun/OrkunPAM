# Orkun PAM - Sprint Planı

> Agent'lar bu dosyayı okuyarak hangi sprint'te olduğumuzu ve öncelikleri anlar.

## ~~Sprint 1 - Security Hardening~~ ✅ TAMAMLANDI
**Tarih:** 10-13 Mayıs 2026
**Durum:** Tamamlandı — 43 security bulgu fix'lendi (11 critical, 15 high, 13 medium)
**Tag:** `v0.2.0-security-hardened`

---

## ~~Sprint 2 - SSH Proxy + Temel UI~~ ✅ TAMAMLANDI
**Tarih:** 14-20 Mayıs 2026
**Durum:** Tamamlandı — Native SSH proxy, Web terminal, Session recording, Blazor UI, SAML SSO

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #21 | SSH Proxy - native C# | MVP-SESSION | ✅ Kapatıldı |
| #25 | HTML5 Web SSH Terminal | MVP-SESSION | ✅ Kapatıldı |
| #47 | Session Recording | MVP-SESSION | ✅ Kapatıldı |
| #20 | Blazor Admin Dashboard (login, dashboard, nav) | MVP-UI | ✅ Kapatıldı |
| #45 | SAML 2.0 / SSO | MVP-AUTH | ✅ Kapatıldı |

**İlerleme:** 5/5 tamamlandı (%100) ✅
**Tag:** `v0.3.0-ssh-proxy`

---

## ~~Sprint 3 - RDP + Vault + Reporting~~ ✅ TAMAMLANDI
**Tarih:** 21-27 Mayıs 2026
**Durum:** Tamamlandı — RDP Proxy TCP relay, Raporlar & Audit UI, Parola Rotasyonu, Onay Akışı UI

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #23 | RDP Proxy - TCP relay + session token flow | MVP-SESSION | ✅ Kapatıldı |
| #27 | Temel Raporlar | MVP-REPORTING | ✅ Kapatıldı |
| #32 | Otomatik Parola Rotasyonu | MVP-VAULT | ✅ Kapatıldı |
| #79 | Onay Akışı Yönetim Paneli | MVP-UI | ✅ Kapatıldı |

**İlerleme:** 4/4 tamamlandı (%100) ✅
**Not:** Sprint 3, planlanan 21-27 Mayıs tarihinden önce (13 Mayıs) tamamlandı — 8 gün erken.
**Tag:** `v0.4.0-rdp`

---

## ~~Sprint 4 - Enterprise Features + Installer~~ ✅ TAMAMLANDI
**Tarih:** 14-24 Mayıs 2026
**Durum:** Tamamlandı — Enterprise demo hazır, MSI installer çalışıyor

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #46 | Break-the-Glass acil erişim | MVP-SECURITY | ✅ Kapatıldı |
| #54 | SMTP Bildirim | MVP-INFRA | ✅ Kapatıldı |
| #53 | BYOK + Key Rotation UI | MVP-SECURITY | ✅ Kapatıldı |
| #38 | JIT Privileged Access | MVP-SECURITY | ✅ Kapatıldı |
| #40 | Privileged Account Discovery | MVP-DEVICE | ✅ Kapatıldı |
| #63 | SIEM Syslog/CEF Entegrasyonu | MVP-INTEGRATION | ✅ Kapatıldı |
| #39 | Self-Service Portal | MVP-UX | ✅ Kapatıldı |
| #55 | Backup/DR | MVP-DEPLOYMENT | ✅ Kapatıldı |
| #36 | MSI Installer | MVP-UX | ✅ Kapatıldı |

**İlerleme:** 9/9 tamamlandı (%100) ✅
**Tag:** `v1.0.0-rc1` ✅

---

## ~~Sprint 5 - Ek MVP Features + Audit Chain~~ ✅ TAMAMLANDI
**Tarih:** 25 Mayıs - 4 Haziran 2026
**Durum:** Tamamlandı — Tamper-proof audit chain, LDAP sync, CSV export, MFA TOTP, SSH key mgmt

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #91 | Tamper-Proof Audit Log - Hash Chain | MVP-SECURITY | ✅ Kapatıldı |
| #90 | LDAP/AD Zamanlanmış Senkronizasyon | MVP-INTEGRATION | ✅ Kapatıldı |
| #89 | Rapor CSV/PDF Export ve Zamanlama | MVP-REPORTING | ✅ Kapatıldı |
| #85 | Toplu Kullanıcı İçe Aktarma (CSV) | MVP-USER | ✅ Kapatıldı |
| #84 | Session Policy Runtime Enforcement | MVP-SECURITY | ✅ Kapatıldı |
| #83 | MFA TOTP QR Code Enrollment | MVP-AUTH | ✅ Kapatıldı |
| #80 | SSH Key Yönetimi | MVP-VAULT | ✅ Kapatıldı |

**İlerleme:** 7/7 tamamlandı (%100) ✅
**Tag:** `v1.0.0-rc2`

---

## ~~Sprint 6 - Polish + Proxy Completion + GA~~ ✅ TAMAMLANDI
**Tarih:** 13-14 Mayıs 2026
**Durum:** Tamamlandı — Tüm proxy'ler ✅ + E2E test suite ✅ + perf-baseline.md ✅

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #64 | SQL Database Proxy | MVP-SESSION | ✅ Tamamlandı |
| #101 | VNC Proxy — Native C# RFC 6143 | MVP-PROXY | ✅ Tamamlandı |
| #102 | HTTP/HTTPS Reverse Proxy — Native C# | MVP-PROXY | ✅ Tamamlandı |
| #100 | E2E Test Suite + Performance Benchmark | MVP-TEST | ✅ Tamamlandı |
| - | Dokümantasyon (docs/perf-baseline.md) | Docs | ✅ Tamamlandı |

**İlerleme:** 5/5 tamamlandı (%100) ✅
**Tag:** `v1.0.0` ✅ (18 Mayıs 2026 atıldı)

**E2E Test Detayları:**
- `OrkunPAM.E2ETests` projesi oluşturuldu (tests/ altında)
- 30+ test, `[Trait("Category","E2E")]` ile filtrelenebilir
- Kapsam: HttpRequestParser (11), TdsPacket (8), SshEncoding (11), CryptoPerformance (6), HttpProxyE2E (4)
- `docs/perf-baseline.md` commit'lendi — AES-256-GCM < 0.1 ms/op (hedef < 5 ms) ✅

---

## ~~Sprint 7 - v2.0.0 Network Device Access (TACACS+/RADIUS)~~ ✅ TAMAMLANDI
**Tarih:** 14 Mayıs 2026
**Durum:** Tamamlandı — TACACS+/RADIUS native C# + RDP Full Integration

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #111 | TACACS+/RADIUS Built-in Server | v2-PROXY | ✅ Kapatıldı |
| #110 | RDP Full Integration (RDS Gateway) | v2-PROXY | ✅ Kapatıldı |
| #112 | Multi-Tenancy (MSP) | v2-ARCH | 🔲 v3+ ertelendi (CLAUDE.md) |

**İlerleme:** 2/2 aktif item = %100 ✅

---

## ~~Sprint 8 - v2.0.0 RFP Gap Features (O&M + Reporting + Compliance)~~ ✅ TAMAMLANDI
**Tarih:** 16 Mayıs 2026
**Durum:** Tamamlandı — System Health, Connection Scheduling, Orphaned Accounts, Access Certifications, Multi-Language UI

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #138 | System Health Monitoring & O&M Dashboard | v2-INFRA | ✅ Tamamlandı |
| #142 | Connection Scheduling (Future Date Reservation) | v2-SESSION | ✅ Tamamlandı |
| #153 | Privileged Account Discovery & Orphaned Account | v2-VAULT | ✅ Tamamlandı |
| #154 | Access Certification Campaigns | v2-COMPLIANCE | ✅ Tamamlandı |
| #143 | Multi-Language UI (TR/EN) | v2-PLATFORM | ✅ Tamamlandı |

**İlerleme:** 5/5 issue (%100) ✅

---

## ~~Sprint 9 - RFP Gap: Reporting + Auth + CLI~~ ✅ TAMAMLANDI
**Tarih:** 16-22 Mayıs 2026
**Durum:** Tamamlandı — Reporting, MFA, UX RFP boşluklarını kapattı

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #160 | O&M System Log Viewer | v2-INFRA | ✅ Tamamlandı |
| #159 | Scheduled Report Delivery | v2-REPORTING | ✅ Tamamlandı |
| #168 | Executive Dashboard & CISO KPIs | v2-REPORTING | ✅ Tamamlandı |
| #150 | Native CLI Connection Profiles | v2-UX | ✅ Tamamlandı |
| #158 | FIDO2/WebAuthn | v2-MFA | ✅ Tamamlandı |

**İlerleme:** 5/5 (%100) ✅

---

## ~~Sprint 10 - RFP Gap: Reporting Round 2 + Auth + Desktop Client~~ ✅ TAMAMLANDI
**Tarih:** 16-25 Mayıs 2026
**Durum:** Tamamlandı — PKI auth, ITSM, Custom Reports, Desktop SSO, Security fixes

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #175 | [HIGH] CWE-285: Report Schedule RBAC eksik | security | ✅ Fix'lendi |
| #176 | [MEDIUM] CWE-116: HTML injection e-posta gövdesi | security | ✅ Fix'lendi |
| #177 | [MEDIUM] CWE-778: Audit log eksik (schedule CRUD + email) | security | ✅ Fix'lendi |
| #172 | Failed Login & Brute Force Security Report | v2-REPORTING | ✅ Tamamlandı |
| #173 | Account Lifecycle & Privilege Change Report | v2-REPORTING | ✅ Tamamlandı |
| #174 | MFA Enrollment & Usage Report | v2-REPORTING | ✅ Tamamlandı |
| #169 | Custom Report Builder | v2-REPORTING | ✅ Kapatıldı |
| #170 | Native Desktop Client SSO Launch | v2-SESSION | ✅ Tamamlandı |
| #115 | PKI / Smart Card Authentication | v2-COMPLIANCE | ✅ Tamamlandı |
| #114 | ITSM Integration (ServiceNow/OneDesk) | v2-COMPLIANCE | ✅ Tamamlandı |

**İlerleme:** 10/10 (%100) — Sprint 10 TAMAMLANDI ✅

---

## ~~Sprint 11 - v2 Auth + Compliance~~ ✅ TAMAMLANDI
**Tarih:** 16-25 Mayıs 2026
**Durum:** Tamamlandı — Email OTP MFA, SOX/PCI-DSS/ISO 27001 uyumluluk raporları, FIPS 140-2

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #178 | Email OTP — E-Posta Tabanlı MFA | v2-MFA | ✅ Tamamlandı |
| #179 | SOX / PCI-DSS / ISO 27001 Uyumluluk Rapor Şablonları | v2-COMPLIANCE | ✅ Tamamlandı |
| #180 | FIPS 140-2 Kriptografik Uyumluluk | v2-SECURITY | ✅ Tamamlandı |

**İlerleme:** 3/3 (%100) ✅

---

## ~~Sprint 12 - Cloud PAM~~ ✅ TAMAMLANDI
**Tarih:** 17 Mayıs 2026
**Durum:** Tamamlandı — AWS/Azure/GCP privileged access, JIT cloud erişimi, multi-cloud dashboard

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|-------|
| #37 | Cloud PAM — AWS/Azure/GCP Privileged Access | v2-CLOUD | ✅ Tamamlandı |

**İlerleme:** 1/1 (%100) ✅

**#37 Cloud PAM — Tamamlanan bileşenler (2026-05-17):**
- `CloudAccount` entity: Provider, AccountIdentifier, AccessKeyIdEnc, SecretKeyEnc, LastSyncAtUtc, ResourceCount
- `CloudResource` entity: NativeId, ResourceType, Region, Status, IpAddress, LastSeenAtUtc (cascade delete)
- `CloudJitRequest` entity: Permission, Justification, Status lifecycle, ExpiresAtUtc, CloudGrantReference
- DbContext: CloudAccounts, CloudResources, CloudJitRequests DbSets + model config + FK ilişkileri
- Migration: `20260517_AddCloudPam.cs` — 3 tablo, index'ler
- API: `GET /api/v1/cloud/dashboard` — multi-cloud ozet (hesap, kaynak, JIT sayilari, son istekler)
- API: `GET/POST /api/v1/cloud/accounts` — cloud hesap CRUD
- API: `PUT /api/v1/cloud/accounts/{id}/toggle` — etkinlestir/devre disi
- API: `DELETE /api/v1/cloud/accounts/{id}` — sil
- API: `POST /api/v1/cloud/accounts/{id}/sync` — kaynak kesfsi (AWS EC2/IAM/S3, Azure VM/KeyVault/SPN, GCP CE/SA/GCS simule)
- API: `GET /api/v1/cloud/resources?provider=&type=` — filtrelenebilir kaynak listesi
- API: `PUT /api/v1/cloud/resources/{id}/toggle` — kaynak etkinlestir/devre disi
- API: `GET/POST /api/v1/cloud/jit` — JIT istek olusturma
- API: `PUT /api/v1/cloud/jit/{id}/approve|deny|revoke` — JIT yaslam dongusu
- Audit: CloudAccountCreated/Deleted/Synced, CloudJitRequested/Approved/Denied/Revoked
- `CloudPam.razor`: 4 tab UI — Dashboard (provider kartlari, son JIT), Accounts (CRUD + sync), Resources (filtreli tablo + JIT baslat), JIT (istek formu + onay/reddet/iptal)
- `PamApiService.cs`: GetCloudDashboardAsync, GetCloudAccountsAsync, CreateCloudAccountAsync, SyncCloudAccountAsync, ToggleCloudAccountAsync, DeleteCloudAccountAsync, GetCloudResourcesAsync, GetCloudJitRequestsAsync, CreateCloudJitRequestAsync, ApproveCloudJitAsync, DenyCloudJitAsync, RevokeCloudJitAsync + tum DTO'lar
- NavMenu.razor: "Cloud" section + Cloud PAM linki eklendi

---

## Sprint 13 - v2 RFP Gap: Session Watermarking + Credential Discovery + Certificate Lifecycle
**Tarih:** 17-31 Mayis 2026
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #190 | Session Watermarking — Oturum Kaydi Kullanici Filigrani | v2-SESSION | ✅ Tamamlandi |
| #189 | Credential Discovery — AD Ayricalikli Hesap Tarama | v2-VAULT | ✅ Tamamlandi |
| #191 | Certificate Lifecycle Management — X.509 Sertifika Envanter | v2-VAULT | ✅ Tamamlandi |

**Ilerleme:** 3/3 (%100) ✅ — Sprint 13 tamamlandi

---

## Sprint 14 - UX Polish: Credential Access Request Flow
**Tarih:** 17 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| — | Credential Access Request — Vault UI + API endpoint | UX-fix | ✅ Tamamlandi |

**Detay:**
- `POST /api/v1/vault/credentials/{id}/request-access` — yeni endpoint
  - Duplicate pending request tespiti (409 yerine 200 + status:Pending)
  - Already-approved tespiti (200 + status:Approved)
  - AdminGroup sentinel GUID ile tum adminlere gorunur step olusturur
  - 48 saat TTL
- `Vault.razor` — "Request Access" butonu (RequiresApproval kredansiyellerde)
  - Modal: Reason (zorunlu) + Ticket Number + bilgilendirici uyari
  - Basari/hata mesaji + mevcut pending request bilgisi
- `PamApiService.cs` — `RequestCredentialAccessAsync` + `CredentialAccessRequestResultDto`

**Ilerleme:** 1/1 (%100) ✅

---

## ~~Sprint 14 - UX Polish: Credential Access Request Flow~~ ✅ TAMAMLANDI (DUPLICATE — bkz. onceki Sprint 14 girisi)

---

## Sprint 15 - v2 Security + MFA + Integration RFP Gap ✅ TAMAMLANDI
**Tarih:** 17 Mayis 2026
**Durum:** Tamamlandi — 3 HIGH security fix + Account Reconciliation + Push MFA + SOAR Integration

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #198 | [HIGH] Vault Permission Endpoint — AdminPolicy Eksik | security | ✅ Kapatildi |
| #199 | [HIGH] Credential Share Endpoint — CanShare Dogrulanmiyor | security | ✅ Kapatildi |
| #200 | [HIGH] Vault Folder Credentials Listing — IDOR | security | ✅ Kapatildi |
| #195 | Account Reconciliation — PAM vs AD/LDAP Drift Detection | v2-COMPLIANCE | ✅ Kapatildi |
| #196 | Push Notification MFA — Mobil Push Onay MFA | v2-MFA | ✅ Kapatildi |
| #197 | SOAR Integration — Splunk SOAR / Palo Alto XSOAR | v2-INTEGRATION | ✅ Kapatildi |

**Ilerleme:** 6/6 (%100) ✅

**Sprint 15 Tamamlanan Bilesenler:**
- **#198 fix:** `/api/v1/vault/permissions` → `RequireAuthorization("AdminPolicy")` eklendi (privilege escalation onlendi)
- **#199 fix:** `POST /vault/credentials/{id}/share` → `CanShare` yetkisi enforced (BFLA onlendi)
- **#200 fix:** `GET /vault/folders/{id}/credentials` → folder-level IDOR korumasi (CWE-639 kapatildi)
- **#195:** `GET/POST /api/v1/compliance/reconciliation/report|auto-remediate|history` + Compliance.razor Reconciliation sekmesi
- **#196:** Push MFA endpoints (enroll/devices/initiate/status/respond) + PushDevices.razor + NavMenu linki
- **#197:** SOAR endpoints (config CRUD + 5 inbound action API, HMAC-SHA256 verified) + Integrations.razor SOAR sekmesi

---

## ~~Sprint 16 - v2 Threat Analytics & SOC Dashboard~~ ✅ TAMAMLANDI
**Tarih:** 18 Mayis 2026
**Durum:** Tamamlandi — ML anomali tespiti + BFLA fix + DoS fix + baseline sifreleme + alert actions

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #35 | ML Tabanli Anomali Tespiti ve Risk Skorlama | v2-ANALYTICS | ✅ Tamamlandi |
| #202 | [HIGH] SOC/Analytics API BFLA | security | ✅ Fix'lendi |
| #203 | [MEDIUM] /soc/timeline DoS Riski | security | ✅ Fix'lendi |
| #204 | [MEDIUM] Baseline Plaintext Storage | security | ✅ Fix'lendi |

**Sprint 16 — 2026-05-18 progress:**
- `AnomalyDetectionService` (BackgroundService, 5 dk): off-hours, unusual IP, unusual device, frequency spike, high-risk command anomaly detection
- `BehaviorBaselineService` (BackgroundService, daily): 30 gunluk session history → TypicalHours, KnownIPs, KnownDevices baseline
- `SocDashboardEndpoints`: `/api/v1/analytics/soc/dashboard|timeline|risk-map|alert-history`, `/api/v1/analytics/baselines/`
- Alert rule toggle/delete endpoints
- `ThreatAnalytics.razor`: SOC Dashboard Blazor sayfasi (5 tab: Overview, Anomalies, Risk Map, Alert Rules, Baselines)
- `PamApiService.cs`: 10 yeni analytics metot + DTO'lar
- NavMenu: "Threat Analytics / SOC Dashboard" linki eklendi
- Program.cs: AnomalyDetectionService + BehaviorBaselineService servis kaydi

**Sprint 16 — 2026-05-18 tamamlama (run 2):**
- **#202 fix [HIGH]:** `SocDashboardEndpoints` + `AnalyticsEndpoints` tum MapGroup'larina + standalone endpoint'lere `RequireAuthorization("AdminPolicy")` eklendi (BFLA onlendi)
- **#203 fix [MEDIUM]:** `/soc/timeline` `hours` parametresi 1-168 arasi clamp + `.Take(10_000)` DoS onleme
- **#204 fix [MEDIUM]:** `BehaviorBaselineService` → `KnownIpsJson`/`KnownDevicesJson` AES-256-GCM sifreli (Base64) saklaniyor; `AnomalyDetectionService` decrypt ederek kullaniyor; vault baslatilmadiysa graceful fallback
- **#35 tamamlama:** `FireAlertRulesAsync` → `AlertRuleAction` (SendSiem/SendEmail/EmailTo) parse ediliyor; SIEM: enabled SiemTarget'lara CEF UDP syslog gonderiliyor; Email: `IEmailService.SendAsync` tetikleniyor; `ActionsTaken` alani gercek action listesiyle dolduruluyor
- **UI:** `ThreatAnalytics.razor` alert rule formuna "Forward to SIEM" checkbox + "Send Email" checkbox + recipient email alani eklendi

**Ilerleme:** 1/1 core feature (%100 — Sprint 16 TAMAMLANDI) ✅

---

## ~~Sprint 17 - v2 Auth: Adaptive MFA + Threat Intelligence + Device Trust~~ ✅ TAMAMLANDI
**Tarih:** 18 Mayis 2026
**Durum:** Tamamlandi — Adaptive MFA + Threat Intelligence Feed tamamlandi; Device Trust Sprint 18'e tasindi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #205 | Adaptive MFA — Anomali Skoruna Gore Step-Up Kimlik Dogrulama | v2-SECURITY | ✅ Tamamlandi |
| #206 | Threat Intelligence Feed — IOC/IP Reputation Entegrasyonu | v2-ANALYTICS | ✅ Tamamlandi |
| #207 | Device Trust ve Context-Aware Access Control | v2-ACCESS | Sprint 18'e tasindi |

**Sprint 17 Tamamlanan Bilesenler (#205 — Adaptive MFA):**
- `AdaptiveMfaHelper` static class: `LoadPolicyAsync` + `CalculateLoginRiskAsync` (IP/hours/frequency risk factors)
- `BehaviorBaselineService.DecryptOrDeserialize` → public static (baseline erisimi icin)
- Login endpoint: risk score calculation → riskScore + riskLevel response fields
- Risk "Critical" → 403 login block; Risk "High" → MFA forced (EmailOtp veya Totp)
- `GET /api/v1/auth/risk-score` endpoint
- `GET/PUT /api/v1/policy/adaptive-mfa` policy endpoints
- `AdaptiveMfaPolicySettings` record (Enabled, Low/Medium/High/Block thresholds)
- `PamApiService.cs`: `AdaptiveMfaPolicySettingsDto` + `GetAdaptiveMfaPolicyAsync` + `SaveAdaptiveMfaPolicyAsync` + `LoginData.RiskScore/RiskLevel`
- `Policies.razor`: "Adaptive MFA" sekmesi + threshold form + save
- `Login.razor`: Risk seviyesi uyari banner (Medium/High icin)
- RFP MFA #8 → PC, User Mgmt #41/#42 → PC

**Sprint 17 Tamamlanan Bilesenler (#206 — Threat Intelligence Feed):**
- `ThreatFeedService.cs` (BackgroundService, saatlik): AbuseIPDB/Emerging Threats/AlienVault OTX feed entegrasyonu
- `ThreatIndicator` entity: IndicatorType (IP/Domain/Hash), Value, Severity, Source, ExpiresAtUtc
- `ThreatFeedConfig` entity: feed URL, API key (AES-256-GCM sifreli), refresh interval, enabled flag
- `AnomalyDetectionService` enrichment: session baslatmada IOC lookup → KnownMaliciousIP +80 risk skoru
- API: `GET /api/v1/analytics/threat-feed/indicators|configs|reports` + `POST /refresh`
- `ThreatAnalytics.razor` Threat Intelligence sekmesi: IOC tablosu, feed config yonetimi, 24h hit listesi
- Suresi dolmus IOC'lerin otomatik temizligi
- RFP User Mgmt #40 → PC, Reporting #32 → PC

**Ilerleme:** 2/2 tamamlandi (%100 — Sprint 17 core items) ✅

---

## ~~Sprint 18 - v2 Access Control + Geolocation + Access Analytics~~ ✅ TAMAMLANDI
**Tarih:** 18-25 Mayis 2026
**Durum:** Tamamlandi — Device Trust, Geolocation Access, Access Pattern Analytics tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #207 | Device Trust ve Context-Aware Access Control | v2-ACCESS | ✅ Tamamlandi |
| #208 | Geolocation-based Access Control | v2-ACCESS | ✅ Tamamlandi |
| #209 | Access Pattern Analytics & API Usage Reporting | v2-REPORTING | ✅ Tamamlandi |

**Ilerleme:** 3/3 (%100) ✅ — Sprint 18 TAMAMLANDI

**#207 Device Trust — Tamamlanan bilesenler (2026-05-18):**
- `TrustedDevice` entity: DeviceFingerprint (SHA-256 of UA), UserId, TrustLevel (Unknown/UserRegistered/AdminApproved/ManagedDevice), IsRevoked, LastSeenAtUtc
- DbContext: TrustedDevices DbSet + model konfigurasyonu + unique index (UserId, DeviceFingerprint)
- `DeviceTrustPolicySettings`: Enabled, RequireTrustedDevice, UnknownDeviceAction (Allow/StepUpAuth/Block), MaxTrustAgeDays, AutoRegisterOnLogin
- `GET/PUT /api/v1/policy/device-trust` — policy CRUD (AdminPolicy)
- `GET /api/v1/my/trusted-devices` — user's own devices
- `PUT /api/v1/my/trusted-devices/{id}/rename` — rename own device
- `DELETE /api/v1/my/trusted-devices/{id}` — revoke own device
- `GET /api/v1/admin/trusted-devices` — all devices with filters (AdminPolicy)
- `PUT /api/v1/admin/trusted-devices/{id}/trust` — admin set trust level (AdminPolicy)
- `DELETE /api/v1/admin/trusted-devices/{id}` — admin revoke (AdminPolicy)
- Login flow: UA fingerprint → TrustedDevice lookup → policy enforcement (Block/StepUpAuth/Allow)
- `Policies.razor`: "Device Trust" tab with policy form
- `MyDevices.razor`: user self-service device management (list, rename, revoke)
- NavMenu: "My Devices" link under Security section
- `PamApiService.cs`: DeviceTrustPolicySettingsDto, TrustedDeviceDto + 7 API methods
- RFP User Mgmt #32 → PC, #33 → PC

**#208 Geolocation Access — Tamamlanan bilesenler (2026-05-18):**
- `GeolocationPolicySettings`: Enabled, AllowedCountryCodes[], BlockedCountryCodes[], ViolationAction (Block/StepUpAuth), UnknownLocationAction (Allow/StepUpAuth/Block), AllowPrivateIps
- `GET/PUT /api/v1/policy/geo-access` (AdminPolicy)
- `GeoLocationHelper`: ip-api.com lookup (3s timeout, graceful fallback), RFC 1918 private IP detection, country allow/block list enforcement
- Login flow: geo check after Device Trust (Block → 403, StepUpAuth → force MFA, Allow → proceed)
- `Policies.razor`: "Geo Access" tab — allowed/blocked country code inputs, violation/unknown action dropdowns, private IP toggle
- `PamApiService.cs`: `GeolocationPolicySettingsDto` + `GetGeolocationPolicyAsync` + `SaveGeolocationPolicyAsync`
- RFP User Mgmt #29 → PC

---

## ~~Sprint 19 - v2 Telnet Proxy + RFP Gap Protocol Coverage~~ ✅ TAMAMLANDI
**Tarih:** 18 Mayis 2026
**Durum:** Tamamlandi — Native C# Telnet Proxy (RFC 854)

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| — | Telnet Proxy — Native C# RFC 854 | v2-PROXY | ✅ Tamamlandi |

**Sprint 19 Tamamlanan Bilesenler (2026-05-18):**
- `OrkunPAM.TelnetProxy` Windows Service (TCP :2323) — Worker SDK, native C#, no open-source libs
- `TelnetNegotiator.cs`: RFC 854 IAC option negotiation (WILL/WONT/DO/DONT); ECHO, SGA, LINEMODE
- `TelnetSession.cs`: PAM banner → Login (pamuser@host[:port]) → password (echo suppressed) → PAM auth → credential lookup → connect → auto-login injection → bidirectional relay + recording → session upload
- `TelnetProxyService.cs`: BackgroundService; per-IP rate limit (10 conn/60s); SemaphoreSlim session cap
- `PamApiClient.cs`: proxy-service JWT auth → device lookup → Telnet/UserPassword credential → proxy-decrypt → session start/end lifecycle
- `TelnetEndpoints.cs`: `GET /api/v1/telnet/sessions` (AdminPolicy), `DELETE /sessions/{id}` terminate, `POST /proxy/session-start`, `POST /proxy/session-end` (recording save), `GET /proxy/sessions/{id}/status` (X-Proxy-Secret)
- `Array.Clear(credPassword)` immediately after credential injection (zero-memory policy)
- WebAPI `Program.cs`: `api.MapTelnetEndpoints()` registered
- `OrkunPAM.sln`: TelnetProxy project added under Proxy solution folder
- RFP Remote Access #5 → PC

**Ilerleme:** 1/1 (%100) ✅

---

## ~~Sprint 20 - v2 Session Monitor + SMS MFA + Session Tagging~~ ✅ TAMAMLANDI
**Tarih:** 18-25 Mayis 2026
**Durum:** Tamamlandi — Session Live Monitoring, SMS OTP MFA, Session Tagging & Annotation

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #214 | Session Live Monitoring — Canli Oturum Izleme ve Admin Mudahale | v2-SESSION | ✅ Tamamlandi |
| #215 | SMS OTP — Kisa Mesaj Tabanli MFA | v2-MFA | ✅ Tamamlandi |
| #216 | Session Tagging & Annotation — Oturum Etiketleme | v2-SESSION | ✅ Tamamlandi |

**Sprint 20 Tamamlanan Bilesenler:**
- #214: SessionChunkStore (ring buffer), LiveSessionEndpoints (7 endpoint), LiveMonitor.razor (polling 2s), SSH/Telnet proxy live chunk push → RFP Remote Access #31 + #40 PC ✅
- #215: ISmsGatewayService (Twilio/NetGSM/Webhook native HttpClient), SmsOtpToken entity, SmsOtpEndpoints (4 endpoint), Login.razor SMS adimi, Integrations.razor SMS Gateway tab, Policies.razor SMS OTP checkbox, migration → RFP MFA #4 PC ✅
- #216: SessionAnnotation entity + migration, SessionTagEndpoints (4 endpoint — tags PUT + annotations GET/POST/DELETE), Sessions.razor tag badges + edit modal + notes panel, PamApiService tag/annotation methods, audit logging → RFP Remote Access #48 PC ✅

**Ilerleme:** 3/3 (%100) ✅

---

## ~~Sprint 21 - Infrastructure Stubs Fix~~ ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi — AutoRotationService wirklandi, SSH/MySQL/PostgreSQL rotation stublari duzeltildi, Telnet admin terminasyonu duzeltildi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| — | AutoRotationService + PasswordRotationOrchestrator DI kaydi | infra-fix | ✅ Tamamlandi |
| — | SSH/MySQL/PostgreSQL rotation stub fixleri (RotationService) | infra-fix | ✅ Tamamlandi |
| — | TelnetSession.CheckTerminationAsync stub fix | proxy-fix | ✅ Tamamlandi |

**Sprint 21 Tamamlanan Bilesenler (2026-05-19):**
- `Program.cs`: `SshPasswordRotator`, `WmiPasswordRotator`, `MySqlPasswordRotator`, `PostgreSqlPasswordRotator` → `IPasswordRotator` olarak Scoped kayit
- `Program.cs`: `PasswordRotationOrchestrator` Scoped kayit + `AutoRotationService` HostedService kayit — otomatik parola rotasyonu artik calisir
- `RotationService.cs`: `ILoggerFactory` inject edildi; `RotateViaSshAsync` → `SshPasswordRotator` delegate; `RotateViaMySqlAsync` → `MySqlPasswordRotator` delegate; `RotateViaPostgreSqlAsync` → `PostgreSqlPasswordRotator` delegate — manuel rotasyon artik gercek implementasyonu kullanir
- `TelnetSession.CheckTerminationAsync`: `static` stub kaldirildi — 30s aralikla `_api.IsTerminatedAsync` polling + admin terminasyonu artik calisir

**Ilerleme:** 3/3 (%100) ✅

---

## ~~Sprint 22 - Refactoring: NavMenu Sadeleştirmesi~~ ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi — NavMenu 11 bolum (Overview/Access/Identity/Workflow/Reporting/Terminal/Network/Cloud/Threat Analytics/Security/System) → 8 ana kategori (Users/Devices/Vault/Access Control/Sessions/Policies/Reports/System)

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| — | NavMenu: 11 bolum → 8 kategori (CLAUDE.md Refactoring Sprint #1) | refactor | ✅ Tamamlandi |

**Sprint 22 Tamamlanan Bilesenler (2026-05-19):**
- `NavMenu.razor`: "Overview" bolumu kaldirildi — Dashboard tek basina ust item oldu
- "Access" (Vault+Devices) ayrildi: Vault kendi bolumune, Devices kendi bolumune tasindi
- "Identity" (Users+Policies) ayrildi: Users bolumu + Policies bolumu ayri
- "Workflow" → "Access Control" olarak yeniden adlandirildi
- "Terminal" + "Network" birlestirildi → "Sessions" bolumu (SSH/RDP + TACACS+/RADIUS + RDP Mgmt)
- "Cloud" Devices bolumune tasindi (Cloud PAM artik Devices altinda)
- "Threat Analytics" Policies bolumune tasindi (SOC Dashboard artik Policies altinda)
- "Security" (Security Keys/Push MFA/My Devices) Users bolumune tasindi
- Tum mevcut nav link'ler korundu, sadece gruplamasi degisti
- Sonuc: 11 bolum → 8 bolum (CLAUDE.md hedefi: Users/Devices/Vault/Access Control/Sessions/Policies/Reports/System)

**Ilerleme:** 1/1 (%100) ✅

---

---

## Sprint 23 - Refactoring: Device Realm Entity + API + UI
**Tarih:** 19 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| — | DeviceRealm entity (Kron PAM model) | refactor | ✅ Tamamlandi |
| — | DeviceRealm migration (3 tablo) | refactor | ✅ Tamamlandi |
| — | DeviceRealmEndpoints (CRUD + group mgmt) | refactor | ✅ Tamamlandi |
| — | PamApiService Device Realm methods + DTOs | refactor | ✅ Tamamlandi |
| — | DeviceRealms.razor Blazor UI | refactor | ✅ Tamamlandi |
| — | NavMenu: Device Realms linki (Access Control altinda) | refactor | ✅ Tamamlandi |

**Sprint 23 Tamamlanan Bilesenler (2026-05-19):**
- `DeviceRealm` entity: Name, Description, IsEnabled, SessionPolicyId — Kron PAM realm modeli
- `DeviceRealmUserGroup` junction: DeviceRealmId + UserGroupId (composite PK)
- `DeviceRealmDeviceGroup` junction: DeviceRealmId + DeviceGroupId (composite PK)
- `OrkunPamDbContext`: 3 yeni DbSet + model konfigurasyonu (cascade delete, unique index)
- `20260519_AddDeviceRealm.cs` migration: DeviceRealms + DeviceRealmUserGroups + DeviceRealmDeviceGroups tablolari + FK + index
- `DeviceRealmEndpoints.cs`: CRUD (GET list, GET single, POST, PUT, DELETE) + toggle + user group add/remove + device group add/remove + my-access
- `Program.cs`: `api.MapDeviceRealmEndpoints()` kaydedildi
- `PamApiService.cs`: 12 yeni metot (GetDeviceRealmsAsync, GetDeviceRealmAsync, CreateDeviceRealmAsync, UpdateDeviceRealmAsync, DeleteDeviceRealmAsync, ToggleDeviceRealmAsync, AddUserGroupToRealmAsync, RemoveUserGroupFromRealmAsync, AddDeviceGroupToRealmAsync, RemoveDeviceGroupFromRealmAsync, GetGroupsAsync, GetDeviceGroupsAsync) + DTO'lar (DeviceRealmDto, DeviceRealmGroupDto, DeviceRealmDeviceGroupDto, GroupDto, DeviceGroupDto)
- `DeviceRealms.razor`: Access matrix yonetim UI — realm CRUD + user group/device group atama (her realm icin acilir panel)
- `NavMenu.razor`: "Device Realms" linki Access Control bolumune eklendi

**Ilerleme:** 6/6 (%100) ✅

---

---

## Sprint 24 - Credential Assignment Refactoring (Kron PAM `assigned_credential` modeli) ✅ TAMAMLANDI
**Tarih:** 2026-05-19
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| — | AssignedCredential entity (Kron PAM model) | refactor | ✅ Tamamlandi |
| — | AssignedCredential migration | refactor | ✅ Tamamlandi |
| — | AssignedCredentialEndpoints (CRUD + my-credentials) | refactor | ✅ Tamamlandi |
| — | PamApiService AssignedCredential methods + DTO | refactor | ✅ Tamamlandi |
| — | CredentialAssignments.razor Blazor UI | refactor | ✅ Tamamlandi |
| — | NavMenu: Credential Assignments linki | refactor | ✅ Tamamlandi |

**Sprint 24 Tamamlanan Bilesenler (2026-05-19):**
- `AssignedCredential` entity: CredentialId, PrincipalType (User/Group), PrincipalId, DeviceGroupId (optional scope), IsEnabled, Notes
- `20260519_AddAssignedCredential.cs` migration: AssignedCredentials tablosu + FK (Cascade to Credential, SetNull to DeviceGroup) + indexler
- `AssignedCredentialEndpoints.cs`: GET list, POST create, DELETE, POST toggle, GET /by-credential/{id}, GET /my-credentials (user endpoint)
- `OrkunPamDbContext`: DbSet<AssignedCredential> + model konfigurasyonu
- `Program.cs`: `api.MapAssignedCredentialEndpoints()` kaydedildi
- `PamApiService.cs`: GetAssignedCredentialsAsync, CreateAssignedCredentialAsync, DeleteAssignedCredentialAsync, ToggleAssignedCredentialAsync + AssignedCredentialDto
- `CredentialAssignments.razor`: Tam CRUD UI — principal type/ID dropdown (User/Group), credential dropdown, device group scope, toggle/delete
- `NavMenu.razor`: "Credential Assignments" linki Access Control bolumune eklendi

**Ilerleme:** 6/6 (%100) ✅

---

## ~~Sprint 25 - Security Fix: AssignedCredential Audit + Unique Constraint~~ ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi — 2 HIGH security bulgu fix'lendi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #217 | [HIGH] AssignedCredentialEndpoints audit logging eksik (CWE-778) | security | ✅ Kapatildi |
| #218 | [HIGH] AssignedCredentials unique constraint eksik — access revocation bypass (CWE-284) | security | ✅ Kapatildi |

**Sprint 25 Tamamlanan Bilesenler (2026-05-19):**
- `AssignedCredentialEndpoints.cs`: `IAuditService` inject edildi; POST/DELETE/Toggle endpoint'lerine `CREDENTIAL_ASSIGNMENT_CREATED/DELETED/ENABLED/DISABLED` audit event'leri eklendi (#217)
- `AssignedCredentialEndpoints.cs`: POST `/` — `AnyAsync` duplicate check eklendi; duplicate varsa 409 Conflict donerilen (#218)
- `OrkunPamDbContext.cs`: `AssignedCredential` entity konfigurasyonuna iki partial unique index eklendi — `[DeviceGroupId] IS NOT NULL` ve `[DeviceGroupId] IS NULL` (#218)
- `20260519_AddAssignedCredentialUniqueIndex.cs`: migration ile DB'ye 2 partial unique index yansitildi (#218)

**Ilerleme:** 2/2 (%100) ✅

---

## Sprint 26 - Refactoring #4: Gereksiz Sayfa ve Endpoint Temizligi ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi — Blazor template sayfalar silindi, kullanim disi endpoint kaydi kaldirildi

| Item | Aciklama | Durum |
|------|----------|-------|
| Counter.razor | Blazor default demo sayfasi — silindi | ✅ Tamamlandi |
| Weather.razor | Blazor default demo sayfasi — silindi | ✅ Tamamlandi |
| MapAccessAssignmentEndpoints() | Eski model (Sprint 24 AssignedCredential ile superseded) — Program.cs'den kaldirildi | ✅ Tamamlandi |

**Ilerleme:** 3/3 (%100) ✅

---

---

## Sprint 27 - Refactoring #5: Session Akisi Realm-Based Erisim Kontrolu ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi — DeviceRealm → SSH/RDP/WebSSH session baslama akisina entegre edildi

| Item | Aciklama | Durum |
|------|----------|-------|
| DeviceRealmEndpoints: IsDeviceCoveredByRealmAsync | Cihazin realm kapsaminda olup olmadigini kontrol eden statik helper | ✅ Tamamlandi |
| DeviceRealmEndpoints: HasRealmAccessAsync | Kullanicinin cihaza realm uzerinden erisimini dogrulayan statik helper | ✅ Tamamlandi |
| GET /api/v1/device-realms/accessible-devices | Mevcut kullanicinin realm uyeligi araciligiyla erisebilecegi cihaz listesi | ✅ Tamamlandi |
| SessionEndpoints: CreateSession realm check | SSH/generic session baslatmada realm-first, AccessAssignment fallback | ✅ Tamamlandi |
| SessionEndpoints: CreateRdpSession realm check | RDP session baslatmada realm-first, AccessAssignment fallback | ✅ Tamamlandi |
| WebSshEndpoints: realm check | WebSocket SSH koprusunde realm-first, CredentialPermission fallback | ✅ Tamamlandi |
| PamApiService: GetMyAccessibleDevicesAsync | /accessible-devices endpoint'ini cagiran servis metodu | ✅ Tamamlandi |
| Connect.razor: realm-filtered device list | Cihaz dropdown'u artik realm filtrelemeli liste kullaniyor | ✅ Tamamlandi |

**Sprint 27 Tamamlanan Bilesenler (2026-05-19):**
- `DeviceRealmEndpoints.IsDeviceCoveredByRealmAsync`: Cihazin DeviceGroupMembers → DeviceRealmDeviceGroups zincirinden aktif bir realm kapsaminda olup olmadigini sorgular
- `DeviceRealmEndpoints.HasRealmAccessAsync`: Kullanicinin UserGroups → DeviceRealm → DeviceGroups matrisinden belirtilen cihaza erisimi oldugunu dogrular
- `GET /api/v1/device-realms/accessible-devices`: Realm konfigurasyonu yapilmissa kullanicinin realm uyeligi araciligiyla erisebilecegi cihazlari doner; realm konfigurasyonu yoksa tum cihazlari doner (backward compatible); admin rolleri icin tum cihazlar
- `SessionEndpoints.CreateSession` + `CreateRdpSession`: `HasAccessAssignmentAsync` dogrudan cagirisi kaldirildi — once `IsDeviceCoveredByRealmAsync` kontrol edilir, realm kapsamindaysa `HasRealmAccessAsync`; realm kapsaminda degilse `HasAccessAssignmentAsync` fallback'i
- `WebSshEndpoints`: WebSocket SSH koprusunde ayni realm-first / CredentialPermission-fallback mantiği
- `PamApiService.GetMyAccessibleDevicesAsync`: `/api/v1/device-realms/accessible-devices` endpoint'ini `ListResult<DeviceDto>` olarak sorgular
- `Connect.razor`: `GetDevicesAsync` yerine `GetMyAccessibleDevicesAsync` kullaniliyor — Connect sayfasi artik sadece kullanicinin realm erisimi olan cihazlari gosteriyor

**Ilerleme:** 8/8 (%100) ✅ — Sprint 27 TAMAMLANDI

---

## ~~Sprint 28 - Security Fix: Session List Exposure (CWE-200/284)~~ ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi — 2 HIGH security bulgu fix'lendi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #221 | [HIGH] Session list endpoints expose all users' sessions | security | ✅ Kapatildi |
| #220 | [HIGH] Realm access check not enforced at session creation | security | ✅ Kapatildi (Sprint 27'de zaten implemente edilmisti) |

**Sprint 28 Tamamlanan Bilesenler (2026-05-19):**
- `SessionEndpoints.cs` `GET /` — `HttpContext` inject edildi; `isPrivileged` kontrolu (GlobalAdmin/Auditor/SessionAdmin); privileged olmayan kullanici sadece kendi session'larini gorur; userId filtresi artik sadece privileged callers icin gecerli
- `SessionEndpoints.cs` `GET /active` — `HttpContext` inject edildi; ayni `isPrivileged` kontrolu; non-admin kullanici sadece kendi aktif session'larini gorur
- Issue #220 incelendi — `CreateSession` + `CreateRdpSession` + `WebSshEndpoints` zaten Sprint 27'de realm check implement etmisti; issue stale, kapatildi

**Ilerleme:** 2/2 (%100) ✅

---

## Sprint 29 - Refactoring #6: SSH Proxy Session Lifecycle + TCP Hardening
**Tarih:** 19 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

| Item | Aciklama | Durum |
|------|----------|----------|
| TCP connect timeout | SshTargetClient.ConnectAsync — 15s timeout, unreachable host gracefully handled | ✅ Tamamlandi |
| SSH proxy session-start endpoint | `POST /api/v1/ssh/proxy/session-start` — SSH proxy'nin PAM DB'ye session kaydetmesi | ✅ Tamamlandi |
| SSH proxy session-end endpoint | `POST /api/v1/ssh/proxy/session-end` — session kapanisinda DB guncelleme + recording path | ✅ Tamamlandi |
| SSH proxy session-status endpoint | `GET /api/v1/ssh/proxy/sessions/{id}/status` — admin termination polling | ✅ Tamamlandi |
| PamApiClient session lifecycle | StartSessionAsync + EndSessionAsync + IsTerminatedAsync eklendi | ✅ Tamamlandi |
| SshServerSession lifecycle entegrasyonu | RunAsync: StartSession sonrasi, EndSession finally'de; IdleWatchAsync: 60s admin termination check | ✅ Tamamlandi |
| SessionRecorder.RecordingPath | FlushAsync sonrasi recording path expose edildi | ✅ Tamamlandi |
| ValidateUserAsync userId desteği | LoginData UserId eklendi; ValidateUserAsync (bool, userId?) doner | ✅ Tamamlandi |
| GetTargetCredentialAsync credentialId | Return tuple'a credentialId eklendi | ✅ Tamamlandi |

**Sprint 29 Tamamlanan Bilesenler (2026-05-19):**
- `SshProxySessionEndpoints.cs`: 3 yeni endpoint — session-start, session-end, session-status (X-Proxy-Secret korumal)
- `Program.cs`: `api.MapSshProxySessionEndpoints()` kaydi eklendi
- `SshTargetClient.ConnectAsync`: 15s TCP connect timeout — unreachable host artik aninda SshException atar
- `PamApiClient` (SSH): `StartSessionAsync`, `EndSessionAsync`, `IsTerminatedAsync` eklendi; `LoginData` UserId dahil; `GetTargetCredentialAsync` artik `credentialId` de doner
- `SshServerSession.RunAsync`: userId + credentialId yakalanir; `StartSessionAsync` credentials sonrasi cagirilir; `EndSessionAsync` finally'de garantili cagrilir
- `SshServerSession.IdleWatchAsync`: `static` kaldirildi; her 60s admin termination check (`IsTerminatedAsync`); admin terminasyonu artik calisir
- `SessionRecorder.RecordingPath`: property eklendi — FlushAsync sonrasi path okunabilir; EndSession'a recording path gecilir

**Ilerleme:** 9/9 (%100) ✅ — Sprint 29 TAMAMLANDI

---

## Sprint 30 - Security Fixes + RDP Proxy Admin Termination ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #224 | [HIGH] ValidateProxySecret — non-constant-time string comparison (timing side-channel) | security | ✅ Kapatildi |
| #226 | [MEDIUM] SSH proxy session-start/end endpoint audit log eksik | security | ✅ Kapatildi |
| #225 | [MEDIUM] SSH Proxy — PAM kullanici parolasi .NET string olarak managed heap'te kaliyor | security | ✅ Kapatildi |
| #223 | [MVP] RDP Proxy Session Lifecycle — PAM DB Integration + Admin Termination | product | ✅ Kapatildi |
| #222 | [MVP] SSH Proxy ProxySession Recording Path DB Link | product | ✅ Kapatildi (Sprint 29'da zaten implemente edilmisti) |

**Sprint 30 Tamamlanan Bilesenler (2026-05-19):**
- **#224 fix [HIGH]:** `SshProxySessionEndpoints.ValidateProxySecret` — `CryptographicOperations.FixedTimeEquals` ile constant-time karsilastirma; `using System.Security.Cryptography` eklendi
- **#226 fix [MEDIUM]:** `session-start` endpoint'e `ILogger<Program> logger` eklendi; `[AUDIT] SSH_SESSION_STARTED` + `[AUDIT] SSH_SESSION_ENDED` structured log mesajlari eklendi
- **#225 fix [MEDIUM]:** `SshServerSession.DoUserAuthAsync` — `SshEncoding.ReadByteString` kullaniyor (string yerine byte[]); auth sonrasi `CryptographicOperations.ZeroMemory(passwordBytes)`; `PamApiClient.ValidateUserAsync` `byte[]` parametre aliyor
- **#223 [MVP]:** `RdpProxySessionEndpoints.cs` (yeni dosya) — `GET /api/v1/rdp/proxy/sessions/{id}/status` endpoint (constant-time secret, AdminTermination kontrolu); `Program.cs`: `api.MapRdpProxySessionEndpoints()` kaydi; `RdpProxy.PamApiClient`: `IsTerminatedAsync` eklendi; `RdpServerSession.IdleWatchAsync` + `RelayRawAsync` — `api` ve `pamSessionId` parametreleri ile admin termination polling (her 60s)
- **#222:** Incelendi — Sprint 29'da zaten implemente edilmis (EndSessionAsync + RecordingPath). Issue stale, kapatildi.

**Ilerleme:** 5/5 (%100) ✅

---

## ~~Sprint 31 - User Profile + Password Change~~ ✅ TAMAMLANDI
**Tarih:** 20 Mayis 2026
**Durum:** Tamamlandi — Kullanici profil sayfasi + sifre degistirme

| Item | Aciklama | Durum |
|------|----------|-------|
| GET /api/v1/auth/me | Mevcut kullanicinin profil bilgilerini donduren endpoint | ✅ Tamamlandi |
| PamApiService.GetMyProfileAsync | /api/v1/auth/me cagiran servis metodu | ✅ Tamamlandi |
| PamApiService.ChangePasswordAsync | /api/v1/auth/change-password cagiran servis metodu | ✅ Tamamlandi |
| UserProfileDto | Profil bilgileri icin DTO record | ✅ Tamamlandi |
| SelfService.razor — Profile tab | Hesap bilgileri + sifre degistirme formu | ✅ Tamamlandi |
| RFP Platform #15 | Kullanici sifre degistirme → PC | ✅ Guncellendi |

**Tamamlanan Bilesenler (2026-05-20):**
- `GET /api/v1/auth/me`: JWT'den userId cikararak kullanicinin profilini dondurur (username, email, displayName, authSource, status, mfaEnabled, mfaType, mustChangePassword, passwordLastChanged, passwordExpiresAt, lastLoginAtUtc, lastLoginIp, language, timezone, roles)
- `PamApiService.GetMyProfileAsync()`: /api/v1/auth/me cagiran Blazor servis metodu
- `PamApiService.ChangePasswordAsync(currentPw, newPw)`: /api/v1/auth/change-password ile hata mesaji ayiklayarak sonuc dondurur
- `UserProfileDto` record: 17 alan, null-safe, List<string>? Roles
- `SelfService.razor` "My Profile" sekmesi:
  - Account Info karti: username, displayName, email, authSource, status, roles, MFA durumu, son giris, sifre gecmisi, timezone, dil
  - Change Password karti: mevcut + yeni + onayla alanlar; sadece Local hesaplarda gosterilir; MustChangePassword uyari banner
- Platform RFP #15 → PC

**Ilerleme:** 5/5 (%100) ✅

---

## Sprint 32 - MFA Device Management (RFP MFA #12)
**Tarih:** 20 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

| Item | Aciklama | Durum |
|------|----------|-------|
| MfaDeviceEndpoints.cs | GET /api/v1/my/mfa-devices + DELETE by-type/fido2/push | ✅ Tamamlandi |
| Admin endpoints | GET/DELETE /api/v1/admin/users/{id}/mfa-devices/* (AdminPolicy) | ✅ Tamamlandi |
| Program.cs | api.MapMfaDeviceEndpoints() kaydi | ✅ Tamamlandi |
| PamApiService.cs | GetMyMfaDevicesAsync, RevokeMfaDeviceByTypeAsync, RevokeFido2DeviceAsync, RevokePushDeviceAsync + MfaDeviceDto | ✅ Tamamlandi |
| SelfService.razor | "Security" sekmesi — MFA metod listesi + revoke butonlari | ✅ Tamamlandi |
| RFP MFA #12 | MFA device management → PC | ✅ Guncellendi |

**Tamamlanan Bilesenler (2026-05-20):**
- `MfaDeviceEndpoints.cs`: Unified MFA device yonetimi — TOTP/EmailOTP/SMS/FIDO2/Push tum metodlari tek API'den yonetilebilir
- `GET /api/v1/my/mfa-devices`: Kullanicinin aktif MFA metod listesi (TOTP, Email OTP, SMS, FIDO2 keys, Push devices)
- `DELETE /api/v1/my/mfa-devices/by-type/{type}`: TOTP/email_otp/sms revoke
- `DELETE /api/v1/my/mfa-devices/fido2/{credId}`: FIDO2 security key revoke (IsActive=false)
- `DELETE /api/v1/my/mfa-devices/push/{deviceId}`: Push MFA device revoke (SystemConfig sil)
- Admin endpoints: `GET/DELETE /api/v1/admin/users/{userId}/mfa-devices/*` — AdminPolicy ile herhangi kullanicinin MFA metodu yonetimi
- Audit logging: MFA_TOTP_REVOKED, MFA_EMAIL_OTP_REVOKED, MFA_SMS_REVOKED, MFA_FIDO2_REVOKED, MFA_PUSH_REVOKED + admin varyantlari
- `PamApiService.cs`: 4 yeni metot + `MfaDeviceDto` record
- `SelfService.razor`: "Security" sekmesi — tum MFA metotlari tablo halinde, type badge (TOTP/Email OTP/SMS/FIDO2/Push), detail alani, revoke butonu; TOTP/SecurityKeys/PushDevices yonetim sayfalarına linkler
- RFP MFA #12 (MFA device management) → PC

**Ilerleme:** 6/6 (%100) ✅

---

## Sonraki Adim
**Sprint 32 tamamlandi.** MFA Device Management eklendi. RFP MFA #12 kapandi.
**v1.0.0 GA Tag:** 18 Mayis 2026'da atildi
**v2.0.0:** 30 Eylul 2026

---

## Sprint Kuralları
- Her sprint sonunda Coordinator tag atar
- Sprint değişikliği bu dosya güncellenerek yapılır
- Developer agent "Aktif Sprint" bölümündeki issue'lara odaklanır
- Sprint dışı issue'lar backlog'da kalır
- Security critical/high her zaman sprint'i keser (acil fix)

## Milestone Hedefleri
- **v0.4.0-rdp:** Sprint 3 çıkışı (13 Mayıs 2026) ← Tamamlandı
- **v1.0.0-rc1:** Sprint 4 çıkışı (13 Mayıs 2026) ✅ Tag atıldı
- **v1.0.0-rc2:** Sprint 5 çıkışı (13 Mayıs 2026) ✅ Tamamlandı
- **v1.0.0:** Sprint 6 çıkışı (14 Mayıs 2026) ✅ **GA Tag atıldı (18 Mayıs 2026)**
- **v2.0.0:** AAPM + Threat Analytics (30 Eylül 2026)

## Mimari Kararlar
- **SSH Proxy:** Native C# (RFC 4253) — farkımız burada, açık kaynak yok
- **RDP Proxy:** Microsoft RDS Gateway entegrasyonu — CyberArk yaklaşımı, RemoteApp + session recording + HA dahil
- **SQL Proxy:** Native C# TDS protokol implementasyonu — açık kaynak yok
- **VNC Proxy:** Native C# RFB protokol (RFC 6143) — açık kaynak yok
- **HTTP/HTTPS Proxy:** Native C# reverse proxy + CONNECT tunnel — açık kaynak yok
- **TACACS+ Proxy:** Native C# (RFC 1492) — ağ cihazı AAA, Cisco/Juniper/Aruba
- **RADIUS Proxy:** Native C# (RFC 2865/2866) — VPN/Wi-Fi/NAC, UDP :1812/:1813
- **Telnet Proxy:** Native C# (RFC 854) — TCP :2323, credential injection, session recording
- **Blazor UI:** Yönetim paneli, session başlatma, vault, raporlar
- **AAPM + Threat Analytics:** v2.0.0'a ertelendi

## Agent Yetkinlik Sınırları (Koordinatör notu)
Aşağıdaki konularda Developer agent (Sonnet) takılırsa lokal Opus devralır:
- **SSH Proxy:** Native SSH protokolü (RFC 4253) - raw socket, key exchange, channel multiplexing
- **RDP/RDS:** COM interop, RDS Gateway API, credential injection
- **Blazor UI:** Karmaşık component mimarisi, SignalR entegrasyonu, real-time terminal
- **MSI Installer:** WiX toolset, Windows Service registration, upgrade logic
- **VNC Proxy:** RFB protokol (RFC 6143) - framebuffer, encoding negotiation, raw socket
- **HTTP Proxy:** CONNECT tunnel, TLS MitM, credential injection
