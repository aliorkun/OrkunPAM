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
|-------|--------|-----|------|
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
|-------|--------|-----|------|
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
|-------|--------|-----|------|
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
|-------|--------|-----|------|
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
|-------|--------|-----|------|
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
|-------|--------|-----|------|
| #111 | TACACS+/RADIUS Built-in Server | v2-PROXY | ✅ Kapatıldı |
| #110 | RDP Full Integration (RDS Gateway) | v2-PROXY | ✅ Kapatıldı |
| #112 | Multi-Tenancy (MSP) | v2-ARCH | 🔲 v3+ ertelendi (CLAUDE.md) |

**İlerleme:** 2/2 aktif item = %100 ✅

---

## ~~Sprint 8 - v2.0.0 RFP Gap Features (O&M + Reporting + Compliance)~~ ✅ TAMAMLANDI
**Tarih:** 16 Mayıs 2026
**Durum:** Tamamlandı — System Health, Connection Scheduling, Orphaned Accounts, Access Certifications, Multi-Language UI

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|------|
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
|-------|--------|-----|------|
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
|-------|--------|-----|------|
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
|-------|--------|-----|------|
| #178 | Email OTP — E-Posta Tabanlı MFA | v2-MFA | ✅ Tamamlandı |
| #179 | SOX / PCI-DSS / ISO 27001 Uyumluluk Rapor Şablonları | v2-COMPLIANCE | ✅ Tamamlandı |
| #180 | FIPS 140-2 Kriptografik Uyumluluk | v2-SECURITY | ✅ Tamamlandı |

**İlerleme:** 3/3 (%100) ✅

---

## ~~Sprint 12 - Cloud PAM~~ ✅ TAMAMLANDI
**Tarih:** 17 Mayıs 2026
**Durum:** Tamamlandı — AWS/Azure/GCP privileged access, JIT cloud erişimi, multi-cloud dashboard

| Issue | Başlık | Tip | Durum |
|-------|--------|-----|------|
| #37 | Cloud PAM — AWS/Azure/GCP Privileged Access | v2-CLOUD | ✅ Tamamlandı |

**İlerleme:** 1/1 (%100) ✅

---

## Sprint 13 - v2 RFP Gap: Session Watermarking + Credential Discovery + Certificate Lifecycle
**Tarih:** 17-31 Mayis 2026
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #190 | Session Watermarking — Oturum Kaydi Kullanici Filigrani | v2-SESSION | ✅ Tamamlandi |
| #189 | Credential Discovery — AD Ayricalikli Hesap Tarama | v2-VAULT | ✅ Tamamlandi |
| #191 | Certificate Lifecycle Management — X.509 Sertifika Envanter | v2-VAULT | ✅ Tamamlandi |

**Ilerleme:** 3/3 (%100) ✅ — Sprint 13 tamamlandi

---

## Sprint 14 - UX Polish: Credential Access Request Flow
**Tarih:** 17 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| — | Credential Access Request — Vault UI + API endpoint | UX-fix | ✅ Tamamlandi |

**Ilerleme:** 1/1 (%100) ✅

---

## Sprint 15 - v2 Security + MFA + Integration RFP Gap ✅ TAMAMLANDI
**Tarih:** 17 Mayis 2026
**Durum:** Tamamlandi — 3 HIGH security fix + Account Reconciliation + Push MFA + SOAR Integration

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #198 | [HIGH] Vault Permission Endpoint — AdminPolicy Eksik | security | ✅ Kapatildi |
| #199 | [HIGH] Credential Share Endpoint — CanShare Dogrulanmiyor | security | ✅ Kapatildi |
| #200 | [HIGH] Vault Folder Credentials Listing — IDOR | security | ✅ Kapatildi |
| #195 | Account Reconciliation — PAM vs AD/LDAP Drift Detection | v2-COMPLIANCE | ✅ Kapatildi |
| #196 | Push Notification MFA — Mobil Push Onay MFA | v2-MFA | ✅ Kapatildi |
| #197 | SOAR Integration — Splunk SOAR / Palo Alto XSOAR | v2-INTEGRATION | ✅ Kapatildi |

**Ilerleme:** 6/6 (%100) ✅

---

## ~~Sprint 16 - v2 Threat Analytics & SOC Dashboard~~ ✅ TAMAMLANDI
**Tarih:** 18 Mayis 2026
**Durum:** Tamamlandi — ML anomali tespiti + BFLA fix + DoS fix + baseline sifreleme + alert actions

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #35 | ML Tabanli Anomali Tespiti ve Risk Skorlama | v2-ANALYTICS | ✅ Tamamlandi |
| #202 | [HIGH] SOC/Analytics API BFLA | security | ✅ Fix'lendi |
| #203 | [MEDIUM] /soc/timeline DoS Riski | security | ✅ Fix'lendi |
| #204 | [MEDIUM] Baseline Plaintext Storage | security | ✅ Fix'lendi |

**Ilerleme:** 1/1 core feature (%100 — Sprint 16 TAMAMLANDI) ✅

---

## ~~Sprint 17 - v2 Auth: Adaptive MFA + Threat Intelligence + Device Trust~~ ✅ TAMAMLANDI
**Tarih:** 18 Mayis 2026
**Durum:** Tamamlandi — Adaptive MFA + Threat Intelligence Feed tamamlandi; Device Trust Sprint 18'e tasindi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #205 | Adaptive MFA — Anomali Skoruna Gore Step-Up Kimlik Dogrulama | v2-SECURITY | ✅ Tamamlandi |
| #206 | Threat Intelligence Feed — IOC/IP Reputation Entegrasyonu | v2-ANALYTICS | ✅ Tamamlandi |
| #207 | Device Trust ve Context-Aware Access Control | v2-ACCESS | Sprint 18'e tasindi |

**Ilerleme:** 2/2 tamamlandi (%100 — Sprint 17 core items) ✅

---

## ~~Sprint 18 - v2 Access Control + Geolocation + Access Analytics~~ ✅ TAMAMLANDI
**Tarih:** 18-25 Mayis 2026
**Durum:** Tamamlandi — Device Trust, Geolocation Access, Access Pattern Analytics tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #207 | Device Trust ve Context-Aware Access Control | v2-ACCESS | ✅ Tamamlandi |
| #208 | Geolocation-based Access Control | v2-ACCESS | ✅ Tamamlandi |
| #209 | Access Pattern Analytics & API Usage Reporting | v2-REPORTING | ✅ Tamamlandi |

**Ilerleme:** 3/3 (%100) ✅ — Sprint 18 TAMAMLANDI

---

## ~~Sprint 19 - v2 Telnet Proxy + RFP Gap Protocol Coverage~~ ✅ TAMAMLANDI
**Tarih:** 18 Mayis 2026
**Durum:** Tamamlandi — Native C# Telnet Proxy (RFC 854)

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| — | Telnet Proxy — Native C# RFC 854 | v2-PROXY | ✅ Tamamlandi |

**Ilerleme:** 1/1 (%100) ✅

---

## ~~Sprint 20 - v2 Session Monitor + SMS MFA + Session Tagging~~ ✅ TAMAMLANDI
**Tarih:** 18-25 Mayis 2026
**Durum:** Tamamlandi — Session Live Monitoring, SMS OTP MFA, Session Tagging & Annotation

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #214 | Session Live Monitoring — Canli Oturum Izleme ve Admin Mudahale | v2-SESSION | ✅ Tamamlandi |
| #215 | SMS OTP — Kisa Mesaj Tabanli MFA | v2-MFA | ✅ Tamamlandi |
| #216 | Session Tagging & Annotation — Oturum Etiketleme | v2-SESSION | ✅ Tamamlandi |

**Ilerleme:** 3/3 (%100) ✅

---

## ~~Sprint 21 - Infrastructure Stubs Fix~~ ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| — | AutoRotationService + PasswordRotationOrchestrator DI kaydi | infra-fix | ✅ Tamamlandi |
| — | SSH/MySQL/PostgreSQL rotation stub fixleri (RotationService) | infra-fix | ✅ Tamamlandi |
| — | TelnetSession.CheckTerminationAsync stub fix | proxy-fix | ✅ Tamamlandi |

**Ilerleme:** 3/3 (%100) ✅

---

## ~~Sprint 22 - Refactoring: NavMenu Sadeleştirmesi~~ ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| — | NavMenu: 11 bolum → 8 kategori (CLAUDE.md Refactoring Sprint #1) | refactor | ✅ Tamamlandi |

**Ilerleme:** 1/1 (%100) ✅

---

## Sprint 23 - Refactoring: Device Realm Entity + API + UI
**Tarih:** 19 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| — | DeviceRealm entity (Kron PAM model) | refactor | ✅ Tamamlandi |
| — | DeviceRealm migration (3 tablo) | refactor | ✅ Tamamlandi |
| — | DeviceRealmEndpoints (CRUD + group mgmt) | refactor | ✅ Tamamlandi |
| — | PamApiService Device Realm methods + DTOs | refactor | ✅ Tamamlandi |
| — | DeviceRealms.razor Blazor UI | refactor | ✅ Tamamlandi |
| — | NavMenu: Device Realms linki (Access Control altinda) | refactor | ✅ Tamamlandi |

**Ilerleme:** 6/6 (%100) ✅

---

## Sprint 24 - Credential Assignment Refactoring (Kron PAM `assigned_credential` modeli) ✅ TAMAMLANDI
**Tarih:** 2026-05-19
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| — | AssignedCredential entity (Kron PAM model) | refactor | ✅ Tamamlandi |
| — | AssignedCredential migration | refactor | ✅ Tamamlandi |
| — | AssignedCredentialEndpoints (CRUD + my-credentials) | refactor | ✅ Tamamlandi |
| — | PamApiService AssignedCredential methods + DTO | refactor | ✅ Tamamlandi |
| — | CredentialAssignments.razor Blazor UI | refactor | ✅ Tamamlandi |
| — | NavMenu: Credential Assignments linki | refactor | ✅ Tamamlandi |

**Ilerleme:** 6/6 (%100) ✅

---

## ~~Sprint 25 - Security Fix: AssignedCredential Audit + Unique Constraint~~ ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi — 2 HIGH security bulgu fix'lendi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #217 | [HIGH] AssignedCredentialEndpoints audit logging eksik (CWE-778) | security | ✅ Kapatildi |
| #218 | [HIGH] AssignedCredentials unique constraint eksik — access revocation bypass (CWE-284) | security | ✅ Kapatildi |

**Ilerleme:** 2/2 (%100) ✅

---

## Sprint 26 - Refactoring #4: Gereksiz Sayfa ve Endpoint Temizligi ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi

| Item | Aciklama | Durum |
|------|----------|-------|
| Counter.razor | Blazor default demo sayfasi — silindi | ✅ Tamamlandi |
| Weather.razor | Blazor default demo sayfasi — silindi | ✅ Tamamlandi |
| MapAccessAssignmentEndpoints() | Eski model (Sprint 24 AssignedCredential ile superseded) — Program.cs'den kaldirildi | ✅ Tamamlandi |

**Ilerleme:** 3/3 (%100) ✅

---

## Sprint 27 - Refactoring #5: Session Akisi Realm-Based Erisim Kontrolu ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi

**Ilerleme:** 8/8 (%100) ✅ — Sprint 27 TAMAMLANDI

---

## ~~Sprint 28 - Security Fix: Session List Exposure (CWE-200/284)~~ ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi — 2 HIGH security bulgu fix'lendi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #221 | [HIGH] Session list endpoints expose all users' sessions | security | ✅ Kapatildi |
| #220 | [HIGH] Realm access check not enforced at session creation | security | ✅ Kapatildi (Sprint 27'de zaten implemente edilmisti) |

**Ilerleme:** 2/2 (%100) ✅

---

## Sprint 29 - Refactoring #6: SSH Proxy Session Lifecycle + TCP Hardening
**Tarih:** 19 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

**Ilerleme:** 9/9 (%100) ✅ — Sprint 29 TAMAMLANDI

---

## Sprint 30 - Security Fixes + RDP Proxy Admin Termination ✅ TAMAMLANDI
**Tarih:** 19 Mayis 2026
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #224 | [HIGH] ValidateProxySecret — non-constant-time string comparison (timing side-channel) | security | ✅ Kapatildi |
| #226 | [MEDIUM] SSH proxy session-start/end endpoint audit log eksik | security | ✅ Kapatildi |
| #225 | [MEDIUM] SSH Proxy — PAM kullanici parolasi .NET string olarak managed heap'te kaliyor | security | ✅ Kapatildi |
| #223 | [MVP] RDP Proxy Session Lifecycle — PAM DB Integration + Admin Termination | product | ✅ Kapatildi |
| #222 | [MVP] SSH Proxy ProxySession Recording Path DB Link | product | ✅ Kapatildi (Sprint 29'da zaten implemente edilmisti) |

**Ilerleme:** 5/5 (%100) ✅

---

## ~~Sprint 31 - User Profile + Password Change~~ ✅ TAMAMLANDI
**Tarih:** 20 Mayis 2026
**Durum:** Tamamlandi

**Ilerleme:** 5/5 (%100) ✅

---

## Sprint 32 - MFA Device Management (RFP MFA #12)
**Tarih:** 20 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

**Ilerleme:** 6/6 (%100) ✅

---

## Sprint 33 - Security Fix: MFA + Geolocation + Enrollment
**Tarih:** 20 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #227 | [HIGH] Admin MFA revoke — tip kontrolu eksik (CWE-287) | security | ✅ Kapatildi |
| #228 | [MEDIUM] Geolocation IP lookup HTTP → HTTPS (CWE-319) | security | ✅ Kapatildi |
| #229 | [MEDIUM] MFA enrollment GET endpoint — rate limiting + idempotency eksik | security | ✅ Kapatildi |

**Ilerleme:** 3/3 (%100) ✅

---

## Sprint 34 - MVP Feature: Credential Risk Scoring (#232)
**Tarih:** 20 Mayis 2026
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #232 | [MVP] Credential Risk Scoring — Vault Kimlik Bilgisi Risk Skoru | product | ✅ Kapatildi |

**Sprint 34 Tamamlanan Bilesenler (2026-05-20):**
- **Credential entity:** `ExpiresAtUtc`, `RiskScore`, `RiskLevel`, `RiskScoredAtUtc` alanlari eklendi
- **Migration:** `20260520_AddCredentialRiskScore.cs` — 4 yeni kolon + IX_Credentials_RiskLevel index
- **CredentialRiskScoringService** (BackgroundService, gunluk): 7 risk faktoru hesaplama — rotasyon yasi, hic rotasyon yok, coklu assignment, orphaned, sifre suresi dolmus, basarisiz session, admin/root kullanici adi
- **CredentialRiskEndpoints.cs:** 3 endpoint — risk-summary, high-risk (AdminPolicy), rescore (AdminPolicy)
- **Program.cs:** `AddHostedService<CredentialRiskScoringService>` + `MapCredentialRiskEndpoints()` kaydi
- **PamApiService.cs:** `CredentialDto` +3 alan (RiskScore/RiskLevel/RiskScoredAtUtc) + `GetCredentialRiskSummaryAsync` + `GetHighRiskCredentialsAsync` + `RescoreCredentialAsync` + `CredentialRiskSummaryDto` + `HighRiskCredentialDto`
- **Vault.razor:** Risk badge kolonu (renk kodlu: Yesil/Sari/Kirmizi/Mor)
- **Home.razor:** "High Risk Credentials" stat card + top-5 tablosu widget
- RFP Password Vault #25 + #31 → PC, Reporting #14 guclendirildi, Platform #39 guclendirildi

**Ilerleme:** 8/8 (%100) ✅

---

## ~~Sprint 35 - MVP Feature: Session Command Filter Admin UI (#231)~~ ✅ TAMAMLANDI
**Tarih:** 20 Mayis 2026
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #231 | [MVP] Session Command Filter Admin UI | product | ✅ Kapatildi |

**Sprint 35 Tamamlanan Bilesenler (2026-05-20):**
- **Domain entities:** `CommandFilterPolicy` (AuditableEntity) + `CommandFilterPolicyRule` — ProxySession.cs'e eklendi
- **Migration:** `20260520_AddCommandFilterPolicy.cs` — CommandFilterPolicies + CommandFilterPolicyRules tablolari, FK cascade delete, 2 index
- **DbContext:** `CommandFilterPolicies` + `CommandFilterPolicyRules` DbSet + EF Core konfigurasyonu (MaxLength, HasConversion<byte>, cascade)
- **CommandFilterPolicyEndpoints.cs:** 10 endpoint `/api/v1/policies/command-filter` altinda (AdminPolicy) — CRUD + toggle + rule yonetimi + /effective (SSH proxy JSON uyumlulugu)
- **Program.cs:** `MapCommandFilterPolicyEndpoints()` kaydedildi
- **PamApiService.cs:** 8 yeni method + 3 DTO (CommandFilterPolicyDto, CommandFilterPolicyDetailDto, CommandFilterRuleDto)
- **Policies.razor:** "Command Filter" sekmesi — policy listesi, rule viewer, add-rule formu, New Policy modali, Delete modali (11 yeni method + 20 yeni field)
- SSH proxy backward-compatibility: /effective endpoint mevcut JSON formatini uretir, proxy degisiklik gerektirmez

**Ilerleme:** 8/8 (%100) ✅

---

## Sonraki Adim
**Sprint 35 tamamlandi.** #231 Session Command Filter Admin UI implement edildi ve push edildi.
**Siradaki:** Sprint 36 — Backlog'daki bir sonraki priority:mvp issue
**v1.0.0 GA Tag:** 18 Mayis 2026'da atildi
**v2.0.0:** 30 Eylul 2026

---

## Sprint Kuralları
- Her sprint sonunda Coordinator tag atar
- Sprint değişlikliği bu dosya güncellenerek yapılır
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
