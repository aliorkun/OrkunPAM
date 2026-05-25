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
|------|----------|---|
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

## Sprint 36 - CommandFilterPolicy DB Integration (SSH Proxy Enforcement)
**Tarih:** 20 Mayis 2026 (aktif)
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #234 | CommandFilterService → CommandFilterPolicy DB Integration | MVP-PROXY | ✅ Tamamlandi |

**Sprint 36 Tamamlanan Bilesenler (2026-05-20):**
- **PolicyEndpoints.cs `GET /api/v1/policy/session`:** `CommandFilterPolicies` DB'den etkin global politikayi okuyarak `CommandFilterMode` + `CommandFilterRulesJson` alanlarini override eder — Sprint 35 admin UI'da tanimlanan politikalar artik SSH proxy'e ulasiyor
- **IMemoryCache (5 dakika TTL):** `policy:session:effective` cache key — SSH proxy session-start'ta DB'ye her seferinde gitmez
- **Cache invalidation:** `POST /api/v1/policy/session` artik `policy:session:effective` cache'ini de temizliyor
- **Rules JSON:** Her kural `pattern`, `isRegex`, `riskScore`, `action` alanlarini icerir
- **CommandFilterRule.Action:** Proxy'nin `CommandFilterRule` entity'sine `Action` alani eklendi
- **Alert action support:** `Action = "Alert"` kurallar → proxy `FilterAction.Warn` dondurur (komut gecer, uyari logu yazilir) — onceden hic desteklenmiyordu
- **Deny action (default):** Mevcut `FilterAction.Block` davranisi korundu (Blacklist mode + matched = block)
- **using import:** `PolicyEndpoints.cs`'e `using OrkunPAM.Domain.Entities.Session;` eklendi

**Ilerleme:** 4/4 (%100) ✅

---

## Sprint 37 - Credential Rotation Failure Alerts (PV #33)
**Tarih:** 20 Mayis 2026
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #235 | Credential Rotation Failure Alerts — Email + Dashboard Notification | MVP-VAULT | ✅ Tamamlandi |
| #237 | Cache Invalidation: CommandFilterPolicy mutations | security | ✅ Tamamlandi |
| #238 | Missing `action` field in /effective endpoint | bug | ✅ Tamamlandi |

**Sprint 37 Tamamlanan Bilesenler (2026-05-20):**
- **Credential.cs entity:** `LastRotationError`, `RotationFailureCount`, `LastRotationFailedAtUtc` alanlari eklendi
- **Migration 20260520_AddCredentialRotationFailure:** 3 yeni kolon Credentials tablosuna eklendi
- **AutoRotationService.cs:** Rotasyon basarisiz olduğunda `IEmailService` ile VaultAdmin/GlobalAdmin rollerine email bildirimi
- **CredentialRiskEndpoints.cs:** `GET /api/v1/vault/credentials/rotation-failures` endpoint eklendi
- **Home.razor:** "Rotation Failures (24h)" stat card + son 5 rotation failure widget
- **Vault.razor:** Başarısız rotasyon için kirmizi "Failed" badge + tooltip
- **VaultEndpoints.cs:** Projeksiyonlara `RotationFailureCount`, `LastRotationError`, `LastRotationFailedAtUtc` eklendi
- **PamApiService.cs:** `CredentialDto` +3 alan, `GetRotationFailuresAsync()`, `RotationFailureItemDto`, `RotationFailuresResponseDto`
- **Cache fixes (#237/#238):** CommandFilterPolicy mutation'lari cache temizliyor, /effective endpoint'e `action` alani eklendi

**Ilerleme:** 3/3 (%100) ✅

---

## Sprint 38 - Session Compliance View (RA #34 + #35)
**Tarih:** 20 Mayis 2026
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #236 | Session Compliance View — Policy Violation Summary Dashboard | MVP-SESSIONS | ✅ Tamamlandi |

**Sprint 38 Tamamlanan Bilesenler (2026-05-20):**
- **SessionComplianceEndpoints.cs (yeni):** 3 endpoint — `/summary`, `/violations`, `/governance-report`
- **Sessions.razor:** "Compliance" sekmesi eklendi — compliance rate, stat cards, violation types, top users/devices
- **CSV Export:** Compliance raporu CSV olarak indirilebilir
- **Program.cs:** `MapSessionComplianceEndpoints()` kayit edildi
- **PamApiService.cs:** `GetSessionComplianceSummaryAsync()`, `SessionComplianceSummaryDto`, `ComplianceViolatingUserDto`, `ComplianceViolatingDeviceDto`
- **SessionDto:** `Tags` alani eklendi (optional, mevcut kod uyumlulugu)

**Ilerleme:** 1/1 (%100) ✅

---

## Sprint 39 - Credential Governance + Export + Alerts (RFP PV #20, #33, #35)
**Tarih:** 20 Mayis 2026
**Durum:** Tamamlandi ✅

| Item | Baslik | Tip | Durum |
|------|--------|-----|-------|
| — | CredentialGovernanceEndpoints.cs — 4 endpoint (summary, access-matrix, stale-access, export) | refactor | ✅ Tamamlandi |
| — | CredentialAlertService.cs — gunluk expiry + critical-risk email alert BackgroundService | infra | ✅ Tamamlandi |
| — | CredentialGovernance.razor — Blazor UI (summary cards, Access Matrix tab, Stale Access tab) | UI | ✅ Tamamlandi |
| — | PamApiService.cs — governance DTOs + 4 yeni method | infra | ✅ Tamamlandi |
| — | NavMenu: Vault → Governance linki eklendi | UI | ✅ Tamamlandi |
| — | Program.cs — CredentialAlertService + MapCredentialGovernanceEndpoints kaydi | infra | ✅ Tamamlandi |
| — | RFP-CHECKLIST.md — RA #34, RA #35, PV #20, PV #33, PV #35 → PC | docs | ✅ Tamamlandi |

**Sprint 39 Tamamlanan Bilesenler (2026-05-20):**
- **CredentialGovernanceEndpoints.cs:** 4 endpoint — `/api/v1/vault/governance/summary` (expired/expiring/never-rotated/critical counts), `/access-matrix` (paginated who-has-access-to-what), `/stale-access` (unused assignments 30-180d), `/api/v1/vault/credentials/export` (CSV metadata, no passwords)
- **CredentialAlertService.cs:** Daily BackgroundService — expiry alert for credentials expiring ≤7 days; critical-risk alert for Critical-level credentials; emails VaultAdmin/GlobalAdmin; 24h dedup via AuditLog (`CREDENTIAL_EXPIRY_ALERT`, `CREDENTIAL_CRITICAL_RISK_ALERT` events)
- **CredentialGovernance.razor:** `/vault/governance` page — 8 summary stat cards, Access Matrix tab (paginated), Stale Access tab (configurable 30/60/90/180d window), CSV export button
- **PamApiService.cs:** `GetCredentialGovernanceSummaryAsync`, `GetCredentialAccessMatrixAsync`, `GetStaleCredentialAccessAsync`, `ExportCredentialsCsvAsync` + 6 new DTOs
- **NavMenu.razor:** "Governance" link under Vault section
- **RFP items closed:** Remote Access #34 (session compliance) → PC, Remote Access #35 (session governance) → PC, Password Vault #20 (credential export) → PC, Password Vault #33 (credential alerts) → PC, Password Vault #35 (credential governance) → PC

**Ilerleme:** 7/7 (%100) ✅

---

## ~~Sprint 40 - Security Fix: Governance Endpoint Hardening~~ ✅ TAMAMLANDI
**Tarih:** 20 Mayis 2026
**Durum:** Tamamlandi — 3 HIGH security bulgu fix'lendi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #242 | [HIGH] /credentials/export audit log eksik (CWE-778) | security | ✅ Kapatildi |
| #243 | [HIGH] AutoRotationService hata mesajlari sifre sizdirabilir (CWE-209) | security | ✅ Kapatildi |
| #244 | [HIGH] stale-access endpoint sinarsiz sorgu OOM/DoS riski (CWE-400) | security | ✅ Kapatildi |

**Ilerleme:** 3/3 (%100) ✅

---

## ~~Sprint 41 - MVP Feature: Session Recording Export & Download (#239)~~ ✅ TAMAMLANDI
**Tarih:** 20 Mayis 2026
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #239 | Session Recording Export & Download — Compliance Auditor Erisimi (RA #45) | MVP-SESSION | ✅ Kapatildi |

**Sprint 41 Tamamlanan Bilesenler (2026-05-20):**
- **SessionEndpoints.cs:** `GET /api/v1/sessions/{id}/export` — ZIP bundle: `session-{id}/metadata.json` (session details) + `recording.json` (SSH asciinema_v2) or `recording.bin` (other types); role-guard GlobalAdmin/Auditor/SessionAdmin; audit log `SESSION_RECORDING_EXPORTED`
- **SessionEndpoints.cs:** `GET /api/v1/sessions/export/bulk` — multi-session ZIP of metadata.json files; limit clamped 1-500; filter by from/to/userId/deviceId; role-guard GlobalAdmin/Auditor; audit log `SESSION_RECORDING_BULK_EXPORTED`
- **SessionPlayback.razor:** `@inject IJSRuntime JS` + `DownloadRecordingAsync()` → `JS.InvokeVoidAsync("open", url, "_self")` — Download button triggers real browser file download
- **PamApiService.cs:** `GetSessionExportUrl(sessionId)` + `GetSessionBulkExportUrl(from, to, userId, deviceId, limit)` URL builder helpers
- **RFP-CHECKLIST.md:** Remote Access #45 (session export) → PC

**Ilerleme:** 5/5 (%100) ✅

---

## Sprint 42 - Credential Automation Scripts (RFP PV #37)
**Tarih:** 2026-05-21 (aktif)
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|------|
| #241 | [MVP] Credential Automation Scripts — Custom Rotation Handlers | MVP-VAULT | ✅ Tamamlandi |

**Sprint 42 Tamamlanan Bilesenler (2026-05-21):**
- **RotationScriptType enum:** PowerShell/Bash/Python — `Enums.cs`'e eklendi
- **RotationScript entity:** Name, DeviceType, ScriptType, ScriptContent, TestScriptContent, IsEnabled, CredentialId/DeviceGroupId FK — `Credential.cs`'e eklendi
- **Credential.cs:** `RotationScriptId` + `RotationScript?` nav prop eklendi
- **Migration `20260521_AddRotationScript`:** RotationScripts tablosu + Credentials.RotationScriptId FK + indexler
- **DbContext:** `RotationScripts` DbSet eklendi
- **RotationScriptRunner.cs (Persistence/Services):** Static sandbox runner — 60s timeout, temp file, env vars, stdout/stderr truncation
- **RotationScriptEndpoints.cs (WebAPI/Endpoints):** 6 endpoint — CRUD + /test + /rotate-with-script (AdminPolicy); 7 audit events
- **Program.cs:** `MapRotationScriptEndpoints()` kaydedildi
- **AutoRotationService.cs:** RotationScript check — credential'a custom script baglysa script path kullanir; env vars: PAM_TARGET_IP/USERNAME/CURRENT_PASSWORD/NEW_PASSWORD
- **PamApiService.cs:** 6 yeni method + RotationScriptDto/RotationScriptDetailDto/RotationScriptCreatedDto/ScriptTestResultDto
- **Vault.razor:** "Rotation Scripts" tab — script listesi, New Script modal (editor + testScriptContent), test output panel; SwitchTab() + 12 yeni field + 5 yeni method
- **RFP-CHECKLIST.md:** PV #37 → PC

**Ilerleme:** 8/8 (%100) ✅

---

---

## Sprint 43 - Security Fixes + Visual Screen Capture (#240)
**Tarih:** 2026-05-21 (aktif)
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #245 | [HIGH] Custom script rotation: new password never saved to vault | security | ✅ Fix'lendi |
| #246 | [HIGH] Rotation script stdout leaking sensitive data in API response | security | ✅ Fix'lendi |
| #247 | [HIGH] Modulo bias in password generation (CWE-331) | security | ✅ Fix'lendi |
| #240 | [MVP] Visual Screen Capture for RDP/VNC Sessions (RA #28 + #30) | product | ✅ Tamamlandi |

**Sprint 43 Tamamlanan Bilesenler (2026-05-21):**
- **#245:** RotationScriptEndpoints.cs `rotate-with-script` endpoint: IVaultEncryptionService inject + `credential.PasswordEnc = vault.EncryptString(newPassword).Value` basarili rotasyondan sonra; AutoRotationService.cs custom-script yolunda da ayni duzeltme
- **#246:** `rotate-with-script` basari yaniti artik `result.Output` icermiyor; `RedactSensitivePatterns()` helper: regex ile password/secret/token pattern'lari [REDACTED] ile maskeler, 2048 char limit
- **#247:** `GeneratePassword()`: modulo bias giderildi — rejection sampling (NIST SP 800-132): `limit = 256 - (256 % chars.Length) = 248`, bias range'i atlar
- **#240:** ScreenCaptureFrame entity (ProxySession.cs) + migration 20260521_AddScreenCaptureFrame + DbContext DbSet; ScreenCaptureEndpoints.cs (3 endpoint); Program.cs kaydı; VNC proxy (VncSession.cs): ServerInit'ten width/height parse + 5s periyodik capture timer + `_api.ReportScreenCaptureAsync()`; RDP proxy (RdpServerSession.cs): 5s periyodik capture timer; Both PamApiClients: `ReportScreenCaptureAsync()` method; SessionPlayback.razor: Screen Captures tab (timeline table + progress bar); PamApiService.cs: `GetScreenCapturesAsync()` + ScreenCaptureFrameDto; RFP-CHECKLIST.md: RA #28 → PC, RA #30 → PC

**Ilerleme:** 4/4 (%100) ✅

---

## Sprint 44 — Credential Templates (2026-05-21)
**Issue:** #248 — PV #21 Credential Templates
**Status:** COMPLETE

### Implemented
- `CredentialTemplate` entity (AuditableEntity with IsBuiltIn protection)
- Migration `20260521_AddCredentialTemplate` with 8 built-in templates (linux-root, linux-service, windows-admin, windows-service, mssql-sa, cisco-enable, juniper-admin, nas-admin)
- `CredentialTemplateEndpoints.cs` — GET list, GET single, POST create, PUT update, DELETE, POST apply (all with AdminPolicy; built-in templates are read-only)
- `OrkunPamDbContext`: CredentialTemplates DbSet + EF config
- `Program.cs`: MapCredentialTemplateEndpoints() + MapScreenCaptureEndpoints() registered
- `PamApiService.cs`: GetCredentialTemplatesAsync, CreateCredentialTemplateAsync, UpdateCredentialTemplateAsync, DeleteCredentialTemplateAsync, CredentialTemplateDto
- `Vault.razor`: Templates tab with table (built-in/custom badge), New/Edit modal, Delete confirm modal
- RFP PV #21 → PC

---

## Sprint 45 — Peripheral Redirection Control (#249)
**Tarih:** 2026-05-21 (aktif)
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #249 | [MVP] RDP/VNC USB & Peripheral Redirection Control | MVP-SESSION | ✅ Tamamlandi |

**Sprint 45 Tamamlanan Bilesenler (2026-05-21):**
- **PeripheralRedirectionPolicy entity** (ProxySession.cs): Name, IsEnabled, AllowClipboard, AllowDriveRedirection, AllowPrinterRedirection, AllowUsbRedirection, AllowAudioRedirection, AllowSmartCardRedirection, DeviceGroupId FK
- **Migration `20260521_AddPeripheralRedirectionPolicy`:** PeripheralRedirectionPolicies tablosu + 2 index (IsEnabled, DeviceGroupId)
- **DbContext:** PeripheralRedirectionPolicies DbSet + OnModelCreating config
- **PeripheralPolicyEndpoints.cs:** 5 endpoint — GET list, POST, GET {id}, PUT, DELETE (AdminPolicy) + GET /effective (X-Proxy-Secret); secure defaults when no policy configured
- **Program.cs:** MapPeripheralPolicyEndpoints() kaydedildi
- **PamApiService.cs:** PeripheralRedirectionPolicyDto + GetPeripheralPoliciesAsync, CreatePeripheralPolicyAsync, UpdatePeripheralPolicyAsync, DeletePeripheralPolicyAsync
- **Policies.razor:** "Peripheral Control" tab — policy table (emoji channel indicators), New/Edit modal (checkbox toggles per channel), Delete confirm modal; SwitchTab case + LoadPrpAsync
- **RDP PamApiClient:** GetPeripheralPolicyAsync() — X-Proxy-Secret header, fallback to secure defaults
- **RdpCommandAuditor:** SetPeripheralPolicy() + ShouldBlockPdu() — CLIPRDR/RDPDR/RDPSND channels dropped when blocked; CLIPBOARD_REDIRECTION_BLOCKED / DRIVE_REDIRECTION_BLOCKED / AUDIO_REDIRECTION_BLOCKED audit log
- **RdpServerSession:** peripheralPolicy fetched at session start, passed to auditor; PumpWithAuditAsync checks ShouldBlockPdu before forwarding
- **RFP-CHECKLIST.md:** RA #26 → PC

**Ilerleme:** 10/10 (%100) ✅

---

## Sprint 46 — API Key Authentication for Service Accounts (#250) ✅ TAMAMLANDI
**Tarih:** 2026-05-21
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #250 | [MVP] MFA for API Access — Service Account API Key + HMAC-Timestamp Binding (MFA #17, #18) | MVP-AUTH | ✅ Tamamlandi |

**Sprint 46 Tamamlanan Bilesenler (2026-05-21):**
- **ApiKey entity:** Name, Prefix, KeyHash (SHA-256), HmacSecretEnc (AES-encrypted 32-byte HMAC secret), ServiceAccountUserId FK, AllowedIpCidrsJson, ExpiresAtUtc, UsageCount, IsActive
- **User.IsServiceAccount flag:** Added to User entity — service accounts skip interactive MFA
- **Migration `20260521_AddApiKey`:** ApiKeys table + Users.IsServiceAccount column + 3 indexes
- **DbContext:** ApiKeys DbSet + EF Core configuration (unique prefix index, cascade delete)
- **ApiKeyAuthMiddleware.cs:** Runs before UseAuthentication — X-Api-Key + X-Timestamp + X-Signature validation; SHA-256 key hash verify (constant-time); HMAC-SHA256 signature verify; ±5 min timestamp tolerance; replay attack protection via IMemoryCache nonce; IP CIDR restriction; injects short-lived JWT (5 min) for the service account user
- **ApiKeyEndpoints.cs:** 5 endpoints — GET list, POST create (returns one-time raw key + HMAC secret), GET single, DELETE revoke, POST rotate; 3 audit events (API_KEY_CREATED/REVOKED/ROTATED); AdminPolicy protected
- **Program.cs:** `app.UseMiddleware<ApiKeyAuthMiddleware>()` before UseAuthentication + `api.MapApiKeyEndpoints()` registered
- **PamApiService.cs:** `GetApiKeysAsync`, `CreateApiKeyAsync`, `RevokeApiKeyAsync`, `RotateApiKeyAsync` + `ApiKeyDto` + `ApiKeyCreatedDto`
- **Integrations.razor:** "API Keys" tab — create form, one-time key material display panel (warn banner), key table (prefix/status/usage/expiry) + Rotate/Revoke actions
- **RFP-CHECKLIST.md:** MFA #17 → PC, MFA #18 → PC

**Ilerleme:** 9/9 (%100) ✅

---

## Sprint 47 - MFA Exceptions: Auth Flow Enforcement (#259) + HMAC ZeroMemory Fix (#260)
**Tarih:** 2026-05-21
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #259 | [HIGH] MFA Exception enforcement missing in auth flow | security | ✅ Fix'lendi |
| #260 | [MEDIUM] HMAC secret bytes not zeroed after vault.Encrypt() | security | ✅ Fix'lendi |

**Sprint 47 Tamamlanan Bilesenler (2026-05-21):**
- **AuthEndpoints.cs:** `using System.Net` + `using OrkunPAM.Application.Contracts` eklendi; login handler'a `IAuditService audit` inject edildi; MFA Exception check blogu eklendi — `Status == Approved && ExpiresAtUtc > now && UsageCount < MaxUsageCount && !RevokedAtUtc.HasValue`; IP CIDR restriction kontrolu; `UsageCount++`; `MFA_EXCEPTION_USED` audit log; `data = data with { MfaRequired = false }` ile bypass
- **AuthEndpoints.cs:** `MfaCidrHelper` static class eklendi — `IsIpAllowed` + `IsInCidr` (ApiKeyAuthMiddleware'daki aynı CIDR logic)
- **ApiKeyEndpoints.cs:** `CryptographicOperations.ZeroMemory(hmacSecret)` — create endpoint satir 98 + rotate endpoint satir 208 sonrasina eklendi (CWE-316)

**Ilerleme:** 2/2 (%100) ✅

---

## Sprint 48 - Credential Orchestration (#251) — PV #38
**Tarih:** 2026-05-21
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #251 | [MVP] Credential Orchestration — Multi-System Synchronized Rotation (PV #38) | MVP-VAULT | ✅ Tamamlandi |

**Sprint 48 Tamamlanan Bilesenler (2026-05-21):**
- **Enums.cs:** `OrchestrationExecutionMode` (Sequential/Parallel) + `OrchestrationRunStatus` (Pending/Running/Success/PartialFailure/RolledBack/Failed) eklendi
- **Credential.cs:** `CredentialOrchestrationSet` + `CredentialOrchestrationMember` + `CredentialOrchestrationRun` entity'leri eklendi
- **Migration `20260521_AddCredentialOrchestration`:** 3 tablo — CredentialOrchestrationSets, CredentialOrchestrationMembers, CredentialOrchestrationRuns
- **DbContext:** 3 DbSet + OnModelCreating config (cascade delete, FK'lar, index'ler)
- **CredentialOrchestrationEndpoints.cs:** 7 endpoint — GET list, POST create, GET detail, PUT update, DELETE, POST run (sequential/parallel + rollback + email), GET runs history; 6 audit event
- **Program.cs:** `MapCredentialOrchestrationEndpoints()` kaydedildi
- **PamApiService.cs:** `GetOrchestrationSetsAsync`, `CreateOrchestrationSetAsync`, `UpdateOrchestrationSetAsync`, `DeleteOrchestrationSetAsync`, `RunOrchestrationAsync`, `GetOrchestrationRunsAsync` + 6 DTO (OrchestrationSetDto, OrchestrationSetDetailDto, OrchestrationMemberDto, OrchestrationRunResultDto, OrchestrationRunDto, IdDto)
- **Vault.razor:** "Orchestration" tab — set listesi, Run/History/Delete butonlari, New Set modali (mode/rollback/notify/cron), history modali (run log)
- **RFP-CHECKLIST.md:** PV #38 → PC

**Ilerleme:** 8/8 (%100) ✅

---

## Sprint 49 — MFA Session Persistence (#257) — Trusted Browser Token
**Tarih:** 2026-05-24
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #257 | [MVP] MFA Session Persistence — Trusted Browser Token (MFA #20) | MVP-AUTH | ✅ Tamamlandi |

**Sprint 49 Tamamlanan Bilesenler (2026-05-24):**
- **MfaTrustedSession entity** (User.cs): UserId FK, BrowserFingerprint (SHA-256), DeviceLabel, TrustExpiresAtUtc, GrantedFromIp, GrantedAtUtc, LastUsedAtUtc, IsRevoked
- **Migration `20260524_AddMfaTrustedSession`:** MfaTrustedSessions tablosu + 2 index (UserId_IsRevoked, BrowserFingerprint)
- **DbContext:** MfaTrustedSessions DbSet + EF Core konfigurasyonu (cascade delete, max lengths)
- **AuthEndpoints.cs — login flow:** Trusted session check eklendi (MFA exception check'ten sonra); gecerli trusted session bulunursa MFA atlaniyor; audit log: MFA_SESSION_TRUST_USED
- **AuthEndpoints.cs — yeni endpointler:**
  - `GET /api/v1/auth/mfa-trust-policy` (anonim) — MaxMfaTrustHours doner (0=kapali)
  - `POST /api/v1/auth/trusted-sessions` (auth) — mevcut browseri guvene al; mevcut kaydı revoke eder; audit: MFA_SESSION_TRUST_GRANTED
  - `GET /api/v1/auth/trusted-sessions` (auth) — kullanici kendi aktif trusted session listesini gorur
  - `DELETE /api/v1/auth/trusted-sessions/{id}` (auth) — self-service revoke; audit: MFA_SESSION_TRUST_REVOKED
  - `GET /api/v1/admin/users/{userId}/trusted-sessions` (AdminPolicy) — admin goruntuleme
  - `DELETE /api/v1/admin/users/{userId}/trusted-sessions` (AdminPolicy) — admin bulk revoke; audit: MFA_SESSION_TRUST_ADMIN_REVOKED_ALL
- **Login.razor:** `_rememberDevice` + `_mfaTrustMaxHours` alanlari; MFA step'e "Trust this browser for N hours" checkbox (policy MaxHours > 0 ise gorunur); `HandleLoginAsync`'de trust policy yukleniyor; `CompleteLoginAsync`'de `CreateTrustedSessionAsync` cagrisi
- **SelfService.razor:** "Trusted Devices" sekme eklendi — aktif trusted session listesi (label, IP, tarihler, bitis), Revoke butonu; `LoadTrustedSessionsAsync` + `RevokeTrustedSessionAsync` metodlari
- **PamApiService.cs:** LoginData record eksik alanlari duzeltildi (MfaType, MfaEnrollmentRequired, MustChangePassword, PasswordExpired, PortalProfile, RiskLevel, RiskScore); `GetMfaTrustPolicyAsync`, `CreateTrustedSessionAsync`, `GetTrustedSessionsAsync`, `RevokeTrustedSessionAsync` metodlari; `MfaTrustPolicyDto` + `MfaTrustedSessionDto` kayitlari
- **Policy config:** `mfa.trust.max_hours` SystemConfig anahtari (int, 0=kapali, max 168h=7gun); admin System Settings'ten ayarlanabilir
- **RFP-CHECKLIST.md:** MFA #20 (MFA session persistence) → PC
- **Fingerprint:** DeviceTrustHelper.ComputeFingerprint() ile hesaplaniyor — User-Agent + Accept-Language + Accept-Encoding + subnet-level IP SHA-256

**Ilerleme:** 8/8 (%100) ✅

---

## Sprint 50 - Live Session Shadowing (#258) ✅ TAMAMLANDI
**Tarih:** 2026-05-24
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #258 | [MVP] Live Session Shadowing — Admin Co-Watch for Compliance (RA #40) | MVP-SESSION | ✅ Tamamlandi |

**Sprint 50 Tamamlanan Bilesenler (2026-05-24):**
- **SessionShadow entity** (ProxySession.cs): SessionId FK, ShadowByUserId, ShadowByUsername, StartedAtUtc, EndedAtUtc, ShadowIp, IsActive
- **Migration `20260524_AddSessionShadow`:** SessionShadows tablosu + 2 index (SessionId, SessionId+IsActive) + FK → ProxySessions CASCADE
- **DbContext:** SessionShadows DbSet + EF Core config (max lengths, indexes)
- **ShadowEndpoints.cs:** 4 endpoint — POST /shadow (create + observer++), DELETE /shadow (end + observer--), GET /shadows (active list), POST /shadow/revoke-all (admin bulk revoke); 3 audit events (SESSION_SHADOW_STARTED/ENDED/REVOKED)
- **Program.cs:** MapShadowEndpoints() kaydedildi
- **SshTargetClient.cs:** RelayToClientAsync + TargetToClientLoopAsync — `liveChunk` callback parametresi eklendi; target→client byte stream her chunki liveChunk?.Invoke() ile iletir
- **SshServerSession.cs:** `pamSessionId != null ? text => _api.SendLiveChunk(pamSessionId, text) : null` callback RelayToClientAsync'e gecirildi — SSH terminal output artik SessionChunkStore'a yaziliyor
- **Sessions.razor:** ShadowAsync() metodu duzeltildi — RDP download yerine `/shadow/{sessionId}` navigasyonu; Shadow butonu basitledirildi
- **SessionShadow.razor:** Yeni sayfa `/shadow/{SessionId}` — StartShadowAsync ile DB kaydedilen shadow baslatma; 2s poll ile terminal output stream; Status panel (observers, risk score, target IP); Recent Commands panel; Terminate Session modal; DisposeAsync'de StopShadowAsync ile temiz kapanma
- **PamApiService.cs:** Eksik private metodlar eklendi: GetAuthClientAsync + GetAsync<T> (data-field extractor with root fallback); Yeni live session metodlar: JoinLiveSessionAsync, LeaveLiveSessionAsync, BroadcastLiveMessageAsync, GetSessionCommandsAsync; Yeni shadow metodlar: StartShadowAsync, StopShadowAsync, GetLiveStreamAsync; GetLiveSessionStatusAsync → LiveSessionStatusDto; Yeni DTOs: ShadowStartDto, LiveStreamDto, LiveSessionStatusDto, LiveObserverDto, SessionCommandDto
- **RFP-CHECKLIST.md:** RA #40 (session collaboration) → PC

**Ilerleme:** 8/8 (%100) ✅

---

## Sprint 51 - OATH Hardware Token (#261) ✅ TAMAMLANDI
**Tarih:** 2026-05-24
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #261 | [MVP] OATH Hardware Token Support — Physical MFA for Air-Gapped Environments (MFA #7) | MVP-MFA | ✅ Tamamlandi |

**Sprint 51 Tamamlanan Bilesenler (2026-05-24):**
- **HardwareToken entity** (Identity/HardwareToken.cs): Id, UserId FK, SerialNumber, SecretKeyEnc (AES-GCM), TokenType (TOTP/HOTP), CounterValue, Algorithm (SHA1/256/512), Digits (6/8), PeriodSeconds, IsActive, Label, ProvisionedAtUtc
- **Migration `20260524_AddHardwareToken`:** HardwareTokens tablosu + 2 index (UserId, UserId+IsActive) + FK → Users CASCADE
- **DbContext:** HardwareTokens DbSet + EF Core config; ModelSnapshot guncellendi
- **HardwareTokenEndpoints.cs:** 4 endpoint — POST /hardware-tokens (provision, AdminPolicy), GET /hardware-tokens (list, self or admin), DELETE /hardware-tokens/{id} (revoke), POST /verify-hardware-otp (OTP verify → JWT); RFC 4226 HOTP (±5 look-ahead window) + RFC 6238 TOTP (±1 period); SHA1/SHA256/SHA512; 3 audit events (HARDWARE_TOKEN_PROVISIONED/VERIFIED/REVOKED); OathHelper static class with Base32Decode
- **Program.cs:** MapHardwareTokenEndpoints() kaydedildi
- **Login.razor:** HardwareToken MFA step eklendi (🗹 ikon, 6-8 digit input, HandleHardwareTokenAsync + OnHardwareTokenKeyUp)
- **Integrations.razor:** Hardware Tokens sekmesi — token provision formu (User ID, Serial, Base32 secret, type, algorithm, digits, period, label); token listesi tablosu (serial, type, algorithm, status, revoke butonu); state variables + SetTab case + ProvisionTokenAsync + RevokeTokenAsync metodlari
- **PamApiService.cs:** ProvisionHardwareTokenAsync, GetHardwareTokensAsync, GetAllHardwareTokensAsync, RevokeHardwareTokenAsync, VerifyHardwareOtpAsync; HardwareTokenDto record
- **RFP-CHECKLIST.md:** MFA #7 (OATH hardware tokens) → PC

**Ilerleme:** 8/8 (%100) ✅

---

## Sprint 52 — Session Handoff (#263) — RA #41
**Tarih:** 2026-05-24
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #263 | [MVP] Session Handoff — Admin Session Transfer for Shift Changes & Escalation (RA #41) | MVP-SESSION | ✅ Tamamlandi |

**Sprint 52 Tamamlanan Bilesenler (2026-05-24):**
- **SessionHandoff entity** (ProxySession.cs): Id, SessionId FK, RequestedByUserId, RequestedByUsername, RequestedToUserId, RequestedToUsername, RequestedAtUtc, AcceptedAtUtc, Status (Pending/Accepted/Declined/Expired), TransferNotes, ExpiresAtUtc (15 dk TTL)
- **Migration `20260524_AddSessionHandoff`:** SessionHandoffs tablosu + 2 index (SessionId, RequestedToUserId+Status) + FK → ProxySessions CASCADE
- **DbContext:** SessionHandoffs DbSet + EF Core konfigurasyonu (cascade delete, max lengths, indexes)
- **SessionHandoffEndpoints.cs:** 5 endpoint — POST /handoff (request, cancels prior pending), POST /handoff/accept (ownership transfer + ProxySession.UserId güncelleme), POST /handoff/decline, GET /handoff/pending (stale auto-expire), GET /{id}/handoffs (admin history); 5 audit event: SESSION_HANDOFF_REQUESTED/ACCEPTED/DECLINED/EXPIRED + SESSION_TRANSFERRED
- **Program.cs:** MapSessionHandoffEndpoints() kaydedildi
- **PamApiService.cs:** RequestHandoffAsync, AcceptHandoffAsync, DeclineHandoffAsync, GetPendingHandoffsAsync + HandoffCreatedDto + PendingHandoffDto
- **Sessions.razor:** Handoff button (active sessions), pending badge (header), Handoff request modal (user dropdown + notes), Pending Handoffs panel (Accept/Decline); LoadPendingHandoffsAsync on page load
- **Live stream notification:** Handoff request + acceptance banners injected into SessionChunkStore (visible to shadow observers)
- **RFP-CHECKLIST.md:** RA #41 → PC

**Ilerleme:** 8/8 (%100) ✅

---

## Sprint 54 - OIDC Federation — Azure AD / Okta / Auth0 (#271)
**Tarih:** 2026-05-25
**Durum:** Tamamlandi ✅

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #271 | [MVP] OpenID Connect (OIDC) Federation — Azure AD / Okta / Auth0 Identity Provider Support (UM #48) | MVP-AUTH | ✅ Tamamlandi |

**Sprint 54 Tamamlanan Bilesenler (2026-05-25):**
- **OidcProvider entity** (LdapConfig.cs): Name (slug), DisplayName, Authority (issuer URL), ClientId, ClientSecretEnc (AES-256-GCM), Scopes, GroupClaimType, GroupRoleMapping (JSON), AutoProvisionUsers, DefaultRole, IsEnabled
- **Migration `20260525_AddOidcProvider`:** OidcProviders tablosu + unique index on Name + IsEnabled index
- **DbContext:** OidcProviders DbSet + EF Core konfigurasyonu (unique Name, max lengths)
- **OidcAuthEndpoints.cs:** 7 endpoint — GET /providers (public), GET /{name}/login (PKCE+state+nonce redirect), GET /{name}/callback (code exchange + ID token validation + user provision + PAM JWT → /oidc-callback redirect); Admin CRUD: GET/POST/PUT/DELETE /api/v1/system/oidc-providers, POST /test
- **PKCE (RFC 7636):** code_verifier (32 bytes random) + S256 code_challenge; state + nonce in IMemoryCache (10 min TTL); replay protection
- **ID token validation:** exp/iss/aud/nonce checks; flexible issuer comparison; no signature verification needed (direct token endpoint fetch over TLS)
- **User auto-provision:** First login creates User with AuthSource=Oidc + ExternalId=sub; default role assignment; subsequent logins sync by sub claim
- **3 audit events:** OIDC_LOGIN_SUCCESS, OIDC_LOGIN_FAILED, OIDC_USER_PROVISIONED
- **Program.cs:** MapOidcAuthEndpoints() kaydedildi
- **OidcCallback.razor:** /oidc-callback page — token parse + SetSessionAsync → same pattern as SamlCallback
- **Login.razor:** GetOidcProvidersPublicAsync() on load; "or sign in with" divider + provider buttons (forceLoad:true to follow 302 redirects)
- **Integrations.razor:** "OIDC Federation" sekmesi — provider listesi, New/Edit modal (authority/clientId/scopes/groupClaim/defaultRole/autoProvision), Test butonu (discovery endpoint ping), Delete confirm modal; SetTab case + 8 yeni method + 21 yeni state field
- **PamApiService.cs:** GetOidcProvidersPublicAsync, GetOidcProvidersAdminAsync, CreateOidcProviderAsync, UpdateOidcProviderAsync, DeleteOidcProviderAsync, TestOidcProviderAsync + OidcProviderPublicDto + OidcProviderDto + OidcTestResultDto
- **RFP-CHECKLIST.md:** UM #48 → PC

**Ilerleme:** 8/8 (%100) ✅

---

## Sprint 55 - MFA for Privileged Workstations (#270) ✅ TAMAMLANDI
**Tarih:** 2026-05-25
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|—----|
| #270 | [MVP] MFA for Privileged Workstations — Device-Type Specific MFA Enforcement Policy (MFA #22) | MVP-AUTH | ✅ Tamamlandi |

**Sprint 55 Tamamlanan Bilesenler (2026-05-25):**
- **DeviceMfaPolicy entity** (ProxySession.cs): Name, Description, DeviceGroupId/DeviceId FK, RequiredMfaLevel (string: None/Totp/Fido2/HardwareToken/Any), EnforceAtSessionStart, IsEnabled
- **Migration `20260525_AddDeviceMfaPolicy`:** DeviceMfaPolicies tablosu + 3 index (IsEnabled, DeviceGroupId, DeviceId)
- **DbContext:** DeviceMfaPolicies DbSet + OnModelCreating config (maxLengths, indexes)
- **DeviceMfaPolicyEndpoints.cs:** 5 endpoint (CRUD + /effective) + `POST /api/v1/sessions/step-up-verify` (TOTP dogrulama → IMemoryCache 15-dk completion token); 3 audit event (CREATED/UPDATED/DELETED); GetEffectivePolicyAsync: device → device-group → global fallback
- **SessionEndpoints.cs:** `CreateSession` fonksiyonuna adim-yukleme kontrolu eklendi — `stepup:{userId}:{deviceId}` cache key; 403 + stepUpToken donerken `SESSION_MFA_STEP_UP_REQUIRED` audit event
- **Program.cs:** `MapDeviceMfaPolicyEndpoints()` kayitlandi
- **Policies.razor:** "Device MFA" sekmesi — policy tablosu, New/Edit modal (level dropdown/enforce/enabled), Delete confirm; state fields + 8 metod
- **PamApiService.cs:** `GetDeviceMfaPoliciesAsync`, `CreateDeviceMfaPolicyAsync`, `UpdateDeviceMfaPolicyAsync`, `DeleteDeviceMfaPolicyAsync` + `DeviceMfaPolicyDto`; **+** eksik `CommandFilterPolicy` metodlari eklendi (GetCommandFilterPoliciesAsync/GetCommandFilterPolicyAsync/ToggleCommandFilterPolicyAsync/CreateCommandFilterPolicyAsync/DeleteCommandFilterPolicyAsync/AddCommandFilterRuleAsync/DeleteCommandFilterRuleAsync + 3 DTO); **+** eksik `PeripheralRedirectionPolicy` metodlari eklendi (GetPeripheralPoliciesAsync/CreatePeripheralPolicyAsync/UpdatePeripheralPolicyAsync/DeletePeripheralPolicyAsync + DTO)
- **RFP-CHECKLIST.md:** MFA #22 → PC

**Ilerleme:** 8/8 (%100) ✅

---

## Sprint 56 - Hardware Token Resynchronization (#277) ✅ TAMAMLANDI
**Tarih:** 2026-05-25
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #277 | [MVP] Hardware Token Resync — HOTP Counter Drift Recovery (MFA #23) | MVP-AUTH | ✅ Tamamlandi |

**Sprint 56 Tamamlanan Bilesenler (2026-05-25):**
- **OathHelper.TryResyncHotp:** RFC 4226 §7.4 forward-window scan (window=100); otp1+otp2 çifti bulunursa counter = pos+2
- **HardwareTokenEndpoints.cs:** 3 yeni endpoint:
  - `POST /api/v1/auth/hardware-tokens/{id}/resync` — self-service; 2-OTP çifti → RFC4226 resync; 2 audit event (RESYNC_SUCCESS/FAILED)
  - `POST /api/v1/auth/hardware-tokens/{id}/admin-resync` — admin counter override (AdminPolicy); 1 audit event (ADMIN_RESYNC)
  - `GET /api/v1/auth/hardware-tokens/drift-report` — son 7 günde resync ihtiyacı olan tokenlar (AuditLogs join)
- **GET /api/v1/auth/hardware-tokens select:** CounterValue eklendi
- **SelfService.razor:** Security sekmesine "Hardware HOTP Tokens" bölümü; Resync butonu + 2-OTP modal; LoadMyHwTokensAsync
- **Integrations.razor:** Hardware Tokens tablosuna "Counter" sütunu + HOTP tokenlar için "Resync (Admin)" butonu; Admin Resync modal (counter override); "Drift Report" kartı (son 7 gün)
- **PamApiService.cs:** `GetMyHardwareTokensAsync`, `ResyncHardwareTokenAsync`, `AdminResyncHardwareTokenAsync`, `GetTokenDriftReportAsync` + `HardwareTokenDto.CounterValue` eklendi + `TokenDriftReportItemDto`
- **RFP-CHECKLIST.md:** MFA #23 → PC

**Ilerleme:** 7/7 (%100) ✅

---

## Sprint 57 - Operational Reports Bundle (#278) ✅ TAMAMLANDI
**Tarih:** 2026-05-25
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #278 | Operational Reports Bundle — Capacity Planning, Performance & SLA Reports (R #39-41) | MVP-REPORTING | ✅ Tamamlandi |

**Sprint 57 Tamamlanan Bilesenler (2026-05-25):**
- **OperationalReportsEndpoints.cs (yeni):** 3 endpoint:
  - `GET /api/v1/reports/operational/capacity?months=N` — haftalık device/credential/user/storage trend + 90-gün linear projeksiyon
  - `GET /api/v1/reports/operational/performance?from=&to=` — session basari orani, rotation coverage, proxy uptime by protocol, top failed devices
  - `GET /api/v1/reports/operational/sla?from=&to=` — rotation on-time %, recording coverage %, approval response time, checkout compliance %, MFA enrollment %; SLA breach listesi
- **Program.cs:** `MapOperationalReportsEndpoints()` kaydedildi
- **Reports.razor:** "Operational" sekmesi eklendi — 3 alt sekme (Capacity | Performance | SLA); stat cards renk kodlu (yesil/sari/kirmizi); haftalık tablo; SLA breach listesi; JSON export
- **PamApiService.cs:** `GetCapacityReportAsync`, `GetPerformanceReportAsync`, `GetSlaReportAsync`, `GetOperationalReportCsvAsync` + `GetAuthHttpClientAsync`; `CapacityReportDto`, `PerformanceReportDto`, `SlaReportDto`
- **RFP-CHECKLIST.md:** Reporting #39 → PC, #40 → PC, #41 → PC

**Ilerleme:** 7/7 (%100) ✅

---

## Sprint 58 - Session Restoration (#279) ✅ TAMAMLANDI
**Tarih:** 2026-05-25
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #279 | Session Restoration — Reconnect Interrupted Sessions Without Re-Auth (RA #47) | MVP-SESSION | ✅ Tamamlandi |

**Sprint 58 Tamamlanan Bilesenler (2026-05-25):**
- **SessionStatus.Disconnected (=4):** Enum'a yeni deger eklendi — unexpected network disconnect icin ayri durum
- **SessionRestoreToken entity** (ProxySession.cs): OriginalSessionId FK, UserId, DeviceId, CredentialId, Protocol, CreatedAtUtc, ExpiresAtUtc (15 dk), IsUsed, RestoredSessionId; `Disconnect()` method ProxySession'a eklendi
- **Migration `20260525_AddSessionRestoreToken`:** SessionRestoreTokens tablosu + 2 index (UserId+IsUsed, ExpiresAtUtc) + FK → ProxySessions CASCADE
- **DbContext:** SessionRestoreTokens DbSet + EF Core konfigurasyonu (maxLength, index, cascade delete)
- **SessionRestorationEndpoints.cs (yeni):** 4 endpoint:
  - `POST /api/v1/sessions/{id}/mark-disconnected` — X-Proxy-Secret auth; session.Disconnect() + restore token olusturur
  - `GET /api/v1/sessions/restorable` — kullanicinin aktif (IsUsed=false, ExpiresAt>now) token listesi
  - `POST /api/v1/sessions/restore/{tokenId}` — token ile yeni session olusturur; 2 audit event (RESTORE_INITIATED/COMPLETED)
  - `DELETE /api/v1/sessions/restore/{tokenId}` — token iptali
- **Program.cs:** MapSessionRestorationEndpoints() kayitlandi
- **SshProxy/PamApiClient.cs:** `MarkSessionDisconnectedAsync()` — best-effort, asla throw etmez; X-Proxy-Secret ile dogrulanir
- **SshServerSession.cs:** `unexpectedDisconnect` flag; `IOException`/`SocketException` catch'te `true` set edilir; finally'de `MarkSessionDisconnectedAsync()` cagrisi
- **AccountLifecycleJob.cs:** Gunluk temizlik — `IsUsed=true` veya `ExpiresAtUtc<now` tokenlari `ExecuteDeleteAsync` ile siler
- **Sessions.razor:** "Disconnected" status filter secenegi; pam-status-warning badge; Restorable sessions sarı uyarı bannerı (adet badge + "Restore Sessions" butonu); Restore butonu disconnected satirlar icin; restore panel modali (protocol, disconnect saati, bitis saati, Restore/Cancel butonlari); LoadRestorableSessionsAsync + OpenRestorePanel + RestoreFromSessionAsync + RestoreTokenAsync + CancelRestoreTokenAsync metodlari; OnAfterRenderAsync'de LoadRestorableSessionsAsync
- **PamApiService.cs:** GetRestorableSessionsAsync, RestoreSessionAsync, CancelRestoreTokenAsync + RestorableSessionDto + SessionRestoreResponseDto
- **RFP-CHECKLIST.md:** RA #47 → PC

**Ilerleme:** 12/12 (%100) ✅

---

## Sprint 59 - Biometric Authentication (#282) ✅ TAMAMLANDI
**Tarih:** 2026-05-25
**Durum:** Tamamlandi

| Issue | Baslik | Tip | Durum |
|-------|--------|-----|-------|
| #282 | [MVP] Biometric Authentication — Windows Hello / Touch ID via WebAuthn Platform Authenticators (Platform #44) | MVP-AUTH | ✅ Tamamlandi |

**Sprint 59 Tamamlanan Bilesenler (2026-05-25):**
- **Fido2Credential entity:** `AuthenticatorType` alani eklendi ("cross-platform" default, "platform" = biometric)
- **Migration `20260525_AddFido2AuthenticatorType`:** Fido2Credentials tablosuna AuthenticatorType kolonu (maxLength:32, default:"cross-platform")
- **OrkunPamDbContext:** Fido2Credential EF config'e `AuthenticatorType` max length + default value eklendi
- **Fido2Endpoints.cs `register/begin`:** `?type=platform|cross-platform` query param; `authenticatorAttachment` dinamik; platform → `userVerification=required`; cache key'e type suffix eklendi
- **Fido2Endpoints.cs `register/complete`:** `AuthenticatorType` body'den okunuyor + credential'a yaziliyor; audit events: `BIOMETRIC_PASSKEY_REGISTERED` / `FIDO2_KEY_REGISTERED`
- **Fido2Endpoints.cs `authenticate/complete`:** `BIOMETRIC_AUTH_SUCCESS` / `FIDO2_AUTH_SUCCESS` / `BIOMETRIC_AUTH_FAILED` audit events; IAuditService inject edildi
- **Fido2Endpoints.cs `list`:** `authenticatorType` alani response'a eklendi
- **Fido2RegisterRequest:** `AuthenticatorType?` alani eklendi
- **PamApiService.cs:** `BeginFido2RegistrationAsync(type)`, `GetFido2CredentialsAsync()`, `RevokeFido2DeviceAsync(credId)` + `Fido2CredentialDto` eklendi
- **SelfService.razor:** "Add Biometric Passkey" butonu + `_biometricMsg`/`_biometricSuccess` state + `RegisterBiometricPasskeyAsync()` metodu
- **RFP-CHECKLIST.md:** Platform #44 → PC

**Security Fixes (ayni commit):**
- **#286 [HIGH]:** SessionRestorationEndpoints.cs restore endpoint — kullanici hesap durumu + credential assignment re-check (CWE-285)
- **#287 [MEDIUM]:** SessionRestorationEndpoints.cs mark-disconnected — FixedTimeEquals constant-time comparison (CWE-208)
- **#288 [MEDIUM]:** SshProxy PamApiClient.cs ValidateUserAsync — Utf8JsonWriter ile password string heap'te daha kisa sureli (CWE-316)

**Ilerleme:** 4/4 (%100) ✅

---

## Sonraki Adim
**Sprint 59 tamamlandi.** Platform #44 + 3 security fix → PC.
**Sprint 60 hedefi:** #283 Network Segmentation (RA #8) veya #284 Credential Federation (PV #12)
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
