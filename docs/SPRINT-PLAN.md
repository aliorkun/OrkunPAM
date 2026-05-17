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
**Tag:** `v1.0.0-rc1` (atılacak)

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
**Tag:** `v1.0.0-rc2` (atılacak)

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
**Tag:** `v1.0.0` (atılacak)

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
- API: `GET /api/v1/cloud/dashboard` — multi-cloud özet (hesap, kaynak, JIT sayıları, son istekler)
- API: `GET/POST /api/v1/cloud/accounts` — cloud hesap CRUD
- API: `PUT /api/v1/cloud/accounts/{id}/toggle` — etkinleştir/devre dışı
- API: `DELETE /api/v1/cloud/accounts/{id}` — sil
- API: `POST /api/v1/cloud/accounts/{id}/sync` — kaynak keşfi (AWS EC2/IAM/S3, Azure VM/KeyVault/SPN, GCP CE/SA/GCS simüle)
- API: `GET /api/v1/cloud/resources?provider=&type=` — filtrelenebilir kaynak listesi
- API: `PUT /api/v1/cloud/resources/{id}/toggle` — kaynak etkinleştir/devre dışı
- API: `GET/POST /api/v1/cloud/jit` — JIT istek oluşturma
- API: `PUT /api/v1/cloud/jit/{id}/approve|deny|revoke` — JIT yaşam döngüsü
- Audit: CloudAccountCreated/Deleted/Synced, CloudJitRequested/Approved/Denied/Revoked
- `CloudPam.razor`: 4 tab UI — Dashboard (provider kartları, son JIT), Accounts (CRUD + sync), Resources (filtreli tablo + JIT başlat), JIT (istek formu + onay/reddet/iptal)
- `PamApiService.cs`: GetCloudDashboardAsync, GetCloudAccountsAsync, CreateCloudAccountAsync, SyncCloudAccountAsync, ToggleCloudAccountAsync, DeleteCloudAccountAsync, GetCloudResourcesAsync, GetCloudJitRequestsAsync, CreateCloudJitRequestAsync, ApproveCloudJitAsync, DenyCloudJitAsync, RevokeCloudJitAsync + tüm DTO'lar
- NavMenu.razor: "Cloud" section + Cloud PAM linki eklendi

---

## Sonraki Adım: v1.0.0 GA Tag
**Kriter:** Sprint 6 tamamlandı → CI yeşil → `v1.0.0` tag atılacak
**v2.0.0:** AAPM + Threat Analytics (30 Eylül 2026)

---

## Sprint Kuralları
- Her sprint sonunda Coordinator tag atar
- Sprint değişikliği bu dosya güncellenerek yapılır
- Developer agent "Aktif Sprint" bölümündeki issue'lara odaklanır
- Sprint dışı issue'lar backlog'da kalır
- Security critical/high her zaman sprint'i keser (acil fix)

## Milestone Hedefleri
- **v0.4.0-rdp:** Sprint 3 çıkışı (13 Mayıs 2026) ← Tamamlandı
- **v1.0.0-rc1:** Sprint 4 çıkışı (13 Mayıs 2026) ← Tamamlandı
- **v1.0.0-rc2:** Sprint 5 çıkışı (13 Mayıs 2026) ← Tamamlandı
- **v1.0.0:** Sprint 6 çıkışı (14 Mayıs 2026) ← Tamamlandı
- **v2.0.0:** AAPM + Threat Analytics (30 Eylül 2026)

## Mimari Kararlar
- **SSH Proxy:** Native C# (RFC 4253) — farkımız burada, açık kaynak yok
- **RDP Proxy:** Microsoft RDS Gateway entegrasyonu — CyberArk yaklaşımı, RemoteApp + session recording + HA dahil
- **SQL Proxy:** Native C# TDS protokol implementasyonu — açık kaynak yok
- **VNC Proxy:** Native C# RFB protokol (RFC 6143) — açık kaynak yok
- **HTTP/HTTPS Proxy:** Native C# reverse proxy + CONNECT tunnel — açık kaynak yok
- **TACACS+ Proxy:** Native C# (RFC 1492) — ağ cihazı AAA, Cisco/Juniper/Aruba
- **RADIUS Proxy:** Native C# (RFC 2865/2866) — VPN/Wi-Fi/NAC, UDP :1812/:1813
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
