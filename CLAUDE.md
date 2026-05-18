# Orkun PAM - Development Guide

## Project Overview
Enterprise Privileged Access Management (PAM) solution. Windows-based, .NET 8+, modular architecture.

## Architecture
- **Clean Architecture** with modular vertical slices
- Backend: C# / .NET 8+ (ASP.NET Minimal APIs + Blazor Server)
- Database: SQL Server with 11 schemas
- Encryption: Custom AES-256-GCM vault engine (3-tier key hierarchy)
- Session Proxies: SSH, RDP, VNC, SQL, HTTP (separate Windows Services)
- Internal comms: gRPC between proxy services and core
- Event bus for SIEM, webhooks, analytics

## Key Directories
- `src/Core/` - Domain entities, Application CQRS, SharedKernel
- `src/Infrastructure/` - Persistence, Cryptography, Identity, AD, Messaging
- `src/Modules/` - Feature modules (UserMgmt, Vault, Session, etc.)
- `src/Proxy/` - Protocol proxy implementations
- `src/Presentation/` - WebAPI, Blazor Web, gRPC, Installer
- `docs/` - Architecture, phase plans, DB schema, API docs
- `tests/` - Unit, Integration, Security, E2E tests

## Development Phases
See `docs/phases/` for detailed plans:
- Phase 0: Foundation (scaffolding, crypto engine, DB)
- Phase 1: User Management + Workflow Engine
- Phase 2: Vault + Device Management
- Phase 3: Session Manager (SSH/RDP/SQL/VNC/HTTP proxies)
- Phase 4: AAPM + Threat Analytics
- Phase 5: Compliance + Reporting

## Conventions
- All API endpoints under `/api/v1/{module}/{resource}`
- Response envelope: `{ success, data, errors, meta }`
- CQRS with MediatR (Commands for writes, Queries for reads)
- FluentValidation for input validation
- Serilog for structured logging
- Audit everything via domain events → event bus → audit log

## Security Rules
- Never log plaintext credentials
- Zero memory after credential decryption
- All data at rest encrypted (TDE + column-level AES-256-GCM)
- TLS 1.3 for all communication
- Rate limiting on auth endpoints
- Tamper-proof audit logs (hash chain)

## Tracking
- GitHub Issues for task tracking
- `docs/RFP-CHECKLIST.md` - RFP compliance checklist (readable by agents, 600+ items)
- `docs/PAM Template.xlsx` - Original RFP source (binary, agents cannot read)
- Phase checklists in `docs/phases/`

## AI Agent Coordination

### Roles
- **Developer (Claude):** Architecture, implementation, code review. Kod yazar, fix'ler, refactor eder.
- **Tester & Security Auditor:** Kod review, security audit, functional testing. GitHub Issues açar (label: `security`, `bug`, `test-failure`, `missing-validation`, `code-quality`). Severity: `severity:critical`, `severity:high`, `severity:medium`, `severity:low`.
- **Product Manager:** Feature gap analizi, RFP uyumluluk, rakip analizi, UX önerileri. GitHub Issues açar (label: `product`, `feature-request`, `ux`, `rfp-gap`, `competitor-gap`). Priority: `priority:mvp`, `priority:v2`, `priority:nice-to-have`.

### Workflow (Sürekli Döngü - GitHub Kontrollü)
Her döngü GitHub Issues üzerinden koordine edilir. Agent'lar repoyu GitHub'dan takip eder.

**Adım 1 - Developer geliştirir:**
- TODO'ları temizler, yeni özellik implement eder, commit atar, push eder

**Adım 2 - Security/Tester inceler (her push/versiyon sonrası):**
- GitHub reposunu çeker, tüm değişiklikleri inceler
- Zafiyet, bug, eksik validation, test failure bulursa GitHub Issue açar
- Label: `security`, `bug`, `severity:critical/high/medium/low`

**Adım 3 - Developer fix'ler:**
- `gh issue list --label security` ile açık bug'ları çeker
- Önce critical/high, sonra medium/low fix'ler
- Commit'te `fixes #issue-no` referansı kullanır, push eder

**Adım 4 - Security/Tester tekrar inceler:**
- Fix'lerin doğruluğunu kontrol eder
- Yeni sorun yoksa issue'ları kapatır, varsa yeni issue açar

**Adım 5 - Product Manager yeni feature ekler:**
- GitHub reposunu inceler, mevcut durumu değerlendirir
- RFP gap, rakip eksiklik, UX iyileştirme, yeni özellik talepleri açar
- Label: `product`, `feature-request`, `priority:mvp/v2`

**Adım 6 - Developer yeni feature'ları implement eder:**
- `gh issue list --label product --label priority:mvp` ile talepleri çeker
- Implement eder, push eder → Adım 2'ye dön

**Döngü sürekli tekrar eder. Her agent GitHub'ı tek kaynak olarak kullanır.**

### ⚠️ MEVCUT DURUM (2026-05-18) — REFACTORING MODU AKTİF

**YENİ FEATURE YAZMA! REFACTORING SPRINT'İ DEVAM EDİYOR.**

Mevcut kod yapısı gerçek bir PAM ürünü değil. Agent'lar 30+ sprint boyunca birbirinden bağımsız, anlamsız feature'lar üretmiş. Sonuç:
- 30+ menü butonu var, çoğu çalışmıyor veya anlamsız
- Gerçek PAM erişim kontrolü yok (kim nereye nasıl bağlanacak)
- Proxy'ler çalışmıyor
- Build hataları sürekli çıkıyor
- DB yapısı düz, realm/access control modeli yok

### Referans: Kron PAM Veri Modeli (10.1.1.23)

Kron PAM'ın çekirdek yapısı:

```
User → User Group → Device Realm ← Device Group ← Device
                         ↓
                    Policy Key
                         ↓
                  Session + Credential
```

**Temel tablolar:**
1. `t_user` — user_id (UUID), name, surname, email, internal
2. `t_group` — group_id, group_eid (readable name), users (many-to-many)
3. `t_device` — dbid, name, element_type_id, management_ip, access_protocol
4. `t_device_group` — name, parent_group_id (hierarchy)
5. `t_device_realm` — **Erişim matrisi**: Device Group'ları + User Group'ları birleştirir
6. `sapm_account` — Credential: username, password (enc), device_id, change_period
7. `sapm_group` — Credential folder/group (hierarchy)
8. `assigned_credential` — Credential'ı user/group'a device/device_group bazında ata
9. `sc_sessions` — Session kaydı
10. `t_function_group` — Portal yetki grupları (SAPM Admin, Network Admin, Log Admin)

### Developer Kuralları — REFACTORING SPRINT
- **YENİ FEATURE EKLEME** — Sadece mevcut yapıyı düzelt
- **Menü sadeleştirmesi:** Sadece 8 ana menü: Users, Devices, Vault, Access Control, Sessions, Policies, Reports, System
- **Device Realm implementasyonu:** AccessAssignment'ı Kron PAM realm modeline çevir
- **Credential assignment:** Kron PAM `assigned_credential` modelini uygula
- **Her commit ÖNCE build + çalıştır + login test et**
- **PM agent YENİ issue AÇMAZ** — Sadece mevcut issue'ları yönetir
- **Security agent sadece critical açar** — Medium/low ertelendi
- **Developer agent sadece refactoring yapar** — Yeni endpoint/sayfa EKLEME

### Refactoring Sprint Sırası
1. Blazor menü sadeleştirmesi (30+ → 8 ana kategori)
2. Device Realm entity + endpoint + UI
3. Credential assignment refactoring (Kron PAM modeli)
4. Gereksiz endpoint'leri kaldır veya gizle
5. Session akışını realm-based erişim kontrolüyle entegre et
6. Proxy'leri çalışır hale getir (SSH öncelikli)

### Remote Agent Schedule (15 run/gün - tam limit)

| Agent | Cron (UTC) | Senin Saatin (UTC+7) | Run/gün |
|-------|------------|----------------------|---------|
| Developer | `:30 */3h` | 07:30, 10:30, 13:30, 16:30, 19:30, 22:30, 01:30, 04:30 | 8 |
| Security | `05:00, 13:00, 21:00` | 12:00, 20:00, 04:00 | 3 |
| PM | `08:00, 20:00` | 15:00, 03:00 | 2 |
| Coordinator | `00:00, 12:00` | 07:00, 19:00 | 2 |

### Agent Kuralları
- **Push:** Remote agent'lar `mcp__github__push_files` kullanır (git push çalışmaz)
- **Issue:** `mcp__github__create_issue`, `mcp__github__update_issue` ile açar/kapatır
- **Developer:** Run başına 3-5 fix. critical/high açıkken feature çalışmaz
- **Security/PM:** Koda dokunmaz, sadece okur ve issue yönetir
- **Çakışma önleme:** Agent'lar farklı saatlerde çalışır, üst üste binmez
- **Duplicate:** Tüm agent'lar önce mevcut issue'ları kontrol eder

### v2 Aktif Geliştirme — DURDURULDU
**Tüm v2 feature'lar DONDURULDU. Refactoring sprint'i tamamlanana kadar yeni feature yok.**

Refactoring tamamlandıktan sonra sıra:
1. Device Realm tabanlı erişim kontrolü (Kron PAM modeli)
2. SSH Proxy çalışır hale getirme
3. Session recording + playback
4. RDP Proxy

### Ertelenen Alanlar (v3+ — ŞU AN DOKUNMA)
Bu alanlarda PM issue **AÇMAZ**, Developer kod **YAZMAZ**:

| Alan | RFP Bölümü | Neden Ertelendi |
|------|-----------|-----------------|
| Multitenancy | Bölüm 9 | Tek tenant yeterli şimdilik |
| Data Access Manager (DB Proxy) | Bölüm 10 | SQL proxy sonra |
| Privileged Task Automation | Bölüm 12 | Otomasyon sonra |

### Backlog Sağlık Kuralları
- Toplam açık issue > 35 → PM yeni issue açmayı durdurur
- Toplam açık issue > 35 → Security sadece critical/high açar
- 3 gün üst üste backlog büyürse → Developer fix-only moda geçer
- severity:critical 24 saatten fazla açık kalamaz

### Versiyon & Milestone
- **Coordinator** günde 2 kez çalışır: sabah (milestone check) + akşam (tag + rapor)
- **Tag formatı:** `v0.X.Y-dev-YYYY-MM-DD` (commit varsa atılır)
- **Milestone:** severity:critical/high + priority:mvp → aktif milestone
- **Taşıma:** Çözülmeyen issue'lar sonraki milestone'a taşınır (silinmez)
- **Rapor:** `[DAILY]` label'lı issue olarak açılır, backlog trend + anomali uyarıları
