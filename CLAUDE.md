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
- `docs/PAM Template.xlsx` - RFP compliance tracking
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

### Developer Kuralları
- `gh issue list --label security` → Security agent bulgularını takip et
- `gh issue list --label product` → PM taleplerini takip et
- `severity:critical` ve `severity:high` issue'lar her şeyden önce fix'lenir
- `priority:mvp` issue'lar `priority:v2`'den önce gelir
- Her fix commit'inde ilgili issue numarasını referansla
- Proxy katmanında açık kaynak kütüphane KULLANMA - native C# implementasyon
- Security agent'ın açtığı ticket'larda belirtilen dosya:satır bilgisini dikkate al
