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

## AI Agents
- Developer (Claude): Architecture, implementation, code review
- Tester: Automated testing, security testing
- Product Manager: Feature prioritization, UX review
