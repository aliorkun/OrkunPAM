# Phase 0 - Foundation

**Duration:** Week 1-3
**Goal:** Project scaffolding, core infrastructure, development environment

---

## Tasks

### 0.1 Development Environment
- [ ] Install .NET 8+ SDK
- [ ] Install SQL Server Express (or configure connection to existing)
- [ ] Setup Visual Studio 2022 / VS Code with C# Dev Kit
- [ ] Configure Git hooks (pre-commit: format, lint)

### 0.2 Solution Scaffolding
- [ ] Create `OrkunPAM.sln` with all project references
- [ ] Core: `OrkunPAM.Domain`, `OrkunPAM.Application`, `OrkunPAM.SharedKernel`
- [ ] Infrastructure: `OrkunPAM.Persistence`, `OrkunPAM.Cryptography`, `OrkunPAM.Identity`, `OrkunPAM.ActiveDirectory`, `OrkunPAM.Messaging`, `OrkunPAM.WindowsServices`
- [ ] Modules: All 11 module projects (empty shells)
- [ ] Proxy: SSH, RDP, SQL, HTTP, VNC (empty shells)
- [ ] Presentation: WebAPI, GrpcServices, Web (Blazor), Installer
- [ ] Tests: UnitTests, IntegrationTests, SecurityTests, E2ETests
- [ ] Tools: DbMigrator, CLI

### 0.3 SharedKernel
- [ ] `Result<T>` and `Error` types (railway-oriented error handling)
- [ ] `AuditableEntity` base class (CreatedAt, UpdatedAt, CreatedBy)
- [ ] `IRepository<T>` generic repository interface
- [ ] `IDomainEvent` and `IEventPublisher` interfaces
- [ ] `Guard` class for precondition checks
- [ ] `PagedResult<T>` for pagination
- [ ] `ICurrentUserService` abstraction

### 0.4 Domain Layer
- [ ] Base entity classes for all modules (identity, vault, device, session, etc.)
- [ ] All enums: `AuthSource`, `DeviceType`, `CredentialType`, `SessionType`, `PermissionLevel`, etc.
- [ ] Value objects: `EncryptedBlob`, `IpAddress`, `PermissionCode`
- [ ] Domain interfaces: `ICredentialRepository`, `IUserRepository`, `IDeviceRepository`, etc.

### 0.5 Persistence
- [ ] `OrkunPamDbContext` with schema separation (11 schemas)
- [ ] EF Core configurations for all entity types
- [ ] `NEWSEQUENTIALID()` convention for GUID PKs
- [ ] Shadow properties for audit columns
- [ ] Generic `Repository<T>` implementation
- [ ] `IUnitOfWork` pattern
- [ ] Initial migration (all schemas, crypto tables first)

### 0.6 Cryptography Engine
- [ ] `IMasterKeyProvider` (DPAPI + passphrase-based implementations)
- [ ] `IVaultEncryptionService`: `Encrypt(byte[]) → EncryptedBlob`, `Decrypt(EncryptedBlob) → byte[]`
- [ ] AES-256-GCM implementation using `System.Security.Cryptography.AesGcm`
- [ ] 3-tier key hierarchy: KEK → MK → DEK
- [ ] Key rotation support (re-encrypt DEKs on MK rotate)
- [ ] Sealed key cache (`IMemoryCache`, cleared on service stop)
- [ ] Memory zeroing after decryption (`CryptographicOperations.ZeroMemory`)
- [ ] Unit tests: roundtrip, rotation, tamper detection

### 0.7 Application Layer Patterns
- [ ] MediatR integration (Commands / Queries / Notifications)
- [ ] `IPipelineBehavior` for: validation, logging, audit trail, transaction
- [ ] `ApiResponse<T>` envelope: `{ success, data, errors, meta }`
- [ ] Pagination, filtering, sorting abstractions
- [ ] Exception handling middleware
- [ ] FluentValidation integration

### 0.8 Event Bus
- [ ] `IEventBus` interface with `Publish<T>(T @event)`
- [ ] In-process event bus implementation (for single-instance deployment)
- [ ] Event types base: `DomainEvent`, `AuditEvent`, `SecurityEvent`
- [ ] Event handlers: audit log writer, (placeholder) SIEM forwarder

### 0.9 Presentation Shell
- [ ] WebAPI: Minimal API setup, Swagger/OpenAPI, API versioning (v1)
- [ ] GrpcServices: Proto files, initial service stubs
- [ ] Web (Blazor Server): Layout shell, navigation skeleton, auth state provider
- [ ] Health check endpoints
- [ ] CORS, HSTS, CSP headers
- [ ] Installer skeleton (WiX v4 project)

### 0.10 CI/CD
- [ ] GitHub Actions workflow: build + test on push
- [ ] Code coverage reporting
- [ ] Dependabot configuration

---

## Deliverables
- Compiling solution with all projects
- Working cryptography engine with unit tests
- Empty but connected DB with all schemas
- Running WebAPI with Swagger UI
- Running Blazor app with layout shell
- Event bus processing domain events
- CI pipeline green

---

## Dependencies
- .NET 8+ SDK
- SQL Server 2019+ (Express OK for dev)
