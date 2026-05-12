# Orkun PAM

**Enterprise Privileged Access Management Solution**

Orkun PAM is a Windows-based, modular, API-first Privileged Access Management platform designed for enterprise environments. It provides comprehensive privileged access security with native protocol proxying, encrypted password vault, session recording, threat analytics, and compliance reporting.

---

## Key Features

### Identity & Access
- Multi-source authentication: Local, Active Directory, SAML 2.0, OIDC
- Multi-Factor Authentication (TOTP, SMS, Push)
- Role-Based Access Control (RBAC) with hierarchical permissions
- Just-in-Time (JIT) access & temporary users
- Multi-level approval workflows with escalation
- Emergency break-glass access with full audit trail

### Password Vault & Secrets Management
- AES-256-GCM encrypted credential storage (3-tier key hierarchy)
- Check-in / Check-out with reservation & approval
- Automated password rotation (Windows, Linux, Network, Database)
- Credential discovery & takeover
- SSH key, SSL certificate, API key, cloud key management
- Personal vaults & secure credential sharing

### Session Management
- **Native Protocol Proxies (core):** Standalone Windows Services per protocol — SSH (:2222), RDP (:3389), VNC (:5900), SQL (:1433). No third-party proxy libraries; all protocol handling is implemented in native C#.
- **HTML5 Browser Clients (convenience):** Optional web-based access via Blazor + WebSocket bridge to native proxies. No plugin/client install required.
- Credential injection: users never see target passwords — vault → proxy → target
- Session recording (text + video) with OCR search
- Keystroke logging & command auditing
- Real-time session shadowing, takeover & termination
- Clipboard, drive mapping & file transfer control
- RDP watermarking
- Command blacklisting/whitelisting

### Device Management
- Multi-source import: CSV, Active Directory, LDAP, cloud (AWS/Azure/GCP)
- VLAN-based, type-based, and dynamic grouping
- Platform templates for connection configuration
- Reachability monitoring

### Threat Analytics
- User Behavior Analytics (UBA) with command scoring
- Anomaly detection (off-hours, unusual IP, unusual commands)
- Risk scoring (per session & per user)
- SIEM integration (Syslog, CEF)
- Real-time alerts (email, SMS, push)
- SOC dashboard

### Compliance & Governance
- Compliance templates: SOX, PCI-DSS, ISO 27001, HIPAA, GDPR, KVKK
- Tamper-proof audit logs
- Segregation of Duties (SoD) enforcement
- Attestation campaigns & evidence collection
- Compliance posture dashboard

### AAPM (Application-to-Application)
- OAuth2 client credentials grant
- REST API for credential retrieval
- Kubernetes init/sidecar container
- Jenkins secret plugin
- SDKs: C#, Python, PowerShell

### Reporting
- 15+ built-in report templates
- Custom report builder
- Export: PDF, CSV, Excel
- Customizable dashboard widgets
- Scheduled report delivery

---

## Architecture

```
┌─────────────────────────────────────────────────────┐
│                    Blazor Server UI                   │
│              (HTML5 SSH/RDP/VNC/SQL Clients)          │
├─────────────────────────────────────────────────────┤
│                   REST API (v1)                       │
│              (ASP.NET Minimal APIs)                   │
├──────────┬──────────┬───────────┬───────────────────┤
│  User    │  Vault   │  Session  │  Threat    │  ... │
│  Mgmt    │  Module  │  Manager  │  Analytics │      │
├──────────┴──────────┴───────────┴───────────────────┤
│                  Event Bus                            │
│         (SIEM, Webhooks, Analytics)                   │
├─────────────────────────────────────────────────────┤
│  Cryptography  │  Identity  │  Persistence           │
│  (AES-256-GCM) │ (AD/SAML)  │  (EF Core + SQL)      │
├─────────────────────────────────────────────────────┤
│               gRPC Internal Services                  │
├──────────┬──────────┬───────────┬───────────────────┤
│ SSH Proxy│ RDP Proxy│ SQL Proxy │ VNC/HTTP Proxy     │
│ :2222    │ :3389    │ :1433+    │ :5900 / :8443     │
└──────────┴──────────┴───────────┴───────────────────┘
```

---

## Tech Stack

| Component | Technology |
|-----------|-----------|
| Backend | C# / .NET 8+ |
| Frontend | Blazor Server |
| Database | SQL Server (TDE + Always Encrypted) |
| Encryption | Custom AES-256-GCM (3-tier key hierarchy: KEK → MK → DEK) |
| SSH Proxy | Native C# (RFC 4253/4252/4254 - no third-party library) |
| RDP Proxy | Microsoft RDS Gateway integration (credential injection + session recording) |
| Internal Comms | gRPC |
| External API | REST (Minimal APIs) |
| CQRS | MediatR |
| Logging | Serilog |
| Installer | WiX v4 (MSI) |

---

## Project Structure

```
OrkunPAM/
├── src/
│   ├── Core/
│   │   ├── OrkunPAM.Domain/
│   │   ├── OrkunPAM.Application/
│   │   └── OrkunPAM.SharedKernel/
│   ├── Infrastructure/
│   │   ├── OrkunPAM.Persistence/
│   │   ├── OrkunPAM.Cryptography/
│   │   ├── OrkunPAM.Identity/
│   │   ├── OrkunPAM.ActiveDirectory/
│   │   ├── OrkunPAM.Messaging/
│   │   └── OrkunPAM.WindowsServices/
│   ├── Modules/
│   │   ├── OrkunPAM.Module.UserManagement/
│   │   ├── OrkunPAM.Module.Vault/
│   │   ├── OrkunPAM.Module.DeviceManagement/
│   │   ├── OrkunPAM.Module.SessionManager/
│   │   ├── OrkunPAM.Module.AAPM/
│   │   ├── OrkunPAM.Module.Reporting/
│   │   ├── OrkunPAM.Module.ThreatAnalytics/
│   │   ├── OrkunPAM.Module.Compliance/
│   │   ├── OrkunPAM.Module.WorkflowEngine/
│   │   ├── OrkunPAM.Module.RemoteAccess/
│   │   └── OrkunPAM.Module.CloudPAM/
│   ├── Proxy/
│   │   ├── OrkunPAM.Proxy.SSH/
│   │   ├── OrkunPAM.Proxy.RDP/
│   │   ├── OrkunPAM.Proxy.SQL/
│   │   ├── OrkunPAM.Proxy.HTTP/
│   │   └── OrkunPAM.Proxy.VNC/
│   └── Presentation/
│       ├── OrkunPAM.WebAPI/
│       ├── OrkunPAM.GrpcServices/
│       ├── OrkunPAM.Web/
│       ├── OrkunPAM.DesktopLauncher/
│       └── OrkunPAM.Installer/
├── tests/
├── sdk/
├── tools/
└── docs/
```

---

## Development Phases

| Phase | Scope | Target |
|-------|-------|--------|
| **Phase 0** | Foundation (scaffolding, crypto, DB, API shell) | Week 1-3 |
| **Phase 1** | User Management + Workflow Engine | Week 4-7 |
| **Phase 2** | Password Vault + Device Management | Week 8-12 |
| **Phase 3** | Session Manager (SSH/RDP/SQL/VNC/HTTP) | Week 13-18 |
| **Phase 4** | AAPM + Threat Analytics | Week 19-21 |
| **Phase 5** | Compliance + Reporting | Week 22-24 |

See [docs/phases/](docs/phases/) for detailed phase documentation.

---

## Deployment Models

- **On-Premise:** Windows Server MSI installer
- **SaaS:** Multi-tenant cloud deployment
- **Hybrid:** On-premise with cloud management portal

## Licensing

- Subscription-based (monthly/annual)
- Per-module licensing
- Per-user or per-device tiers

---

## Prerequisites

- Windows Server 2019+ or Windows 10/11 (development)
- .NET 8+ SDK
- SQL Server 2019+ (or SQL Server Express for development)
- Visual Studio 2022+ or VS Code with C# extension

---

## Getting Started

```bash
# Clone
git clone https://github.com/aliorkun/OrkunPAM.git
cd OrkunPAM

# Restore & Build
dotnet restore
dotnet build

# Run migrations
dotnet run --project tools/OrkunPAM.DbMigrator

# Run the application
dotnet run --project src/Presentation/OrkunPAM.WebAPI
```

---

## Contributing

This project is developed with AI-assisted development:
- **Developer Agent:** Architecture, implementation, code review
- **Tester Agent:** Automated testing, security testing
- **Product Manager Agent:** Feature prioritization, UX review

---

## License

MIT License - see [LICENSE](LICENSE) for details.
