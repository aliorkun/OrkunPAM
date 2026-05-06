# Phase 2 - Password Vault & Device Management

**Duration:** Week 8-12
**Depends On:** Phase 1 (User Management for permissions)
**Goal:** Encrypted credential vault with rotation, discovery, and complete device inventory

---

## Module 2A: Password Vault / Secrets Management

### 2.1 Vault Core
- [ ] VaultFolder entity with tree structure (parent-child)
- [ ] Credential CRUD with AES-256-GCM encryption
- [ ] Credential types: Password, SSH Key, API Key, Certificate, Connection String, Custom Key-Value
- [ ] All sensitive fields encrypted at rest (password, private key, additional data)
- [ ] Credential versioning (track every change)
- [ ] Credential tags/labels for categorization
- [ ] API: `/api/v1/vault/folders/*`, `/api/v1/vault/credentials/*`

### 2.2 Permission Sets
- [ ] Permission levels: View, Use (checkout), Manage, Owner
- [ ] Folder-level permissions (inherited by all credentials within)
- [ ] Credential-level permissions (override folder)
- [ ] User-level and Group-level permission assignments
- [ ] Effective permission resolution engine (user + groups + folder hierarchy)
- [ ] Bulk permission assignment
- [ ] API: `/api/v1/vault/permissions/*`

### 2.3 Personal Vaults
- [ ] Auto-created per user (isolated folder)
- [ ] Owner-only access (no admin override without break-glass)
- [ ] Personal credential CRUD
- [ ] API: `/api/v1/vault/personal/*`

### 2.4 Check-In / Check-Out System
- [ ] Exclusive checkout (only one user at a time)
- [ ] Time-limited checkout (configurable max duration)
- [ ] Auto-checkin on expiry (IHostedService watchdog)
- [ ] Reservation system (schedule future checkout)
- [ ] Approval-required checkout (integration with Workflow Engine)
- [ ] Reason/justification required (configurable)
- [ ] ITSM ticket linking for checkout
- [ ] Checkout queue (if credential is busy)
- [ ] API: `/api/v1/vault/credentials/{id}/checkout`, `/api/v1/vault/credentials/{id}/checkin`

### 2.5 Credential Sharing
- [ ] Share credential with another user
- [ ] Time-limited sharing (auto-expire)
- [ ] Use-count-limited sharing (N uses then revoke)
- [ ] Share permission level (View only, Use)
- [ ] Revoke sharing
- [ ] API: `/api/v1/vault/credentials/{id}/share`

### 2.6 Password Rotation Engine
- [ ] `IRotationConnector` interface with pluggable implementations:
  - [ ] `WinRmRotationConnector` - Windows local/AD passwords via WinRM/PowerShell
  - [ ] `SshRotationConnector` - Linux passwords via SSH
  - [ ] `LdapRotationConnector` - AD passwords via LDAP
  - [ ] `SnmpRotationConnector` - Network device passwords (SNMP v3)
  - [ ] `DatabaseRotationConnector` - SQL Server, Oracle, MySQL, PostgreSQL
  - [ ] `WindowsServiceConnector` - Windows service account passwords
  - [ ] `ScheduledTaskConnector` - Windows scheduled task credentials
- [ ] Rotation policies: interval (days), complexity rules, rotate-on-checkin
- [ ] Scheduled rotation (cron-based, IHostedService)
- [ ] On-demand rotation via API
- [ ] Password generation (configurable complexity: length, uppercase, digits, symbols, exclude ambiguous)
- [ ] Rotation failure handling: retry, alert, rollback
- [ ] Rotation history tracking
- [ ] API: `/api/v1/vault/rotation-policies/*`, `/api/v1/vault/credentials/{id}/rotate`

### 2.7 Credential Discovery
- [ ] Discovery job engine with pluggable scanners:
  - [ ] AD privileged accounts (Domain Admins, Enterprise Admins, Schema Admins, etc.)
  - [ ] Windows local admin accounts (via WMI/WinRM)
  - [ ] Linux accounts (via SSH, parse /etc/passwd + /etc/group)
  - [ ] SQL Server logins
  - [ ] Service accounts running on Windows services
- [ ] Scheduled discovery (cron-based)
- [ ] On-demand discovery
- [ ] Discovery results review (pending list)
- [ ] API: `/api/v1/vault/discovery-jobs/*`, `/api/v1/vault/discovered-accounts/*`

### 2.8 Credential Takeover
- [ ] Takeover workflow: select discovered account → generate new password → rotate → import as managed
- [ ] Bulk takeover
- [ ] Takeover verification (test new credential works)
- [ ] API: `/api/v1/vault/discovered-accounts/{id}/takeover`

### 2.9 SSH Key Management
- [ ] SSH key pair generation (RSA, Ed25519)
- [ ] Public key distribution to target servers
- [ ] SSH key rotation
- [ ] SSH key association with devices

### 2.10 Certificate & API Key Tracking
- [ ] SSL/TLS certificate storage (with expiry tracking)
- [ ] Certificate expiry alerts
- [ ] API key / token storage with rotation
- [ ] Cloud access key storage (AWS, Azure, GCP)

### 2.11 Password History
- [ ] Encrypted history of previous passwords
- [ ] Configurable retention (keep last N or keep for N days)
- [ ] Prevent password reuse (check against history)

---

## Module 2B: Device Management

### 2.12 Device Core
- [ ] Device CRUD (hostname, IP, FQDN, type, OS, port, protocol)
- [ ] Device types: Windows Server, Linux Server, Network Switch, Router, Firewall, Database Server, Web Application, Hypervisor, Cloud Instance, IoT, Other
- [ ] Device status: Active, Disabled, Maintenance, Unreachable
- [ ] Device properties / custom attributes
- [ ] Device tags/labels
- [ ] API: `/api/v1/devices/*`

### 2.13 Platform Templates
- [ ] Pre-built templates: "Windows Server (RDP)", "Linux Server (SSH)", "Cisco IOS (SSH)", "SQL Server", etc.
- [ ] Custom platform creation
- [ ] Template fields: default protocol, port, rotation connector, connection parameters
- [ ] API: `/api/v1/platforms/*`

### 2.14 Device Import
- [ ] CSV/Excel import with configurable column mapping
- [ ] AD computer object import (reuse LDAP integration)
- [ ] LDAP-based import with search filter
- [ ] Network scan import (IP range → discover devices)
- [ ] Cloud import: AWS EC2, Azure VM, GCP Compute (v1.5)
- [ ] Bulk import progress tracking
- [ ] Import validation and error reporting
- [ ] API: `/api/v1/devices/import/*`

### 2.15 Device Grouping
- [ ] Manual grouping (custom groups)
- [ ] VLAN-based grouping (auto-assign by IP/subnet)
- [ ] Device type-based grouping
- [ ] AD OU-based grouping
- [ ] Dynamic groups (filter-based: auto-membership based on rules)
- [ ] Nested groups (group within group)
- [ ] API: `/api/v1/device-groups/*`

### 2.16 Device-Credential Association
- [ ] Link credentials to devices (many-to-many)
- [ ] Purpose classification: Administrative, Service, Emergency, Discovery
- [ ] Primary credential designation per device
- [ ] API: `/api/v1/devices/{id}/credentials`

### 2.17 Reachability Monitoring
- [ ] Ping + port check
- [ ] Scheduled reachability checks
- [ ] Reachability history
- [ ] Alerts on unreachable devices
- [ ] DNS-based resolution

---

## UI (Blazor)

### Vault Pages
- [ ] Vault browser (folder tree + credential list)
- [ ] Credential detail page (metadata, checkout button, history)
- [ ] Checkout dialog (reason, duration, ITSM ticket)
- [ ] Credential create/edit form (type-specific fields)
- [ ] Approval queue (pending checkout requests)
- [ ] Personal vault section
- [ ] Credential sharing dialog
- [ ] Rotation policy management
- [ ] Discovery jobs list and results
- [ ] Discovered accounts review (takeover buttons)
- [ ] Password history viewer
- [ ] Vault search (filter by folder, type, device, tags, status)

### Device Pages
- [ ] Device inventory (searchable, filterable table)
- [ ] Device detail page (properties, linked credentials, reachability)
- [ ] Device create/edit form
- [ ] Import wizard (CSV upload, AD sync, manual)
- [ ] Device group management (tree view)
- [ ] Platform template editor
- [ ] Bulk operations page

---

## Audit Events
- Vault.Credential.Created, .Updated, .Deleted
- Vault.Credential.CheckedOut, .CheckedIn, .CheckOutExpired
- Vault.Credential.Rotated, .RotationFailed
- Vault.Credential.Shared, .ShareRevoked
- Vault.Credential.Viewed (metadata), .PasswordRetrieved (actual password)
- Vault.Discovery.Started, .Completed, .AccountFound
- Vault.Takeover.Initiated, .Completed, .Failed
- Device.Created, .Updated, .Deleted, .Imported
- Device.Unreachable, .Recovered

---

## Deliverables
- Fully functional encrypted vault with folder tree
- Check-in/check-out working with approval integration
- At least 3 rotation connectors working (WinRM, SSH, LDAP)
- Discovery scanning for AD and Windows
- Complete device inventory with import
- All UI pages functional
- Performance: <100ms for credential decrypt
