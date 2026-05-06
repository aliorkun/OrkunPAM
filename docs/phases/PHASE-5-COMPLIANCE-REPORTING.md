# Phase 5 - Compliance & Reporting

**Duration:** Week 22-24
**Depends On:** Phase 4 (Analytics data for compliance)
**Goal:** Compliance framework support and comprehensive reporting/dashboard system

---

## Module 5A: Compliance & Governance

### 5.1 Tamper-Proof Audit Logs
- [ ] Append-only audit log tables (separate DB principal, no DELETE permission)
- [ ] Log integrity verification (hash chain: each log entry includes hash of previous)
- [ ] Log export with integrity proof
- [ ] Log retention policies (configurable per compliance framework)
- [ ] API: `/api/v1/audit-logs/*`

### 5.2 Compliance Templates
- [ ] SOX (Sarbanes-Oxley) control mapping
- [ ] PCI-DSS v4.0 requirement mapping
- [ ] ISO 27001:2022 control mapping
- [ ] HIPAA security rule mapping
- [ ] GDPR article mapping
- [ ] KVKK (Turkish Data Protection) mapping
- [ ] Each template: list of controls → which PAM features satisfy them → evidence collection
- [ ] Custom compliance framework import (YAML/JSON definition)
- [ ] API: `/api/v1/compliance/templates/*`

### 5.3 Compliance Posture Dashboard
- [ ] Per-framework compliance score (percentage of controls satisfied)
- [ ] Control-by-control status (Compliant / Non-Compliant / Partial / N/A)
- [ ] Trend chart (compliance score over time)
- [ ] Remediation recommendations for non-compliant controls
- [ ] Drill-down to evidence for each control

### 5.4 Evidence Collection
- [ ] Automated evidence gathering per compliance control
- [ ] Evidence types: audit logs, configuration snapshots, session recordings, reports
- [ ] Evidence bundle export (ZIP with index)
- [ ] Auditor role (read-only access to evidence)
- [ ] Evidence retention management
- [ ] API: `/api/v1/compliance/evidence/*`

### 5.5 Segregation of Duties (SoD)
- [ ] SoD rule definitions (user cannot have both Role A and Role B)
- [ ] SoD violation detection
- [ ] SoD violation alerts
- [ ] Exception management (approved SoD exceptions with justification)
- [ ] API: `/api/v1/compliance/sod/*`

### 5.6 Attestation Campaigns
- [ ] Periodic access review campaigns (who has access to what)
- [ ] Campaign creation: scope (all users, specific groups, specific vaults)
- [ ] Reviewer assignment (manager reviews direct reports)
- [ ] Approve / Revoke / Modify decisions
- [ ] Campaign deadline and reminders
- [ ] Auto-revoke if no response
- [ ] Campaign results report
- [ ] API: `/api/v1/compliance/attestations/*`

### 5.7 Policy Violation Tracking
- [ ] Policy violation log (with severity classification)
- [ ] Incident linking (create incident from violation)
- [ ] Violation trend analysis
- [ ] Auto-actions on repeated violations

---

## Module 5B: Reporting

### 5.8 Built-In Reports (15+ templates)
- [ ] **Password Age Report** - credentials approaching expiry
- [ ] **Privileged Access Report** - who accessed what, when (by user, device, date range)
- [ ] **Session Activity Report** - session count, duration, protocol breakdown
- [ ] **Failed Login Report** - failed auth attempts by user, IP, time
- [ ] **Checkout History Report** - credential checkouts with duration and reason
- [ ] **Rotation Compliance Report** - passwords rotated vs overdue
- [ ] **Orphaned Account Report** - discovered but unmanaged accounts
- [ ] **User Access Matrix** - user × resource permission matrix
- [ ] **Group Membership Report** - users per group, groups per user
- [ ] **AAPM Usage Report** - API client credential retrievals
- [ ] **Session Risk Report** - sessions by risk score
- [ ] **Compliance Summary Report** - per-framework compliance status
- [ ] **Device Inventory Report** - devices by type, status, reachability
- [ ] **MFA Adoption Report** - users with/without MFA
- [ ] **Break-Glass Usage Report** - emergency access usage
- [ ] API: `/api/v1/reports/*`

### 5.9 Custom Report Builder
- [ ] Visual query builder (select module, entities, filters, columns)
- [ ] SQL-based report (for advanced users, read-only access)
- [ ] Report parameters (date range, user, device, etc.)
- [ ] Save custom reports
- [ ] Share reports with other users/groups

### 5.10 Report Export
- [ ] PDF export (QuestPDF)
- [ ] CSV export
- [ ] Excel export (ClosedXML)
- [ ] On-screen table with sorting, filtering, pagination

### 5.11 Report Scheduling
- [ ] Cron-based schedule (daily, weekly, monthly)
- [ ] Email delivery (SMTP) with attachment
- [ ] Multiple recipients (users, groups, external emails)
- [ ] Schedule management UI
- [ ] API: `/api/v1/reports/schedules/*`

### 5.12 Dashboard System
- [ ] Admin dashboard: system overview (active sessions, recent alerts, pending approvals)
- [ ] SOC dashboard: security-focused (risk scores, anomalies, SIEM events)
- [ ] Compliance dashboard: framework scores, control status
- [ ] Operational dashboard: rotation status, device reachability, job health
- [ ] Per-user customizable dashboard
- [ ] Widget types:
  - [ ] Counter (number with trend arrow)
  - [ ] Bar chart, line chart, pie chart
  - [ ] Table (top N list)
  - [ ] Timeline (recent events)
  - [ ] Map (geographic, if applicable)
  - [ ] Gauge (compliance score, risk level)
- [ ] Widget data refresh (real-time via SignalR or polling)
- [ ] Dashboard layout: drag-and-drop widget positioning
- [ ] API: `/api/v1/dashboard/*`

---

## UI (Blazor)

### Compliance Pages
- [ ] Compliance frameworks list (with scores)
- [ ] Framework detail (control-by-control view)
- [ ] Evidence collection page
- [ ] SoD rules management
- [ ] SoD violations list
- [ ] Attestation campaigns list
- [ ] Campaign detail (reviewer decisions)
- [ ] Policy violation log

### Reporting Pages
- [ ] Report catalog (built-in + custom)
- [ ] Report runner (parameter input → results)
- [ ] Report viewer (table with export buttons)
- [ ] Custom report builder wizard
- [ ] Schedule management
- [ ] Dashboard editor (widget selection + layout)

---

## Audit Events
- Compliance.Assessment.Run, .Score.Changed
- Compliance.Violation.Detected, .Resolved
- Compliance.Evidence.Exported
- Compliance.Attestation.Started, .Completed, .AccessRevoked
- Compliance.SoD.ViolationDetected, .ExceptionGranted
- Report.Generated, .Exported, .Scheduled, .Delivered

---

## Deliverables
- All 6 compliance templates with control mappings
- Compliance posture dashboard working
- Evidence export bundle functional
- SoD rule enforcement working
- At least one attestation campaign cycle working
- All 15+ built-in reports working
- PDF/CSV/Excel export working
- Dashboard with customizable widgets
- Report scheduling with email delivery
