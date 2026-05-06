# Phase 4 - AAPM & Threat Analytics

**Duration:** Week 19-21
**Depends On:** Phase 3 (Session Manager for analytics data)
**Goal:** Application-to-application credential management and security analytics

---

## Module 4A: AAPM (Application-to-Application Password Management)

### 4.1 API Client Management
- [ ] API client registration (client_id + client_secret)
- [ ] Client secret shown once at creation, hashed with Argon2id
- [ ] IP allowlist per client (CIDR ranges)
- [ ] Client status: Active, Disabled
- [ ] Client credential access scoping (which vault credentials the client can access)
- [ ] API: `/api/v1/aapm/clients/*`

### 4.2 OAuth2 Authentication
- [ ] Client credentials grant flow (`POST /aapm/token`)
- [ ] Scoped JWT tokens (limited to specific credentials)
- [ ] Token expiry (configurable, short-lived)
- [ ] Rate limiting per client (sliding window)

### 4.3 Credential Retrieval
- [ ] `GET /aapm/credentials/{id}` - retrieve password (API client auth)
- [ ] Response: username + password (or SSH key, API key, etc.)
- [ ] TTL-based caching policy (client can cache for N seconds)
- [ ] Force-refresh option (bypass cache)
- [ ] Every retrieval logged to audit trail

### 4.4 SDKs
- [ ] C# NuGet package (`OrkunPAM.SDK.CSharp`)
- [ ] Python package (`orkunpam-sdk`)
- [ ] PowerShell module (`OrkunPAM.PowerShell`)
- [ ] SDK features: credential retrieval, rotation trigger, health check

### 4.5 Kubernetes Integration
- [ ] Init container for secret injection at pod startup
- [ ] Sidecar container for live credential rotation
- [ ] Kubernetes Secret sync (ExternalSecrets operator compatibility)
- [ ] Helm chart for deployment

### 4.6 Jenkins Plugin
- [ ] Jenkins credentials provider
- [ ] Pipeline step for credential retrieval
- [ ] Credential masking in build logs

### 4.7 Service Account Management
- [ ] Link API clients to service account users
- [ ] Service account lifecycle: create, rotate, disable
- [ ] Credential injection methods: env var, file-based, API

---

## Module 4B: Threat Analytics

### 4.8 User Behavior Analytics (UBA)
- [ ] Command risk scoring (assign risk values to command patterns)
- [ ] Cumulative session risk score
- [ ] User risk profile (historical behavior baseline)
- [ ] Risk threshold configuration (low/medium/high/critical)
- [ ] Auto-actions on threshold breach: alert, terminate session, lock user
- [ ] API: `/api/v1/analytics/uba/*`

### 4.9 Anomaly Detection
- [ ] Off-hours access detection (define business hours per user/group)
- [ ] Unusual source IP detection (baseline known IPs per user)
- [ ] Unusual device access (user accesses device they've never accessed before)
- [ ] Frequency anomaly (sudden spike in credential access)
- [ ] Geographic anomaly (impossible travel detection, if geo-IP available)

### 4.10 Risk Scoring Engine
- [ ] Per-session risk score (real-time, updated as commands execute)
- [ ] Per-user risk score (rolling window, aggregated from sessions)
- [ ] Risk factors: command patterns, time of day, source IP, device sensitivity, credential type
- [ ] Risk dashboard widget
- [ ] API: `/api/v1/analytics/risk-scores/*`

### 4.11 SIEM Integration
- [ ] Syslog output (UDP/TCP/TLS to configurable endpoint)
- [ ] CEF (Common Event Format) for security events
- [ ] Event mapping: PAM events → SIEM event categories
- [ ] Configurable: which events to forward, which to suppress
- [ ] Bulk event forwarding (batch mode for high-volume)
- [ ] API: `/api/v1/integrations/siem/*`

### 4.12 Real-Time Alerts
- [ ] Alert rules engine (condition → action)
- [ ] Conditions: event type, risk score, user, device, time, command pattern
- [ ] Actions: email, SMS, push notification, webhook, terminate session, lock user
- [ ] Alert suppression (avoid alert fatigue: cooldown period, aggregation)
- [ ] Alert history and acknowledgment
- [ ] API: `/api/v1/analytics/alerts/*`

### 4.13 SOC Dashboard
- [ ] Real-time threat overview (current risk levels)
- [ ] Active sessions with risk indicators
- [ ] Recent alerts timeline
- [ ] Top risky users / devices
- [ ] Anomaly timeline (last 24h / 7d / 30d)
- [ ] Geographic map of access (if geo-IP data available)

---

## UI (Blazor)

### AAPM Pages
- [ ] API client list (status, last used, access count)
- [ ] API client create/edit (secret generation, IP config, credential scoping)
- [ ] API client access log
- [ ] SDK documentation page (embedded)

### Analytics Pages
- [ ] SOC dashboard (real-time widgets)
- [ ] UBA configuration (command scoring rules)
- [ ] Anomaly detection settings
- [ ] Alert rules management
- [ ] Alert inbox (pending, acknowledged, resolved)
- [ ] Risk score reports (user-level, session-level)
- [ ] SIEM integration configuration

---

## Audit Events
- AAPM.Client.Created, .Updated, .Disabled
- AAPM.Credential.Retrieved, .Denied, .RateLimited
- AAPM.Token.Issued, .Expired
- Analytics.Anomaly.Detected
- Analytics.RiskThreshold.Exceeded
- Analytics.Alert.Triggered, .Acknowledged, .Resolved
- Analytics.Session.AutoTerminated

---

## Deliverables
- AAPM API fully functional with OAuth2
- At least C# SDK published
- Kubernetes init container working
- UBA scoring engine working
- Anomaly detection for off-hours and unusual IP
- Syslog SIEM output working
- Alert engine sending emails on policy violations
- SOC dashboard with real-time data
