# Phase 3 - Session Manager

**Duration:** Week 13-18
**Depends On:** Phase 2 (Vault for credentials, Devices for targets)
**Goal:** Full session proxy suite with recording, monitoring, and policy enforcement

---

## Proxy Implementations

### 3.1 SSH Proxy
- [ ] TCP listener on configurable port (default 2222)
- [ ] SSH server-side implementation (using SSH.NET or custom)
- [ ] Authentication: session token extraction from SSH username (`token:<session-token>`)
- [ ] Token validation via gRPC to core service
- [ ] Credential retrieval from vault (decrypted, never sent to client)
- [ ] SSH client connection to target device
- [ ] Bidirectional I/O pipe with middleware pipeline
- [ ] Shell, exec, and subsystem (SFTP) channel support
- [ ] Connection pooling for concurrent sessions
- [ ] Graceful session termination
- [ ] Windows Service hosting

### 3.2 RDP Proxy
- [ ] Custom RD Gateway implementation (MS-TSGU protocol)
- [ ] Pre-authenticated .rdp file generation with gateway settings
- [ ] Token-based authentication on gateway
- [ ] NLA credential injection (server-side, user never sees password)
- [ ] Bitmap stream interception for recording
- [ ] RemoteFX / GFX pipeline handling
- [ ] Multi-monitor support passthrough
- [ ] Windows Service hosting
- [ ] Alternative: HTML5 RDP via web (using custom rendering)

### 3.3 VNC Proxy
- [ ] VNC protocol proxy (RFB)
- [ ] Authentication injection
- [ ] Frame buffer capture for recording
- [ ] Clipboard interception

### 3.4 SQL Proxy
- [ ] TDS protocol proxy (SQL Server - port 1433)
- [ ] MySQL protocol proxy (port 3306)
- [ ] PostgreSQL protocol proxy (port 5432)
- [ ] Oracle TNS proxy (port 1521)
- [ ] Authentication injection (credential from vault)
- [ ] Query logging (all SQL statements captured)
- [ ] Query filtering (block DROP, DELETE, TRUNCATE if policy says so)

### 3.5 HTTP/HTTPS Proxy
- [ ] Reverse proxy for web applications
- [ ] Cookie/token injection for authentication
- [ ] Request/response logging
- [ ] URL filtering
- [ ] SSL termination and re-encryption

### 3.6 SFTP Monitoring
- [ ] SFTP subsystem handling within SSH proxy
- [ ] File transfer logging (filename, size, direction, timestamp)
- [ ] File transfer policies (block by extension, size, direction)
- [ ] File content inspection (optional, v1.5)

---

## Session Recording

### 3.7 SSH Recording
- [ ] Asciinema v2 format (JSON lines: timestamp + output data)
- [ ] Input and output stream separation
- [ ] Compressed storage (gzip)
- [ ] Encrypted at rest (session DEK)

### 3.8 RDP/VNC Recording
- [ ] Custom binary format: timestamp + bitmap deltas (compressed)
- [ ] Efficient delta encoding (only changed regions)
- [ ] On-demand conversion to video (MP4/WebM)
- [ ] Configurable quality/compression trade-off

### 3.9 SQL Recording
- [ ] Query log format: timestamp + direction + SQL text
- [ ] Result set metadata capture (row count, columns)

### 3.10 Recording Infrastructure
- [ ] File system storage with configurable path
- [ ] Encryption at rest (per-session key)
- [ ] Recording index in database (session metadata + timestamps)
- [ ] Retention policies (auto-delete after N days)
- [ ] Recording export (for forensics)
- [ ] Storage quota monitoring

---

## Session Monitoring & Control

### 3.11 Keystroke Logging
- [ ] Input direction capture (client → server)
- [ ] Timestamp per keystroke batch
- [ ] Encrypted storage
- [ ] Searchable keystroke log

### 3.12 OCR Processing
- [ ] RDP/VNC screenshot capture at intervals
- [ ] OCR text extraction (Windows OCR API or Tesseract)
- [ ] Full-text search on session content
- [ ] Indexed for compliance queries

### 3.13 Session Shadowing
- [ ] Real-time admin co-viewing via WebSocket
- [ ] Read-only mode (observe only)
- [ ] Multiple admins can shadow simultaneously
- [ ] Shadow notification to user (configurable: visible or stealth)

### 3.14 Session Takeover
- [ ] Admin takes control of active session
- [ ] Original user becomes observer (or disconnected)
- [ ] Takeover logged as separate audit event
- [ ] Requires elevated permissions

### 3.15 Session Termination
- [ ] Admin force-disconnect active session
- [ ] Reason required for termination
- [ ] Graceful disconnect sequence
- [ ] User notification on termination

### 3.16 Live Session Dashboard
- [ ] Active sessions list (real-time update via SignalR)
- [ ] Session details: user, device, duration, risk score
- [ ] Quick actions: shadow, takeover, terminate
- [ ] Session count by type (SSH, RDP, SQL, etc.)

---

## Session Policies

### 3.17 Policy Engine
- [ ] Session duration limits (max time)
- [ ] Idle session timeout
- [ ] Concurrent session limits per user
- [ ] Clipboard control (block copy/paste in RDP)
- [ ] Drive mapping control (block RDP drive redirection)
- [ ] Printer redirection control
- [ ] File transfer policy (allow/deny by type, size, direction)
- [ ] Two-person rule (require live monitor for session to proceed)
- [ ] Session reason/justification requirement
- [ ] ITSM ticket requirement

### 3.18 Command Filtering (SSH/SQL)
- [ ] Whitelist mode: only allowed commands
- [ ] Blacklist mode: block specific commands
- [ ] Regex pattern matching
- [ ] Real-time blocking (intercept before forwarding to target)
- [ ] Block notification to user
- [ ] Alert to admin on blocked command attempt

### 3.19 UBA Command Scoring
- [ ] Command risk score calculation
- [ ] Cumulative session risk score
- [ ] Threshold-based alerts
- [ ] Auto-terminate if risk exceeds critical threshold

### 3.20 Watermarking (RDP)
- [ ] Overlay user identity on RDP session
- [ ] Configurable: username, IP, timestamp
- [ ] Semi-transparent, non-removable by user
- [ ] Forensic evidence in screenshots

---

## HTML5 Browser Clients

### 3.21 Web SSH Client
- [ ] xterm.js based terminal in Blazor (JS interop)
- [ ] WebSocket connection to SSH proxy
- [ ] Copy/paste support (if policy allows)
- [ ] Terminal resize handling
- [ ] File upload/download via SFTP (if policy allows)

### 3.22 Web RDP Client
- [ ] HTML5 Canvas-based RDP rendering
- [ ] WebSocket connection to RDP proxy
- [ ] Keyboard and mouse input forwarding
- [ ] Resolution adaptation
- [ ] Multi-monitor support (v1.5)

### 3.23 Web VNC Client
- [ ] noVNC-style implementation
- [ ] WebSocket to VNC proxy

### 3.24 Web SQL Client
- [ ] SQL editor with syntax highlighting
- [ ] Query execution via SQL proxy
- [ ] Result set display (table format)
- [ ] Query history

---

## Session Metadata & Connection

### 3.25 Quick Connect
- [ ] Type hostname → auto-resolve device → select credential → connect
- [ ] Recent connections list
- [ ] Favorites / bookmarks
- [ ] One-click connect from device page

### 3.26 Session Metadata
- [ ] Tag sessions with ticket IDs, change requests
- [ ] Custom metadata fields
- [ ] Session notes (post-session comments by admin)

---

## UI (Blazor)

- [ ] Active sessions dashboard (real-time)
- [ ] Session history (searchable, filterable)
- [ ] Session detail page (metadata, recording link, keystrokes)
- [ ] Session playback page (SSH terminal replay, RDP video player)
- [ ] Keystroke log viewer (timeline with search)
- [ ] Session policy management page
- [ ] Command filter rules editor
- [ ] Quick connect page
- [ ] Favorites management
- [ ] Live monitoring view (shadow sessions)

---

## Audit Events
- Session.Started, Session.Ended, Session.Terminated
- Session.Shadowed, Session.TakenOver
- Session.CommandBlocked, Session.CommandExecuted
- Session.PolicyViolation
- Session.RecordingStarted, Session.RecordingStopped
- Session.FileTransferred, Session.FileBlocked
- Session.RiskThresholdExceeded

---

## Deliverables
- SSH Proxy working with recording + keystroke logging
- RDP Proxy working with recording
- At least SQL Proxy for MSSQL working
- HTML5 SSH client in browser
- Session shadowing and termination working
- Command filtering working for SSH
- Session playback working
- All UI pages functional
