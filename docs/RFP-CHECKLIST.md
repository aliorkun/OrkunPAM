# PAM RFP Template - Compliance Checklist

> Auto-generated from PAM Template.xlsx. PM Agent uses this for feature gap analysis.
> Status: FC=Fully Compliant, PC=Partially Compliant, NC=Not Compliant
> Last updated: 2026-05-14 (PM run #4)

## Platform (44 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall support appliance base installation | PC | WiX v4 MSI + PowerShell Install.ps1 + OrkunPAM.Installer CLI — component selection, DB init, cert gen, service registration; single-package Windows Server deployment (#36) |
| 2 | Solution shall support Vmware and Hyper-V based installation |  |  |
| 3 | Solution shall be deployable On‑Premise and provided as a cloud  offering. |  |  |
| 4 | Solution shall support agent-less architecture. No additional software agent shall be required to install on devices, se |  |  |
| 5 | Solution GUI shall run with updated version of well-known browsers (i.e. Microsoft Edge, Google Chrome, Firefox, Safari) | PC | OrkunPAM.Web (Blazor Server — Edge/Chrome/Firefox) |
| 6 | Solution shall support SSO (Single-Sign-On) | PC | SAML 2.0 SSO implemented — SamlAuthEndpoints.cs SP-initiated flow, SamlCallback.razor (#45) |
| 7 | Solution shall support both CLI and web interfaces | PC | Blazor web UI (OrkunPAM.Web) + REST API (OrkunPAM.WebAPI) |
| 8 | Solution shall support SAML authentication for secure portal access to PAM platform | PC | SAML 2.0 SP-initiated + ACS — SamlAuthEndpoints.cs; XML sig validation, ±5 min clock skew, auto-provision (#45) |
| 9 | Solution shall support SAML provider configuration on a per-tenant basis, allowing separate identity provider settings f |  |  |
| 10 | Solution shall support Public Key Infrastructure (PKI) Authentication for secure portal access using digital certificate |  |  |
| 11 | Solution shall support Windows Authentication fo |  |  |
| 12 | Solution shall have out of the box management capability for network devices and systems (Juniper, Cisco IOS, Cisco IOS- | PC | OrkunPAM.TacacsProxy — native C# TACACS+ (RFC 1492) built-in server; Cisco/Juniper/Aruba CLI AAA via TCP :49 (#111) |
| 13 | Solution shall support adapting to different brand/model devices and systems, which will be used in the future. |  |  |
| 14 | Solution shall have out of the box support for script usage on NAS devices. |  |  |
| 15 | Solution shall support users to change their passwords and force to create the passwords in a complex way as well as cha |  |  |
| 16 | Solution shall support to be scaled to serve a carrier grade number of devices and users besides redundancy which lets 9 |  |  |
| 17 | Solution shall support to active-active redundancy. |  |  |
| 18 | Solution shall support disaster recovery. | PC | BackupService.cs — AES-256-GCM encrypted backup/restore, Hangfire scheduler, Blazor UI (#55) |
| 19 | Solution shall support different software versions of a network device simultaneously. |  |  |
| 20 | Solution software shall support working on industry standard operating systems such as Unix, Linux, etc. |  |  |
| 21 | Solution shall be able to work on only one server for minimal installation. | PC | Single .NET 8 host — WebAPI + Blazor + SSH proxy on one Windows Server |
| 22 | Solution shall support to keep logs and video records on different database with required configuration. |  |  |
| 23 | Solution shall support also support expansion by adding new server(s) to the related layer to increase capacity. Existin |  |  |
| 24 | Solution shall support hierarchical user grouping structure. | PC | UserEndpoints.cs — user group CRUD |
| 25 | Solution shall support hierarchical device grouping structure. | PC | DeviceEndpoints.cs — device group CRUD |
| 26 | Solution shall support hierarchical grouping structure for administrators. | PC | RoleEndpoints.cs + UserEndpoints.cs |
| 27 | Solution shall support business and operational model of managed service providers |  |  |
| 28 | Solution shall support business and operational model of geographically distributed organizations |  |  |
| 29 | Solution shall support a controller layer above of the geographically distributed organizations . Solution shall support |  |  |
| 30 | All the audits and control activities shall be managed by controller layer in a geographically distributed implementatio |  |  |
| 31 | In a geographically distributed implementation each location shall be run indepently  in a possible network service outa |  |  |
| 32 | In a geographically distributed implementation the controller layer shall support centrally controller screens to monito |  |  |
| 33 | Solution shall have multi-language support |  |  |
| 34 | Solution shall support to limit the screens that a user can see | PC | RBAC middleware — menus restricted by role |
| 35 | Solution shall support preventing users to see the rights assigned to them. | PC | RBAC — roles not exposed to end users in UI |
| 36 | Solution shall support to configure access to specified IP addresses and IP address ranges to the system. | PC | AccessPolicyService.cs — IP whitelist/blacklist per user/group (#89) |
| 37 | Solution shall support to configure time-based access to the system. | PC | AccessPolicyService.cs — TimeRestriction: allowed hours/days of week per user/group (#89) |
| 38 | Solution shall support MFA (Multi Factor Authentication) to the platform. | PC | MfaRecoveryService.cs + MfaEndpoints.cs — TOTP MFA with backup codes, admin policy enforcement (#90) |
| 39 | Solution shall support configuration of MFA settings via UI | PC | Policies.razor MFA tab — per-group MFA policy, grace period, bypass for privileged ops (#90) |
| 40 | Solution shall support Windows or Kerberos Authentication for API interactions to enhance security and interoperability. |  |  |
| 41 | Solution shall support configuration of security settings via UI | PC | Admin.razor — global security config |
| 42 | Solution shall support role based administration. | PC | RoleEndpoints.cs + RBAC middleware — full role-permission matrix |
| 43 | Solution shall support two-man rule for specified sessions | PC | Approvals.razor — multi-step approval requiring ≥2 approvers (#79) |
| 44 | Solution shall support to add custom fields to privileged accounts | PC | CredentialEndpoints.cs — metadata/custom-fields on credentials |

## User Management (47 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall have internal(local) user management module and support manual user management. | FC | UserEndpoints.cs — full local user CRUD |
| 2 | Solution shall support self registration of new user requests with manager approval. |  |  |
| 3 | Solution shall support automaticaly user/user groups synchronization with Active Directories |  |  |
| 4 | Solution shall support temporary users, which are active for a limited period of time and de-active automatically. | PC | AccountLifecyclePolicyService.cs — ExpiresAt DateTime on user, background service auto-deactivates expired accounts; Users.razor expiry field (#135 #137) |
| 5 | Solution shall support grouping of the users. | PC | UserEndpoints.cs — user group CRUD |
| 6 | Solution shall support defining the admin or manager of the user group |  |  |
| 7 | Solution shall support multi domain active directories or forest structure |  |  |
| 9 | Solution shall support Admin users to assign additional roles to user groups | PC | RoleEndpoints.cs — assign roles to groups |
| 10 | Solution shall support Admin users to delete role definitions. | PC | RoleEndpoints.cs — delete role definitions |
| 11 | Solution shall support Admin users to change (adding or deleting authorization) defined roles. | PC | RoleEndpoints.cs — add/remove permissions from roles |
| 12 | Solution shall support creating bulk users automatically such as importing from a file | PC | BulkUserImport.razor + BulkImportEndpoints.cs — CSV/Excel bulk user import (#85) |
| 13 | Solution shall support locking all the users in a group and removing the all of the locked users. |  |  |
| 14 | Solution shall support locking user after a configurable inactivity period | PC | AccountLifecyclePolicyService.cs — InactivityLockoutDays policy setting, InactiveAt tracking, background LockInactiveUsers; password age lockout (#135) |
| 15 | Solution shall support changing parameters and values for all of the users in a group. |  |  |
| 16 | Solution shall support to force changing passwords of all of the users in a group on the next login. |  |  |
| 17 | Solution shall be able to list active users . | PC | Users.razor — active user list with filter |
| 18 | Solution shall support secondary password management as a configurative an optional |  |  |
| 19 | Admin user shall have the right to reset the other users' passwords. When the password is reset, an e-mail shall be sent | PC | ForgotPassword.razor — self-service reset via email token (30min TTL); SmtpNotificationService — reset email; admin reset via Users.razor |
| 20 | Solution shall have configurable password strength settings | PC | UserEndpoints.cs — password strength settings per policy |
| 21 | Solution shall support enriched approval request information, including detailed start and expiration times for enhanced | PC | Approvals.razor — expiry countdown with red warning, start/end times, multi-level step indicator (#79) |
| 22 | Solution shall support detailed logs about device group modifications for improved tracking and reporting of system chan |  |  |
| 23 | Solution shall provide audit logs that include granular details on policy actions and system configuration changes for c |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

## Reporting (46 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall have a dashboard to monitor successful authentications per user and device on a daily bases. | PC | Dashboard.razor — daily auth success chart |
| 2 | Solution shall have a dashboard to monitor successful sessions per user and device on a daily bases. | PC | Dashboard.razor + Sessions.razor |
| 3 | Solution shall have a dashboard to monitor failed authentications per user and device on a daily bases. | PC | Dashboard.razor — failed auth count |
| 4 | Solution shall have a dashboard to monitor blocked command per user and device on a daily bases | PC | Dashboard.razor — blocked command count widget |
| 5 | Solution shall have a dashboard to monitor password changes per user and device on a daily bases |  |  |
| 6 | Solution shall be able to report expired passwords, | PC | Reports.razor — expired passwords report |
| 7 | Solution shall be able to report users who have logged in the system. | PC | Reports.razor — user login audit report |
| 8 | Solution shall be able to report users who have initiated sessions to target devices | PC | Reports.razor — session initiation report |
| 9 | Solution shall be able to report all the activities performed by users while in session | PC | Reports.razor — in-session activity report |
| 10 | Solution shall be able to report session initiations | PC | Reports.razor — session initiation report |
| 11 | Solution shall be able to report commands executed in sessions | PC | Reports.razor — command execution report |
| 12 | Solution shall be able to report blocked commands in sessions | PC | Reports.razor — blocked commands report |
| 13 | Solution shall be able to report  video records of sessions | PC | Reports.razor — session recording report |
| 14 | Solution shall be able to report approved/ denied sessions | PC | Reports.razor — approval history report |
| 15 | Solution shall be able to report exported passwords (checkout) | PC | Reports.razor — checkout/export report |
| 16 | Solution shall be able to report user login attempts. | PC | Reports.razor — login attempt report |
| 17 | Solution shall be able to report locked/unlocked users | PC | Reports.razor — locked user report |
| 18 | Solution shall be able to report password change policy violations | PC | Reports.razor — policy violation report |
| 19 | Solution shall be able to report privileged account access by non-owners | PC | Reports.razor — non-owner access report |
| 20 | Solution shall be able to generate compliance reports for industry regulations such as PCI-DSS | PC | Reports.razor — compliance report (PCI-DSS/ISO) |
| 21 | Solution shall be able to provide scheduling for reports | PC | ReportScheduler — Hangfire-based scheduled report delivery |
| 22 | Solution shall be able to provide export functionality for reports: CSV, PDF | PC | ReportExportService.cs — CSV + PDF export |
| 23 | Solution shall support for custom reports | PC | Reports.razor — custom report builder |
| 24 | Solution shall support to monitor real time sessions | PC | Sessions.razor — real-time session list |
| 25 | Solution shall support to monitor system events in real time |  |  |
| 26 | Solution shall support to view the session logs with filtering and sorting options | PC | Sessions.razor — filter by user, device, protocol, date |
| 27 | Solution shall have reports in both table and chart format | PC | Reports.razor — table + Chart.js bar/pie charts |
| 28 | Solution shall have reports in full text search | PC | Reports.razor — full-text search filter |
| 29 | Solution shall support scheduling of reports |  |  |
| 30 | Solution shall support to define the report recipients |  |  |
| 31 | Solution shall support e-mailing of scheduled reports | PC | ReportScheduler — email delivery via SmtpNotificationService |
| 32 | Solution shall support custom role-based reporting | PC | Reports.razor — RBAC-gated report views |
| 33 | Solution shall provide built-in reports out of the box | PC | Reports.razor — 9+ pre-built reports (#27) |
| 34 | Solution shall support generating risk reports |  |  |
| 35 | Solution shall support full compliance reporting against industry standards |  |  |
| 36 | Solution shall support standard report format including time, user, server and action details | PC | Reports.razor — standardized columns |
| 37 | Solution shall support historical data, generating reports from previous months | PC | Reports.razor — date-range filter including historical |
| 38 | Solution shall support creating reports from real time data | PC | Reports.razor — live query |
| 39 | Solution shall support report exporting functions, such as PDF, CSV, Excel. | PC | ReportExportService.cs — PDF + CSV export |
| 40 | Solution shall support customizing report templates | PC | Reports.razor — custom report builder with field selection |
| 41 | Solution shall support report printing option |  |  |
| 42 | Solution shall support report retention for a  minimum of 5 years | PC | RetentionPolicyService.cs — configurable retention period |
| 43 | Solution shall support viewing the instant status (online/offline) of the target devices | PC | Devices.razor — live device status indicator |
| 44 | Solution shall support instant monitoring of active users on target devices | PC | Sessions.razor — active session monitor |
| 45 | Solution shall support detailed view for active session. | PC | Sessions.razor — session detail panel |
| 46 | Solution shall support monitoring of open sessions on network devices | PC | Sessions.razor — network device session filter |

## Session Manager (162 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | General | Solution shall support MFA (Multi Factor Authentication) when a user attempts to open a CLI/RDP/HTTP/SFTP/SQL sessions t | PC | MFA policy enforcement (group/role bazlı) — Policies.razor MFA tab + AuthenticationService.cs; TOTP required before SSH/RDP session opens |
| 2 | General | Solution shall support SSL protocol for network management and terminal (console) servers. |  |
| 3 | General | Solution shall support using TELNET, STELNET, SSH, VNC, RDP, HTTP, HTTPS protocols to login to end devices. | PC | SshProxyService.cs — native SSH (RFC 4253); OrkunPAM.RdpProxy — TCP 3389 relay, TPKT/X.224, .rdp download (#23) |
| 4 | General | Solution shall be able to manage and interact with multiple remote sessions  for both Remote Desktop Protocol (RDP) ,SSH |  |
| 5 | General | Solution shall be able to launch and configure sessions across multiple  environments with credentials automatically inj | PC | SshServerSession.cs — vault credential injection to target |
| 6 | General | Solution shall support native CLI clients like SecureCRT, Putty, MobaXterm etc. |  |
| 7 | General | Solution shall support SSH and RDP connections to target servers from any device without any native client or agent inst | PC | Connect.razor + SshProxyService.cs — browser-based SSH terminal |
| 8 | General | Solution shall support double confirmation of execution of the command that can cause a service interrupt or any request | PC | DangerousCommandFilter.cs — SSH double-confirmation for destructive commands (rm -rf, shutdown, reboot, DROP, format, mkfs); configurable command list (#136) |
| 9 | General | Solution shall support geofence validation through mobile application for the command executions. |  |
| 10 | General | Solution shall support duration based restriction policy for the sessions | PC | SessionPolicyService.cs — session duration/timeout enforcement at runtime (#84) |
| 11 | General | Solution shall have a connection reservation functionalty for future date connections |  |
| 12 | General | Solution shall support to open SSH/RDP/HTTP sessions via desktop application on user workstation (without logging into P |  |
| 13 | General | Solution shall support to log users' client IP addresses even if users access the Web GUI through the loadbalancer. |  |
| 14 | General | Solution shall support to use its own secure tunnel (connector) to connect to target devices located in remote data cent |  |
| 15 | General | Solution shall support users to create a connection reservation request for a future date and get administrator approval | PC | Approvals.razor — approval workflow, expiry countdown, multi-step approval (#79) |
| 16 | General | Solution shall support expiration of connection reservation requests that are not approved/devied for a certain period o |  |
| 17 | General | Solution shall support administrators to change the selected date/time during connection request approval. |  |
| 18 | General | Solution shall allow connections to target Linux/Unix and Windows systems by entering IP addresses, restr |  |
| 19 | General | Solution shall allow connections to target Linux/Unix and Windows systems by entering IP addresses, restr |  |
| 20 | General | Solution shall support a connection retry mechanism to ensure reliable sessions when initial connection attempts fail. |  |
| 21 | General | Solution shall support the ability to send and receive files between a privileged account and target systems using SFTP | PC | SshProxyService.cs — SFTP subsystem relay |
| 22 | General | Solution shall support to audit the files transferred through SFTP. | PC | AuditService.cs — SFTP transfer event logging |
| 23 | SSH | Solution shall provide SSH protocol connection to managed systems. | FC | SshProxyService.cs — native C# SSH (RFC 4253): kex, user-auth, channel, exec, shell, subsystem |
| 24 | SSH | Solution shall be able to manage multiple protocols simultaneously (telnet and SSH etc) |  |
| 25 | SSH | Solution shall support full interaction with CLI sessions in SSH protocol | FC | SshServerSession.cs — full interactive shell via SshProxyService |
| 26 | SSH | Solution shall support terminal emulation (VT100, ANSI, xterm) in SSH protocol | PC | SshProxyService.cs — VT100/ANSI/xterm terminal emulation over WebSocket |
| 27 | SSH | Solution shall support to send a command to multiple sessions simultaneously via SSH protocol | PC | CommandDispatchEndpoints.cs — multi-session parallel command dispatch |
| 28 | SSH | Solution shall support connection to systems using SSH certificates | PC | SshKeyEndpoints.cs — certificate-based auth, RSA/OpenSSH key storage |
| 29 | SSH | Solution shall support SSH host key verification | PC | SshProxyService.cs — known_hosts style host key fingerprint verification |
| 30 | SSH | Solution shall support for creating and storing SSH public/private key pairs for SSH protocol | PC | SshKeyEndpoints.cs — key pair generation, RSA/OpenSSH formats |
| 31 | SSH | Solution shall support configuring SSH-related parameter settings (port, encryption algorithm, MACs,  key exchange algo | PC | SshProxyService.cs — configurable ciphers, KEX, MACs |
| 32 | SSH | Solution shall support connection multiplexing (ControlMaster) for SSH to allow multiple sessions to share a single TCP |  |
| 33 | SSH | Solution shall support IPv6 addressing for SSH connections |  |
| 34 | SSH | Solution shall support the ability to save connection configurations (host, port, credentials) as profiles | PC | DeviceEndpoints.cs — device profile with saved SSH settings |
| 35 | SSH | Solution shall provide mechanism for an administrator to view active SSH sessions and their details. | PC | Sessions.razor — active session list with SSH filter |
| 36 | SSH | Solution shall provide mechanism to monitor (listen, join) active SSH sessions in real-time. |  |
| 37 | SSH | Solution shall provide mechanism for an administrator to take over (assuming control from the user) and leave an active |  |
| 38 | SSH | Solution shall provide mechanism to terminate active sessions: one by one or all at once | PC | SessionEndpoints.cs — DELETE /sessions/{id} + DELETE /sessions (bulk) |
| 39 | SSH | Solution shall support sending messages to active SSH sessions. |  |
| 40 | SSH | Solution shall support session duration limit for SSH sessions | PC | SessionPolicyService.cs — max session duration per group |
| 41 | SSH | Solution shall support automatic logout from SSH sessions due to keyboard inactivity | PC | SessionPolicyService.cs — idle timeout |
| 42 | SSH | Solution shall support SSH sessions to be stored in logs as video/text records | PC | SessionRecordingService.cs — text log + binary recording |
| 43 | SSH | Solution shall support searching in recorded sessions by keyword | PC | SessionPlaybackEndpoints.cs — full-text search in recorded sessions (#34) |
| 44 | SSH | Solution shall support playback of recorded SSH sessions | PC | SessionPlaybackEndpoints.cs + Playback.razor — replay with timestamp seek (#34) |
| 45 | SSH | Solution shall support SSH session recording in text format | PC | SessionRecordingService.cs — text log (asciinema compatible) |
| 46 | SSH | Solution shall support to define SSH connection parameters at the group level |  |
| 47 | SSH | Solution shall support to configure authorization based on source IP for SSH sessions | PC | AccessPolicyService.cs — IP whitelist/blacklist per group |
| 48 | SSH | Solution shall support recording SSH session keystrokes | PC | SessionRecordingService.cs — keystroke-level recording |
| 49 | SSH | Solution shall support command filtering for SSH sessions | PC | CommandFilterService.cs — whitelist/blacklist command filter, regex patterns (#91) |
| 50 | SSH | Solution shall support command authorization | PC | CommandFilterService.cs — per-group command authorization rules |
| 51 | SSH | Solution shall support to track pattern-based commands for SSH sessions | PC | CommandFilterService.cs — regex pattern tracking |
| 52 | SSH | Solution shall support pattern-based command blocking | PC | CommandFilterService.cs — block+audit on pattern match |
| 53 | SSH | Solution shall support configuring the commands that may produce alerts when executed | PC | CommandFilterService.cs — alert-on-match config |
| 54 | SSH | Solution shall support privileged command execution (sudo) authorization within SSH sessions | PC | CommandFilterService.cs — sudo command tracking and authorization |
| 55 | SSH | Solution shall support SSH command execution and interception | PC | SshServerSession.cs — command intercept, filter, pass/block |
| 56 | SSH | Solution shall support tracking all SSH commands in logs | FC | AuditService.cs — every SSH command logged with user/device/timestamp |
| 57 | SSH | Solution shall support SFTP protocol and all its functionality in SSH protocol | PC | SshProxyService.cs — SFTP subsystem relay |
| 58 | SSH | Solution shall support full SCP functionality in SSH protocol | PC | SshProxyService.cs — SCP channel relay |
| 59 | SSH | Solution shall support to track files transferred in SFTP sessions | PC | AuditService.cs — SFTP file transfer audit |
| 60 | SSH | Solution shall support multi-hop connections through PAM to target systems |  |
| 61 | SSH | Solution shall support running post-session scripts automatically upon connection close | PC | SessionPostActionService.cs — configurable post-session automation |
| 62 | SSH | Solution shall support watermarking (identifying) terminal session screen with session ID and user info |  |
| 63 | SSH | Solution shall support OCR-based content extraction from recorded sessions |  |
| 64 | SSH | Solution shall support disabling copy-paste in SSH sessions |  |
| 65 | SSH | Solution shall support configuring clipboard access for sessions |  |
| 66 | SSH | Solution shall support alert notifications for keywords detected in SSH session content | PC | CommandFilterService.cs — keyword alert on pattern match |
| 67 | SSH | Solution shall support defining risk levels for commands in sessions |  |
| 68 | SSH | Solution shall support associating SSH sessions with work orders and incidents | PC | Approvals.razor — approval request linked to session via workorder reference |
| 69 | SSH | Solution shall support multi-hop through a bastion host for SSH protocol |  |
| 70 | VNC | Solution shall support VNC connections to target servers | PC | OrkunPAM.VncProxy — VNC proxy: RFB protocol, TCP relay, auth, recording stub |
| 71 | VNC | Solution shall support recording VNC sessions | PC | VncProxyService.cs — session recording hook |
| 72 | VNC | Solution shall support playback of recorded VNC sessions |  |
| 73 | VNC | Solution shall support clipboard access configuration for VNC sessions |  |
| 74 | VNC | Solution shall support screen sharing via VNC |  |
| 75 | VNC | Solution shall support file transfer within VNC sessions |  |
| 76 | RDP | Solution shall provide RDP protocol connection to managed systems. | PC | OrkunPAM.RdpProxy — TCP 3389 relay, TPKT/X.224, NLA TLS, .rdp download (#23, #124) |
| 77 | RDP | Solution shall support Full RDP sessions with credential injection | PC | RdpProxyService.cs — NLA credential injection + TLS termination (#124) |
| 78 | RDP | Solution shall support RemoteApp functionality in RDP sessions |  |
| 79 | RDP | Solution shall support multiple concurrent RDP sessions for a single user |  |
| 80 | RDP | Solution shall support Group Policy enforcement for RDP sessions |  |
| 81 | RDP | Solution shall support RDP session shadowing | PC | RdpProxyService.cs — shadow channel via WMI Win32_TSSession (partial) |
| 82 | RDP | Solution shall support simultaneous connections to multiple RDP targets |  |
| 83 | RDP | Solution shall support administrator take-over of RDP sessions |  |
| 84 | RDP | Solution shall support RDP session management (connect/disconnect/reconnect) | PC | SessionEndpoints.cs — session lifecycle management |
| 85 | RDP | Solution shall support configuring display settings for RDP sessions (color depth, resolution) |  |
| 86 | RDP | Solution shall support RemoteApp publishing through PAM |  |
| 87 | RDP | Solution shall support RDP recording | PC | RdpProxyService.cs — bitmap capture recording |
| 88 | RDP | Solution shall support RDP session playback |  |
| 89 | RDP | Solution shall support RDP NLA (Network Level Authentication) | PC | RdpProxyService.cs — NLA passthrough + TLS (#124) |
| 90 | RDP | Solution shall support RDP session clipboard control |  |
| 91 | RDP | Solution shall support RDP printer redirection control |  |
| 92 | RDP | Solution shall support RDP drive redirection control |  |
| 93 | RDP | Solution shall support RDP audio redirection |  |
| 94 | RDP | Solution shall support RDP HA (High Availability) with multiple RDSH nodes |  |
| 95 | RDP | Solution shall support RDP Gateway integration |  |
| 96 | HTTP | Solution shall support HTTP/HTTPS connections to web consoles of network devices | PC | OrkunPAM.HttpProxy — HTTP/HTTPS reverse proxy, header injection, SSRF guard (#123) |
| 97 | HTTP | Solution shall support recording HTTP sessions | PC | HttpProxyService.cs — request/response logging |
| 98 | HTTP | Solution shall support HTTP header injection for credential pass-through | PC | HttpProxyService.cs — Authorization/Cookie header injection |
| 99 | HTTP | Solution shall support session-based HTTP proxy for web application access |  |
| 100 | HTTP | Solution shall support HTTP session recording with replay | PC | HttpProxyService.cs — full request/response capture |
| 101 | HTTP | Solution shall support URL filtering in HTTP sessions |  |
| 102 | SQL | Solution shall support SQL database connections (MySQL, PostgreSQL, MSSQL) |  |
| 103 | SQL | Solution shall support credential injection for SQL connections |  |
| 104 | SQL | Solution shall support recording SQL sessions |  |
| 105 | SQL | Solution shall support SQL command filtering |  |
| 106 | SFTP | Solution shall support SFTP connections to target servers | PC | SshProxyService.cs — SFTP subsystem relay |
| 107 | SFTP | Solution shall support file transfer audit in SFTP sessions | PC | AuditService.cs — SFTP audit |
| 108 | SFTP | Solution shall support file filtering in SFTP sessions |  |
| 109 | SFTP | Solution shall support SFTP session recording |  |
| 110 | TELNET | Solution shall support TELNET connections to target systems |  |
| 111 | TELNET | Solution shall support TELNET session recording |  |
| 112 | TELNET | Solution shall support TELNET command filtering |  |
| 113 | Network | Solution shall support TACACS+ protocol for network device access | PC | OrkunPAM.TacacsProxy — native C# TACACS+ RFC 1492, built-in server, auth/authz/accounting (#111) |
| 114 | Network | Solution shall support RADIUS protocol for network device access | PC | OrkunPAM.TacacsProxy — native C# RADIUS RFC 2865: PAP/CHAP/PEAP, MFA TOTP, Message-Authenticator (#111) |
| 115 | Network | Solution shall support TACACS+ command authorization | PC | TacacsAuthorizationHandler.cs — per-command whitelist/blacklist authorization (#111) |
| 116 | Network | Solution shall support RADIUS accounting | PC | RadiusAccountingHandler.cs — Start/Stop/Interim-Update packets (#111) |
| 117 | Network | Solution shall support network device session recording | PC | TacacsProxyService.cs — full session recording hook |
| 118 | Network | Solution shall support network device command filtering | PC | TacacsAuthorizationHandler.cs — command filter with regex |
| 119 | Network | Solution shall support RADIUS NAS IP validation | PC | RadiusHandler.cs — NAS-IP-Address attribute validation |
| 120 | Network | Solution shall support Cisco IOS device management |  |
| 121 | Network | Solution shall support Juniper device management |  |
| 122 | Network | Solution shall support Aruba device management | PC | TacacsAuthorizationHandler.cs — vendor-agnostic TACACS+ works with Aruba |
| 123 | Network | Solution shall support multi-vendor network device management |  |
| 124 | Network | Solution shall support network device configuration backup |  |
| 125 | Network | Solution shall support network device configuration comparison |  |
| 126 | Network | Solution shall support network device discovery |  |
| 127 | Network | Solution shall support network device compliance checking |  |
| 128 | Network | Solution shall support network device patch management |  |
| 129 | Network | Solution shall support network device firmware management |  |
| 130 | Network | Solution shall support network device inventory |  |
| 131 | Network | Solution shall support SNMP monitoring integration |  |
| 132 | Network | Solution shall support syslog collection from network devices |  |
| 133 | Network | Solution shall support NetFlow/IPFIX collection |  |
| 134 | Network | Solution shall support network device performance monitoring |  |
| 135 | Network | Solution shall support network topology visualization |  |
| 136 | Network | Solution shall support network device grouping |  |
| 137 | Network | Solution shall support network device tagging |  |
| 138 | Network | Solution shall support network device search |  |
| 139 | Network | Solution shall support network device export |  |
| 140 | Network | Solution shall support network device import |  |
| 141 | Network | Solution shall support network device bulk operations |  |
| 142 | Network | Solution shall support network device health monitoring |  |
| 143 | Network | Solution shall support network device alert configuration |  |
| 144 | Network | Solution shall support network device SLA monitoring |  |
| 145 | Network | Solution shall support network device capacity planning |  |
| 146 | Network | Solution shall support network device change management |  |
| 147 | Network | Solution shall support network device incident management |  |
| 148 | Network | Solution shall support network device problem management |  |
| 149 | Remote Access | Solution shall support remote access for a user only to authorized devices and only during permitted time periods |  |
| 150 | Remote Access | Solution shall support access control policies for remote access |  |
| 151 | Remote Access | Solution shall support remote access session timeout |  |
| 152 | Remote Access | Solution shall support remote access with MFA |  |
| 153 | Remote Access | Solution shall support remote access audit logging |  |
| 154 | Remote Access | Solution shall support remote access for third-party vendors |  |
| 155 | Remote Access | Solution shall support remote access with IP restrictions |  |
| 156 | Remote Access | Solution shall support remote access with time-based restrictions |  |
| 157 | Remote Access | Solution shall support remote access session recording |  |
| 158 | Remote Access | Solution shall support remote access with approval workflow |  |
| 159 | Remote Access | Solution shall support remote access with notification |  |
| 160 | Remote Access | Solution shall support remote access report |  |
| 161 | Remote Access | Solution shall support remote access with certificate-based auth |  |
| 162 | Remote Access | Solution shall support remote access emergency access procedure |  |

## Password Vault (92 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | General | Solution shall support password management of Linux/Unix, Windows OS, databases, network elements, LDAP, Active Director | PC | VaultEndpoints.cs — POST /credentials/{id}/rotate: SSH, WinRM, LDAP/AD, SQL Server, MySQL, PostgreSQL (#32) |
| 2 | General | Solution shall support to manage Windows Local accounts using Active Directory domain admin accounts. |  |
| 3 | General | Solution shall support password management of users accounts on NMS/EMS (Nokia 5620 SAM, Huawei U2000, Juniper Managemen |  |
| 4 | General | Solution shall support password management of Web applications' password |  |
| 5 | General | Solution shall support managing privileged accounts on the cloud service provider, such as AWS IAM accounts. |  |
| 6 | General | Solution shall support managing API access keys on the cloud service provider, such as AWS API Access Key/Secrets. |  |
| 7 | General | Solution shall support managing secrets/passwords stored within configuration files |  |
| 8 | General | Solution shall support all functionalities without any agent to be installed on target server(agentless) |  |
| 9 | General | Solution shall support storing files in the password vault. |  |
| 10 | General | Solution shall support storing passwords for files stored in the password vault. |  |
| 11 | General | Solution shall support to store password with AES 256 encryption. | FC | CryptoService.cs — AES-256-GCM per-credential encryption |
| 12 | General | Solution shall support to store encryption keys on Hardware Security Module (HSM) devices |  |
| 13 | General | Solution shall support SSH-Key Management for RSA and OpenSSH key formats | PC | SshKeyEndpoints.cs — RSA/OpenSSH key pair storage, rotation, push to target device (#80) |
| 14 | General | Solution shall support auto-detection and onboarding of Windows  Local User & Administrative Accounts | PC | DiscoveryService.cs — Windows local account discovery |
| 15 | General | Solution shall support auto-detection and onboarding of Unix/Linux accounts |  |
| 16 | General | Solution shall support auto-detection and onboarding of Active Directory accounts | PC | DiscoveryService.cs — AD/LDAP account discovery |
| 17 | General | Solution shall support auto-detection and onboarding of database accounts |  |
| 18 | General | Solution shall support auto-detection and onboarding of network device accounts |  |
| 19 | General | Solution shall support auto-detection and onboarding of cloud accounts |  |
| 20 | General | Solution shall support auto-detection and onboarding of application accounts |  |
| 21 | General | Solution shall support automatic password rotation | PC | RotationService.cs — auto-rotation on schedule: SSH, WinRM, SQL, MySQL, PostgreSQL (#32) |
| 22 | General | Solution shall support customizable rotation schedules | PC | RotationService.cs — cron-style schedule per credential group (#32) |
| 23 | General | Solution shall support password rotation notifications | PC | SmtpNotificationService.cs — rotation success/fail email (#32) |
| 24 | General | Solution shall support checkout of passwords for manual use | PC | VaultEndpoints.cs — POST /credentials/{id}/checkout with time-limit (#44) |
| 25 | General | Solution shall support check-in of passwords | PC | VaultEndpoints.cs — POST /credentials/{id}/checkin |
| 26 | General | Solution administrator shall not be able to view the passwords for privileged accounts |  |  |
| 27 | General | Solution shall support dual control for password access |  |
| 28 | General | Solution shall support exclusive access mode (only one user at a time) |  |
| 29 | General | Solution shall support password history | PC | CredentialEndpoints.cs — password history with configurable depth |
| 30 | General | Solution shall support password complexity enforcement | PC | UserEndpoints.cs — password complexity rules (length, uppercase, symbols) |
| 31 | General | Solution shall support custom password policies per group | PC | Policies.razor — per-group password policy |
| 32 | General | Solution shall support password expiry | PC | RotationService.cs — configurable max password age |
| 33 | General | Solution shall support password age enforcement | PC | RotationService.cs — age enforcement with auto-rotation trigger (#32) |
| 34 | General | Solution shall support password reset workflow | PC | ForgotPassword.razor — self-service reset via email token |
| 35 | General | Solution shall support password change audit logging | FC | AuditService.cs — every password change logged with user, timestamp, source |
| 36 | General | Solution shall support password breach detection |  |
| 37 | General | Solution shall support integration with external vaults (HashiCorp Vault, CyberArk) |  |
| 38 | General | Solution shall support KMIP for key management |  |
| 39 | General | Solution shall support key rotation | PC | CryptoService.cs — DEK rotation, KEK hierarchy (#57) |
| 40 | General | Solution shall support key escrow |  |
| 41 | General | Solution shall support disaster recovery for keys | PC | BackupService.cs — encrypted key backup (#55) |
| 42 | General | Solution shall support key expiry |  |
| 43 | General | Solution shall support key lifecycle management | PC | CryptoService.cs — DEK/KEK lifecycle management |
| 44 | General | Solution shall support signing of secrets |  |
| 45 | General | Solution shall support secrets injection into CI/CD pipelines |  |
| 46 | General | Solution shall support secrets rotation for CI/CD |  |
| 47 | General | Solution shall support dynamic secrets generation |  |
| 48 | General | Solution shall support Kubernetes secrets management |  |
| 49 | General | Solution shall support certificate lifecycle management |  |
| 50 | General | Solution shall support certificate issuance |  |
| 51 | General | Solution shall support certificate renewal |  |
| 52 | General | Solution shall support certificate revocation |  |
| 53 | General | Solution shall support certificate import |  |
| 54 | General | Solution shall support certificate export |  |
| 55 | General | Solution shall support self-signed certificate generation |  |
| 56 | General | Solution shall support CA (Certificate Authority) integration |  |
| 57 | General | Solution shall support ACME protocol for certificate issuance |  |
| 58 | General | Solution shall support certificate monitoring |  |
| 59 | General | Solution shall support certificate alerting |  |
| 60 | General | Solution shall support certificate reporting |  |
| 61 | General | Solution shall support SSH certificate authority |  |
| 62 | General | Solution shall support SSH certificate signing |  |
| 63 | General | Solution shall support SSH certificate revocation |  |
| 64 | General | Solution shall support SSH certificate monitoring |  |
| 65 | General | Solution shall support SSH certificate alerting |  |
| 66 | General | Solution shall support SSH certificate reporting |  |
| 67 | General | Solution shall support SSH certificate lifecycle management |  |
| 68 | General | Solution shall support SSH certificate export |  |
| 69 | General | Solution shall support SSH certificate import |  |
| 70 | General | Solution shall support SSH certificate renewal |  |
| 71 | General | Solution shall support SSH certificate auto-renewal |  |
| 72 | General | Solution shall support SSH certificate CRL |  |
| 73 | General | Solution shall support SSH certificate OCSP |  |
| 74 | General | Solution shall support SSH certificate chain validation |  |
| 75 | General | Solution shall support SSH certificate subject alternative names |  |
| 76 | General | Solution shall support SSH certificate key usage extensions |  |
| 77 | General | Solution shall support SSH certificate extended key usage extensions |  |
| 78 | General | Solution shall support SSH certificate custom extensions |  |
| 79 | General | Solution shall support SSH certificate policies |  |
| 80 | General | Solution shall support SSH certificate key pinning |  |
| 81 | General | Solution shall support SSH certificate trust store management |  |
| 82 | General | Solution shall support SSH certificate profile management |  |
| 83 | General | Solution shall support SSH certificate template management |  |
| 84 | General | Solution shall support SSH certificate enrollment |  |
| 85 | General | Solution shall support SSH certificate auto-enrollment |  |
| 86 | General | Solution shall support SSH certificate multi-domain |  |
| 87 | General | Solution shall support SSH certificate wildcard |  |
| 88 | General | Solution shall support SSH certificate SANs |  |
| 89 | General | Solution shall support SSH certificate IP SANs |  |
| 90 | General | Solution shall support SSH certificate URI SANs |  |
| 91 | General | Solution shall support SSH certificate email SANs |  |
| 92 | General | Solution shall support SSH certificate directory SANs |  |

## Integration (17 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall support integration with SIEM systems | PC | SiemForwarderService.cs — Syslog CEF/RFC 5424, TCP/UDP, configurable (#122) |
| 2 | Solution shall support CEF format for SIEM integration | PC | SiemForwarderService.cs — CEF event format (#122) |
| 3 | Solution shall support Syslog format for SIEM integration | PC | SiemForwarderService.cs — RFC 5424 syslog (#122) |
| 4 | Solution shall support webhook notifications | PC | WebhookService.cs — POST notifications to registered endpoints |
| 5 | Solution shall support SMTP email notifications | PC | SmtpNotificationService.cs — email alerts, approval notify, rotation alerts |
| 6 | Solution shall support LDAP/AD integration | PC | LdapService.cs — LDAP bind, user search, group sync (#47) |
| 7 | Solution shall support SAML 2.0 for SSO | PC | SamlAuthEndpoints.cs — SP-initiated SAML 2.0 (#45) |
| 8 | Solution shall support SCIM for user provisioning |  |  |
| 9 | Solution shall support ITSM integration (ServiceNow, OneDesk) |  |  |
| 10 | Solution shall support ticketing system integration |  |  |
| 11 | Solution shall support SNMP traps |  |  |
| 12 | Solution shall support REST API for all management operations | FC | OrkunPAM.WebAPI — full REST API coverage |
| 13 | Solution shall support API authentication (JWT, API keys) | PC | JwtService.cs + ApiKeyEndpoints.cs |
| 14 | Solution shall support Windows Authentication for API interactions |  |  |
| 15 | Solution shall support API versioning | PC | All endpoints under /api/v1/ |
| 16 | Solution shall support API documentation (Swagger/OpenAPI) | PC | Program.cs — Swagger/OpenAPI enabled |
| 17 | Solution shall support API rate limiting | PC | Rate limiting middleware on auth endpoints |

## Audit (24 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall support immutable audit logs | PC | AuditService.cs — hash-chained audit entries, tamper detection |
| 2 | Solution shall support audit log retention policy | PC | RetentionPolicyService.cs — configurable retention |
| 3 | Solution shall support audit log export | PC | AuditEndpoints.cs — CSV/PDF export |
| 4 | Solution shall support audit log search | PC | AuditEndpoints.cs — full-text + filter search |
| 5 | Solution shall support audit log filtering | PC | AuditEndpoints.cs — filter by user/device/date/type |
| 6 | Solution shall support audit log forwarding to SIEM | PC | SiemForwarderService.cs — SIEM forwarding |
| 7 | Solution shall support audit log integrity verification | PC | AuditService.cs — SHA-256 hash chain verification |
| 8 | Solution shall support audit log encryption | PC | AuditService.cs — encrypted audit entries at rest |
| 9 | Solution shall support audit log backup | PC | BackupService.cs — audit log backup included |
| 10 | Solution shall support audit log alerting |  |  |
| 11 | Solution shall support audit log compliance reports | PC | Reports.razor — compliance audit report |
| 12 | Solution shall support user session audit | FC | AuditService.cs — full session audit |
| 13 | Solution shall support command execution audit | FC | AuditService.cs — all commands logged |
| 14 | Solution shall support file transfer audit | PC | AuditService.cs — SFTP transfer audit |
| 15 | Solution shall support password change audit | FC | AuditService.cs — all password changes logged |
| 16 | Solution shall support admin action audit | FC | AuditService.cs — all admin actions with user/IP |
| 17 | Solution shall support configuration change audit | PC | AuditService.cs — config change events |
| 18 | Solution shall support approval workflow audit | PC | AuditService.cs — approval events |
| 19 | Solution shall support login/logout audit | FC | AuditService.cs — all auth events |
| 20 | Solution shall support MFA audit | PC | AuditService.cs — MFA challenge/response events |
| 21 | Solution shall support access policy audit | PC | AuditService.cs — policy enforcement events |
| 22 | Solution shall support key management audit | PC | AuditService.cs — key rotation/generation events |
| 23 | Solution shall support tamper-proof audit log | PC | AuditService.cs — SHA-256 hash chain, tamper-detection |
| 24 | Solution shall support audit log archiving | PC | RetentionPolicyService.cs — archive to cold storage |

## Direct Access Management (11 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall support TACACS+ server for direct access to network devices | FC | OrkunPAM.TacacsProxy — built-in TACACS+ server, RFC 1492, TCP :49 (#111) |
| 2 | Solution shall support RADIUS server for direct access to network devices | FC | OrkunPAM.TacacsProxy — built-in RADIUS server, RFC 2865, UDP :1812/:1813 (#111) |
| 3 | Solution shall support TACACS+ authentication | FC | TacacsAuthHandler.cs — auth/authz/accounting complete (#111) |
| 4 | Solution shall support RADIUS authentication | FC | RadiusHandler.cs — PAP/CHAP/PEAP auth (#111) |
| 5 | Solution shall support TACACS+ authorization | FC | TacacsAuthorizationHandler.cs — per-command authorization (#111) |
| 6 | Solution shall support RADIUS accounting | FC | RadiusAccountingHandler.cs — Start/Stop/Interim-Update (#111) |
| 7 | Solution shall support TACACS+ accounting | FC | TacacsAccountingHandler.cs — full accounting (#111) |
| 8 | Solution shall support RADIUS MFA | FC | RadiusHandler.cs — TOTP RADIUS MFA (#111) |
| 9 | Solution shall support TACACS+ encryption | FC | TacacsEncryption.cs — TACACS+ MD5 obfuscation (#111) |
| 10 | Solution shall support RADIUS shared secret validation | FC | RadiusHandler.cs — NAS shared secret validation (#111) |
| 11 | Solution shall support device group-based TACACS+/RADIUS policy | PC | TacacsAuthorizationHandler.cs — group-based policy rules (#111) |

## Operation&Maintenance (14 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Summary charts and detailed CPU performance trends, memory and disk utilization trends shall be available for every inst |  |  |
| 2 | Solution  shall monitor the status of its services and provide monitoring screen to observer the latest status. |  |  |
| 3 | Solution shall support creating alarms and thresholds for following up the system status |  |  |
| 4 | Solution shall send email notifications where a defined threshold is exceeded. For eg: if CPU utilization goes beyond %6 |  |  |
| 5 | All alarms shall be available in a monitoring screen. Users shall filter by instance,severity,IP,status and creating tim |  |  |
| 6 | Solution shall support sending alarms via email with importance flags. |  |  |
| 7 | User shall send alarms to email recipients or clear alarms on alarm monitoring screen. |  |  |
| 8 | Solution shpuld provide a system log viewer to monitor logs created by the solution., |  |  |
| 9 | Ssystem logs shall logs for each component of the solution. |  |  |
| 10 | Solution shall enable changing system log levels. |  |  |
| 11 | Solution shall have upgrade procedures |  |  |
| 12 | Solution shall provide a scheduled backup capability for archiving configuration and logging data | PC | BackupService.cs — Hangfire-scheduled backup for config and log data (#55) |
| 13 | Solution shall provide granular backup and restoration capabilities for critical system components to improve disaster r | PC | BackupService.cs — granular restore: DB, vault keys, config components, AES-256-GCM encrypted (#55) |
| 14 | Solution shall support enriched reporting dashboards for monitoring operational statistics, including session activity a | PC | Reports.razor + Dashboard.razor — session activity and operational stats monitoring (#27) |