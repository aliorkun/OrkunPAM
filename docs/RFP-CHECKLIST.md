# PAM RFP Template - Compliance Checklist

> Auto-generated from PAM Template.xlsx. PM Agent uses this for feature gap analysis.
> Status: FC=Fully Compliant, PC=Partially Compliant, NC=Not Compliant

## Platform (44 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall support appliance base installation |  |  |
| 2 | Solution shall support Vmware and Hyper-V based installation |  |  |
| 3 | Solution shall be deployable On‐Premise and provided as a cloud  offering. |  |  |
| 4 | Solution shall support agent-less architecture. No additional software agent shall be required to install on devices, se |  |  |
| 5 | Solution GUI shall run with updated version of well-known browsers (i.e. Microsoft Edge, Google Chrome, Firefox, Safari) |  |  |
| 6 | Solution shall support SSO (Single-Sign-On) |  |  |
| 7 | Solution shall support both CLI and web interfaces |  |  |
| 8 | Solution shall support SAML authentication for secure portal access to PAM platform |  |  |
| 9 | Solution shall support SAML provider configuration on a per-tenant basis, allowing separate identity provider settings f |  |  |
| 10 | Solution shall support Public Key Infrastructure (PKI) Authentication for secure portal access using digital certificate |  |  |
| 11 | Solution shall support Windows Authentication for secure portal access |  |  |
| 12 | Solution shall have out of the box management capability for network devices and systems (Juniper, Cisco IOS, Cisco IOS- |  |  |
| 13 | Solution shall support adapting to different brand/model devices and systems, which will be used in the future. |  |  |
| 14 | Solution shall have out of the box support for script usage on NAS devices. |  |  |
| 15 | Solution shall support users to change their passwords and force to create the passwords in a complex way as well as cha |  |  |
| 16 | Solution shall support to be scaled to serve a carrier grade number of devices and users besides redundancy which lets 9 |  |  |
| 17 | Solution shall support to active-active redundancy. |  |  |
| 18 | Solution shall support disaster recovery. |  |  |
| 19 | Solution shall support different software versions of a network device simultaneously. |  |  |
| 20 | Solution software shall support working on industry standard operating systems such as Unix, Linux, etc. |  |  |
| 21 | Solution shall be able to work on only one server for minimal installation. |  |  |
| 22 | Solution shall support to keep logs and video records on different database with required configuration. |  |  |
| 23 | Solution shall support also support expansion by adding new server(s) to the related layer to increase capacity. Existin |  |  |
| 24 | Solution shall support hierarchical user grouping structure. |  |  |
| 25 | Solution shall support hierarchical device grouping structure. |  |  |
| 26 | Solution shall support hierarchical grouping structure for administrators. |  |  |
| 27 | Solution shall support business and operational model of managed service providers |  |  |
| 28 | Solution shall support business and operational model of geographically distributed organizations |  |  |
| 29 | Solution shall support a controller layer above of the geographically distributed organizations . Solution shall support |  |  |
| 30 | All the audits and control activities shall be managed by controller layer in a geographically distributed implementatio |  |  |
| 31 | In a geographically distributed implementation each location shall be run indepently  in a possible network service outa |  |  |
| 32 | In a geographically distributed implementation the controller layer shall support centrally controller screens to monito |  |  |
| 33 | Solution shall have multi-language support |  |  |
| 34 | Solution shall support to limit the screens that a user can see |  |  |
| 35 | Solution shall support preventing users to see the rights assigned to them. |  |  |
| 36 | Solution shall have a  break-the-glass procedure to a bypass the PAM solution in emergency situations. |  |  |
| 37 | Solution shall have enhanced break the glass procedure so that credentials shall be restored without restoring the entir |  |  |
| 38 | Solution shall support granular backup and restoration capabilities to improve disaster recovery and minimize downtime r |  |  |
| 39 | Solution shall support the customization of the login screen background and logo to align with organizational branding. |  |  |
| 40 | Solution shall support Windows or Kerberos Authentication for API interactions to enhance security and interoperability. |  |  |
| 41 | Solution shall provide System Information menu to show system version and other system details |  |  |
| 42 | Solution support limiting the System Information menu to authorized users to restrict access to sensitive configuration  |  |  |
| 43 | Solution shall provide enriched statistical data on the main dashboard, including user-related access and activity repor |  |  |
| 44 | Solution shall support granular role-based access control for PAM portal menus and features |  |  |

## Integration (46 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall support plug & play integration with the Active Directory/LDAP servers |  |  |
| 2 | Solution's Active Directory Integration must allow for a configurable  synchronization schedule to automate onboarding n |  |  |
| 3 | Solution shall support integration with Active Directory for improved device importing, including enhancements for devic |  |  |
| 4 | Solution shall support  users to login with username@domain, if there is multi ldap integration. |  |  |
| 5 | Solution shall offer an extensive web services API with create, read,  update, and delete functions. |  |  |
| 6 | Solution's web services API use must be auditable by the PAM  Solution. |  |  |
| 7 | Solution shall support restful API’s to CRUD for User/Device/Policy/Secret |  |  |
| 8 | Solution shall support restful API’s to Lock/Unlock for Users |  |  |
| 9 | Solution shall support restful API’S to integrate any ITSM systems (ticketing systems)  (ServiceNow, OneDesk etc.) |  |  |
| 10 | Solution shall support SAML Authentication for both SP-initiated and IdP-initiated authentication requests |  |  |
| 11 | Solution shall support syslog integration with SIEM systems |  |  |
| 12 | Solution shall support integration with SIEM systems in CEF and Key-Value formats for improved log management and extern |  |  |
| 13 | Solution shall support SNMP integration with OSS/NMS systems |  |  |
| 14 | Solution shall support Windows Authentication |  |  |
| 15 | Solution shall support integration with  CMDB/Asset management system for onboarding devices and device group hierarchie |  |  |
| 16 | Solution shall support automatic device discovery and updates from an external Device/Asset management system |  |  |
| 17 | Solution shall support automatic device discovery by searching given subnets |  |  |
| 18 | Solution shall support importing devices from cloud service providers like AWS, Azure and GCP |  |  |
| 19 | Solution shall allow system administrators to configure enhanced element type information retrieval via OS tags during d |  |  |
| 20 | Solution shall support SMPP integration with OSS Systems |  |  |
| 21 | Solution shall support ready-to use plugins for DevOps platforms (Jenkins and Kubernetes) |  |  |
| 22 | Solution shall integrate with VMware for automatic and regular import of virtual servers into the system for streamlined |  |  |
| 23 | Solution shall support enriched dashboard reporting with additional statistical data and device import logs for better m |  |  |
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

## Security (54 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall support security of network elements and itself on highest level. |  |  |
| 2 | Solution shall support forcing users to create passwords less/more than a specific character number. |  |  |
| 3 | Solution shall support preventing usage of expired passwords. |  |  |
| 4 | Solution shall support creating passwords in a pre-defined complexity. |  |  |
| 5 | Solution shall support forcing the users to change their passwords after created by the Admin user. |  |  |
| 6 | Solution shall support locking the user accounts of which password was not changed in the defined period of time. |  |  |
| 7 | Solution shall support sending e-mail in case of a password expiry. |  |  |
| 8 | Solution shall support locking the user accounts of which were not used in a specific period of time(inactive user). |  |  |
| 9 | Solution shall support terminating the idle sessions which are not used in a specific period of time. |  |  |
| 10 | Solution shall support configuration of the number of maximum login failures. |  |  |
| 11 | Solution shall support blocking the user account for a configurable duration after a configurable number of login failur |  |  |
| 12 | Solution shall support creation of alarm messages after a configurable number of login failure. |  |  |
| 13 | Solution shall support restricting admin user logins by IP address, preventing logins from unauthorized IP addresses. |  |  |
| 14 | User Accounts (Usernames and encrypted passwords) can only be managed by the admin privileged users. |  |  |
| 15 | All sensitive data stored within the PAM system must be encrypted in transit and at rest. Encryption mechanism shall sup |  |  |
| 16 | The cryptographic keys that are used to encrypt and decrypt the data within the solution must be backed-up and stored in |  |  |
| 17 | Data encryption key shall be generated during runtime with complex key generation function |  |  |
| 18 | Solution shall support to change the keys used in encryption and entered by the customer during installation, when neede |  |  |
| 19 | Solution should use the SSL encrypted communication between the application and database itself |  |  |
| 20 | Solution shall support TLS v1.3. |  |  |
| 21 | Solution shall provide enhanced logging for policy-related actions, including granular details for better auditing and s |  |  |
| 22 | Solution shall support notifications for administrators when recorded sessions are replayed to enhance user activity mon |  |  |
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
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

## User Management (47 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall have internal(local) user management module and support manual user management. |  |  |
| 2 | Solution shall support self registration of new user requests with manager approval. |  |  |
| 3 | Solution shall support automaticaly user/user groups synchronization with Active Directories |  |  |
| 4 | Solution shall support temporary users, which are active for a limited period of time and de-active automatically. |  |  |
| 5 | Solution shall support grouping of the users. |  |  |
| 6 | Solution shall support defining the admin or manager of the user group |  |  |
| 7 | Solution shall support multi domain active directories or forest structure |  |  |
| 9 | Solution shall support Admin users to assign additional roles to user groups |  |  |
| 10 | Solution shall support Admin users to delete role definitions. |  |  |
| 11 | Solution shall support Admin users to change (adding or deleting authorization) defined roles. |  |  |
| 12 | Solution shall support creating bulk users automatically such as importing from a file |  |  |
| 13 | Solution shall support locking all the users in a group and removing the all of the locked users. |  |  |
| 14 | Solution shall support locking user after a configurable inactivity period |  |  |
| 15 | Solution shall support changing parameters and values for all of the users in a group. |  |  |
| 16 | Solution shall support to force changing passwords of all of the users in a group on the next login. |  |  |
| 17 | Solution shall be able to list active users . |  |  |
| 18 | Solution shall support secondary password management as a configurative an optional |  |  |
| 19 | Admin user shall have the right to reset the other users’ passwords. When the password is reset, an e-mail shall be sent |  |  |
| 20 | Solution shall have configurable password strength settings |  |  |
| 21 | Solution shall support enriched approval request information, including detailed start and expiration times for enhanced |  |  |
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
|  |  |  |  |

## Reporting (46 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall have a dashboard to monitor successful authentications per user and device on a daily bases. |  |  |
| 2 | Solution shall have a dashboard to monitor successful sessions per user and device on a daily bases. |  |  |
| 3 | Solution shall have a dashboard to monitor failed authentications per user and device on a daily bases. |  |  |
| 4 | Solution shall have a dashboard to monitor blocked command per user and device daily bases. |  |  |
| 5 | Solution shall have a dashboard to monitor policy realms |  |  |
| 6 | Solution shall have a dashboard to monitor the activities taken on Solution itself. (User creation,deletion, policy chan |  |  |
| 7 | Solution shall have a dashboard to displays information on which passwords are  rotated and by who. Also, dashboard shal |  |  |
| 8 | Solution shall have view, filter and export functionality for each type of session, activity log and user dashboards.  |  |  |
| 9 | Solution shall have flexibility of exporting reports to CSV and PDF format.  |  |  |
| 11 | The solution shall provide a comprehensive audit-trail and reporting for the privileged access. It shall also provide an |  |  |
| 12 | Solution shall support Windows Local Users Audit Report feature. |  |  |
| 13 | Soluiton shall support to audit Windows target systems to create report to list local user accounts, service accounts an |  |  |
| 14 | Solution shall support Linux Local Users Audit Report feature. |  |  |
| 15 | Solution shall support reporting of users' SSH keys in Linux Audit Reports for enhanced credential management visibility |  |  |
| 16 | Solution shall support to report the last login dates, password ages, and account types of the accounts detected on the  |  |  |
| 17 | Solution shall support flagging accounts previously added to passord vault in Windows and Linux local account reports. |  |  |
| 18 | Solution shall allow users to create their own reports and dashboards. |  |  |
| 19 | Solution shall have out of box dashboards for ease of use. Such as access violation dashboard, session and authenticatio |  |  |
| 20 | Solution shall provide role management for reporting module. |  |  |
| 21 | Solution shall support implicit Filter feature. Whenever user creates a new report,it shall run based on the profile of  |  |  |
| 22 | Solution shall support PDF and CSV export of scheduling dashboards/charts. |  |  |
| 23 | Solution shall enable users to schedule created reports to receive automated emails. |  |  |
| 24 | Solution shall provide ready to use dashboards for Compliancies |  |  |
| 25 | Solution shall support listing and reporting AWS , Azure and GCP IAM accounts, virtual machines and managed database and |  |  |
| 26 | Solution shall support listing and reporting security advices for AWS , Azure and GCP IAM accounts, virtual machines and |  |  |
| 27 | Solution shall support enriched reporting dashboards that are dynamically filtered based on user authorization levels. |  |  |
| 28 | Solution shall support customizable dashboards to monitor user session data, including session start and end times, appr |  |  |
| 29 | Solution shall support session replay activity reports, providing visibility into sessions that were accessed or reviewe |  |  |
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

## Session Manager (162 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | General | Solution shall support MFA (Multi Factor Authentication) when a user attempts to open a CLI/RDP/HTTP/SFTP/SQL sessions t |  |
| 2 | General | Solution shall support SSL protocol for network management and terminal (console) servers. |  |
| 3 | General | Solution shall support using TELNET, STELNET, SSH, VNC, RDP, HTTP, HTTPS protocols to login to end devices. |  |
| 4 | General | Solution shall be able to manage and interact with multiple remote sessions  for both Remote Desktop Protocol (RDP) ,SSH |  |
| 5 | General | Solution shall be able to launch and configure sessions across multiple  environments with credentials automatically inj |  |
| 6 | General | Solution shall support native CLI clients like SecureCRT, Putty, MobaXterm etc. |  |
| 7 | General | Solution shall support SSH and RDP connections to target servers from any device without any native client or agent inst |  |
| 8 | General | Solution shall support double confirmation of execution of the command that can cause a service interrupt or any request |  |
| 9 | General | Solution shall support geofence validation through mobile application for the command executions. |  |
| 10 | General | Solution shall support duration based restriction policy for the sessions |  |
| 11 | General | Solution shall have a connection reservation functionalty for future date connections |  |
| 12 | General | Solution shall support to open SSH/RDP/HTTP sessions via desktop application on user workstation (without logging into P |  |
| 13 | General | Solution shall support to log users' client IP addresses even if users access the Web GUI through the loadbalancer. |  |
| 14 | General | Solution shall support to use its own secure tunnel (connector) to connect to target devices located in remote data cent |  |
| 15 | General | Solution shall support users to create a connection reservation request for a future date and get administrator approval |  |
| 16 | General | Solution shall support expiration of connection reservation requests that are not approved/devied for a certain period o |  |
| 17 | General | Solution shall support administrators to change the selected date/time during connection request approval. |  |
| 18 | General | Solution shall allow connections to target Linux/Unix and Windows systems by entering IP addresses, restricted on a subn |  |
| 19 | General | Solution shall support setting a minimum character limit for the "connection reason" field for SSH/Telnet and RDP/VNC co |  |
| 20 | General | Solution shall automatically terminate sessions when their reserved end time expires to prevent unauthorized extended ac |  |
| 21 | General | Solution shall support dismissal of warning messages in the Wire-to-Session feature to improve user experience and reduc |  |
| 22 | General | Solution shall support assinged credentials with a validity date range for temporary access management to enhance securi |  |
| 23 | Policy Enforcement | Solution shall support granting access rights and authorization according to target device group, user group and specifi |  |
| 24 | Policy Enforcement | Solution shall support policy enforcement rules to be syncronized with NMS/EMS (Nokia 5620 SAM, Huawei U2000, Juniper Ma |  |
| 25 | Policy Enforcement | Solution shall support administrator level users to see the rights assigned to themselves and other users. |  |
| 26 | Policy Enforcement | Solution shall support authorizing the users on the devices they accessed by blocking and enabling the “specific” CLI co |  |
| 27 | Policy Enforcement | Solution shall support the policies that is used for enabling or preventing the commands which the users can execute on  |  |
| 28 | Policy Enforcement | Solution shall support managing different privileged accounts for user groups on target servers. |  |
| 29 | Policy Enforcement | Solution shall support listing all the users assigned to a role (privilege level). |  |
| 30 | Policy Enforcement | Solution shall support the capability to request access to more than one privileged account and allow the user to choose |  |
| 31 | Policy Enforcement | Solution shall support executing commands/scripts in the background before the user's SSH/Telnet session starts. These s |  |
| 32 | Policy Enforcement | Solution shall support SSH Key forwarding with the SSH-agent feature when connecting to the target device via SSH protoc |  |
| 33 | Policy Enforcement | Solution shall support to restrict the number of concurrent sessions that a user can initiate. |  |
| 34 | Context Aware Enforcement | Solution shall support “context-aware” privilege management on CLI commands. For example, allow “disable” command for in |  |
| 35 | Session Monitoring | Solution shall support listing of active CLI, RDP/VNC sessions from the web-GUI by the privileged users. |  |
| 36 | Session Monitoring | Solution shall support real-time monitoring of an active CLI/RDP session from the web-GUI by the privileged users(Suppor |  |
| 37 | Session Monitoring | Solution shall support session take-over and session-leave functionality by the privileged users on active CLI/RDP sessi |  |
| 38 | Session Monitoring | Solution shall support to terminate active user sessions one by one or all together. |  |
| 39 | Session Monitoring | Solution shall support send messages to active CLI/RDP sessions. |  |
| 40 | Session Monitoring | Solution shall support send messages to active Web GUI Sessions |  |
| 41 | Session Monitoring | Solution shall support authentication policy tracking per user to monitor operators’ access rights. |  |
| 42 | Session Monitoring | Solution shall support authorization policy tracking per user to monitor policy enforcement rules. |  |
| 43 | Session Monitoring | Solution shall support to monitor command violations. |  |
| 44 | Session Monitoring | Solution shall support to monitor successful commands besides commands forbidden due to policy enforcement. |  |
| 45 | Managerial Approval/Aware | Solution shall support managerial approval request via email/mobile push notification to execute specific CLI commands ( |  |
| 46 | Managerial Approval/Aware | Solution shall support managerial approval request via email/mobile push notification while connecting devices. |  |
| 47 | Managerial Approval/Aware | Solution shall support managerial approval request via SMS |  |
| 48 | Managerial Approval/Aware | If any user runs a command which is out of his/her privilege level, the system shall send an e-mail to that user and use |  |
| 49 | Managerial Approval/Aware | Solution shall support sending push-notifications to the mobile users for managerial approval scenarios |  |
| 50 | Managerial Approval/Aware | Solution shall support managerial approval definition by user group and device group level |  |
| 51 | Managerial Approval/Aware | Solution shall support multil-level approval workflows. Number of approval levels shall be customized per approval workf |  |
| 52 | Managerial Approval/Aware | Solution shall enable users to see the progress for a multi-level approval workflow so that user will have information o |  |
| 53 | Managerial Approval/Aware | Solution shall support to void or escalate administrator approval requests that have not been approved for a certain per |  |
| 54 | Maintenance Mode | Solution shall support the maintenance window activities to be done just in the defined time frame with only the privile |  |
| 55 | Maintenance Mode | Solution shall support operational and maintenance mode (Specific Date&Time Frame) of the devices. |  |
| 56 | Maintenance Mode | Solution shall support to force choosing the maintenance mode users and prevent other users to login during maintenance  |  |
| 57 | Maintenance Mode | Solution shall support to terminate all active connections automatically on network elements when the maintenance mode s |  |
| 58 | Logging | Session and command logs shall include the name of the device, IP address, the command that is run, date/time. |  |
| 59 | Logging | The text-based session log files can be downloaded in text .csv and .xls formats. |  |
| 60 | Logging | Solution shall support logging the access times and durations to the web GUI. |  |
| 61 | Logging | Solution shall support video-like replay of text-based commands of the CLI session logs. These video logs shall contain  |  |
| 62 | Logging | Solution shall support the logs inspection and classification functionality. |  |
| 63 | Logging | Solution shall support command and session based search functionality of session logs. |  |
| 64 | Logging | Solution shall support periodic archiving of the log files by the system administrator. |  |
| 65 | Logging | Solution shall support manual and automatic archiving. |  |
| 66 | Logging | All session logs shall be stored for at least 6 months and shall include session identifier, session time, client IP add |  |
| 67 | Logging | Users who wire into sessions shall also be logged in session logs |  |
| 68 | Logging | Solution shall have tamper proof logging capability to prevent and capture any modification or deletion of a log record  |  |
| 69 | Logging | Solution shall tag any modified log record as "Tampered"  |  |
| 70 | Logging | Solution shall support sending notification to administrators when a recorded session replayed |  |
| 71 | User Behavior Analytics | Solution shall provide a comprehensive threat intelligence module to identify potential insider threats. |  |
| 72 | User Behavior Analytics | Solution shall support real-time monitoring and analysis of privileged user behavior to detect anomalies. |  |
| 73 | User Behavior Analytics | Solution shall include advanced machine learning algorithms for detecting unusual activity patterns. |  |
| 74 | User Behavior Analytics | Solution shall support customizable rules for alerting based on user activity and thresholds. |  |
| 75 | User Behavior Analytics | Solution shall support user-based anomaly detection from user session logs. |  |
| 76 | User Behavior Analytics | Solution shall provide risk scoring based on behavioral patterns and policy violations. |  |
| 77 | User Behavior Analytics | Solution shall support to classify the detected anomalies according to their risk scores and severity. |  |
| 78 | User Behavior Analytics | Solution shall support taking automatic action against detected anomalies based on their risk scores and severity. |  |
| 79 | User Behavior Analytics | Solution shall support sending alarm for detected anomalies to system admins. |  |
| 80 | User Behavior Analytics | Solution shall support the visualization of user activity through dashboards for quick threat assessment. |  |
| 81 | RDP | Solution shall support RDP (Remote Desktop Protocol - GUI) connections |  |
| 82 | RDP | Solution shall support simultaneous connection of two users to same RDP session. |  |
| 83 | RDP | Solution shall support "take control" option for admin users on active RDP connections |  |
| 84 | RDP | Solution shall support "Kill" option for active connections |  |
| 85 | RDP | Solution shall support "Send Message" option to active connections over RDP connections |  |
| 86 | RDP | Solution shall support RDP connections which permits to reach only allowed applications |  |
| 87 | RDP | Solution shall support execution of remote application with parameters |  |
| 88 | RDP | Solution shall support execution of automation scripts to automate desktop applications |  |
| 89 | RDP | Solution shall support auto-login to the remote applications in RDP Single Application connections. |  |
| 90 | RDP | Solution shall support auto-login to remote apps with different account types. SAPM, SDV, AD, Local |  |
| 91 | RDP | Solution shall support approval mechanisim for auto-login to remote applications for different account types. |  |
| 92 | RDP | Solution shall support using credentials from another Active Directory (AD) while PAM user belongs to different AD in RD |  |
| 93 | RDP | Solution shall support least privilege capability for the applications on Windows Servers in RDP Session |  |
| 94 | RDP | Solution shall support NLA(Network Level Authentication) for RDP connection. |  |
| 95 | RDP | Solution shall support file transfer between endpoints in RDP connections. |  |
| 96 | RDP | Solution shall support configuring users/user groups to allow/deny file transfer and enabling/disabling clipboard in RDP |  |
| 97 | RDP | Solution shall support enabling/disabling the clipboard separately for inbound and outbound Windows RDP sessions. |  |
| 98 | RDP | Solution shall support changing Resolution, Keyboard Layout, Color Dept on active RDP connections to end users |  |
| 99 | RDP | Solution shall support applying default RDP connection configurations, identified according to  requirment, globally to  |  |
| 100 | RDP | Solution shall support idle timeout configuration for RDP connecitons |  |
| 101 | RDP | Solution shall support session timeout configuration for RDP connections |  |
| 102 | RDP | Solution shall support MFA functionality to connect RDP devices.  |  |
| 103 | RDP | Solution shall support Reason Required Field to connect RDP devices.  |  |
| 104 | RDP | Solution shall support Legal Disclaimer Message while connecting RDP Devices |  |
| 105 | RDP | Solution shall support printer sharing of RDP connections |  |
| 106 | RDP | Solution shall support speaker sharing of RDP connections |  |
| 107 | RDP | Solution shall support filesharing on an RDP session |  |
| 108 | RDP | Solution shall support video recording of RDP sessions |  |
| 109 | RDP | Solution shall support re-playing of recorded RDP sessions |  |
| 110 | RDP | Solution shall support downloading of recorded RDP sessions video file. |  |
| 111 | RDP | Solution shall support key-logging in RDP sessions |  |
| 112 | RDP | Solution shall support searching functionality among the key-logging logs in RDP sessions |  |
| 113 | RDP | Solution shall support OCR (Optical Character Recognition) in RDP sessions |  |
| 114 | RDP | Solution shall support configuration of OCR sensitivity |  |
| 115 | RDP | Solution shall support displaying a Watermark containing user information on RDP connections to target systems. |  |
| 116 | RDP | Solution shall support masking of text transferred via the clipboard to prevent data leakage |  |
| 117 | VNC | Solution shall support VNC (Virtual Network Computing - GUI) connections |  |
| 118 | VNC | Solution shall support to open an VNC session directly from user's desktop (without logging into Web GUI) |  |
| 119 | VNC | Solution shall support video recording of VNC sessions |  |
| 120 | VNC | Solution shall support re-playing of recorded VNC sessions |  |
| 121 | VNC | Solution shall support key logging in VNC sessions |  |
| 122 | VNC | Solution shall support OCR (Optical Character Recognition) in VNC sessions |  |
| 123 | SFTP | Solution shall support SFTP connections |  |
| 124 | SFTP | Solution shall support global user and ssh key combination for SFTP connections. |  |
| 125 | SFTP | Solution shall support logging the access times and durations to SFTP connections |  |
| 126 | SFTP | Solution shall support logging commands in SFTP connections |  |
| 127 | SFTP | Solution shall support managerial approval for SFTP proxy connections. |  |
| 128 |  | Solution shall support MFA functionality for SFTP proxy connections. |  |
| 129 | SFTP | Solution shall support time limitation for sending managerial approval emails for SFTP proxy connections. |  |
| 130 | HTTP/HTTPS | Solution shall support HTTP/HTTPS connections |  |
| 131 | HTTP/HTTPS | Platfrom shall support digest authentication for HTTP/HTTPS connections. |  |
| 132 | HTTP/HTTPS | Solution shall support auto login to HTTP/HTTPS web applications |  |
| 133 | HTTP/HTTPS | Solution shall support logging of HTTP/HTTPS messages |  |
| 134 | HTTP/HTTPS | Solution shall support policy enforcement on HTTP/HTTPS sessions (blocking URLs for specific user groups etc.) |  |
| 135 | HTTP/HTTPS | Solution shall support managerial approval for HTTP/HTTPS proxy connections. |  |
| 136 | HTTP/HTTPS | Solution shall support MFA (2 Factor authentication) for HTTP/HTTPS proxy connections. |  |
| 137 | HTTP/HTTPS | Solution shall support to log user's client IP addresses even if users access target web application through HTTPS Proxy |  |
| 138 | HTTP/HTTPS | Solution shall support to record all HTTPS activities in pass-through mode without applying the policy. |  |
| 139 | HTTP/HTTPS | Solution shall support auto-login to target web applications that use XHR requests. |  |
| 140 | HTTP/HTTPS | Solution shall support connecting to target web applications that support TLS v1.3 via HTTPS Proxy. |  |
| 141 | HTTP/HTTPS | Solution shall support video recording of HTTPS Proxy sessions to web applications without the need for any jump server. |  |
| 142 | HTTP/HTTPS | Solution shall support listing the web applications that users have permission to access on the HTTP Proxy login page, s |  |
| 143 | Auto Login | Solution shall support multi-user option for remote applications auto-login. |  |
| 144 | SSH Keys | Solution shall support SSH-Keys while login to devices. |  |
| 145 | SSH Keys | Solution shall support forcing users to use SSH keys and password authentication at the same time. |  |
| 146 | Remote Access | Solution shall support secure remote access using encrypted SSL/TLS protocols. |  |
| 147 | Remote Access | Solution shall support remote access for a user only to authorized devices and only during permitted time periods. |  |
| 148 | Remote Access | Solution shall support remote access, allowing users to connect to target devices without needing to install any agents  |  |
| 149 | Remote Access | Solution shall support remote access for users via a temporary connection link. |  |
| 150 | Remote Access | Solution shall provide just-in-time access capabilities for minimizing attack surfaces during remote access. |  |
| 151 | Remote Access | Solution shall support users to log in with MFA along with username and password for remote access. |  |
| 152 | Remote Access | Solution shall support the installation of the remote access portal on a public or private cloud. |  |
| 153 | Remote Access | Solution shall provide session recording and playback for all remote access sessions. |  |
| 154 | Remote Access | Solution shall provide detailed audit trails of commands and actions executed during remote sessions. |  |
| 155 | Remote Access | Solution shall support session shadowing for real-time supervision and intervention for remote access sessions |  |
| 156 | Remote Access | Solution shall support session termination and the ability to send messages to active remote sessions |  |
| 157 | Remote Access | Solution shall allow auditing and reporting of all remote access activities. |  |
| 158 | Remote Access | Solution shall allow administrators to define and enforce time-based restrictions for remote access. |  |
| 159 | Remote Access | Solution shall enable administrators to grant or revoke remote access dynamically without service interruption. |  |
| 160 | Remote Access | Solution shall offer seamless integration with privileged access workflows for end-to-end session lifecycle management. |  |
|  |  |  |  |
|  |  |  |  |

## Password Vault (92 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | General | Solution shall support password management of Linux/Unix, Windows OS, databases, network elements, LDAP, Active Director |  |
| 2 | General | Solution shall support to manage Windows Local accounts using Active Directory domain admin accounts. |  |
| 3 | General | Solution shall support password management of users accounts on NMS/EMS (Nokia 5620 SAM, Huawei U2000, Juniper Managemen |  |
| 4 | General | Solution shall support password management of Web applications' password |  |
| 5 | General | Solution shall support managing privileged accounts on the cloud service provider, such as AWS IAM accounts. |  |
| 6 | General | Solution shall support managing API access keys on the cloud service provider, such as AWS API Access Key/Secrets. |  |
| 7 | General | Solution shall support managing secrets/passwords stored within configuration files |  |
| 8 | General | Solution shall support all functionalities without any agent to be installed on target server(agentless) |  |
| 9 | General | Solution shall support storing files in the password vault. |  |
| 10 | General | Solution shall support storing passwords for files stored in the password vault. |  |
| 11 | General | Solution shall support to store password with AES 256 encryption. |  |
| 12 | General | Solution shall support to store encryption keys on Hardware Security Module (HSM) devices |  |
| 13 | General | Solution shall support SSH-Key Management for RSA and OpenSSH key formats |  |
| 14 | General | Solution shall support auto-detection and onboarding of Windows  Local User & Administrative Accounts |  |
| 15 | General | Solution shall support auto-detection and onboarding of Linux Local User & Administrative Accounts |  |
| 16 | General | Solution shall support auto-detection and onboarding of Unix Local Users & Administrative Accounts  |  |
| 17 | General | Solution shall support devices which are in public or private cloud (Amazon, Azure, GCP etc) |  |
| 18 | General | Solution shall support bulk import of devices. |  |
| 19 | General | Solution shall enable configurable Auto discovery of both public and private interfaces on Cloud IaaS |  |
| 20 | General | Solution shall support automatic device updates from public or private cloud environments. |  |
| 21 | General | Solution shall support bulk import of privileged accounts |  |
| 22 | General | Solution shall support bulk reset of privileged passwords |  |
| 23 | General | Solution shall support to delete new users on target devices when discovered. |  |
| 24 | General | Solution shall support logging details of new user when discovered |  |
| 25 | General | Solution shall report the status of new discovered accounts to inform administrators on whether or not they are managed  |  |
| 26 | General | Solution administrator shall not be able to view the passwords for privileged accounts |  |
| 27 | General | Solution shall have roles and capabilities for secret management such as admin user,normal user, end user and auditor us |  |
| 28 | General | Solution shall be able to assign vaulted AD users  for authentication on target servers. |  |
| 29 | General | Solution shall support grouping of privileged accounts and secrets stored in the password vault. |  |
| 30 | General | Solution shall support to set permission on group level. |  |
| 31 | General | Solution shall support setting password requirements, including length and character types, for each account individuall |  |
| 32 | General | The solution shall support to check the validity of passwords periodically and to flag invalid passwords in the web inte |  |
| 33 | General | Solution shall support to manage the passwords of target devices located in remote data centers with the connector solut |  |
| 34 | General | Solution shall support to save notes for accounts and secrets stored in the managed password vault. |  |
| 35 | General | Solution shall support triggering password resets in bulk by selecting multiple privileged accounts. |  |
| 36 | General | Solution shall support bulk editing of accounts/secrets stored in the password vault. |  |
| 37 | General | Solution shall support the management of Azure Application Keys to securely store and manage credentials for Azure servi |  |
| 38 | General | Solution shall provide a password blacklist feature to warn users against selecting weak or commonly used passwords. |  |
| 39 | General | Solution shall support a Recycle Bin feature for account recovery, enabling the restoration of deleted accounts within a |  |
| 40 | General | Solution shall include a password generator to create complex passwords that meet defined security policies. |  |
| 41 | General | Solution shall support bulk deletion of configurations connected to Password Vault accounts when the accounts are delete |  |
| 42 | General | Solution shall allow manual password setting for Password Vault accounts, which can then be applied directly to target d |  |
| 43 | General | Solution shall support application triggers to sequentially restart Windows services to ensure system stability during p |  |
| 44 | General | Solution shall enable masking of passwords during bulk imports to enhance security and prevent sensitive data exposure. |  |
| 45 | One Time Password | Solution shall support one-time password (changing password after every checkout or changing password before checkout) |  |
| 46 | One Time Password | Solution shall support periodic password change interval, even if nobody use/change password. |  |
| 47 | One Time Password | Password change duration shall be configurable per privileged account. |  |
| 48 | One Time Password | Solution shall have an upper limit for password change duration. |  |
| 49 | One Time Password | Users can get password for a specific time duration. During this period, other users/applications cannot get the passwor |  |
| 50 | One Time Password | Users shall specify reason of taking one-time password. |  |
| 51 | Password Request | Solution shall support password reservation for future date with or without managerial approval. |  |
| 52 | Password Request | Solution shall support split password feature for password requests. |  |
| 53 | Password Request | Solution shall support password request via mobile application. |  |
| 54 | Password Request | Solution shall support managerial approval for password requests via email |  |
| 55 | Password Request | Solution shall support multi-level of managerial approval for password requests |  |
| 56 | Password Request | Solution shall  support administrators to approve or deny password access requests via mobile application and email. |  |
| 57 | Logging | Paltform shall support logging password related actions (retrieval, release, reset, comments, ownership modification) |  |
| 58 | Logging | Solution shall log the events for a specific account. (Add/delete to/from a user group) |  |
| 59 | Logging | Solution shall allow detailed logging of password usage for improved tracking and compliance reporting. |  |
| 60 | Email Notifications | Solution shall support to send email notification to admins when password seen by user. |  |
| 61 | Email Notifications | Solution shall support to send email notification to admins when when password reset fails. |  |
| 62 | Email Notifications | Solution shall support to send email notification to admins when password validation fails (password was changed. but no |  |
| 63 | Email Notifications | Solution shall support to send email notification to admins when new user found. |  |
| 64 | Email Notifications | Solution shall support to send email notification to admins when password retrieval requires manager approval. |  |
| 65 | Aplication to Aplication Password Manager | Solution shall support password managerment for application to application connection |  |
| 66 | Aplication to Aplication Password Manager | Solution shall support PIN code validation for the client application |  |
| 67 | Aplication to Aplication Password Manager | Solution shall support application path check and process validation for the client application |  |
| 68 | Aplication to Aplication Password Manager | Solution shall support hash-value validation for the client application |  |
| 69 | Aplication to Aplication Password Manager | Solution shall support secure Restful API to eleminate hard-coded, clear text credentials in configuration files and scr |  |
| 70 | Aplication to Aplication Password Manager | Solution shall support secure Restful API to retrieve passwords used by applications or scripts. |  |
| 71 | Aplication to Aplication Password Manager | Solution shall support responding password request in JSON format via Restful API. |  |
| 72 | Aplication to Aplication Password Manager | Solution shall support multi level authentications for Restful API to retrieve passwords used by applications or scripts |  |
| 73 | Aplication to Aplication Password Manager | Solution shall support checking a real-time shared PIN code in request of applications that are trying to fetch password |  |
| 74 | Aplication to Aplication Password Manager | Solution shall support checking hash and path of applications that are trying to fetch password through solution's Restf |  |
| 75 | Aplication to Aplication Password Manager | Solution shall support resetting password before the retrieval by client application |  |
| 76 | Aplication to Aplication Password Manager | Solution shall support restarting services and processes after a password that is used by these services and processes i |  |
| 77 | Aplication to Aplication Password Manager | Solution shall have predefined set of values for  application passwords' expiration time. |  |
| 78 | Aplication to Aplication Password Manager | Solution shall change passwords for web applications periodically |  |
| 79 | Aplication to Aplication Password Manager | Solution shall enable use of an  account by different Ips (applications) |  |
| 80 | Aplication to Aplication Password Manager | Solution shall be able to restrict the number of use per application account |  |
| 81 | Aplication to Aplication Password Manager | Solution shall be able to restrict the usage period per application account |  |
| 82 | Aplication to Aplication Password Manager | Solution shall be able to associate a single application account with multiple privileged user groups. |  |
| 83 | Aplication to Aplication Password Manager | Solution shall support updating passwords of Windows services |  |
| 84 | Aplication to Aplication Password Manager | Solution shall support updating passwords of Oracle Weblogic Platforms |  |
| 85 | Aplication to Aplication Password Manager | Solution shall include an RPS (Request per Second) limiter for Application Token Requests to manage server load and prev |  |
| 86 | Aplication to Aplication Password Manager | Solution shall support updating passwords of Jboss Aplication |  |
| 87 | Aplication to Aplication Password Manager | Solution shall support updating passwords of Windfly |  |
| 88 | Aplication to Aplication Password Manager | Solution shall support updating passwords of IBM WebSphere |  |
| 89 | Aplication to Aplication Password Manager | Solution shall support updating passwords of IIS Pool and IIS Anonymous accounts |  |
| 90 | Aplication to Aplication Password Manager | Solution shall support updating passwords of Windows Scheduled Task accounts |  |
| 91 | Aplication to Aplication Password Manager | Solution shall support updating passwords of Windows COM and DCOM accounts |  |
| 92 | Aplication to Aplication Password Manager | Solution shall support updating passwords of Windows Scheduled Task accounts |  |

## MFA Manager (51 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall support radius server with access challange functionality. |  |  |
| 2 | Solution shall support MFA (Multi Factor Authentication) online token generation for MFA. |  |  |
| 3 | Solution shall support MFA (Multi Factor Authentication) offline token generation for MFA. |  |  |
| 4 | Solution shall send QR codes to new onboarded users on PAM |  |  |
| 5 | Solution shall support to send MFA token via SMS. |  |  |
| 6 | Solution shall support to send MFA token via email. |  |  |
| 7 | Solution shall support to send MFA token via mobile application. |  |  |
| 8 | Solution shall support to customizable token expiration duration. |  |  |
| 9 | Solution shall force user to re-authenticate if user does not enter correct OTP for a configurable time period. |  |  |
| 10 | Solution shall support to first time registration via QR code. |  |  |
| 11 | Solution shall allow QR codes for MFA registration to be sent via one-time links with predefined validity durations to e |  |  |
| 12 | Solution shall support MFA Registration QR Codes to be valid only for a certain period of time. |  |  |
| 13 | Solution shall support sending MFA registration QR codes via one-time links |  |  |
| 14 | Solution shall support scanning the QR code used for MFA registration with its own mobile application as well as with 3r |  |  |
| 15 | Solution shall support to generating offline token  by mobile application. |  |  |
| 16 | Solution shall support hardware tokens. |  |  |
| 17 | Solution shall support integration with external MFA providers (Okta, Cisco Duo,Sec Trail) |  |  |
| 18 | Solution shall support users to log in to the mobile application and register for MFA to create one-time password |  |  |
| 19 | Mobile application shall support iOS and Android Solutions |  |  |
| 20 | Mobile application shall be available to download from official iOS and Android Application Stores. |  |  |
| 21 | Solution shall support directing users to MFA verification by activating adaptive MFA, even if the username and password |  |  |
| 22 | Solution shall support FIDO2 tokens for MFA |  |  |
| 23 | Solution shall support multi-factor authentication (MFA) verification using push notifications to provide a secure and c |  |  |
| 24 | Solution shall support authorization levels for managing MFA screens to allow granular role-based control over administr |  |  |
| 25 | Solution shall provide enriched logging for MFA activities, including registration and verification events, for improved |  |  |
| 26 | Solution shall support MFA options for mobile users via mobile application, including push notifications and token-based |  |  |
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
|  |  |  |  |

## Multitenancy (23 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall support multitenancy. |  |  |
| 2 | Tenant configuration data (users, policies, systems) shall be managed and maintained separately and independently |  |  |
| 3 | Solution shall support on behalf of management feature where host admins  manage other tenants on their behalf, whenever |  |  |
| 4 | Solution shall enable host admins to switch tenants through GUI if on-behalf of management is enabled. |  |  |
| 5 | Tenant audit log data (session records, video records, key-stoke logs) shall be maintained separately and independently |  |  |
| 6 | Tenant admin shall be able to restrict or extend the priviliges of tenant users |  |  |
| 7 | Tenant admin shall have access to audit trails of own tenant’s users |  |  |
| 8 | Tenant admin shall only watch live sessions of own tenant’s users |  |  |
| 9 | Tenant user shall only see and access to the systems of its own tenant |  |  |
| 10 | The addition or deletion of tenants shall not affect the processing of other tenants |  |  |
| 11 | Tenants shall be able to manage their own backup&restore policies |  |  |
| 12 | VRF definitions shall be available for tenants. |  |  |
| 13 | Tenants shall be able to manage their own log retention policies |  |  |
| 14 | Solution shall build a secure connection to remote sites over a secure tunnel over the public internet where access is r |  |  |
| 15 | Multitenancy shall enable tenants to integrate their own LDAP, SIEM systems separately |  |  |
| 16 | Tenants shall be able to send distinguishable  SIEM messages to same SIEM server |  |  |
| 17 | Solution shall provide flexible licensing mechanism for shifting licenses between tenants. |  |  |
| 18 | Solution shall support to use its own secure tunnel (connector) solution to connect to target devices located in remote  |  |  |
| 19 | The connector solution shall support both inbound and outbound connection architecture. |  |  |
| 20 | Solution shall support adding tenant identifier in tenant logs sent to the SIEM servers. |  |  |
| 21 | Solution shall provide granular role-based access control for multitenant environments, ensuring tenants can only access |  |  |
| 22 | Solution shall provide tenant-specific licensing management to ensure compliance with access and feature entitlements ac |  |  |
| 23 | Solution shall support reporting and audit logs that segregate tenant activities for enhanced compliance and operational |  |  |

## Data Access Manager (73 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | General | Solution shall support Oracle, Mssql, Mysql, IBM db2, SAP HANA, PostgreSQL, Teradata, Couchbase, Apache Cassandra, Apach |  |
| 2 | General | Solution shall support Single Sign On (SSO) for authentication to Oracle and MSSQL |  |
| 3 | General | Solution shall support native DB clients (TOAD, Navicat, MSSQL Client, etc) |  |
| 4 | General | Solution shall support SSL Encrypted connections for Oracle. |  |
| 5 | General | Solution shall support 2FA for Oracle connection. |  |
| 6 | General | Solution shall support Windows Authentication for MSSQL connection. |  |
| 7 | General | Solution shall be able to hide the IP:Port and Service Name information of target database for all DB connections. |  |
| 8 | General | Solution shall support Oracle/MySQL/MSSQL/PostgreSQL/Teradata/Hive/Cassandra/DB2/Hana SQL connections. |  |
| 9 | General | Solution shall support logging the access times and durations to Oracle/MySQL/MSSQL/ PostgreSQL /Teradata/Hive/Cassandra |  |
| 10 | General | Solution shall support logging commands in Oracle/MySQL/MSSQL/ PostgreSQL /Teradata/Hive/Cassandra SQL/DB2/Hana connecti |  |
| 11 | General | Solution shall support policy enforcement on SQL sessions (blocking queries for specific SQL users) for Oracle/MySQL/MSS |  |
| 12 | General | Solution shall support regular expression based policy definitions for SQL queries. |  |
| 13 | General | Solution shall support different Oracle JDBC drivers (ojdbc6, ojdbc7, ojdbc8, etc.) |  |
| 14 | General | Solution shall support different Oracle Installed Clients (OraClient11gHome1, OraClient12Home1, OraClient12Home2, OraCli |  |
| 15 | General | Solution shall support JDBC drivers for MSSQL. |  |
| 16 | General | Solution shall support ODBC drivers for Teradata. |  |
| 17 | General | Solution shall support single or multi-level administrator approval workflows for database access. |  |
| 18 | General | Soluiton shall support reporting local users on target databases |  |
| 19 | General | The solution shall support generating vulnerability reports for target database servers. |  |
| 20 | General | Solution shall support reporting open CVEs for target databases. |  |
| 21 | General | Solution shall support connection approval features to provide enhanced control for database access. |  |
| 22 | General | Solution shall support query approval features to provide enhanced control over database access activities. |  |
| 23 | General | Solution shall support enhanced database discovery processes to improve efficiency in identifying and managing new datab |  |
| 24 | General | Solution shall provide enriched audit logs for database access activities, including detailed command and session inform |  |
| 25 | General | Solution shall provide analysis of local database users and generate report for audit purposes |  |
| 26 | Activity Monitoring | Solution shall support logging the access times and durations to Oracle, MsSQL, MySQL, IBM DB2, SAP HANA, PostgreSQL, Te |  |
| 27 | Activity Monitoring | Solution shall support logging commands in Oracle, MsSQL, MySQL, IBM DB2, SAP HANA, PostgreSQL, Teradata, Couchbase, Apa |  |
| 28 | Activity Monitoring | Solution shall support policy enforcement on SQL sessions (blocking queries for specific SQL users) for Oracle, MsSQL, M |  |
| 29 | Activity Monitoring | Solution shall support single or multi-level administrator approval flows for query execution. |  |
| 30 | Activity Monitoring | Solution shall support logging of all session activities per user. |  |
| 31 | Activity Monitoring | Solution shall applying a policy on a specified user group, preventing users to run specific queries |  |
| 32 | Activity Monitoring | The solution shall be able to monitor, log and apply white-listing/black-listing on DDL (Data Definition Language) comma |  |
| 33 | Activity Monitoring | The Solution shall support regex formats (compatible with the target database supports) when defining white-listing/blac |  |
| 34 | Activity Monitoring | The solution shall be able to log and report the sessions and the queries sent in these sessions in real-time. |  |
| 35 | Activity Monitoring | The solution shall offer filtering per user and per database instance among the logs. |  |
| 36 | Activity Monitoring | Solution shall support Database Vulnerability Scanner reports, listing database versions and CVE-based vulnerability ass |  |
| 37 | Activity Monitoring | Solution shall support the generation of vulnerability assessment reports to assist in identifying security gaps across  |  |
| 38 | Sensitive Data | Solution shall support sensitive data discovery feature for the databases |  |
| 39 | Sensitive Data | Solution shall have built-in sensitive data discovery libraries. |  |
| 40 | Sensitive Data | Solution shall support scheduling sensitive data discoveries for the databases |  |
| 41 | Sensitive Data | Solution shall support to define new customizable patterns for sensitive data discovery |  |
| 42 | Sensitive Data | Solution shall support bulk data import functionality from an external system/file for sensitive data discovery |  |
| 43 | Sensitive Data | Solution shall support running in a multi-threat architecture for sensitive data discovery |  |
| 44 | Sensitive Data | Solution shall analyze the content of the records by comparing the records against the regex expression identifying the  |  |
| 45 | Sensitive Data | Solution shall be support sensitive data discovery among all metadata (schema, column, table) and report the match rate  |  |
| 46 | Sensitive Data | Solution shall support reporting on classified sensitive data for compliance purposes, including data classification and |  |
| 47 | Sensitive Data | Solution shall provide data classification and compliance reporting features for Sensitive Data Discovery to meet regula |  |
| 48 | Data Masking | Solution shall support Redaction/Nulling data masking rule |  |
| 49 | Data Masking | Solution shall support shuffling data masking rule |  |
| 50 | Data Masking | Solution shall support bluring data masking rule |  |
| 51 | Data Masking | Solution shall support custom data masking rule |  |
| 52 | Data Masking | Solution shall support dynamic data masking (applying rules in realtime) |  |
| 53 | Data Masking | Solution shall enable setting a row limit for masking policy so that only a predefined number of rows can be received. |  |
| 54 | Data Masking | Solution shall block queries on masked fields. |  |
| 55 | Data Masking | Solution shall block functions/conditions on masked fields. |  |
| 56 | Data Masking | Solution shall support configuring customizable masking rules. |  |
| 57 | Data Masking | Solution shall enable transferring all masking definitions when user copies a table from an existing table where masking |  |
| 58 | Data Masking | Solution shall support adding/editing masking policies through APIs. |  |
| 59 | Data Masking | Solution shall support view masking. |  |
| 60 | Data Masking | Solution shall support synonym masking. |  |
| 61 | Data Masking | Solution shall support dynamic masking of sensitive data during database access to protect critical information from una |  |
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

## Direct Access Management (43 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Direct Access to Network Elements | Solution shall support built-in TACACS+ Server |  |
| 2 | Direct Access to Network Elements | Solution shall support built-in Radius Server |  |
| 3 | Direct Access to Network Elements | Solution shall support multi-domains on TACACS authentication. |  |
| 4 | Direct Access to Network Elements | Solution shall support MFA for TACACS connections. |  |
| 5 | Direct Access to Network Elements | Solution shall work as a standalone AAA solution and support RADIUS and TACACS+ protocols. |  |
| 6 | Direct Access to Network Elements | Solution shall support to add custom AVP (Attribute Value Pair) |  |
|  | Direct Access to Network Elements | Solution shall have authentication mechanism even the connection between LDAP server and Solution's tacacs server is dow |  |
| 7 | Direct Access to Network Elements | Solution shall support up to 250.000 devices |  |
| 8 | Direct Access to Network Elements | Solution shall support up to 5000 TPS |  |
| 9 | Direct Access to Network Elements | Solution shall support user account without password expiry to support auto scripts in TACACS devices. |  |
| 10 | Direct Access to Network Elements | Solution shall support preventing direct accesses that cause loss of CLI session logging, via SSH or TELNET connection t |  |
| 11 | Direct Access to Linux/Windows Servers | Solution shall provide an agent solution to manage direct access to Linux/Windows Servers  |  |
| 12 | Direct Access to Linux/Windows Servers | Solution shall provide agent software so that Window/Linux servers will be running as a policy enforcement points. |  |
| 13 | Direct Access to Linux/Windows Servers | Solution shall track all user activity and handle the user’s privilege elevation requests with agents on Linux/Windows s |  |
| 14 | Direct Access to Linux/Windows Servers | Solution shall detect any user attempts to execute a command on the Linux server or application started on windows serve |  |
| 15 | Direct Access to Linux/Windows Servers | Solution shall track, monitor and log all user activity on the Linux/Windows servers, and send all logs to the centraliz |  |
| 16 | Direct Access to Linux/Windows Servers | Solution's agent shall support Fedora, Centos,Ubuntu and Debian, Windows server 2016 and 2019, 2022 and Windows 10, Wind |  |
| 17 | Direct Access to Linux/Windows Servers | Solution should support session video record via EPM agent for Windows sessions |  |
| 18 | Direct Access to Linux/Windows Servers | Solution shall support subprocess Blocking and Allowed for granular control over windows application execution |  |
| 19 | Direct Access to Linux/Windows Servers | Solution shall support folder-based automatic, scheduled Application Discovery on Windows endpoints for improved asset m |  |
| 20 | Direct Access to Linux/Windows Servers | Solution shall provide registration token for secure agent installation. |  |
| 21 | Direct Access to Linux/Windows Servers | Solution shall provide secure(https) communication between  agent and central server |  |
| 22 | Direct Access to Linux/Windows Servers | Solution shall provide secure uninstallation functionality for security agent for windows |  |
| 23 | Direct Access to Linux/Windows Servers | Solution shall provide MFA functionality while logging to Windows server |  |
| 24 | Direct Access to Linux/Windows Servers | Solution shall provide a logging mechanism for all authantication attampts to windows server. And should send this logs  |  |
| 25 | Direct Access to Linux/Windows Servers | Solution shall provide application blocking functionality according to hash and application name on windows server |  |
| 26 | Direct Access to Linux/Windows Servers | Solution shall provide command line installation functionality for agent on windows server and remote installation thoro |  |
| 27 | Direct Access to Linux/Windows Servers | Solution's agent shall offline authentincation if central server is down. Offline authentication shall have configurable |  |
| 28 | Direct Access to Linux/Windows Servers | Solution's agent shoyld log all end user processes from the moment the file/application is started till when it is termi |  |
| 29 | Direct Access to Linux/Windows Servers | Solution's agent shall support application based restriction on Windows servers. |  |
| 30 | Direct Access to Linux/Windows Servers | Solution's agent shall require managerial approval or MFA authentication for sudo execution. |  |
| 31 | Direct Access to Linux/Windows Servers | Solution's agent shall restrict jumping to other servers with SSH from an authenticated server |  |
| 32 | Direct Access to Linux/Windows Servers | Solution shall able to create a "home" folder on linux server based on home folder policy |  |
| 33 | Direct Access to Linux/Windows Servers | Solution shall support automatic removal of unreachable Windows EPM agents after a defined period to maintain an accurat |  |
| 34 | Direct Access to Linux/Windows Servers | Solution shall update endpoint IP addresses dynamically when they change to ensure accurate EPM Agent tracking and inven |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |
|  |  |  |  |

## Privileged Task Automation (26 items)

| # | Requirement | Status | Notes |
|---|-------------|--------|-------|
| 1 | Solution shall provide an automation module/manager which can schedule maintenance window activities in advance. |  |  |
| 3 | Solution shall provide for a script manager to help in access controlling scripts and allow to run the scripts on multip |  |  |
| 5 | Solution shall apply least priviege principle to give required permissions to users for executing the scripts. |  |  |
| 6 | Solution shall display all the details of he executed scripts. |  |  |
| 7 | Solution shall enable filtering script execution logs by time,user and device information |  |  |
| 8 | Solution's task autmation module shall support  following protocols : SSH, TELNET, WinRM |  |  |
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
| 12 | Solution shall provide a scheduled backup capability for archiving configuration and logging data |  |  |
| 13 | Solution shall provide granular backup and restoration capabilities for critical system components to improve disaster r |  |  |
| 14 | Solution shall support enriched reporting dashboards for monitoring operational statistics, including session activity a |  |  |

