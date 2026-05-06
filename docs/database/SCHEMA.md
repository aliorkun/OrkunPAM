# Orkun PAM - Database Schema

## Overview

SQL Server 2019+ with TDE (Transparent Data Encryption) enabled.
Always Encrypted for sensitive columns (MFA secrets, LDAP bind passwords).
11 schemas for module isolation.

---

## Schema: [identity]

### Users
```sql
CREATE TABLE [identity].[Users] (
    Id                   UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Username             NVARCHAR(256) NOT NULL UNIQUE,
    NormalizedUsername    NVARCHAR(256) NOT NULL UNIQUE,
    DisplayName          NVARCHAR(512),
    Email                NVARCHAR(512),
    PasswordHash         NVARCHAR(1024) NULL,          -- Argon2id (local users only)
    AuthSource           TINYINT NOT NULL,              -- 0=Local, 1=AD, 2=SAML, 3=OIDC
    ExternalId           NVARCHAR(1024) NULL,           -- AD objectGUID or SAML NameID
    MfaEnabled           BIT DEFAULT 0,
    MfaSecret            VARBINARY(256) NULL,           -- ALWAYS ENCRYPTED
    MfaType              TINYINT DEFAULT 0,             -- 0=TOTP, 1=SMS, 2=Push
    Phone                NVARCHAR(50) NULL,             -- For SMS MFA
    Status               TINYINT DEFAULT 1,             -- 0=Disabled, 1=Active, 2=Locked, 3=Expired
    IsTemporary          BIT DEFAULT 0,
    TemporaryExpiresUtc  DATETIME2 NULL,
    PasswordLastChanged  DATETIME2 NULL,
    LastLoginAt          DATETIME2 NULL,
    LastLoginIp          NVARCHAR(45) NULL,
    FailedLoginCount     INT DEFAULT 0,
    LockoutEndUtc        DATETIME2 NULL,
    Language             NVARCHAR(10) DEFAULT 'tr-TR',
    Timezone             NVARCHAR(64) DEFAULT 'Europe/Istanbul',
    CreatedAtUtc         DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedAtUtc         DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CreatedBy            UNIQUEIDENTIFIER NULL REFERENCES [identity].[Users](Id)
);
```

### Groups
```sql
CREATE TABLE [identity].[Groups] (
    Id               UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name             NVARCHAR(256) NOT NULL,
    Description      NVARCHAR(2000),
    GroupSource      TINYINT NOT NULL,    -- 0=Local, 1=AD, 2=SAML
    ExternalGroupId  NVARCHAR(1024) NULL,
    ParentGroupId    UNIQUEIDENTIFIER NULL REFERENCES [identity].[Groups](Id),
    CreatedAtUtc     DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedAtUtc     DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE [identity].[UserGroups] (
    UserId   UNIQUEIDENTIFIER REFERENCES [identity].[Users](Id),
    GroupId  UNIQUEIDENTIFIER REFERENCES [identity].[Groups](Id),
    PRIMARY KEY (UserId, GroupId)
);
```

### Roles & Permissions
```sql
CREATE TABLE [identity].[Roles] (
    Id            UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name          NVARCHAR(128) NOT NULL UNIQUE,
    Description   NVARCHAR(1000),
    IsSystemRole  BIT DEFAULT 0
);

CREATE TABLE [identity].[Permissions] (
    Code         NVARCHAR(128) PRIMARY KEY,  -- e.g. 'vault.credential.checkout'
    Module       NVARCHAR(64) NOT NULL,
    Description  NVARCHAR(500)
);

CREATE TABLE [identity].[RolePermissions] (
    RoleId          UNIQUEIDENTIFIER REFERENCES [identity].[Roles](Id),
    PermissionCode  NVARCHAR(128) REFERENCES [identity].[Permissions](Code),
    PRIMARY KEY (RoleId, PermissionCode)
);

CREATE TABLE [identity].[UserRoles] (
    UserId  UNIQUEIDENTIFIER REFERENCES [identity].[Users](Id),
    RoleId  UNIQUEIDENTIFIER REFERENCES [identity].[Roles](Id),
    PRIMARY KEY (UserId, RoleId)
);

CREATE TABLE [identity].[GroupRoles] (
    GroupId  UNIQUEIDENTIFIER REFERENCES [identity].[Groups](Id),
    RoleId   UNIQUEIDENTIFIER REFERENCES [identity].[Roles](Id),
    PRIMARY KEY (GroupId, RoleId)
);
```

### Policies
```sql
CREATE TABLE [identity].[Policies] (
    Id          UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name        NVARCHAR(256) NOT NULL,
    PolicyType  NVARCHAR(64) NOT NULL,  -- PasswordPolicy, SessionPolicy, VaultPolicy, AccessPolicy
    Scope       TINYINT NOT NULL,       -- 0=Global, 1=Group, 2=User
    ScopeId     UNIQUEIDENTIFIER NULL,  -- GroupId or UserId (null for Global)
    PolicyJson  NVARCHAR(MAX) NOT NULL,
    Priority    INT DEFAULT 0,
    IsEnabled   BIT DEFAULT 1,
    CreatedAtUtc DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
```

### LDAP & SAML Configurations
```sql
CREATE TABLE [identity].[LdapConfigurations] (
    Id                   UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name                 NVARCHAR(256) NOT NULL,
    Host                 NVARCHAR(512) NOT NULL,
    Port                 INT DEFAULT 389,
    UseSsl               BIT DEFAULT 1,
    BaseDn               NVARCHAR(1024) NOT NULL,
    BindDn               NVARCHAR(1024),
    BindPasswordEnc      VARBINARY(512),  -- Encrypted with vault engine
    UserSearchFilter     NVARCHAR(1024) DEFAULT '(&(objectClass=user)(sAMAccountName={0}))',
    GroupSearchFilter    NVARCHAR(1024) DEFAULT '(objectClass=group)',
    UserAttributeMapping NVARCHAR(MAX),   -- JSON: AD attr → PAM field
    GroupMapping         NVARCHAR(MAX),   -- JSON: AD group DN → PAM group ID
    SyncIntervalMinutes  INT DEFAULT 60,
    LastSyncAtUtc        DATETIME2 NULL,
    IsEnabled            BIT DEFAULT 1,
    CreatedAtUtc         DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE [identity].[SamlProviders] (
    Id                    UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name                  NVARCHAR(256) NOT NULL,
    EntityId              NVARCHAR(1024) NOT NULL,
    MetadataUrl           NVARCHAR(2048) NULL,
    MetadataXml           NVARCHAR(MAX) NULL,
    SigningCertThumbprint  NVARCHAR(128),
    AssertionConsumerUrl  NVARCHAR(2048),
    SingleLogoutUrl       NVARCHAR(2048) NULL,
    AttributeMapping      NVARCHAR(MAX),   -- JSON: SAML attr → PAM field
    GroupAttributeName    NVARCHAR(256),
    GroupMapping          NVARCHAR(MAX),   -- JSON: SAML group → PAM group
    IsEnabled             BIT DEFAULT 1,
    CreatedAtUtc          DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
```

### Auth Sessions & Delegation
```sql
CREATE TABLE [identity].[AuthSessions] (
    Id           UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    UserId       UNIQUEIDENTIFIER NOT NULL REFERENCES [identity].[Users](Id),
    TokenHash    VARBINARY(64) NOT NULL,  -- SHA-256 of JWT
    RefreshTokenHash VARBINARY(64),
    IpAddress    NVARCHAR(45),
    UserAgent    NVARCHAR(512),
    CreatedAtUtc DATETIME2 NOT NULL,
    ExpiresAtUtc DATETIME2 NOT NULL,
    RevokedAtUtc DATETIME2 NULL
);

CREATE TABLE [identity].[Delegations] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    DelegatorUserId UNIQUEIDENTIFIER REFERENCES [identity].[Users](Id),
    DelegateUserId  UNIQUEIDENTIFIER REFERENCES [identity].[Users](Id),
    DelegationType  NVARCHAR(64),  -- 'ApprovalAuthority', 'VaultAccess'
    StartsAtUtc     DATETIME2 NOT NULL,
    ExpiresAtUtc    DATETIME2 NOT NULL,
    IsActive        BIT DEFAULT 1
);
```

---

## Schema: [vault]

### Folders & Credentials
```sql
CREATE TABLE [vault].[VaultFolders] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    ParentFolderId  UNIQUEIDENTIFIER NULL REFERENCES [vault].[VaultFolders](Id),
    Name            NVARCHAR(256) NOT NULL,
    Description     NVARCHAR(2000),
    IsPersonalVault BIT DEFAULT 0,
    OwnerUserId     UNIQUEIDENTIFIER NULL REFERENCES [identity].[Users](Id),
    CreatedAtUtc    DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CreatedBy       UNIQUEIDENTIFIER REFERENCES [identity].[Users](Id)
);

CREATE TABLE [vault].[Credentials] (
    Id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    FolderId            UNIQUEIDENTIFIER NOT NULL REFERENCES [vault].[VaultFolders](Id),
    Name                NVARCHAR(512) NOT NULL,
    Description         NVARCHAR(2000),
    CredentialType      TINYINT NOT NULL,   -- 0=UserPass, 1=SSHKey, 2=APIKey, 3=Certificate, 4=ConnString, 5=Custom
    Username            NVARCHAR(512),
    PasswordEnc         VARBINARY(MAX),     -- AES-256-GCM encrypted
    PrivateKeyEnc       VARBINARY(MAX) NULL,
    AdditionalDataEnc   VARBINARY(MAX) NULL, -- JSON blob encrypted
    DeviceId            UNIQUEIDENTIFIER NULL REFERENCES [device].[Devices](Id),
    KeyVersion          INT NOT NULL,
    Tags                NVARCHAR(1000) NULL, -- Comma-separated tags
    IsDiscovered        BIT DEFAULT 0,
    IsTakenOver         BIT DEFAULT 0,
    RotationPolicyId    UNIQUEIDENTIFIER NULL,
    LastRotatedAtUtc    DATETIME2 NULL,
    NextRotationAtUtc   DATETIME2 NULL,
    CheckedOutByUserId  UNIQUEIDENTIFIER NULL REFERENCES [identity].[Users](Id),
    CheckedOutAtUtc     DATETIME2 NULL,
    CheckOutExpiresUtc  DATETIME2 NULL,
    MaxCheckoutMinutes  INT DEFAULT 60,
    RequiresApproval    BIT DEFAULT 0,
    Status              TINYINT DEFAULT 1,  -- 0=Disabled, 1=Active, 2=CheckedOut, 3=Rotating
    Version             INT DEFAULT 1,
    CreatedAtUtc        DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedAtUtc        DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
```

### Permissions, Sharing, History, Rotation, Discovery
```sql
CREATE TABLE [vault].[CredentialPermissions] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    CredentialId    UNIQUEIDENTIFIER NULL REFERENCES [vault].[Credentials](Id),
    FolderId        UNIQUEIDENTIFIER NULL REFERENCES [vault].[VaultFolders](Id),
    PrincipalType   TINYINT NOT NULL,   -- 0=User, 1=Group
    PrincipalId     UNIQUEIDENTIFIER NOT NULL,
    PermissionLevel TINYINT NOT NULL,   -- 0=View, 1=Use, 2=Manage, 3=Owner
    CanShare        BIT DEFAULT 0
);

CREATE TABLE [vault].[CheckOutHistory] (
    Id              BIGINT IDENTITY PRIMARY KEY,
    CredentialId    UNIQUEIDENTIFIER NOT NULL,
    UserId          UNIQUEIDENTIFIER NOT NULL,
    CheckedOutAtUtc DATETIME2 NOT NULL,
    CheckedInAtUtc  DATETIME2 NULL,
    Reason          NVARCHAR(2000),
    TicketNumber    NVARCHAR(256) NULL,
    ApprovedBy      UNIQUEIDENTIFIER NULL,
    WasAutoCheckedIn BIT DEFAULT 0
);

CREATE TABLE [vault].[CredentialShares] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    CredentialId    UNIQUEIDENTIFIER NOT NULL,
    SharedByUserId  UNIQUEIDENTIFIER NOT NULL,
    SharedToUserId  UNIQUEIDENTIFIER NOT NULL,
    PermissionLevel TINYINT DEFAULT 0,
    ExpiresAtUtc    DATETIME2 NULL,
    MaxUseCount     INT NULL,
    UseCount        INT DEFAULT 0
);

CREATE TABLE [vault].[PasswordHistory] (
    Id              BIGINT IDENTITY PRIMARY KEY,
    CredentialId    UNIQUEIDENTIFIER NOT NULL,
    PasswordEnc     VARBINARY(MAX) NOT NULL,
    ChangedAtUtc    DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    ChangedBy       UNIQUEIDENTIFIER NULL,
    ChangeReason    TINYINT NOT NULL  -- 0=Manual, 1=Scheduled, 2=CheckIn, 3=Takeover, 4=OnDemand
);

CREATE TABLE [vault].[RotationPolicies] (
    Id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name                NVARCHAR(256) NOT NULL,
    IntervalDays        INT DEFAULT 30,
    PasswordComplexity  NVARCHAR(MAX),  -- JSON
    RotateOnCheckIn     BIT DEFAULT 0,
    NotifyBeforeDays    INT DEFAULT 3,
    ConnectorType       NVARCHAR(128),  -- WinRM, SSH, LDAP, SNMP, Database
    RetryCount          INT DEFAULT 3,
    RetryIntervalMinutes INT DEFAULT 15
);

CREATE TABLE [vault].[DiscoveryJobs] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name            NVARCHAR(256) NOT NULL,
    DiscoveryType   TINYINT NOT NULL,  -- 0=AD, 1=WindowsLocal, 2=Linux, 3=Database, 4=Cloud
    TargetScope     NVARCHAR(MAX),     -- JSON: OUs, IP ranges, etc.
    Schedule        NVARCHAR(128),     -- Cron expression
    LastRunAtUtc    DATETIME2 NULL,
    LastRunResult   NVARCHAR(MAX) NULL,
    Status          TINYINT DEFAULT 1,
    CreatedBy       UNIQUEIDENTIFIER NOT NULL
);

CREATE TABLE [vault].[DiscoveredAccounts] (
    Id               UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    DiscoveryJobId   UNIQUEIDENTIFIER NOT NULL,
    DeviceId         UNIQUEIDENTIFIER NULL,
    AccountName      NVARCHAR(512) NOT NULL,
    AccountType      NVARCHAR(128),
    DiscoveredAtUtc  DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    TakeoverStatus   TINYINT DEFAULT 0,  -- 0=Pending, 1=TakenOver, 2=Ignored
    LinkedCredentialId UNIQUEIDENTIFIER NULL
);
```

---

## Schema: [device]

```sql
CREATE TABLE [device].[Platforms] (
    Id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name                NVARCHAR(256) NOT NULL,
    DefaultProtocol     TINYINT NOT NULL,
    DefaultPort         INT NOT NULL,
    RotationConnector   NVARCHAR(128),
    ConnectionTemplate  NVARCHAR(MAX)
);

CREATE TABLE [device].[Devices] (
    Id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Hostname            NVARCHAR(256) NOT NULL,
    FQDN                NVARCHAR(512) NULL,
    IpAddress           NVARCHAR(45) NULL,
    DeviceType          TINYINT NOT NULL,
    OperatingSystem     NVARCHAR(256) NULL,
    ConnectionPort      INT NULL,
    ConnectionProtocol  TINYINT NOT NULL,
    PlatformId          UNIQUEIDENTIFIER NULL REFERENCES [device].[Platforms](Id),
    IsManaged           BIT DEFAULT 1,
    IsReachable         BIT NULL,
    LastReachableCheck  DATETIME2 NULL,
    AdObjectGuid        NVARCHAR(128) NULL,
    ImportSource        TINYINT DEFAULT 0,
    Tags                NVARCHAR(1000) NULL,
    Notes               NVARCHAR(MAX),
    Status              TINYINT DEFAULT 1,
    CreatedAtUtc        DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedAtUtc        DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE [device].[DeviceGroups] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name            NVARCHAR(256) NOT NULL,
    GroupType       TINYINT NOT NULL,  -- 0=Manual, 1=VLAN, 2=DeviceType, 3=ADOu, 4=Dynamic
    DynamicFilter   NVARCHAR(MAX) NULL,
    VlanId          INT NULL,
    SubnetCidr      NVARCHAR(18) NULL,
    ParentGroupId   UNIQUEIDENTIFIER NULL REFERENCES [device].[DeviceGroups](Id),
    CreatedAtUtc    DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE [device].[DeviceGroupMembers] (
    DeviceId       UNIQUEIDENTIFIER REFERENCES [device].[Devices](Id),
    DeviceGroupId  UNIQUEIDENTIFIER REFERENCES [device].[DeviceGroups](Id),
    PRIMARY KEY (DeviceId, DeviceGroupId)
);

CREATE TABLE [device].[DeviceCredentials] (
    DeviceId      UNIQUEIDENTIFIER REFERENCES [device].[Devices](Id),
    CredentialId  UNIQUEIDENTIFIER REFERENCES [vault].[Credentials](Id),
    Purpose       TINYINT DEFAULT 0,
    IsPrimary     BIT DEFAULT 0,
    PRIMARY KEY (DeviceId, CredentialId)
);
```

---

## Schema: [session]

```sql
CREATE TABLE [session].[SessionPolicies] (
    Id                   UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name                 NVARCHAR(256) NOT NULL,
    MaxDurationMinutes   INT NULL,
    IdleTimeoutMinutes   INT NULL,
    AllowFileTransfer    BIT DEFAULT 0,
    AllowClipboard       BIT DEFAULT 0,
    AllowDriveMapping    BIT DEFAULT 0,
    AllowPrinting        BIT DEFAULT 0,
    RecordingEnabled     BIT DEFAULT 1,
    KeystrokeLogging     BIT DEFAULT 1,
    RequireReason        BIT DEFAULT 0,
    RequireTicket        BIT DEFAULT 0,
    TwoPersonRule        BIT DEFAULT 0,
    EnableWatermark      BIT DEFAULT 0,
    CommandFilterMode    TINYINT DEFAULT 0,  -- 0=None, 1=Whitelist, 2=Blacklist
    CommandFilterRules   NVARCHAR(MAX) NULL  -- JSON array of regex patterns
);

CREATE TABLE [session].[ProxySessions] (
    Id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    UserId              UNIQUEIDENTIFIER NOT NULL,
    DeviceId            UNIQUEIDENTIFIER NOT NULL,
    CredentialId        UNIQUEIDENTIFIER NOT NULL,
    SessionPolicyId     UNIQUEIDENTIFIER NULL,
    SessionType         TINYINT NOT NULL,  -- 0=SSH, 1=RDP, 2=VNC, 3=SQL, 4=HTTP, 5=SFTP, 6=Telnet
    StartedAtUtc        DATETIME2 NOT NULL,
    EndedAtUtc          DATETIME2 NULL,
    DurationSeconds     INT NULL,
    ClientIpAddress     NVARCHAR(45),
    TargetIpAddress     NVARCHAR(45),
    TargetPort          INT,
    Status              TINYINT NOT NULL,  -- 0=Active, 1=Completed, 2=Terminated, 3=Failed
    TerminatedBy        UNIQUEIDENTIFIER NULL,
    TerminationReason   NVARCHAR(1000) NULL,
    Reason              NVARCHAR(2000) NULL,
    TicketNumber        NVARCHAR(256) NULL,
    RecordingPath       NVARCHAR(1024) NULL,
    RecordingSizeBytes  BIGINT NULL,
    HasKeystrokeLog     BIT DEFAULT 0,
    HasOcrData          BIT DEFAULT 0,
    RiskScore           DECIMAL(5,2) DEFAULT 0,
    Tags                NVARCHAR(1000) NULL
);

CREATE TABLE [session].[KeystrokeLogs] (
    Id           BIGINT IDENTITY PRIMARY KEY,
    SessionId    UNIQUEIDENTIFIER NOT NULL,
    Timestamp    DATETIME2 NOT NULL,
    Direction    TINYINT NOT NULL,  -- 0=Input, 1=Output
    DataEnc      VARBINARY(MAX) NOT NULL
);

CREATE TABLE [session].[CommandLogs] (
    Id           BIGINT IDENTITY PRIMARY KEY,
    SessionId    UNIQUEIDENTIFIER NOT NULL,
    Timestamp    DATETIME2 NOT NULL,
    Command      NVARCHAR(MAX),
    RiskScore    DECIMAL(5,2) DEFAULT 0,
    WasBlocked   BIT DEFAULT 0,
    BlockReason  NVARCHAR(500) NULL
);
```

---

## Schema: [workflow]

```sql
CREATE TABLE [workflow].[WorkflowDefinitions] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name            NVARCHAR(256) NOT NULL,
    Description     NVARCHAR(2000),
    TriggerType     NVARCHAR(128),  -- 'CredentialCheckout', 'SessionConnect', 'BreakGlass'
    StepsJson       NVARCHAR(MAX),  -- JSON: ordered steps with approver rules
    IsEnabled       BIT DEFAULT 1,
    CreatedAtUtc    DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE [workflow].[ApprovalRequests] (
    Id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    WorkflowId          UNIQUEIDENTIFIER NOT NULL,
    RequesterId         UNIQUEIDENTIFIER NOT NULL,
    ResourceType        NVARCHAR(64),   -- 'Credential', 'Session', 'BreakGlass'
    ResourceId          UNIQUEIDENTIFIER,
    CurrentStep         INT DEFAULT 0,
    Status              TINYINT DEFAULT 0,  -- 0=Pending, 1=Approved, 2=Denied, 3=Expired, 4=Escalated
    Reason              NVARCHAR(2000),
    TicketNumber        NVARCHAR(256) NULL,
    ExpiresAtUtc        DATETIME2 NULL,
    CreatedAtUtc        DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    CompletedAtUtc      DATETIME2 NULL
);

CREATE TABLE [workflow].[ApprovalSteps] (
    Id              BIGINT IDENTITY PRIMARY KEY,
    RequestId       UNIQUEIDENTIFIER NOT NULL,
    StepOrder       INT NOT NULL,
    ApproverId      UNIQUEIDENTIFIER NULL,
    ApproverGroupId UNIQUEIDENTIFIER NULL,
    ActualApproverId UNIQUEIDENTIFIER NULL,
    Decision        TINYINT NULL,  -- 0=Pending, 1=Approved, 2=Denied
    DecisionAtUtc   DATETIME2 NULL,
    Comments        NVARCHAR(2000)
);
```

---

## Schema: [aapm]

```sql
CREATE TABLE [aapm].[ApiClients] (
    Id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name                NVARCHAR(256) NOT NULL,
    ClientId            NVARCHAR(128) NOT NULL UNIQUE,
    ClientSecretHash    VARBINARY(128) NOT NULL,
    AllowedIpRanges     NVARCHAR(MAX) NULL,
    ServiceAccountId    UNIQUEIDENTIFIER NULL,
    RateLimitPerMinute  INT DEFAULT 60,
    IsEnabled           BIT DEFAULT 1,
    LastUsedAtUtc       DATETIME2 NULL,
    CreatedAtUtc        DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE [aapm].[ApiClientCredentialAccess] (
    ApiClientId   UNIQUEIDENTIFIER REFERENCES [aapm].[ApiClients](Id),
    CredentialId  UNIQUEIDENTIFIER REFERENCES [vault].[Credentials](Id),
    PRIMARY KEY (ApiClientId, CredentialId)
);

CREATE TABLE [aapm].[ApiAccessLog] (
    Id              BIGINT IDENTITY PRIMARY KEY,
    ApiClientId     UNIQUEIDENTIFIER NOT NULL,
    CredentialId    UNIQUEIDENTIFIER NOT NULL,
    RequestedAtUtc  DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    ClientIpAddress NVARCHAR(45),
    Outcome         TINYINT NOT NULL  -- 0=Granted, 1=Denied, 2=RateLimited
);
```

---

## Schema: [analytics]

```sql
CREATE TABLE [analytics].[CommandRiskRules] (
    Id          UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Pattern     NVARCHAR(1024) NOT NULL,  -- Regex pattern
    RiskScore   DECIMAL(5,2) NOT NULL,
    Category    NVARCHAR(128),
    Description NVARCHAR(500)
);

CREATE TABLE [analytics].[UserBehaviorBaselines] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    UserId          UNIQUEIDENTIFIER NOT NULL,
    TypicalHoursJson NVARCHAR(MAX),     -- JSON: typical access hours
    KnownIpsJson    NVARCHAR(MAX),      -- JSON: known source IPs
    KnownDevicesJson NVARCHAR(MAX),     -- JSON: typically accessed devices
    BaselineDate    DATETIME2 NOT NULL,
    UpdatedAtUtc    DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);

CREATE TABLE [analytics].[Anomalies] (
    Id              BIGINT IDENTITY PRIMARY KEY,
    UserId          UNIQUEIDENTIFIER NOT NULL,
    SessionId       UNIQUEIDENTIFIER NULL,
    AnomalyType     NVARCHAR(64),  -- 'OffHours', 'UnusualIP', 'UnusualDevice', 'FrequencySpike'
    Severity        TINYINT NOT NULL,
    Details         NVARCHAR(MAX),
    DetectedAtUtc   DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    IsAcknowledged  BIT DEFAULT 0
);

CREATE TABLE [analytics].[AlertRules] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name            NVARCHAR(256) NOT NULL,
    ConditionJson   NVARCHAR(MAX) NOT NULL,
    ActionJson      NVARCHAR(MAX) NOT NULL,
    CooldownMinutes INT DEFAULT 15,
    IsEnabled       BIT DEFAULT 1
);

CREATE TABLE [analytics].[AlertHistory] (
    Id              BIGINT IDENTITY PRIMARY KEY,
    AlertRuleId     UNIQUEIDENTIFIER NOT NULL,
    TriggeredAtUtc  DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    Details         NVARCHAR(MAX),
    ActionsTaken    NVARCHAR(MAX),
    AcknowledgedBy  UNIQUEIDENTIFIER NULL,
    AcknowledgedAt  DATETIME2 NULL
);
```

---

## Schema: [compliance]

```sql
CREATE TABLE [compliance].[ComplianceFrameworks] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name            NVARCHAR(256) NOT NULL,
    Version         NVARCHAR(64),
    IsBuiltIn       BIT DEFAULT 0,
    ControlsJson    NVARCHAR(MAX) NOT NULL  -- JSON: control definitions
);

CREATE TABLE [compliance].[ControlAssessments] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    FrameworkId     UNIQUEIDENTIFIER NOT NULL,
    ControlCode     NVARCHAR(64) NOT NULL,
    Status          TINYINT NOT NULL,  -- 0=NonCompliant, 1=Compliant, 2=Partial, 3=NA
    EvidenceJson    NVARCHAR(MAX),
    AssessedAtUtc   DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    AssessedBy      UNIQUEIDENTIFIER NULL
);

CREATE TABLE [compliance].[SodRules] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name            NVARCHAR(256) NOT NULL,
    RoleA           UNIQUEIDENTIFIER NOT NULL,
    RoleB           UNIQUEIDENTIFIER NOT NULL,
    IsEnabled       BIT DEFAULT 1
);

CREATE TABLE [compliance].[AttestationCampaigns] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name            NVARCHAR(256) NOT NULL,
    Scope           NVARCHAR(MAX),     -- JSON: which users/groups/vaults
    ReviewerRule    NVARCHAR(MAX),     -- JSON: who reviews
    StartsAtUtc     DATETIME2 NOT NULL,
    DeadlineUtc     DATETIME2 NOT NULL,
    Status          TINYINT DEFAULT 0,
    AutoRevokeOnMiss BIT DEFAULT 0
);

CREATE TABLE [compliance].[AttestationDecisions] (
    Id              BIGINT IDENTITY PRIMARY KEY,
    CampaignId      UNIQUEIDENTIFIER NOT NULL,
    ReviewerUserId  UNIQUEIDENTIFIER NOT NULL,
    SubjectUserId   UNIQUEIDENTIFIER NOT NULL,
    ResourceType    NVARCHAR(64),
    ResourceId      UNIQUEIDENTIFIER,
    Decision        TINYINT NULL,  -- 0=Approve, 1=Revoke, 2=Modify
    DecisionAtUtc   DATETIME2 NULL,
    Comments        NVARCHAR(2000)
);
```

---

## Schema: [crypto]

```sql
CREATE TABLE [crypto].[MasterKeys] (
    Id                      INT IDENTITY PRIMARY KEY,
    KeyVersion              INT NOT NULL UNIQUE,
    EncryptedKeyMaterial    VARBINARY(MAX) NOT NULL,
    KeyStatus               TINYINT NOT NULL,  -- 0=Active, 1=DecryptOnly, 2=Retired
    CreatedAtUtc            DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    RotatedAtUtc            DATETIME2 NULL
);

CREATE TABLE [crypto].[DataEncryptionKeys] (
    Id                          INT IDENTITY PRIMARY KEY,
    KeyVersion                  INT NOT NULL UNIQUE,
    Purpose                     NVARCHAR(64) NOT NULL,
    EncryptedByMasterKeyVersion INT NOT NULL,
    EncryptedKeyMaterial        VARBINARY(256) NOT NULL,
    IsActive                    BIT DEFAULT 1,
    CreatedAtUtc                DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME()
);
```

---

## Schema: [system]

```sql
CREATE TABLE [system].[AuditLog] (
    Id              BIGINT IDENTITY PRIMARY KEY,
    Timestamp       DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    EventCategory   NVARCHAR(64) NOT NULL,
    EventType       NVARCHAR(128) NOT NULL,
    ActorUserId     UNIQUEIDENTIFIER NULL,
    ActorUsername   NVARCHAR(256),
    ActorIpAddress  NVARCHAR(45),
    TargetType      NVARCHAR(64),
    TargetId        NVARCHAR(256),
    Details         NVARCHAR(MAX),
    Outcome         TINYINT NOT NULL,  -- 0=Success, 1=Failure, 2=Denied
    PreviousHash    VARBINARY(64) NULL,  -- Hash chain for tamper-proofing
    EntryHash       VARBINARY(64) NOT NULL,
    INDEX IX_AuditLog_Timestamp (Timestamp DESC),
    INDEX IX_AuditLog_Actor (ActorUserId, Timestamp DESC),
    INDEX IX_AuditLog_Target (TargetType, TargetId, Timestamp DESC)
);

CREATE TABLE [system].[SystemConfig] (
    Key         NVARCHAR(256) PRIMARY KEY,
    Value       NVARCHAR(MAX),
    IsEncrypted BIT DEFAULT 0,
    Category    NVARCHAR(128),
    Description NVARCHAR(500),
    UpdatedAtUtc DATETIME2 NOT NULL DEFAULT SYSUTCDATETIME(),
    UpdatedBy   UNIQUEIDENTIFIER NULL
);

CREATE TABLE [system].[BackgroundJobs] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    JobType         NVARCHAR(256) NOT NULL,
    CronExpression  NVARCHAR(128) NULL,
    LastRunAtUtc    DATETIME2 NULL,
    NextRunAtUtc    DATETIME2 NULL,
    LastRunResult   NVARCHAR(MAX) NULL,
    IsEnabled       BIT DEFAULT 1,
    Configuration   NVARCHAR(MAX) NULL
);

CREATE TABLE [reporting].[ReportDefinitions] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    Name            NVARCHAR(256) NOT NULL,
    Category        NVARCHAR(128),
    IsBuiltIn       BIT DEFAULT 0,
    QueryTemplate   NVARCHAR(MAX) NOT NULL,
    Parameters      NVARCHAR(MAX),
    CreatedBy       UNIQUEIDENTIFIER NULL
);

CREATE TABLE [reporting].[ReportSchedules] (
    Id                  UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    ReportDefinitionId  UNIQUEIDENTIFIER NOT NULL,
    CronExpression      NVARCHAR(128),
    Recipients          NVARCHAR(MAX),
    OutputFormat        TINYINT DEFAULT 0,
    LastRunAtUtc        DATETIME2 NULL,
    IsEnabled           BIT DEFAULT 1
);

CREATE TABLE [reporting].[DashboardWidgets] (
    Id              UNIQUEIDENTIFIER PRIMARY KEY DEFAULT NEWSEQUENTIALID(),
    UserId          UNIQUEIDENTIFIER NOT NULL,
    WidgetType      NVARCHAR(128) NOT NULL,
    Position        INT DEFAULT 0,
    SizeColumns     INT DEFAULT 4,
    Configuration   NVARCHAR(MAX) NULL
);
```
