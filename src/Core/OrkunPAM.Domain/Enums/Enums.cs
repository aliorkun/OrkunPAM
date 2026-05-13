namespace OrkunPAM.Domain.Enums;

public enum AuthSource : byte { Local = 0, ActiveDirectory = 1, Saml = 2, Oidc = 3 }
public enum UserStatus : byte { Disabled = 0, Active = 1, Locked = 2, Expired = 3 }
public enum MfaType : byte { Totp = 0, Sms = 1, Push = 2, Hardware = 3 }
public enum GroupSource : byte { Local = 0, ActiveDirectory = 1, Saml = 2 }

public enum CredentialType : byte
{
    UserPassword = 0, SshKey = 1, ApiKey = 2, Certificate = 3,
    ConnectionString = 4, Custom = 5
}
public enum CredentialStatus : byte { Disabled = 0, Active = 1, CheckedOut = 2, Rotating = 3 }
public enum PermissionLevel : byte { View = 0, Use = 1, Manage = 2, Owner = 3 }
public enum PrincipalType : byte { User = 0, Group = 1 }
public enum PasswordChangeReason : byte { Manual = 0, Scheduled = 1, CheckIn = 2, Takeover = 3, OnDemand = 4 }

public enum DeviceType : byte
{
    WindowsServer = 0, LinuxServer = 1, NetworkSwitch = 2, NetworkRouter = 3,
    Firewall = 4, DatabaseServer = 5, WebApplication = 6, Hypervisor = 7,
    CloudInstance = 8, WindowsWorkstation = 9, IoT = 10, Other = 99
}
public enum ConnectionProtocol : byte
{
    Ssh = 0, Rdp = 1, Vnc = 2, Telnet = 3, Http = 4, Https = 5,
    SqlServer = 6, Oracle = 7, MySql = 8, PostgreSql = 9, Snmp = 10
}
public enum DeviceStatus : byte { Disabled = 0, Active = 1, Maintenance = 2, Unreachable = 3 }
public enum DeviceGroupType : byte { Manual = 0, Vlan = 1, DeviceType = 2, AdOu = 3, Dynamic = 4 }
public enum ImportSource : byte { Manual = 0, Csv = 1, AdSync = 2, Discovery = 3, Cloud = 4 }
public enum CredentialPurpose : byte { Administrative = 0, Service = 1, Emergency = 2, Discovery = 3 }

public enum SessionType : byte { Ssh = 0, Rdp = 1, Vnc = 2, Sql = 3, Http = 4, Sftp = 5, Telnet = 6 }
public enum SessionStatus : byte { Active = 0, Completed = 1, Terminated = 2, Failed = 3 }
public enum CommandFilterMode : byte { None = 0, Whitelist = 1, Blacklist = 2 }

public enum ApprovalStatus : byte { Pending = 0, Approved = 1, Denied = 2, Expired = 3, Escalated = 4 }
public enum AuditOutcome : byte { Success = 0, Failure = 1, Denied = 2 }

public enum PolicyType { PasswordPolicy, SessionPolicy, VaultPolicy, AccessPolicy }
public enum PolicyScope : byte { Global = 0, Group = 1, User = 2 }

public enum DiscoveryType : byte { ActiveDirectory = 0, WindowsLocal = 1, Linux = 2, Database = 3, Cloud = 4 }
public enum TakeoverStatus : byte { Pending = 0, TakenOver = 1, Ignored = 2 }
public enum RotationConnector { WinRm, Ssh, Ldap, Snmp, SqlServer, Oracle, MySql, PostgreSql }

public enum KeyStatus : byte { Active = 0, DecryptOnly = 1, Retired = 2 }

public enum BreakGlassStatus : byte { Active = 0, Acknowledged = 1, Expired = 2, Revoked = 3 }

public enum JitAccessStatus : byte { Pending = 0, Approved = 1, Active = 2, Expired = 3, Revoked = 4, Denied = 5 }
