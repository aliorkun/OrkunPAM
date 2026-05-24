using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Session;

public class ProxySession : Entity
{
    public Guid UserId { get; set; }
    public Guid DeviceId { get; set; }
    public Guid CredentialId { get; set; }
    public Guid? SessionPolicyId { get; set; }
    public SessionType SessionType { get; set; }
    public DateTime StartedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? EndedAtUtc { get; set; }
    public int? DurationSeconds { get; set; }
    public string? ClientIpAddress { get; set; }
    public string? TargetIpAddress { get; set; }
    public int? TargetPort { get; set; }
    public SessionStatus Status { get; set; } = SessionStatus.Active;
    public Guid? TerminatedBy { get; set; }
    public string? TerminationReason { get; set; }
    public string? Reason { get; set; }
    public string? TicketNumber { get; set; }
    public string? RecordingPath { get; set; }
    public long? RecordingSizeBytes { get; set; }
    public bool HasKeystrokeLog { get; set; }
    public bool HasOcrData { get; set; }
    public decimal RiskScore { get; set; }
    public string? Tags { get; set; }
    public string? SessionTokenHash { get; set; }

    public void End()
    {
        EndedAtUtc = DateTime.UtcNow;
        DurationSeconds = (int)(EndedAtUtc.Value - StartedAtUtc).TotalSeconds;
        Status = SessionStatus.Completed;
    }

    public void Terminate(Guid adminUserId, string reason)
    {
        EndedAtUtc = DateTime.UtcNow;
        DurationSeconds = (int)(EndedAtUtc.Value - StartedAtUtc).TotalSeconds;
        Status = SessionStatus.Terminated;
        TerminatedBy = adminUserId;
        TerminationReason = reason;
    }
}

public class SessionPolicy : Entity
{
    public string Name { get; set; } = string.Empty;
    public int? MaxDurationMinutes { get; set; }
    public int? IdleTimeoutMinutes { get; set; }
    public bool AllowFileTransfer { get; set; }
    public bool AllowClipboard { get; set; }
    public bool AllowDriveMapping { get; set; }
    public bool AllowPrinting { get; set; }
    public bool RecordingEnabled { get; set; } = true;
    public bool KeystrokeLogging { get; set; } = true;
    public bool RequireReason { get; set; }
    public bool RequireTicket { get; set; }
    public bool TwoPersonRule { get; set; }
    public bool EnableWatermark { get; set; }
    public CommandFilterMode CommandFilterMode { get; set; }
    public string? CommandFilterRulesJson { get; set; }
}

public class CommandLog
{
    public long Id { get; set; }
    public Guid SessionId { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string? Command { get; set; }
    public decimal RiskScore { get; set; }
    public bool WasBlocked { get; set; }
    public string? BlockReason { get; set; }
}

public class CommandFilterPolicy : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public CommandFilterMode Mode { get; set; } = CommandFilterMode.Blacklist;
    public Guid? DeviceGroupId { get; set; }
    public ICollection<CommandFilterPolicyRule> Rules { get; set; } = [];
}

public class CommandFilterPolicyRule
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid PolicyId { get; set; }
    public string Pattern { get; set; } = string.Empty;
    public bool IsRegex { get; set; }
    public string Action { get; set; } = "Deny";
    public int RiskScore { get; set; } = 50;
    public string? Justification { get; set; }
    public int SortOrder { get; set; }
}

/// <summary>
/// Controls which RDP/VNC virtual channels are permitted in a session.
/// Policies are scoped to a DeviceGroup (or global if DeviceGroupId is null).
/// </summary>
public class PeripheralRedirectionPolicy : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsEnabled { get; set; } = true;
    public bool AllowClipboard { get; set; } = false;
    public bool AllowDriveRedirection { get; set; } = false;
    public bool AllowPrinterRedirection { get; set; } = true;
    public bool AllowUsbRedirection { get; set; } = false;
    public bool AllowAudioRedirection { get; set; } = false;
    public bool AllowSmartCardRedirection { get; set; } = true;
    public Guid? DeviceGroupId { get; set; }
}

/// <summary>
/// Represents a session ownership transfer request (handoff) between two admins.
/// The requesting admin initiates the transfer; the receiving admin accepts/declines.
/// On acceptance, ProxySession.UserId is updated to the new owner.
/// </summary>
public class SessionHandoff
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SessionId { get; set; }
    public Guid RequestedByUserId { get; set; }
    public string? RequestedByUsername { get; set; }
    public Guid RequestedToUserId { get; set; }
    public string? RequestedToUsername { get; set; }
    public DateTime RequestedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? AcceptedAtUtc { get; set; }
    /// <summary>Pending | Accepted | Declined | Expired</summary>
    public string Status { get; set; } = "Pending";
    public string? TransferNotes { get; set; }
    public DateTime ExpiresAtUtc { get; set; } = DateTime.UtcNow.AddMinutes(15);
}

/// <summary>
/// Tracks a real-time shadow (read-only observation) of an active proxy session.
/// </summary>
public class SessionShadow
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SessionId { get; set; }
    public Guid ShadowByUserId { get; set; }
    public string? ShadowByUsername { get; set; }
    public DateTime StartedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? EndedAtUtc { get; set; }
    public string? ShadowIp { get; set; }
    public bool IsActive { get; set; } = true;
}

/// <summary>
/// A periodic screen-capture snapshot taken during an RDP or VNC session.
/// DataBase64 is null when actual pixel capture is not available (TCP-relay mode).
/// </summary>
public class ScreenCaptureFrame
{
    public long Id { get; set; }
    public Guid SessionId { get; set; }
    public DateTime CapturedAtUtc { get; set; } = DateTime.UtcNow;
    public int FrameIndex { get; set; }
    public int? Width { get; set; }
    public int? Height { get; set; }
    public string? DataBase64 { get; set; }
    public string SessionType { get; set; } = "Unknown";
}

/// <summary>
/// Grants a delegatee scoped temporary access to start sessions against a device or device group
/// using the delegator's credential. Distinct from Handoff (no active session transferred) and
/// Shadow (not read-only observation). RA #42.
/// </summary>
public class SessionDelegation
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid DelegatorUserId { get; set; }
    public string? DelegatorUsername { get; set; }
    public Guid DelegateUserId { get; set; }
    public string? DelegateUsername { get; set; }
    /// <summary>Target device. Null means DeviceGroupId is used.</summary>
    public Guid? DeviceId { get; set; }
    /// <summary>Target device group. Null means DeviceId is used.</summary>
    public Guid? DeviceGroupId { get; set; }
    /// <summary>Specific credential granted. Null = any credential the delegator owns on the target.</summary>
    public Guid? CredentialId { get; set; }
    public DateTime GrantedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    /// <summary>Active | Expired | Revoked | Used</summary>
    public string Status { get; set; } = "Active";
    public int MaxSessionCount { get; set; } = 1;
    public int UsageCount { get; set; } = 0;
    public string? DelegationNote { get; set; }
}
