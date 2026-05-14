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
