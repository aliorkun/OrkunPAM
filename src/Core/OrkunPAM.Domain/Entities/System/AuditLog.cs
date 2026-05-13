using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Domain.Entities.System;

public class AuditLogEntry
{
    public long Id { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;
    public string EventCategory { get; set; } = string.Empty;
    public string EventType { get; set; } = string.Empty;
    public Guid? ActorUserId { get; set; }
    public string? ActorUsername { get; set; }
    public string? ActorIpAddress { get; set; }
    public string? TargetType { get; set; }
    public string? TargetId { get; set; }
    public string? Details { get; set; }
    public AuditOutcome Outcome { get; set; }
    public string? TraceId { get; set; }
    public byte[]? PreviousHash { get; set; }
    public byte[]? EntryHash { get; set; }
    public bool IsTampered { get; set; }
}

public class SystemConfig
{
    public string Key { get; set; } = string.Empty;
    public string? Value { get; set; }
    public bool IsEncrypted { get; set; }
    public string? Category { get; set; }
    public string? Description { get; set; }
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid? UpdatedBy { get; set; }
}

public class BackgroundJob
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string JobType { get; set; } = string.Empty;
    public string? CronExpression { get; set; }
    public DateTime? LastRunAtUtc { get; set; }
    public DateTime? NextRunAtUtc { get; set; }
    public string? LastRunResult { get; set; }
    public bool IsEnabled { get; set; } = true;
    public string? ConfigurationJson { get; set; }
}
