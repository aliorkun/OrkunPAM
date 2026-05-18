using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Analytics;

public class CommandRiskRule : Entity
{
    public string Pattern { get; set; } = string.Empty; // Regex pattern
    public decimal RiskScore { get; set; }
    public string? Category { get; set; }
    public string? Description { get; set; }
}

public class UserBehaviorBaseline : Entity
{
    public Guid UserId { get; set; }
    public string? TypicalHoursJson { get; set; } // JSON: typical access hours
    public string? KnownIpsJson { get; set; } // JSON: known source IPs
    public string? KnownDevicesJson { get; set; } // JSON: typically accessed devices
    public DateTime BaselineDate { get; set; }
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
}

public class Anomaly
{
    public long Id { get; set; }
    public Guid UserId { get; set; }
    public Guid? SessionId { get; set; }
    public string AnomalyType { get; set; } = string.Empty; // "OffHours", "UnusualIP", "UnusualDevice", "FrequencySpike"
    public byte Severity { get; set; } // 0=Low, 1=Medium, 2=High, 3=Critical
    public string? Details { get; set; }
    public DateTime DetectedAtUtc { get; set; } = DateTime.UtcNow;
    public bool IsAcknowledged { get; set; }
    public Guid? AcknowledgedBy { get; set; }
    public DateTime? AcknowledgedAtUtc { get; set; }
}

public class AlertRule : Entity
{
    public string Name { get; set; } = string.Empty;
    public string ConditionJson { get; set; } = "{}"; // JSON condition definition
    public string ActionJson { get; set; } = "{}"; // JSON action definition (email, SMS, terminate, etc.)
    public int CooldownMinutes { get; set; } = 15;
    public bool IsEnabled { get; set; } = true;
}

public class AlertHistory
{
    public long Id { get; set; }
    public Guid AlertRuleId { get; set; }
    public DateTime TriggeredAtUtc { get; set; } = DateTime.UtcNow;
    public string? Details { get; set; }
    public string? ActionsTaken { get; set; }
    public Guid? AcknowledgedBy { get; set; }
    public DateTime? AcknowledgedAtUtc { get; set; }
}

// Threat Intelligence Feed (#206)
public class ThreatIndicator
{
    public long   Id            { get; set; }
    public string IndicatorType { get; set; } = "IP"; // IP | Domain | Hash
    public string Value         { get; set; } = string.Empty;
    public byte   Severity      { get; set; } = 2; // 0=Low 1=Med 2=High 3=Critical
    public string Source        { get; set; } = string.Empty;
    public string? Description  { get; set; }
    public DateTime? ExpiresAtUtc  { get; set; }
    public DateTime CreatedAtUtc   { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc   { get; set; } = DateTime.UtcNow;
}

public class ThreatFeedConfig
{
    public Guid    Id                     { get; set; } = Guid.NewGuid();
    public string  Name                   { get; set; } = string.Empty;
    public string  FeedUrl                { get; set; } = string.Empty;
    public string? ApiKeyEnc              { get; set; } // AES-256-GCM encrypted
    public int     RefreshIntervalMinutes { get; set; } = 60;
    public bool    IsEnabled              { get; set; } = true;
    public string  FeedType              { get; set; } = "Custom"; // EmergingThreats | AbuseIPDB | Custom
    public DateTime? LastRefreshedAtUtc  { get; set; }
    public int?    LastIndicatorCount    { get; set; }
    public string? LastError            { get; set; }
    public DateTime CreatedAtUtc        { get; set; } = DateTime.UtcNow;
}
