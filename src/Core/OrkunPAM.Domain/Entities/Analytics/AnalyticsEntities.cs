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
