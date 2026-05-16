using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Compliance;

public class ComplianceFramework : Entity
{
    public string Name { get; set; } = string.Empty;
    public string? Version { get; set; }
    public bool IsBuiltIn { get; set; }
    public string ControlsJson { get; set; } = "[]"; // JSON array of control definitions
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}

public class ControlAssessment : Entity
{
    public Guid FrameworkId { get; set; }
    public string ControlCode { get; set; } = string.Empty;
    public byte Status { get; set; } // 0=NonCompliant, 1=Compliant, 2=Partial, 3=NA
    public string? EvidenceJson { get; set; }
    public DateTime AssessedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid? AssessedBy { get; set; }
}

public class SodRule : Entity
{
    public string Name { get; set; } = string.Empty;
    public Guid RoleA { get; set; }
    public Guid RoleB { get; set; }
    public bool IsEnabled { get; set; } = true;
}

public class AttestationCampaign : Entity
{
    public string Name { get; set; } = string.Empty;
    public string? ScopeJson { get; set; }         // {"type":"AllUsers"} | {"type":"Group","groupId":"..."} | {"type":"Role","roleId":"..."}
    public string? ReviewerRuleJson { get; set; }
    public Guid? ReviewerUserId { get; set; }       // specific reviewer assigned to the campaign
    public DateTime StartsAtUtc { get; set; }
    public DateTime DeadlineUtc { get; set; }
    public byte Status { get; set; }                // 0=Draft, 1=Active, 2=Completed, 3=Cancelled
    public bool AutoRevokeOnMiss { get; set; }
    public DateTime? CompletedAtUtc { get; set; }
}

public class AttestationDecision
{
    public long Id { get; set; }
    public Guid CampaignId { get; set; }
    public Guid ReviewerUserId { get; set; }
    public Guid SubjectUserId { get; set; }
    public string? SubjectUsername { get; set; }
    public string? ResourceType { get; set; }
    public Guid? ResourceId { get; set; }
    public string? ResourceName { get; set; }
    public byte? Decision { get; set; }             // 0=Pending, 1=Approve, 2=Revoke, 3=Defer
    public DateTime? DecisionAtUtc { get; set; }
    public string? Comments { get; set; }
}
