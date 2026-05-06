using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Workflow;

public class WorkflowDefinition : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string TriggerType { get; set; } = string.Empty; // "CredentialCheckout", "SessionConnect", "BreakGlass"
    public string StepsJson { get; set; } = "[]"; // JSON: ordered steps with approver rules
    public bool IsEnabled { get; set; } = true;
}

public class ApprovalRequest : Entity
{
    public Guid WorkflowId { get; set; }
    public Guid RequesterId { get; set; }
    public string ResourceType { get; set; } = string.Empty; // "Credential", "Session", "BreakGlass"
    public Guid? ResourceId { get; set; }
    public int CurrentStep { get; set; }
    public ApprovalStatus Status { get; set; } = ApprovalStatus.Pending;
    public string? Reason { get; set; }
    public string? TicketNumber { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? CompletedAtUtc { get; set; }

    public ICollection<ApprovalStep> Steps { get; set; } = new List<ApprovalStep>();
}

public class ApprovalStep
{
    public long Id { get; set; }
    public Guid RequestId { get; set; }
    public ApprovalRequest Request { get; set; } = null!;
    public int StepOrder { get; set; }
    public Guid? ApproverId { get; set; }
    public Guid? ApproverGroupId { get; set; }
    public Guid? ActualApproverId { get; set; }
    public ApprovalStatus Decision { get; set; } = ApprovalStatus.Pending;
    public DateTime? DecisionAtUtc { get; set; }
    public string? Comments { get; set; }
}
