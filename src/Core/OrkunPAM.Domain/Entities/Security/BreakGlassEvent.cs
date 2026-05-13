using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Security;

public class BreakGlassEvent : Entity
{
    public Guid RequesterId { get; set; }
    public string RequesterUsername { get; set; } = string.Empty;
    public string RequesterIpAddress { get; set; } = string.Empty;
    public string ResourceType { get; set; } = string.Empty;
    public Guid? ResourceId { get; set; }
    public string ResourceName { get; set; } = string.Empty;
    public string EmergencyReason { get; set; } = string.Empty;
    public string? TicketNumber { get; set; }
    public BreakGlassStatus Status { get; set; } = BreakGlassStatus.Active;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? AcknowledgedAtUtc { get; set; }
    public Guid? AcknowledgedByUserId { get; set; }
    public string? AcknowledgedByUsername { get; set; }
    public string? AcknowledgementNotes { get; set; }
}
