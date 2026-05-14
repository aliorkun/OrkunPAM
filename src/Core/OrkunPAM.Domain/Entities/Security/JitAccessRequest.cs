using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Security;

/// <summary>
/// Just-In-Time privileged access request. Grants temporary, time-bounded access
/// to a resource. Access is automatically revoked when ExpiresAtUtc is reached.
/// </summary>
public class JitAccessRequest : Entity
{
    public Guid RequesterId { get; set; }
    public string RequesterUsername { get; set; } = string.Empty;
    public string RequesterIpAddress { get; set; } = string.Empty;

    public string ResourceType { get; set; } = string.Empty;   // "Device" | "Credential"
    public Guid? ResourceId { get; set; }
    public string ResourceName { get; set; } = string.Empty;

    public string Reason { get; set; } = string.Empty;
    public int RequestedDurationMinutes { get; set; }

    public JitAccessStatus Status { get; set; } = JitAccessStatus.Pending;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Approval
    public DateTime? ApprovedAtUtc { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public string? ApprovedByUsername { get; set; }
    public string? DenyReason { get; set; }

    // Active window
    public DateTime? ActivatedAtUtc { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }

    // Revocation
    public string? RevokeReason { get; set; }
    public Guid? RevokedByUserId { get; set; }
    public string? RevokedByUsername { get; set; }

    // Extension
    public bool ExtensionRequested { get; set; }
    public int? ExtensionRequestedMinutes { get; set; }
    public string? ExtensionReason { get; set; }
}
