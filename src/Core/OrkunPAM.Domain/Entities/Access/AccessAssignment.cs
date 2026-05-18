using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Access;

/// <summary>
/// Central PAM authorization matrix: defines who can connect where with which credential.
/// Maps a principal (User or Group) to a target (Device or DeviceGroup) via a specific Credential.
/// </summary>
public class AccessAssignment : AuditableEntity
{
    // Who: User or Group
    public PrincipalType PrincipalType { get; set; }
    public Guid PrincipalId { get; set; }

    // Where: Device or DeviceGroup
    public AccessTargetType TargetType { get; set; }
    public Guid TargetId { get; set; }

    // With what credential (from vault)
    public Guid CredentialId { get; set; }

    // Which protocol (optional override — null means use device default)
    public ConnectionProtocol? Protocol { get; set; }

    // Time-based access control (optional)
    public string? TimeWindowJson { get; set; }  // e.g. "Mon-Fri 09:00-18:00"
    public DateTime? ValidFromUtc { get; set; }
    public DateTime? ValidUntilUtc { get; set; }

    // Session policy override (optional)
    public Guid? SessionPolicyId { get; set; }

    // Status
    public bool IsEnabled { get; set; } = true;
    public string? Description { get; set; }
}
