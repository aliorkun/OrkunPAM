using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Access;

/// <summary>
/// Kron PAM assigned_credential model.
/// Assigns a vault credential to a user or group,
/// optionally scoped to a specific device group.
/// </summary>
public class AssignedCredential : AuditableEntity
{
    public Guid CredentialId { get; set; }
    public Credential Credential { get; set; } = null!;

    // Who gets access: User (0) or Group (1)
    public PrincipalType PrincipalType { get; set; }
    public Guid PrincipalId { get; set; }

    // Optional scope — null means all devices the credential is linked to
    public Guid? DeviceGroupId { get; set; }
    public DeviceGroup? DeviceGroup { get; set; }

    public bool IsEnabled { get; set; } = true;
    public string? Notes { get; set; }
}
