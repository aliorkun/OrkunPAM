namespace OrkunPAM.Domain.Entities.Vault;

public class CredentialTemplate : OrkunPAM.SharedKernel.AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string DeviceType { get; set; } = string.Empty;
    public string? DefaultUsername { get; set; }
    public string CredentialKind { get; set; } = "Linux";
    public int RotationPeriodDays { get; set; } = 90;
    public int PasswordMinLength { get; set; } = 16;
    public bool PasswordRequireSpecial { get; set; } = true;
    public bool SshKeyRotation { get; set; }
    public string? Notes { get; set; }
    public bool IsBuiltIn { get; set; }
}
