using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Vault;

public class VaultFolder : AuditableEntity
{
    public Guid? ParentFolderId { get; set; }
    public VaultFolder? ParentFolder { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public bool IsPersonalVault { get; set; }
    public Guid? OwnerUserId { get; set; }

    public ICollection<VaultFolder> ChildFolders { get; set; } = new List<VaultFolder>();
    public ICollection<Credential> Credentials { get; set; } = new List<Credential>();
    public ICollection<CredentialPermission> Permissions { get; set; } = new List<CredentialPermission>();
}

public class Credential : AuditableEntity
{
    public Guid FolderId { get; set; }
    public VaultFolder Folder { get; set; } = null!;
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public CredentialType CredentialType { get; set; }
    public string? Username { get; set; }
    public byte[]? PasswordEnc { get; set; }
    public byte[]? PrivateKeyEnc { get; set; }
    public byte[]? AdditionalDataEnc { get; set; }
    public Guid? DeviceId { get; set; }
    public int KeyVersion { get; set; }
    public string? Tags { get; set; }
    public bool IsDiscovered { get; set; }
    public bool IsTakenOver { get; set; }
    public Guid? RotationPolicyId { get; set; }
    public RotationPolicy? RotationPolicy { get; set; }
    public DateTime? LastRotatedAtUtc { get; set; }
    public DateTime? NextRotationAtUtc { get; set; }
    public Guid? CheckedOutByUserId { get; set; }
    public DateTime? CheckedOutAtUtc { get; set; }
    public DateTime? CheckOutExpiresUtc { get; set; }
    public int MaxCheckoutMinutes { get; set; } = 60;
    public bool RequiresApproval { get; set; }
    public CredentialStatus Status { get; set; } = CredentialStatus.Active;
    public int Version { get; set; } = 1;

    public ICollection<CredentialPermission> Permissions { get; set; } = new List<CredentialPermission>();
    public ICollection<PasswordHistory> PasswordHistories { get; set; } = new List<PasswordHistory>();

    public bool IsAvailableForCheckout =>
        Status == CredentialStatus.Active && CheckedOutByUserId == null;

    public Result CheckOut(Guid userId, int maxMinutes)
    {
        if (!IsAvailableForCheckout)
            return Result.Failure(Error.Conflict($"Credential '{Name}' is not available. Current status: {Status}"));

        CheckedOutByUserId = userId;
        CheckedOutAtUtc = DateTime.UtcNow;
        CheckOutExpiresUtc = DateTime.UtcNow.AddMinutes(maxMinutes > 0 ? maxMinutes : MaxCheckoutMinutes);
        Status = CredentialStatus.CheckedOut;
        return Result.Success();
    }

    public Result CheckIn()
    {
        if (Status != CredentialStatus.CheckedOut)
            return Result.Failure(Error.Conflict($"Credential '{Name}' is not checked out."));

        CheckedOutByUserId = null;
        CheckedOutAtUtc = null;
        CheckOutExpiresUtc = null;
        Status = CredentialStatus.Active;
        return Result.Success();
    }
}

public class CredentialPermission : Entity
{
    public Guid? CredentialId { get; set; }
    public Credential? Credential { get; set; }
    public Guid? FolderId { get; set; }
    public VaultFolder? Folder { get; set; }
    public PrincipalType PrincipalType { get; set; }
    public Guid PrincipalId { get; set; }
    public PermissionLevel PermissionLevel { get; set; }
    public bool CanShare { get; set; }
}

public class PasswordHistory
{
    public long Id { get; set; }
    public Guid CredentialId { get; set; }
    public byte[] PasswordEnc { get; set; } = [];
    public DateTime ChangedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid? ChangedBy { get; set; }
    public PasswordChangeReason ChangeReason { get; set; }
}

public class RotationPolicy : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public int IntervalDays { get; set; } = 30;
    public string? PasswordComplexityJson { get; set; }
    public bool RotateOnCheckIn { get; set; }
    public int NotifyBeforeDays { get; set; } = 3;
    public RotationConnector ConnectorType { get; set; }
    public int RetryCount { get; set; } = 3;
    public int RetryIntervalMinutes { get; set; } = 15;
}

public class CheckOutHistory
{
    public long Id { get; set; }
    public Guid CredentialId { get; set; }
    public Guid UserId { get; set; }
    public DateTime CheckedOutAtUtc { get; set; }
    public DateTime? CheckedInAtUtc { get; set; }
    public string? Reason { get; set; }
    public string? TicketNumber { get; set; }
    public Guid? ApprovedBy { get; set; }
    public bool WasAutoCheckedIn { get; set; }
}

public class CredentialShare : Entity
{
    public Guid CredentialId { get; set; }
    public Guid SharedByUserId { get; set; }
    public Guid SharedToUserId { get; set; }
    public PermissionLevel PermissionLevel { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }
    public int? MaxUseCount { get; set; }
    public int UseCount { get; set; }
}
