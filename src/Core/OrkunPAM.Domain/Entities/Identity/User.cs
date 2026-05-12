using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Identity;

public class User : SoftDeletableEntity
{
    public string Username { get; set; } = string.Empty;
    public string NormalizedUsername { get; set; } = string.Empty;
    public string? DisplayName { get; set; }
    public string? Email { get; set; }
    public string? PasswordHash { get; set; }
    public AuthSource AuthSource { get; set; } = AuthSource.Local;
    public string? ExternalId { get; set; }
    public bool MfaEnabled { get; set; }
    public byte[]? MfaSecret { get; set; }
    public MfaType MfaType { get; set; } = MfaType.Totp;
    public string? Phone { get; set; }
    public UserStatus Status { get; set; } = UserStatus.Active;
    public bool IsTemporary { get; set; }
    public DateTime? TemporaryExpiresUtc { get; set; }
    public DateTime? PasswordLastChanged { get; set; }
    public DateTime? PasswordExpiresAt { get; set; }
    public bool MustChangePassword { get; set; }
    public DateTime? LastLoginAtUtc { get; set; }
    public string? LastLoginIp { get; set; }
    public int FailedLoginCount { get; set; }
    public DateTime? LockoutEndUtc { get; set; }
    public string Language { get; set; } = "tr-TR";
    public string Timezone { get; set; } = "Europe/Istanbul";

    // Navigation
    public ICollection<UserGroup> UserGroups { get; set; } = new List<UserGroup>();
    public ICollection<UserRole> UserRoles { get; set; } = new List<UserRole>();
    public ICollection<UserPasswordHistory> PasswordHistories { get; set; } = new List<UserPasswordHistory>();

    public bool IsLocked => Status == UserStatus.Locked ||
                           (LockoutEndUtc.HasValue && LockoutEndUtc > DateTime.UtcNow);

    public void RecordLoginSuccess(string ipAddress)
    {
        FailedLoginCount = 0;
        LockoutEndUtc = null;
        LastLoginAtUtc = DateTime.UtcNow;
        LastLoginIp = ipAddress;
    }

    public void RecordLoginFailure(int maxAttempts, int lockoutMinutes)
    {
        FailedLoginCount++;
        if (FailedLoginCount >= maxAttempts)
        {
            Status = UserStatus.Locked;
            LockoutEndUtc = DateTime.UtcNow.AddMinutes(lockoutMinutes);
        }
    }
}

public class UserGroup
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    public Guid GroupId { get; set; }
    public Group Group { get; set; } = null!;
}

public class UserRole
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    public Guid RoleId { get; set; }
    public Role Role { get; set; } = null!;
}

public class UserPasswordHistory
{
    public long Id { get; set; }
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    public string PasswordHash { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
