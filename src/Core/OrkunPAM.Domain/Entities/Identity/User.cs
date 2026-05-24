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

    public bool IsOrphaned { get; set; }
    public DateTime? OrphanedDetectedAtUtc { get; set; }

    // API Key service accounts (#250)
    public bool IsServiceAccount { get; set; }

    // Vendor user fields (#186)
    public UserType UserType { get; set; } = UserType.Regular;
    public Guid? VendorSponsorUserId { get; set; }
    public string? VendorDeviceIdsJson { get; set; }

    // PKI / Smart Card authentication (#115)
    public bool RequirePkiAuth { get; set; }

    // Portal profile — controls which UI sections the user can access
    public PortalProfile PortalProfile { get; set; } = PortalProfile.StandardUser;

    // MFA Enrollment Token (admin-generated, one-time use, 24h TTL)
    public Guid? MfaEnrollmentToken { get; set; }
    public DateTime? MfaEnrollmentTokenExpiry { get; set; }

    // MFA Recovery Codes (JSON array of SHA256-hashed one-time codes)
    public string? RecoveryCodesHash { get; set; }

    // Self-Service Password Reset
    public string? PasswordResetToken { get; set; }
    public DateTime? PasswordResetExpiry { get; set; }

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

// MFA Trusted Session — allows skipping MFA for recognized browsers (#257)
public class MfaTrustedSession
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    public string BrowserFingerprint { get; set; } = string.Empty;
    public string? DeviceLabel { get; set; }
    public DateTime TrustExpiresAtUtc { get; set; }
    public string? GrantedFromIp { get; set; }
    public DateTime GrantedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LastUsedAtUtc { get; set; }
    public bool IsRevoked { get; set; }
}
