namespace OrkunPAM.Domain.Entities.Identity;

public enum TrustLevel { Unknown = 0, UserRegistered = 1, AdminApproved = 2, ManagedDevice = 3 }

public class TrustedDevice
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string DeviceFingerprint { get; set; } = null!;
    public Guid UserId { get; set; }
    public string? DeviceName { get; set; }
    public TrustLevel TrustLevel { get; set; } = TrustLevel.UserRegistered;
    public bool IsRevoked { get; set; } = false;
    public string? UserAgent { get; set; }
    public DateTime RegisteredAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime LastSeenAtUtc { get; set; } = DateTime.UtcNow;
}
