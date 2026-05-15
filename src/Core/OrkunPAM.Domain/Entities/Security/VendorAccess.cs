using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Security;

public class VendorAccess : Entity
{
    // Vendor identity
    public string VendorName { get; set; } = string.Empty;
    public string Company { get; set; } = string.Empty;
    public string Email { get; set; } = string.Empty;
    public string? Phone { get; set; }

    // Access window
    public DateTime StartAtUtc { get; set; }
    public DateTime EndAtUtc { get; set; }
    public int? AllowedHoursStart { get; set; }  // 0-23, null = no restriction
    public int? AllowedHoursEnd { get; set; }    // 0-23, null = no restriction
    public int MaxSessionMinutesPerDay { get; set; } = 120;

    // Authorized devices (JSON array of Guid strings)
    public string AuthorizedDeviceIdsJson { get; set; } = "[]";

    // Optional IP whitelist (comma-separated)
    public string? IpWhitelist { get; set; }

    // Invite link
    public string InviteToken { get; set; } = string.Empty;
    public DateTime InviteExpiresAtUtc { get; set; }
    public DateTime? InviteUsedAtUtc { get; set; }
    public bool SingleUseInvite { get; set; } = false;

    // Status
    public VendorAccessStatus Status { get; set; } = VendorAccessStatus.Pending;

    // Admin who created it
    public Guid CreatedByUserId { get; set; }
    public string CreatedByUsername { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Revocation
    public string? RevokeReason { get; set; }
    public Guid? RevokedByUserId { get; set; }
    public string? RevokedByUsername { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
}
