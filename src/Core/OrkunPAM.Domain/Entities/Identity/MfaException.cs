using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Identity;

public class MfaException : AuditableEntity
{
    public Guid UserId { get; set; }
    public User User { get; set; } = null!;
    public Guid RequestedByUserId { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public string Reason { get; set; } = string.Empty;
    public MfaExceptionStatus Status { get; set; } = MfaExceptionStatus.Pending;
    public DateTime ExpiresAtUtc { get; set; }
    public DateTime? RevokedAtUtc { get; set; }
    public int MaxUsageCount { get; set; } = 1;
    public int UsageCount { get; set; }
    public string? IpCidrRestriction { get; set; }
    public string? AppliedMfaTypesJson { get; set; }
}
