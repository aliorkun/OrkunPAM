using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Identity;

public class ApiKey : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public string Prefix { get; set; } = string.Empty;
    public byte[] KeyHash { get; set; } = Array.Empty<byte>();
    public byte[] HmacSecretEnc { get; set; } = Array.Empty<byte>();
    public Guid ServiceAccountUserId { get; set; }
    public User ServiceAccountUser { get; set; } = null!;
    public string? AllowedIpCidrsJson { get; set; }
    public string? AllowedScopesJson { get; set; }
    public DateTime? ExpiresAtUtc { get; set; }
    public DateTime? LastUsedAtUtc { get; set; }
    public long UsageCount { get; set; }
    public bool IsActive { get; set; } = true;
}
