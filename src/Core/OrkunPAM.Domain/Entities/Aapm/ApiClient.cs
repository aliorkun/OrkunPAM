using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Aapm;

public class ApiClient : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string ClientId { get; set; } = string.Empty;
    public string ClientSecretHash { get; set; } = string.Empty;
    public string? AllowedIpRanges { get; set; } // JSON array of CIDR
    public Guid? ServiceAccountId { get; set; }
    public int RateLimitPerMinute { get; set; } = 60;
    public bool IsEnabled { get; set; } = true;
    public DateTime? LastUsedAtUtc { get; set; }

    public ICollection<ApiClientCredentialAccess> CredentialAccess { get; set; } = new List<ApiClientCredentialAccess>();
}

public class ApiClientCredentialAccess
{
    public Guid ApiClientId { get; set; }
    public ApiClient ApiClient { get; set; } = null!;
    public Guid CredentialId { get; set; }
}

public class ApiAccessLog
{
    public long Id { get; set; }
    public Guid ApiClientId { get; set; }
    public Guid CredentialId { get; set; }
    public DateTime RequestedAtUtc { get; set; } = DateTime.UtcNow;
    public string? ClientIpAddress { get; set; }
    public byte Outcome { get; set; } // 0=Granted, 1=Denied, 2=RateLimited
}
