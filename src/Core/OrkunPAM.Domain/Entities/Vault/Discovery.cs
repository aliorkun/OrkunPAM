using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Vault;

public class DiscoveryJob : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public DiscoveryType DiscoveryType { get; set; }
    public string? TargetScopeJson { get; set; } // JSON: OUs, IP ranges, etc.
    public string? Schedule { get; set; } // Cron expression
    public DateTime? LastRunAtUtc { get; set; }
    public string? LastRunResult { get; set; }
    public bool IsEnabled { get; set; } = true;
}

public class DiscoveredAccount : Entity
{
    public Guid DiscoveryJobId { get; set; }
    public Guid? DeviceId { get; set; }
    public string AccountName { get; set; } = string.Empty;
    public string? AccountType { get; set; } // "LocalAdmin", "DomainAdmin", "ServiceAccount"
    public DateTime DiscoveredAtUtc { get; set; } = DateTime.UtcNow;
    public TakeoverStatus TakeoverStatus { get; set; } = TakeoverStatus.Pending;
    public Guid? LinkedCredentialId { get; set; }
}
