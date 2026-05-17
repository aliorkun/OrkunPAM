using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Integration;

// === Cloud PAM — AWS / Azure / GCP Privileged Access (#37) ===

public class CloudAccount : AuditableEntity
{
    public string Name { get; set; } = string.Empty;
    public string Provider { get; set; } = string.Empty;  // "AWS" | "Azure" | "GCP"
    public string AccountIdentifier { get; set; } = string.Empty; // AWS AccountId / Azure TenantId / GCP ProjectId
    public string? Region { get; set; }                    // default region (AWS)
    public string? AccessKeyIdEnc { get; set; }            // AWS access key / Azure client ID (encrypted)
    public string? SecretKeyEnc { get; set; }              // AWS secret / Azure client secret (encrypted)
    public string? AdditionalConfigJson { get; set; }      // role ARN, subscription ID, etc.
    public bool IsEnabled { get; set; } = true;
    public DateTime? LastSyncAtUtc { get; set; }
    public int ResourceCount { get; set; }
    public string? LastSyncError { get; set; }

    public ICollection<CloudResource> Resources { get; set; } = new List<CloudResource>();
}

public class CloudResource : AuditableEntity
{
    public Guid CloudAccountId { get; set; }
    public CloudAccount? CloudAccount { get; set; }
    public string Provider { get; set; } = string.Empty;   // denormalized for fast queries
    public string NativeId { get; set; } = string.Empty;   // arn:aws:..., /subscriptions/.., projects/...
    public string Name { get; set; } = string.Empty;
    public string ResourceType { get; set; } = string.Empty; // EC2Instance, VM, S3Bucket, IAMUser, IAMRole, KeyVault, GCEInstance
    public string? Region { get; set; }
    public string? Status { get; set; }                    // Running, Stopped, Available, etc.
    public string? IpAddress { get; set; }
    public string? MetadataJson { get; set; }              // tags, OS type, size, etc.
    public bool IsEnabled { get; set; } = true;
    public DateTime? LastSeenAtUtc { get; set; }

    public ICollection<CloudJitRequest> JitRequests { get; set; } = new List<CloudJitRequest>();
}

public class CloudJitRequest : AuditableEntity
{
    public Guid RequestedByUserId { get; set; }
    public string RequestedByUsername { get; set; } = string.Empty;
    public Guid CloudResourceId { get; set; }
    public CloudResource? CloudResource { get; set; }
    public string Permission { get; set; } = string.Empty;  // ReadOnly, PowerUser, Admin, SSHAccess, RDPAccess
    public string Justification { get; set; } = string.Empty;
    public string Status { get; set; } = "Pending";          // Pending, Approved, Active, Expired, Revoked, Denied
    public DateTime RequestedAtUtc { get; set; } = DateTime.UtcNow;
    public int DurationMinutes { get; set; } = 60;
    public DateTime? ExpiresAtUtc { get; set; }
    public Guid? ApprovedByUserId { get; set; }
    public string? ApprovedByUsername { get; set; }
    public DateTime? GrantedAtUtc { get; set; }
    public string? CloudGrantReference { get; set; }  // ARN of assumed role, RBAC assignment ID, etc.
    public DateTime? RevokedAtUtc { get; set; }
    public string? RevokeReason { get; set; }
    public string? TicketNumber { get; set; }
}
