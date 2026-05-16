using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Session;

/// <summary>Connection Scheduling (#142) — ileri tarihli oturum rezervasyonu.</summary>
public class ScheduledSession : Entity
{
    public Guid RequesterId { get; set; }
    public string RequesterUsername { get; set; } = string.Empty;

    public Guid DeviceId { get; set; }
    public string DeviceName { get; set; } = string.Empty;

    public Guid CredentialId { get; set; }
    public SessionType Protocol { get; set; }

    public DateTime ScheduledStartUtc { get; set; }
    public DateTime ScheduledEndUtc { get; set; }

    public string? Reason { get; set; }
    public ScheduledSessionStatus Status { get; set; } = ScheduledSessionStatus.Pending;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;

    // Admin approval
    public Guid? ApprovedById { get; set; }
    public string? ApprovedByUsername { get; set; }
    public DateTime? ApprovedAtUtc { get; set; }
    public string? AdminNotes { get; set; }

    // Auto-expire unapproved reservations (default: 24h after creation)
    public DateTime ExpiresAtUtc { get; set; }

    // Linked session once started
    public Guid? ProxySessionId { get; set; }
    public DateTime? ActualStartUtc { get; set; }
    public DateTime? ActualEndUtc { get; set; }
}
