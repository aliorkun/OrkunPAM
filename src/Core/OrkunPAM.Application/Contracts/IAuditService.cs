using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Application-layer abstraction for tamper-proof audit logging.
/// Implemented by Infrastructure.Persistence.
/// </summary>
public interface IAuditService
{
    Task LogAsync(string category, string eventType, Guid? actorUserId, string? actorUsername,
        string? actorIp, string? targetType, string? targetId, object? details,
        AuditOutcome outcome = AuditOutcome.Success, CancellationToken ct = default);
}
