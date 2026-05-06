using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

public interface IAuditService
{
    Task LogAsync(string category, string eventType, Guid? actorUserId, string? actorUsername,
        string? actorIp, string? targetType, string? targetId, object? details,
        AuditOutcome outcome = AuditOutcome.Success, CancellationToken ct = default);
}

/// <summary>
/// Tamper-proof audit logging with hash chain.
/// Each entry includes SHA-256 hash of previous entry, making tampering detectable.
/// </summary>
public sealed class AuditService : IAuditService
{
    private readonly OrkunPamDbContext _db;
    private readonly ILogger<AuditService> _logger;
    private byte[]? _lastHash;
    private readonly SemaphoreSlim _lock = new(1, 1);

    public AuditService(OrkunPamDbContext db, ILogger<AuditService> logger)
    {
        _db = db;
        _logger = logger;
    }

    public async Task LogAsync(string category, string eventType, Guid? actorUserId, string? actorUsername,
        string? actorIp, string? targetType, string? targetId, object? details,
        AuditOutcome outcome = AuditOutcome.Success, CancellationToken ct = default)
    {
        await _lock.WaitAsync(ct);
        try
        {
            var detailsJson = details != null ? JsonSerializer.Serialize(details) : null;
            var traceId = System.Diagnostics.Activity.Current?.TraceId.ToString();

            var entry = new AuditLogEntry
            {
                EventCategory = category,
                EventType = eventType,
                ActorUserId = actorUserId,
                ActorUsername = actorUsername,
                ActorIpAddress = actorIp,
                TargetType = targetType,
                TargetId = targetId,
                Details = detailsJson,
                Outcome = outcome,
                TraceId = traceId,
                PreviousHash = _lastHash
            };

            // Compute tamper-proof hash: SHA256(timestamp + event + actor + target + previousHash)
            var hashInput = $"{entry.Timestamp:O}|{entry.EventType}|{entry.ActorUserId}|{entry.TargetId}|{Convert.ToBase64String(_lastHash ?? [])}";
            entry.EntryHash = SHA256.HashData(Encoding.UTF8.GetBytes(hashInput));
            _lastHash = entry.EntryHash;

            _db.AuditLogs.Add(entry);
            await _db.SaveChangesAsync(ct);

            _logger.LogDebug("Audit: [{Category}] {EventType} by {Actor} on {Target} = {Outcome}",
                category, eventType, actorUsername ?? "system", targetId ?? "n/a", outcome);
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to write audit log: {Category}/{EventType}", category, eventType);
        }
        finally
        {
            _lock.Release();
        }
    }
}
