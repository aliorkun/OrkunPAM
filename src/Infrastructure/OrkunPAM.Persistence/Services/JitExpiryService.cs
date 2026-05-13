using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Background service that auto-expires JIT access requests when their ExpiresAtUtc passes.
/// Runs every 60 seconds.
/// </summary>
public sealed class JitExpiryService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<JitExpiryService> _logger;
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    public JitExpiryService(IServiceScopeFactory scopeFactory, ILogger<JitExpiryService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("JIT expiry service started");

        using var timer = new PeriodicTimer(Interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try
            {
                await ExpireOverdueRequestsAsync(stoppingToken);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "JIT expiry sweep failed");
            }
        }
    }

    private async Task ExpireOverdueRequestsAsync(CancellationToken ct)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();

        var now = DateTime.UtcNow;
        var expired = await db.JitAccessRequests
            .Where(r => r.Status == JitAccessStatus.Active && r.ExpiresAtUtc <= now)
            .ToListAsync(ct);

        if (expired.Count == 0) return;

        foreach (var req in expired)
        {
            req.Status = JitAccessStatus.Expired;
            _ = audit.LogAsync("JIT", "JitAccessExpired", req.RequesterId, req.RequesterUsername,
                null, req.ResourceType, req.ResourceId?.ToString(),
                new { durationMinutes = req.RequestedDurationMinutes, resourceName = req.ResourceName },
                AuditOutcome.Success, ct);
        }

        await db.SaveChangesAsync(ct);
        _logger.LogInformation("JIT expiry: expired {Count} access request(s)", expired.Count);
    }
}
