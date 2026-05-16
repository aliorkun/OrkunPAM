using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Connection Scheduling (#142) — runs every 60s to:
/// 1. Expire pending reservations that passed their expiry window.
/// 2. Activate approved reservations whose start time has arrived.
/// 3. Complete active scheduled sessions whose end time has passed.
/// </summary>
public sealed class SessionSchedulerService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<SessionSchedulerService> _logger;
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    public SessionSchedulerService(IServiceScopeFactory scopeFactory, ILogger<SessionSchedulerService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("SessionSchedulerService started");

        using var timer = new PeriodicTimer(Interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try { await TickAsync(stoppingToken); }
            catch (Exception ex) { _logger.LogError(ex, "SessionSchedulerService tick failed"); }
        }
    }

    private async Task TickAsync(CancellationToken ct)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();
        var now = DateTime.UtcNow;

        // 1. Expire pending reservations past their expiry window
        var toExpire = await db.ScheduledSessions
            .Where(s => s.Status == ScheduledSessionStatus.Pending && s.ExpiresAtUtc <= now)
            .ToListAsync(ct);

        foreach (var s in toExpire)
        {
            s.Status = ScheduledSessionStatus.Expired;
            try
            {
                await audit.LogAsync("Session", "ScheduledSessionExpired", s.RequesterId, s.RequesterUsername,
                    null, "ScheduledSession", s.Id.ToString(),
                    new { device = s.DeviceName, start = s.ScheduledStartUtc },
                    AuditOutcome.Success, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Audit log failed for ScheduledSessionExpired {SessionId}", s.Id);
            }
        }

        // 2. Activate approved sessions whose start time arrived
        var toActivate = await db.ScheduledSessions
            .Where(s => s.Status == ScheduledSessionStatus.Approved && s.ScheduledStartUtc <= now)
            .ToListAsync(ct);

        foreach (var s in toActivate)
        {
            s.Status = ScheduledSessionStatus.Active;
            s.ActualStartUtc = now;
            try
            {
                await audit.LogAsync("Session", "ScheduledSessionActivated", s.RequesterId, s.RequesterUsername,
                    null, "ScheduledSession", s.Id.ToString(),
                    new { device = s.DeviceName },
                    AuditOutcome.Success, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Audit log failed for ScheduledSessionActivated {SessionId}", s.Id);
            }
        }

        // 3. Complete active sessions whose end time passed
        var toComplete = await db.ScheduledSessions
            .Where(s => s.Status == ScheduledSessionStatus.Active && s.ScheduledEndUtc <= now)
            .ToListAsync(ct);

        foreach (var s in toComplete)
        {
            s.Status = ScheduledSessionStatus.Completed;
            s.ActualEndUtc = now;

            // If there's a linked ProxySession, terminate it
            if (s.ProxySessionId.HasValue)
            {
                var proxy = await db.ProxySessions.FindAsync([s.ProxySessionId.Value], ct);
                if (proxy != null && proxy.Status == SessionStatus.Active)
                    proxy.Terminate(Guid.Empty, "Scheduled session end time reached");
            }

            try
            {
                await audit.LogAsync("Session", "ScheduledSessionCompleted", s.RequesterId, s.RequesterUsername,
                    null, "ScheduledSession", s.Id.ToString(),
                    new { device = s.DeviceName, durationMin = (int)(s.ScheduledEndUtc - s.ScheduledStartUtc).TotalMinutes },
                    AuditOutcome.Success, ct);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Audit log failed for ScheduledSessionCompleted {SessionId}", s.Id);
            }
        }

        var changed = toExpire.Count + toActivate.Count + toComplete.Count;
        if (changed > 0)
        {
            await db.SaveChangesAsync(ct);
            _logger.LogInformation("SessionScheduler: expired={E} activated={A} completed={C}",
                toExpire.Count, toActivate.Count, toComplete.Count);
        }
    }
}
