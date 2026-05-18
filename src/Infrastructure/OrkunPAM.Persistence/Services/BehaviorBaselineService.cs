using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Entities.Analytics;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Runs daily. Analyses the past 30 days of session history per user
/// and computes typical access hours, known IPs, and known devices.
/// </summary>
public sealed class BehaviorBaselineService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<BehaviorBaselineService> _logger;

    public BehaviorBaselineService(IServiceScopeFactory scopeFactory, ILogger<BehaviorBaselineService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromMinutes(10), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await BuildBaselinesAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogError(ex, "Behavior baseline build error"); }
            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }

    internal async Task BuildBaselinesAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();

        var cutoff = DateTime.UtcNow.AddDays(-30);

        // Fetch raw data first, then convert Guid to string client-side (EF can't translate Guid.ToString())
        var rawSessions = await db.ProxySessions
            .Where(s => s.StartedAtUtc >= cutoff)
            .Select(s => new { s.UserId, s.StartedAtUtc, s.ClientIpAddress, s.DeviceId })
            .ToListAsync(ct);

        var sessions = rawSessions
            .Select(s => new { s.UserId, s.StartedAtUtc, s.ClientIpAddress, DeviceId = s.DeviceId.ToString() })
            .ToList();

        if (sessions.Count == 0) return;

        var existing = await db.UserBehaviorBaselines.ToDictionaryAsync(b => b.UserId, ct);
        int updated = 0;

        foreach (var userGroup in sessions.GroupBy(s => s.UserId))
        {
            var list = userGroup.ToList();
            int total = list.Count;

            // Hours with > 10% of session frequency are "typical"
            var typicalHours = list
                .GroupBy(s => s.StartedAtUtc.Hour)
                .Where(g => (double)g.Count() / total > 0.10)
                .Select(g => g.Key)
                .OrderBy(h => h)
                .ToList();

            // IPs seen at least min-count times
            int minIp = total >= 9 ? 3 : 1;
            var knownIps = list
                .Where(s => s.ClientIpAddress != null)
                .GroupBy(s => s.ClientIpAddress!)
                .Where(g => g.Count() >= minIp)
                .Select(g => g.Key)
                .ToList();

            // Devices seen at least 2 times (or once if only 1 session)
            int minDev = total >= 2 ? 2 : 1;
            var knownDevices = list
                .GroupBy(s => s.DeviceId)
                .Where(g => g.Count() >= minDev)
                .Select(g => g.Key)
                .ToList();

            if (existing.TryGetValue(userGroup.Key, out var baseline))
            {
                baseline.TypicalHoursJson  = JsonSerializer.Serialize(typicalHours);
                baseline.KnownIpsJson      = JsonSerializer.Serialize(knownIps);
                baseline.KnownDevicesJson  = JsonSerializer.Serialize(knownDevices);
                baseline.UpdatedAtUtc      = DateTime.UtcNow;
            }
            else
            {
                db.UserBehaviorBaselines.Add(new UserBehaviorBaseline
                {
                    UserId            = userGroup.Key,
                    TypicalHoursJson  = JsonSerializer.Serialize(typicalHours),
                    KnownIpsJson      = JsonSerializer.Serialize(knownIps),
                    KnownDevicesJson  = JsonSerializer.Serialize(knownDevices),
                    BaselineDate      = cutoff,
                    UpdatedAtUtc      = DateTime.UtcNow
                });
            }

            updated++;
        }

        await db.SaveChangesAsync(ct);
        _logger.LogInformation("Behavior baselines updated for {Count} users", updated);
    }
}
