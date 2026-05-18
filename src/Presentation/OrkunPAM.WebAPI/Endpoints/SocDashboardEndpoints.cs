using Microsoft.EntityFrameworkCore;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SocDashboardEndpoints
{
    public static void MapSocDashboardEndpoints(this IEndpointRouteBuilder app)
    {
        var soc = app.MapGroup("/api/v1/analytics/soc").WithTags("Analytics");

        // SOC overview dashboard
        soc.MapGet("/dashboard", async (OrkunPamDbContext db) =>
        {
            var since24h = DateTime.UtcNow.AddHours(-24);

            var totalAnomalies24h = await db.Anomalies.CountAsync(a => a.DetectedAtUtc >= since24h);
            var unacknowledged    = await db.Anomalies.CountAsync(a => !a.IsAcknowledged);
            var criticalUnacked   = await db.Anomalies.CountAsync(a => !a.IsAcknowledged && a.Severity >= 3);

            // Fetch raw for grouping (client-side to avoid EF translation issues with Math.Min / decimal casts)
            var recent24h = await db.Anomalies
                .Where(a => a.DetectedAtUtc >= since24h)
                .Select(a => new { a.AnomalyType })
                .ToListAsync();

            var typeBreakdown = recent24h
                .GroupBy(a => a.AnomalyType)
                .Select(g => new { Type = g.Key, Count = g.Count() })
                .ToList();

            var unackedRaw = await db.Anomalies
                .Where(a => !a.IsAcknowledged)
                .Select(a => new { a.UserId, a.Severity })
                .ToListAsync();

            var topRiskyUsers = unackedRaw
                .GroupBy(a => a.UserId)
                .Select(g => new
                {
                    UserId       = g.Key,
                    AnomalyCount = g.Count(),
                    MaxSeverity  = g.Max(a => a.Severity),
                    RiskScore    = Math.Min(100m, g.Sum(a => (decimal)a.Severity * 25))
                })
                .OrderByDescending(u => u.RiskScore)
                .Take(10)
                .ToList();

            var recentAnomalies = await db.Anomalies
                .OrderByDescending(a => a.DetectedAtUtc)
                .Take(20)
                .Select(a => new
                {
                    a.Id, a.UserId, a.SessionId, a.AnomalyType, a.Severity,
                    a.Details, a.DetectedAtUtc, a.IsAcknowledged
                })
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = new { totalAnomalies24h, unacknowledged, criticalUnacked, typeBreakdown, topRiskyUsers, recentAnomalies }
            });
        });

        // Hourly anomaly timeline (client-side grouping)
        soc.MapGet("/timeline", async (OrkunPamDbContext db, int hours = 24) =>
        {
            var since = DateTime.UtcNow.AddHours(-hours);

            var raw = await db.Anomalies
                .Where(a => a.DetectedAtUtc >= since)
                .Select(a => new { a.DetectedAtUtc, a.Severity })
                .ToListAsync();

            var timeline = raw
                .GroupBy(a => new DateTime(a.DetectedAtUtc.Year, a.DetectedAtUtc.Month,
                    a.DetectedAtUtc.Day, a.DetectedAtUtc.Hour, 0, 0, DateTimeKind.Utc))
                .Select(g => new { Hour = g.Key, Count = g.Count(), MaxSeverity = g.Max(a => a.Severity) })
                .OrderBy(x => x.Hour)
                .ToList();

            return Results.Ok(new { success = true, data = timeline });
        });

        // Per-user risk map (client-side grouping)
        soc.MapGet("/risk-map", async (OrkunPamDbContext db) =>
        {
            var raw = await db.Anomalies
                .Where(a => !a.IsAcknowledged)
                .Select(a => new { a.UserId, a.AnomalyType, a.Severity, a.DetectedAtUtc })
                .ToListAsync();

            var riskMap = raw
                .GroupBy(a => a.UserId)
                .Select(g => new
                {
                    UserId          = g.Key,
                    AnomalyCount    = g.Count(),
                    OffHours        = g.Count(a => a.AnomalyType == "OffHours"),
                    UnusualIp       = g.Count(a => a.AnomalyType == "UnusualIP"),
                    UnusualDevice   = g.Count(a => a.AnomalyType == "UnusualDevice"),
                    FrequencySpike  = g.Count(a => a.AnomalyType == "FrequencySpike"),
                    HighRiskCommand = g.Count(a => a.AnomalyType == "HighRiskCommand"),
                    MaxSeverity     = g.Max(a => a.Severity),
                    RiskScore       = Math.Min(100m, g.Sum(a => (decimal)a.Severity * 25)),
                    LastDetected    = g.Max(a => a.DetectedAtUtc)
                })
                .OrderByDescending(u => u.RiskScore)
                .ToList();

            return Results.Ok(new { success = true, data = riskMap });
        });

        // Alert history
        soc.MapGet("/alert-history", async (OrkunPamDbContext db, int page = 1, int pageSize = 50) =>
        {
            var total = await db.AlertHistories.CountAsync();
            var list = await db.AlertHistories
                .OrderByDescending(h => h.TriggeredAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(h => new { h.Id, h.AlertRuleId, h.TriggeredAtUtc, h.Details, h.ActionsTaken })
                .ToListAsync();
            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        // === Behavior Baselines ===
        var baselines = app.MapGroup("/api/v1/analytics/baselines").WithTags("Analytics");

        baselines.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.UserBehaviorBaselines
                .Select(b => new { b.UserId, b.BaselineDate, b.UpdatedAtUtc, b.TypicalHoursJson, b.KnownIpsJson, b.KnownDevicesJson })
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        baselines.MapGet("/{userId:guid}", async (Guid userId, OrkunPamDbContext db) =>
        {
            var b = await db.UserBehaviorBaselines.FirstOrDefaultAsync(x => x.UserId == userId);
            if (b == null) return Results.NotFound(new { success = false, errors = new[] { "Baseline not found" } });
            return Results.Ok(new { success = true, data = b });
        });

        // Returns 202 — actual work done by BehaviorBaselineService on next daily cycle
        baselines.MapPost("/rebuild", () =>
            Results.Accepted("/api/v1/analytics/baselines", new
            {
                success = true,
                message = "Baseline rebuild queued. Completes within the next background service cycle (up to 24 h)."
            }));

        // Alert rule delete
        app.MapDelete("/api/v1/analytics/alerts/rules/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var rule = await db.AlertRules.FindAsync(id);
            if (rule == null) return Results.NotFound(new { success = false, errors = new[] { "Alert rule not found" } });
            db.AlertRules.Remove(rule);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        }).WithTags("Analytics");

        // Alert rule toggle enabled/disabled
        app.MapPut("/api/v1/analytics/alerts/rules/{id:guid}/toggle", async (Guid id, OrkunPamDbContext db) =>
        {
            var rule = await db.AlertRules.FindAsync(id);
            if (rule == null) return Results.NotFound(new { success = false, errors = new[] { "Alert rule not found" } });
            rule.IsEnabled = !rule.IsEnabled;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { rule.IsEnabled } });
        }).WithTags("Analytics");
    }
}
