using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Analytics;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class AnalyticsEndpoints
{
    public static void MapAnalyticsEndpoints(this IEndpointRouteBuilder app)
    {
        var uba = app.MapGroup("/api/v1/analytics/uba").WithTags("Analytics").RequireAuthorization("AdminPolicy");

        uba.MapGet("/rules", async (OrkunPamDbContext db) =>
        {
            var rules = await db.CommandRiskRules
                .Select(r => new { r.Id, r.Pattern, r.RiskScore, r.Category, r.Description })
                .ToListAsync();
            return Results.Ok(new { success = true, data = rules });
        });

        uba.MapPost("/rules", async (CreateRiskRuleRequest req, OrkunPamDbContext db) =>
        {
            var rule = new CommandRiskRule
            {
                Pattern = req.Pattern,
                RiskScore = req.RiskScore,
                Category = req.Category,
                Description = req.Description
            };
            db.CommandRiskRules.Add(rule);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/analytics/uba/rules/{rule.Id}", new { success = true, data = new { rule.Id } });
        });

        var anomalies = app.MapGroup("/api/v1/analytics/anomalies").WithTags("Analytics").RequireAuthorization("AdminPolicy");

        anomalies.MapGet("/", async (OrkunPamDbContext db, Guid? userId, string? type, int page = 1, int pageSize = 50) =>
        {
            var query = db.Anomalies.AsQueryable();
            if (userId.HasValue) query = query.Where(a => a.UserId == userId.Value);
            if (!string.IsNullOrEmpty(type)) query = query.Where(a => a.AnomalyType == type);

            var total = await query.CountAsync();
            var list = await query
                .OrderByDescending(a => a.DetectedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(a => new
                {
                    a.Id, a.UserId, a.SessionId, a.AnomalyType, a.Severity,
                    a.Details, a.DetectedAtUtc, a.IsAcknowledged
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        anomalies.MapPost("/{id:long}/acknowledge", async (long id, AcknowledgeRequest req, OrkunPamDbContext db) =>
        {
            var anomaly = await db.Anomalies.FindAsync(id);
            if (anomaly == null) return Results.NotFound(new { success = false, errors = new[] { "Anomaly not found" } });

            anomaly.IsAcknowledged = true;
            anomaly.AcknowledgedBy = req.UserId;
            anomaly.AcknowledgedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        var alerts = app.MapGroup("/api/v1/analytics/alerts").WithTags("Analytics").RequireAuthorization("AdminPolicy");

        alerts.MapGet("/rules", async (OrkunPamDbContext db) =>
        {
            var list = await db.AlertRules
                .Select(r => new { r.Id, r.Name, r.ConditionJson, r.ActionJson, r.CooldownMinutes, r.IsEnabled })
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        alerts.MapPost("/rules", async (CreateAlertRuleRequest req, OrkunPamDbContext db) =>
        {
            var rule = new AlertRule
            {
                Name = req.Name,
                ConditionJson = req.ConditionJson,
                ActionJson = req.ActionJson,
                CooldownMinutes = req.CooldownMinutes ?? 15
            };
            db.AlertRules.Add(rule);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/analytics/alerts/rules/{rule.Id}", new { success = true, data = new { rule.Id } });
        });

        alerts.MapGet("/history", async (OrkunPamDbContext db, int page = 1, int pageSize = 50) =>
        {
            var total = await db.AlertHistories.CountAsync();
            var list = await db.AlertHistories
                .OrderByDescending(h => h.TriggeredAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(h => new
                {
                    h.Id, h.AlertRuleId, h.TriggeredAtUtc, h.Details, h.ActionsTaken,
                    h.AcknowledgedBy, h.AcknowledgedAtUtc
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        app.MapGet("/api/v1/analytics/risk-scores/users", async (OrkunPamDbContext db) =>
        {
            var userRisks = await db.Anomalies
                .Where(a => !a.IsAcknowledged)
                .GroupBy(a => a.UserId)
                .Select(g => new
                {
                    UserId = g.Key,
                    AnomalyCount = g.Count(),
                    MaxSeverity = g.Max(a => a.Severity),
                    RiskScore = g.Sum(a => (decimal)a.Severity * 25)
                })
                .OrderByDescending(u => u.RiskScore)
                .Take(50)
                .ToListAsync();

            return Results.Ok(new { success = true, data = userRisks });
        }).WithTags("Analytics").RequireAuthorization("AdminPolicy");

        // === Threat Intelligence Feed (#206) ===
        var tf = app.MapGroup("/api/v1/analytics/threat-feed").WithTags("Analytics").RequireAuthorization("AdminPolicy");

        tf.MapGet("/indicators", async (OrkunPamDbContext db,
            string? type, string? source, int page = 1, int pageSize = 50) =>
        {
            var query = db.ThreatIndicators.AsQueryable();
            if (!string.IsNullOrEmpty(type))   query = query.Where(t => t.IndicatorType == type);
            if (!string.IsNullOrEmpty(source)) query = query.Where(t => t.Source == source);

            var total = await query.CountAsync();
            var list  = await query
                .OrderByDescending(t => t.Severity)
                .ThenByDescending(t => t.UpdatedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(t => new
                {
                    t.Id, t.IndicatorType, t.Value, t.Severity,
                    t.Source, t.Description, t.ExpiresAtUtc, t.UpdatedAtUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        tf.MapGet("/configs", async (OrkunPamDbContext db) =>
        {
            var list = await db.ThreatFeedConfigs
                .OrderBy(c => c.Name)
                .Select(c => new
                {
                    c.Id, c.Name, c.FeedUrl, c.FeedType, c.RefreshIntervalMinutes,
                    c.IsEnabled, c.LastRefreshedAtUtc, c.LastIndicatorCount, c.LastError, c.CreatedAtUtc
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        tf.MapPost("/configs", async (ThreatFeedConfigRequest req, OrkunPamDbContext db,
            IVaultEncryptionService? vault) =>
        {
            string? encKey = null;
            if (!string.IsNullOrEmpty(req.ApiKey) && vault != null)
            {
                var result = vault.EncryptString(req.ApiKey);
                if (result.IsSuccess)
                    encKey = Convert.ToBase64String(result.Value);
            }

            var cfg = new ThreatFeedConfig
            {
                Name                   = req.Name,
                FeedUrl                = req.FeedUrl,
                FeedType               = req.FeedType,
                ApiKeyEnc              = encKey,
                RefreshIntervalMinutes = req.RefreshIntervalMinutes,
                IsEnabled              = req.IsEnabled,
                CreatedAtUtc           = DateTime.UtcNow
            };
            db.ThreatFeedConfigs.Add(cfg);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/analytics/threat-feed/configs/{cfg.Id}",
                new { success = true, data = new { cfg.Id } });
        });

        tf.MapPut("/configs/{id:guid}", async (Guid id, ThreatFeedConfigRequest req,
            OrkunPamDbContext db, IVaultEncryptionService? vault) =>
        {
            var cfg = await db.ThreatFeedConfigs.FindAsync(id);
            if (cfg == null) return Results.NotFound(new { success = false });

            cfg.Name                   = req.Name;
            cfg.FeedUrl                = req.FeedUrl;
            cfg.FeedType               = req.FeedType;
            cfg.RefreshIntervalMinutes = req.RefreshIntervalMinutes;
            cfg.IsEnabled              = req.IsEnabled;

            if (!string.IsNullOrEmpty(req.ApiKey) && vault != null)
            {
                var result = vault.EncryptString(req.ApiKey);
                if (result.IsSuccess) cfg.ApiKeyEnc = Convert.ToBase64String(result.Value);
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        tf.MapDelete("/configs/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var cfg = await db.ThreatFeedConfigs.FindAsync(id);
            if (cfg == null) return Results.NotFound(new { success = false });
            db.ThreatFeedConfigs.Remove(cfg);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        tf.MapPost("/configs/{id:guid}/toggle", async (Guid id, OrkunPamDbContext db) =>
        {
            var cfg = await db.ThreatFeedConfigs.FindAsync(id);
            if (cfg == null) return Results.NotFound(new { success = false });
            cfg.IsEnabled = !cfg.IsEnabled;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { cfg.IsEnabled } });
        });

        tf.MapPost("/refresh", async (OrkunPamDbContext db) =>
        {
            // Force reset last-refresh times so ThreatFeedService picks them up next cycle
            var configs = await db.ThreatFeedConfigs.Where(c => c.IsEnabled).ToListAsync();
            foreach (var c in configs) c.LastRefreshedAtUtc = null;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = "Refresh queued for next cycle (up to 60s)" });
        });

        tf.MapGet("/reports", async (OrkunPamDbContext db) =>
        {
            var now = DateTime.UtcNow;
            var since = now.AddHours(-24);

            var totalActive = await db.ThreatIndicators
                .CountAsync(t => t.ExpiresAtUtc == null || t.ExpiresAtUtc > now);

            var bySeverity = await db.ThreatIndicators
                .Where(t => t.ExpiresAtUtc == null || t.ExpiresAtUtc > now)
                .GroupBy(t => t.Severity)
                .Select(g => new { Severity = (int)g.Key, Count = g.Count() })
                .ToListAsync();

            var bySource = await db.ThreatIndicators
                .Where(t => t.ExpiresAtUtc == null || t.ExpiresAtUtc > now)
                .GroupBy(t => t.Source)
                .Select(g => new { Source = g.Key, Count = g.Count() })
                .ToListAsync();

            var hits24h = await db.Anomalies
                .Where(a => a.AnomalyType == "KnownMaliciousIP" && a.DetectedAtUtc >= since)
                .OrderByDescending(a => a.DetectedAtUtc)
                .Take(50)
                .Select(a => new { a.Id, a.UserId, a.SessionId, a.Details, a.DetectedAtUtc, a.IsAcknowledged })
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    TotalActive   = totalActive,
                    BySeverity    = bySeverity,
                    BySource      = bySource,
                    Hits24h       = hits24h,
                    GeneratedAtUtc = now
                }
            });
        });

        var siem = app.MapGroup("/api/v1/integrations/siem").WithTags("Integrations").RequireAuthorization("AdminPolicy");

        siem.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var config = await db.SystemConfigs
                .Where(c => c.Category == "SIEM")
                .Select(c => new { c.Key, c.Value, c.Description })
                .ToListAsync();
            return Results.Ok(new { success = true, data = config });
        });

        siem.MapPut("/", async (SiemConfigRequest req, OrkunPamDbContext db) =>
        {
            var configs = new Dictionary<string, string?>
            {
                ["siem.enabled"] = req.Enabled.ToString(),
                ["siem.protocol"] = req.Protocol,
                ["siem.host"] = req.Host,
                ["siem.port"] = req.Port?.ToString(),
                ["siem.transport"] = req.Transport
            };

            foreach (var (key, value) in configs)
            {
                var cfg = await db.SystemConfigs.FindAsync(key);
                if (cfg == null)
                    db.SystemConfigs.Add(new Domain.Entities.System.SystemConfig { Key = key, Value = value, Category = "SIEM" });
                else
                    cfg.Value = value;
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = "SIEM configuration updated" });
        });
    }
}

public record CreateRiskRuleRequest(string Pattern, decimal RiskScore, string? Category, string? Description);
public record AcknowledgeRequest(Guid UserId);
public record CreateAlertRuleRequest(string Name, string ConditionJson, string ActionJson, int? CooldownMinutes);
public record SiemConfigRequest(bool Enabled, string Protocol, string Host, int? Port, string Transport);
public record ThreatFeedConfigRequest(
    string Name,
    string FeedUrl,
    string FeedType,
    string? ApiKey,
    int    RefreshIntervalMinutes,
    bool   IsEnabled);
