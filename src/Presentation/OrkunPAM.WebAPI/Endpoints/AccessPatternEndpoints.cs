using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class AccessPatternEndpoints
{
    public static void MapAccessPatternEndpoints(this IEndpointRouteBuilder app)
    {
        // ── Access Pattern Analytics (#209) ─────────────────────────────────────
        var patterns = app.MapGroup("/api/v1/reports/access-patterns")
            .WithTags("AccessPatterns")
            .RequireAuthorization("AdminPolicy");

        // GET /api/v1/reports/access-patterns/summary
        // Top users, targets, peak hours, weekday distribution — RFP Reporting #33
        patterns.MapGet("/summary", async (OrkunPamDbContext db, int days = 30) =>
        {
            days = Math.Clamp(days, 1, 365);
            var since = DateTime.UtcNow.AddDays(-days);

            var sessions = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= since)
                .Select(s => new
                {
                    s.UserId,
                    s.TargetIpAddress,
                    s.StartedAtUtc,
                    s.SessionType,
                    s.Status
                }).ToListAsync();

            var topUsers = sessions
                .GroupBy(s => s.UserId)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .Select(g => new { UserId = g.Key, SessionCount = g.Count() })
                .ToList();

            var topTargets = sessions
                .Where(s => s.TargetIpAddress != null)
                .GroupBy(s => s.TargetIpAddress!)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .Select(g => new { Target = g.Key, SessionCount = g.Count() })
                .ToList();

            var peakHours = sessions
                .GroupBy(s => s.StartedAtUtc.Hour)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => new { Hour = g.Key, SessionCount = g.Count() })
                .OrderBy(x => x.Hour)
                .ToList();

            var weekdayDist = Enumerable.Range(0, 7)
                .Select(d => new
                {
                    Day = ((DayOfWeek)d).ToString(),
                    SessionCount = sessions.Count(s => (int)s.StartedAtUtc.DayOfWeek == d)
                }).ToList();

            var protocolBreakdown = sessions
                .GroupBy(s => s.SessionType.ToString())
                .Select(g => new { Protocol = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .ToList();

            // Login failures from audit log (last N days)
            var loginFailures = await db.AuditLogs
                .Where(a => a.Timestamp >= since && a.EventCategory == "Auth" && a.EventType.Contains("FAIL"))
                .CountAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    period = new { days, since },
                    totalSessions = sessions.Count,
                    uniqueUsers = sessions.Select(s => s.UserId).Distinct().Count(),
                    loginFailures,
                    topUsers,
                    topTargets,
                    peakHours,
                    weekdayDistribution = weekdayDist,
                    protocolBreakdown
                }
            });
        });

        // GET /api/v1/reports/access-patterns/time-of-day
        // 24-hour session histogram — RFP Reporting #46
        patterns.MapGet("/time-of-day", async (OrkunPamDbContext db, int days = 30) =>
        {
            days = Math.Clamp(days, 1, 90);
            var since = DateTime.UtcNow.AddDays(-days);

            var sessions = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= since)
                .Select(s => new { s.UserId, Hour = s.StartedAtUtc.Hour })
                .ToListAsync();

            var auditBlocked = await db.AuditLogs
                .Where(a => a.Timestamp >= since &&
                            (a.EventType == "GEO_BLOCKED" || a.EventType == "DEVICE_BLOCKED" || a.EventType.Contains("BLOCKED")))
                .Select(a => new { Hour = a.Timestamp.Hour })
                .ToListAsync();

            var hourly = Enumerable.Range(0, 24).Select(h => new
            {
                Hour = h,
                SessionCount = sessions.Count(s => s.Hour == h),
                UniqueUsers = sessions.Where(s => s.Hour == h).Select(s => s.UserId).Distinct().Count(),
                BlockedCount = auditBlocked.Count(a => a.Hour == h)
            }).ToList();

            return Results.Ok(new { success = true, data = new { period = new { days, since }, hourly } });
        });

        // GET /api/v1/reports/access-patterns/user/{userId}
        // Per-user access profile — RFP Reporting #33
        patterns.MapGet("/user/{userId:guid}", async (Guid userId, OrkunPamDbContext db, int days = 30) =>
        {
            days = Math.Clamp(days, 1, 180);
            var since = DateTime.UtcNow.AddDays(-days);

            var user = await db.Users.FindAsync(userId);
            if (user == null)
                return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            var sessions = await db.ProxySessions
                .Where(s => s.UserId == userId && s.StartedAtUtc >= since)
                .Select(s => new
                {
                    s.TargetIpAddress,
                    s.SessionType,
                    s.StartedAtUtc,
                    s.DurationSeconds,
                    s.Status
                }).ToListAsync();

            var loginHours = Enumerable.Range(0, 24).Select(h => new
            {
                Hour = h,
                Count = sessions.Count(s => s.StartedAtUtc.Hour == h)
            }).ToList();

            var topTargets = sessions
                .Where(s => s.TargetIpAddress != null)
                .GroupBy(s => s.TargetIpAddress!)
                .Select(g => new
                {
                    Target = g.Key,
                    SessionCount = g.Count(),
                    LastAccessUtc = g.Max(s => s.StartedAtUtc)
                })
                .OrderByDescending(x => x.SessionCount)
                .Take(10)
                .ToList();

            var protocolUsage = sessions
                .GroupBy(s => s.SessionType.ToString())
                .Select(g => new { Protocol = g.Key, Count = g.Count() })
                .OrderByDescending(x => x.Count)
                .ToList();

            var avgDuration = sessions.Where(s => s.DurationSeconds.HasValue)
                .Select(s => s.DurationSeconds!.Value)
                .DefaultIfEmpty(0).Average();

            // Audit events for this user
            var auditSummary = await db.AuditLogs
                .Where(a => a.ActorUserId == userId && a.Timestamp >= since)
                .GroupBy(a => a.EventCategory)
                .Select(g => new { Category = g.Key, Count = g.Count() })
                .ToListAsync();

            // Recent anomalies
            var anomalies = await db.Anomalies
                .Where(a => a.UserId == userId && a.DetectedAtUtc >= since)
                .OrderByDescending(a => a.DetectedAtUtc)
                .Take(5)
                .Select(a => new
                {
                    a.AnomalyType,
                    a.RiskScore,
                    a.DetectedAtUtc,
                    a.IsAcknowledged
                }).ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    user = new { user.Id, user.Username, user.DisplayName },
                    period = new { days, since },
                    totalSessions = sessions.Count,
                    avgSessionDurationSeconds = (int)avgDuration,
                    loginHoursHistogram = loginHours,
                    topTargets,
                    protocolUsage,
                    auditCategorySummary = auditSummary,
                    recentAnomalies = anomalies
                }
            });
        });

        // ── API Usage Reports (#209) ────────────────────────────────────────
        var apiUsage = app.MapGroup("/api/v1/reports/api-usage")
            .WithTags("AccessPatterns")
            .RequireAuthorization("AdminPolicy");

        // GET /api/v1/reports/api-usage/summary — RFP Reporting #38
        apiUsage.MapGet("/summary", async (OrkunPamDbContext db, int days = 30) =>
        {
            days = Math.Clamp(days, 1, 90);
            var since = DateTime.UtcNow.AddDays(-days);

            var logs = await db.ApiAccessLogs
                .Where(l => l.RequestedAtUtc >= since)
                .Select(l => new { l.ApiClientId, l.Outcome, l.RequestedAtUtc })
                .ToListAsync();

            var clients = await db.ApiClients.ToListAsync();

            var totalCalls = logs.Count;
            var granted    = logs.Count(l => l.Outcome == 0);
            var denied     = logs.Count(l => l.Outcome == 1);
            var rateLimited = logs.Count(l => l.Outcome == 2);

            var topClients = logs
                .GroupBy(l => l.ApiClientId)
                .OrderByDescending(g => g.Count())
                .Take(10)
                .Select(g =>
                {
                    var client = clients.FirstOrDefault(c => c.Id == g.Key);
                    return new
                    {
                        ClientId = g.Key,
                        ClientName = client?.Name ?? g.Key.ToString(),
                        TotalCalls = g.Count(),
                        Granted = g.Count(l => l.Outcome == 0),
                        Denied = g.Count(l => l.Outcome == 1),
                        RateLimited = g.Count(l => l.Outcome == 2)
                    };
                }).ToList();

            var hourlyTrend = Enumerable.Range(0, 24).Select(h => new
            {
                Hour = h,
                CallCount = logs.Count(l => l.RequestedAtUtc.Hour == h)
            }).ToList();

            // Audit-level API activity (all event categories)
            var auditTopEventTypes = await db.AuditLogs
                .Where(a => a.Timestamp >= since)
                .GroupBy(a => a.EventType)
                .OrderByDescending(g => g.Count())
                .Take(15)
                .Select(g => new { EventType = g.Key, Count = g.Count() })
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    period = new { days, since },
                    totalCalls,
                    granted,
                    denied,
                    rateLimited,
                    errorRate = totalCalls > 0 ? Math.Round((double)(denied + rateLimited) / totalCalls * 100, 1) : 0,
                    topClients,
                    hourlyTrend,
                    auditTopEventTypes
                }
            });
        });

        // GET /api/v1/reports/api-usage/by-client/{clientId}
        apiUsage.MapGet("/by-client/{clientId:guid}", async (Guid clientId, OrkunPamDbContext db, int days = 30) =>
        {
            days = Math.Clamp(days, 1, 90);
            var since = DateTime.UtcNow.AddDays(-days);

            var client = await db.ApiClients.FindAsync(clientId);
            if (client == null)
                return Results.NotFound(new { success = false, errors = new[] { "API client not found" } });

            var logs = await db.ApiAccessLogs
                .Where(l => l.ApiClientId == clientId && l.RequestedAtUtc >= since)
                .OrderByDescending(l => l.RequestedAtUtc)
                .Take(10_000)
                .Select(l => new { l.Outcome, l.RequestedAtUtc, l.ClientIpAddress })
                .ToListAsync();

            var dailyTrend = logs
                .GroupBy(l => l.RequestedAtUtc.Date)
                .OrderBy(g => g.Key)
                .Select(g => new
                {
                    Date = g.Key.ToString("yyyy-MM-dd"),
                    Calls = g.Count(),
                    Granted = g.Count(l => l.Outcome == 0),
                    Denied = g.Count(l => l.Outcome == 1)
                }).ToList();

            var hourlyProfile = Enumerable.Range(0, 24).Select(h => new
            {
                Hour = h,
                Count = logs.Count(l => l.RequestedAtUtc.Hour == h)
            }).ToList();

            var topIps = logs
                .Where(l => l.ClientIpAddress != null)
                .GroupBy(l => l.ClientIpAddress!)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => new { Ip = g.Key, Count = g.Count() })
                .ToList();

            // Credentials accessed
            var credAccess = await db.ApiClientCredentialAccess
                .Where(a => a.ApiClientId == clientId)
                .CountAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    client = new
                    {
                        client.Id,
                        client.Name,
                        client.ClientId,
                        client.IsEnabled,
                        client.RateLimitPerMinute,
                        client.LastUsedAtUtc,
                        CredentialAccessCount = credAccess
                    },
                    period = new { days, since },
                    totalCalls = logs.Count,
                    granted    = logs.Count(l => l.Outcome == 0),
                    denied     = logs.Count(l => l.Outcome == 1),
                    rateLimited = logs.Count(l => l.Outcome == 2),
                    dailyTrend,
                    hourlyProfile,
                    topSourceIps = topIps
                }
            });
        });

        // GET /api/v1/reports/api-usage/anomalies
        apiUsage.MapGet("/anomalies", async (OrkunPamDbContext db, int days = 7) =>
        {
            days = Math.Clamp(days, 1, 30);
            var since = DateTime.UtcNow.AddDays(-days);

            var logs = await db.ApiAccessLogs
                .Where(l => l.RequestedAtUtc >= since)
                .Select(l => new { l.ApiClientId, l.Outcome, l.RequestedAtUtc })
                .ToListAsync();

            var clients = await db.ApiClients.ToListAsync();

            // High denial rate (> 20%) — potential abuse
            var highDenialClients = logs
                .GroupBy(l => l.ApiClientId)
                .Where(g => g.Count() >= 10)
                .Select(g =>
                {
                    var client = clients.FirstOrDefault(c => c.Id == g.Key);
                    var total  = g.Count();
                    var denied = g.Count(l => l.Outcome == 1);
                    return new
                    {
                        ClientId = g.Key,
                        ClientName = client?.Name ?? g.Key.ToString(),
                        TotalCalls = total,
                        DeniedCalls = denied,
                        DenialRate = Math.Round((double)denied / total * 100, 1)
                    };
                })
                .Where(x => x.DenialRate > 20)
                .OrderByDescending(x => x.DenialRate)
                .ToList();

            // Rate-limited clients
            var rateLimitedClients = logs
                .Where(l => l.Outcome == 2)
                .GroupBy(l => l.ApiClientId)
                .Select(g =>
                {
                    var client = clients.FirstOrDefault(c => c.Id == g.Key);
                    return new { ClientId = g.Key, ClientName = client?.Name ?? g.Key.ToString(), RateLimitHits = g.Count() };
                })
                .OrderByDescending(x => x.RateLimitHits)
                .ToList();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    period = new { days, since },
                    highDenialRateClients = highDenialClients,
                    rateLimitedClients
                }
            });
        });
    }
}
