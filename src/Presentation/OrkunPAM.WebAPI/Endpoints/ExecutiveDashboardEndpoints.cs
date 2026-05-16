using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Domain.Entities.System;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ExecutiveDashboardEndpoints
{
    public static void MapExecutiveDashboardEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/api/v1/dashboard/executive")
            .WithTags("Dashboard")
            .RequireAuthorization();

        grp.MapGet("/", async (
            OrkunPamDbContext db,
            int days = 30,
            string? actorUsername = null,
            string? actorIp = null) =>
        {
            var now       = DateTime.UtcNow;
            var from      = now.AddDays(-days);
            var weekAgo   = now.AddDays(-7);
            var yesterday = now.AddDays(-1);

            // --- KPI counts (sequential — EF Core DbContext is not thread-safe) ---
            var totalUsers       = await db.Users.CountAsync();
            var usersWeekAgo     = await db.Users.CountAsync(u => u.CreatedAtUtc < weekAgo);
            var activeSessions   = await db.ProxySessions.CountAsync(s => s.Status == SessionStatus.Active);
            var openAlarms       = await db.SystemAlarmLogs.CountAsync(a => a.Status == "Active");
            var pendingApprovals = await db.ApprovalRequests.CountAsync(a => a.Status == ApprovalStatus.Pending);
            var failedLogins24h  = await db.AuditLogs.CountAsync(
                a => a.Outcome == AuditOutcome.Failure &&
                     (a.EventType == "Login" || a.EventType == "AUTH_FAILED") &&
                     a.Timestamp >= yesterday);
            var expiringCreds    = await db.Credentials.CountAsync(
                c => c.Status == CredentialStatus.Active &&
                     c.NextRotationAtUtc != null &&
                     c.NextRotationAtUtc < now.AddDays(7));
            var mfaEnabled       = await db.Users.CountAsync(u => u.MfaEnabled);
            var totalActive      = await db.Users.CountAsync(u => u.Status == UserStatus.Active);

            // --- Daily session trend ---
            var sessionsByDay = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= from)
                .GroupBy(s => s.StartedAtUtc.Date)
                .Select(g => new { Date = g.Key, Count = g.Count() })
                .OrderBy(x => x.Date)
                .ToListAsync();

            var sessionTrend = new List<object>();
            for (var d = from.Date; d <= now.Date; d = d.AddDays(1))
            {
                var found = sessionsByDay.FirstOrDefault(x => x.Date == d);
                sessionTrend.Add(new { date = d.ToString("yyyy-MM-dd"), count = found?.Count ?? 0 });
            }

            // --- Protocol distribution (materialize then convert enum to string) ---
            var rawProtocols = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= from)
                .GroupBy(s => s.SessionType)
                .Select(g => new { Protocol = g.Key, Count = g.Count() })
                .ToListAsync();
            var protocolDist = rawProtocols
                .Select(x => new { protocol = x.Protocol.ToString(), count = x.Count })
                .ToList();

            // --- Failed login trend (daily) ---
            var failedByDay = await db.AuditLogs
                .Where(a => a.Outcome == AuditOutcome.Failure &&
                            (a.EventType == "Login" || a.EventType == "AUTH_FAILED") &&
                            a.Timestamp >= from)
                .GroupBy(a => a.Timestamp.Date)
                .Select(g => new { Date = g.Key, Count = g.Count() })
                .OrderBy(x => x.Date)
                .ToListAsync();

            var failedLoginTrend = new List<object>();
            for (var d = from.Date; d <= now.Date; d = d.AddDays(1))
            {
                var found = failedByDay.FirstOrDefault(x => x.Date == d);
                failedLoginTrend.Add(new { date = d.ToString("yyyy-MM-dd"), count = found?.Count ?? 0 });
            }

            // --- Top-5 devices (group first, then look up names) ---
            var topDeviceIds = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= from)
                .GroupBy(s => s.DeviceId)
                .Select(g => new { DeviceId = g.Key, SessionCount = g.Count() })
                .OrderByDescending(x => x.SessionCount)
                .Take(5)
                .ToListAsync();

            var deviceIds    = topDeviceIds.Select(x => x.DeviceId).ToList();
            var deviceLookup = await db.Devices
                .Where(d => deviceIds.Contains(d.Id))
                .Select(d => new { d.Id, d.Name, d.IpAddress })
                .ToListAsync();
            var topDevices = topDeviceIds.Select(x =>
            {
                var dev = deviceLookup.FirstOrDefault(d => d.Id == x.DeviceId);
                return new { id = x.DeviceId.ToString(), name = dev?.Name, ipAddress = dev?.IpAddress, sessionCount = x.SessionCount };
            }).ToList();

            // --- Top-5 users (group first, then look up names) ---
            var topUserIds = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= from)
                .GroupBy(s => s.UserId)
                .Select(g => new { UserId = g.Key, SessionCount = g.Count() })
                .OrderByDescending(x => x.SessionCount)
                .Take(5)
                .ToListAsync();

            var userIds    = topUserIds.Select(x => x.UserId).ToList();
            var userLookup = await db.Users
                .Where(u => userIds.Contains(u.Id))
                .Select(u => new { u.Id, u.Username, u.DisplayName })
                .ToListAsync();
            var topUsers = topUserIds.Select(x =>
            {
                var usr = userLookup.FirstOrDefault(u => u.Id == x.UserId);
                return new { id = x.UserId.ToString(), username = usr?.Username ?? "Unknown", displayName = usr?.DisplayName, sessionCount = x.SessionCount };
            }).ToList();

            // --- Compliance metrics ---
            var totalCreds     = await db.Credentials.CountAsync(c => c.Status == CredentialStatus.Active);
            var compliantCreds = await db.Credentials.CountAsync(
                c => c.Status == CredentialStatus.Active &&
                     (c.NextRotationAtUtc == null || c.NextRotationAtUtc >= now));
            var rotationCompliance = totalCreds > 0
                ? Math.Round(100.0 * compliantCreds / totalCreds, 1)
                : 100.0;

            var mfaRate      = totalActive > 0 ? Math.Round(100.0 * mfaEnabled / totalActive, 1) : 0.0;
            var orphanedCount = await db.Users.CountAsync(u => u.IsOrphaned);

            var lastCampaign = await db.AttestationCampaigns
                .Where(c => c.Status == 2) // 2=Completed
                .OrderByDescending(c => c.CompletedAtUtc)
                .Select(c => new { c.Id, c.CompletedAtUtc })
                .FirstOrDefaultAsync();

            double certCompletionRate = 0;
            if (lastCampaign != null)
            {
                var totalItems   = await db.AttestationDecisions.CountAsync(d => d.CampaignId == lastCampaign.Id);
                var decidedItems = await db.AttestationDecisions.CountAsync(
                    d => d.CampaignId == lastCampaign.Id && d.Decision != null);
                certCompletionRate = totalItems > 0
                    ? Math.Round(100.0 * decidedItems / totalItems, 1)
                    : 100.0;
            }

            // --- Audit: log executive dashboard access ---
            if (!string.IsNullOrWhiteSpace(actorUsername))
            {
                db.AuditLogs.Add(new AuditLogEntry
                {
                    Timestamp      = now,
                    EventCategory  = "Dashboard",
                    EventType      = "ExecutiveDashboardView",
                    ActorUsername  = actorUsername,
                    ActorIpAddress = actorIp,
                    TargetType     = "ExecutiveDashboard",
                    Outcome        = AuditOutcome.Success,
                    Details        = $"days={days}"
                });
                await db.SaveChangesAsync();
            }

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    generatedAtUtc = now,
                    periodDays     = days,
                    kpis = new
                    {
                        totalPrivilegedUsers = totalUsers,
                        userWeeklyChange     = totalUsers - usersWeekAgo,
                        activeSessions,
                        openAlarms,
                        pendingApprovals,
                        failedLoginsLast24h  = failedLogins24h,
                        expiringCredentials  = expiringCreds
                    },
                    sessionTrend,
                    protocolDistribution = protocolDist,
                    failedLoginTrend,
                    topDevices,
                    topUsers,
                    compliance = new
                    {
                        rotationCompliance,
                        mfaEnrollmentRate     = mfaRate,
                        orphanedAccountCount  = orphanedCount,
                        certificationCompleted = lastCampaign != null,
                        certCompletionRate
                    }
                }
            });
        });
    }
}
