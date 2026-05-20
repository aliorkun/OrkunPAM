using Microsoft.EntityFrameworkCore;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SessionComplianceEndpoints
{
    private const int ViolationRiskThreshold = 50;

    public static void MapSessionComplianceEndpoints(this IEndpointRouteBuilder app)
    {
        // GET /api/v1/sessions/compliance/summary?days=30
        app.MapGet("/api/v1/sessions/compliance/summary", async (
            OrkunPamDbContext db,
            int days = 30) =>
        {
            var since = DateTime.UtcNow.AddDays(-days);

            var sessions = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= since)
                .Select(s => new
                {
                    s.Id,
                    s.UserId,
                    s.DeviceId,
                    s.RiskScore,
                    s.Status,
                    s.TerminatedBy,
                    s.StartedAtUtc
                })
                .ToListAsync();

            var total = sessions.Count;
            var violated = sessions.Count(s => s.RiskScore > ViolationRiskThreshold);
            var adminTerminated = sessions.Count(s => s.TerminatedBy != null);
            var clean = total - violated;
            var complianceRate = total > 0 ? Math.Round((double)clean / total * 100, 1) : 100.0;

            // Blocked commands
            var blockedCommands = await db.CommandLogs
                .CountAsync(c => c.Timestamp >= since && c.WasBlocked);

            // Audit-based violation type breakdown
            var auditViolations = await db.AuditLogs
                .Where(a => a.Timestamp >= since && (
                    a.EventType == "COMMAND_BLOCKED_BY_POLICY" ||
                    a.EventType == "COMMAND_BLOCKED" ||
                    a.EventType == "GEO_BLOCKED" ||
                    a.EventType == "DEVICE_BLOCKED" ||
                    a.EventType == "REALM_ACCESS_DENIED" ||
                    a.EventType == "SESSION_TERMINATED_BY_ADMIN" ||
                    a.EventType == "SESSION_RISK_HIGH"))
                .GroupBy(a => a.EventType)
                .Select(g => new { ViolationType = g.Key, Count = g.Count() })
                .ToListAsync();

            // Add sessions with high risk score as "HIGH_RISK_SESSION" if not already represented
            var violationTypes = auditViolations.ToDictionary(x => x.ViolationType, x => x.Count);
            if (violated > 0 && !violationTypes.ContainsKey("HIGH_RISK_SESSION"))
                violationTypes["HIGH_RISK_SESSION"] = violated;

            // Top 5 violating users
            var topViolatingUsers = sessions
                .Where(s => s.RiskScore > ViolationRiskThreshold)
                .GroupBy(s => s.UserId)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => new { UserId = g.Key, ViolationCount = g.Count() })
                .ToList();

            var userIds = topViolatingUsers.Select(u => u.UserId).ToList();
            var userNames = await db.Users
                .Where(u => userIds.Contains(u.Id))
                .Select(u => new { u.Id, u.Username })
                .ToListAsync();
            var userNameMap = userNames.ToDictionary(u => u.Id, u => u.Username);

            var topUsers = topViolatingUsers.Select(u => new
            {
                u.UserId,
                Username = userNameMap.GetValueOrDefault(u.UserId, u.UserId.ToString()[..8]),
                u.ViolationCount
            }).ToList();

            // Top 5 violating devices
            var topViolatingDevices = sessions
                .Where(s => s.RiskScore > ViolationRiskThreshold)
                .GroupBy(s => s.DeviceId)
                .OrderByDescending(g => g.Count())
                .Take(5)
                .Select(g => new { DeviceId = g.Key, ViolationCount = g.Count() })
                .ToList();

            var deviceIds = topViolatingDevices.Select(d => d.DeviceId).ToList();
            var deviceNames = await db.Devices
                .Where(d => deviceIds.Contains(d.Id))
                .Select(d => new { d.Id, d.Hostname, d.IpAddress })
                .ToListAsync();
            var deviceNameMap = deviceNames.ToDictionary(d => d.Id, d => d.Hostname);

            var topDevices = topViolatingDevices.Select(d => new
            {
                d.DeviceId,
                Hostname = deviceNameMap.GetValueOrDefault(d.DeviceId, d.DeviceId.ToString()[..8]),
                d.ViolationCount
            }).ToList();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    periodDays     = days,
                    since,
                    totalSessions  = total,
                    violatedSessions = violated,
                    cleanSessions  = clean,
                    complianceRate,
                    adminTerminated,
                    blockedCommands,
                    violationTypes,
                    topViolatingUsers  = topUsers,
                    topViolatingDevices = topDevices
                }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("Sessions");

        // GET /api/v1/sessions/compliance/violations?from=&to=&type=&page=&pageSize=
        app.MapGet("/api/v1/sessions/compliance/violations", async (
            OrkunPamDbContext db,
            DateTime? from,
            DateTime? to,
            string? type,
            int page = 1,
            int pageSize = 50) =>
        {
            var dateFrom = from ?? DateTime.UtcNow.AddDays(-30);
            var dateTo   = to   ?? DateTime.UtcNow;

            // Pull sessions with violations (high risk score)
            var sessionQuery = db.ProxySessions
                .Where(s => s.StartedAtUtc >= dateFrom && s.StartedAtUtc <= dateTo
                         && s.RiskScore > ViolationRiskThreshold);

            // Pull audit-based violations
            var auditQuery = db.AuditLogs
                .Where(a => a.Timestamp >= dateFrom && a.Timestamp <= dateTo && (
                    a.EventType == "COMMAND_BLOCKED_BY_POLICY" ||
                    a.EventType == "COMMAND_BLOCKED" ||
                    a.EventType == "GEO_BLOCKED" ||
                    a.EventType == "DEVICE_BLOCKED" ||
                    a.EventType == "REALM_ACCESS_DENIED" ||
                    a.EventType == "SESSION_TERMINATED_BY_ADMIN" ||
                    a.EventType == "SESSION_RISK_HIGH"));

            if (!string.IsNullOrEmpty(type))
                auditQuery = auditQuery.Where(a => a.EventType == type);

            var auditViolations = await auditQuery
                .OrderByDescending(a => a.Timestamp)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(a => new
                {
                    SessionId = a.TargetId,
                    User      = a.ActorUsername,
                    Type      = a.EventType,
                    a.Timestamp,
                    RiskScore = (decimal?)null,
                    Source    = "audit"
                })
                .ToListAsync();

            var sessionViolations = await sessionQuery
                .OrderByDescending(s => s.StartedAtUtc)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(s => new
                {
                    SessionId = s.Id.ToString(),
                    User      = (string?)null,
                    Type      = "HIGH_RISK_SESSION",
                    Timestamp = s.StartedAtUtc,
                    RiskScore = (decimal?)s.RiskScore,
                    Source    = "session"
                })
                .ToListAsync();

            var combined = auditViolations
                .Cast<object>()
                .Concat(sessionViolations.Cast<object>())
                .ToList();

            var totalAudit = await auditQuery.CountAsync();
            var totalSession = await sessionQuery.CountAsync();

            return Results.Ok(new
            {
                success = true,
                data    = combined,
                meta    = new
                {
                    page,
                    pageSize,
                    totalAuditViolations   = totalAudit,
                    totalSessionViolations = totalSession
                }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("Sessions");

        // GET /api/v1/sessions/compliance/governance-report?days=30
        app.MapGet("/api/v1/sessions/compliance/governance-report", async (
            OrkunPamDbContext db,
            int days = 30) =>
        {
            var since = DateTime.UtcNow.AddDays(-days);

            // Sessions terminated by admin
            var adminTerminations = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= since && s.TerminatedBy != null)
                .Select(s => new
                {
                    SessionId  = s.Id,
                    s.UserId,
                    s.DeviceId,
                    s.TerminationReason,
                    s.StartedAtUtc,
                    s.EndedAtUtc,
                    s.RiskScore
                })
                .OrderByDescending(s => s.StartedAtUtc)
                .Take(50)
                .ToListAsync();

            // Realm access denied events
            var realmDenied = await db.AuditLogs
                .Where(a => a.Timestamp >= since && a.EventType == "REALM_ACCESS_DENIED")
                .OrderByDescending(a => a.Timestamp)
                .Take(50)
                .Select(a => new
                {
                    a.ActorUsername,
                    a.ActorIpAddress,
                    a.Timestamp,
                    a.Details
                })
                .ToListAsync();

            // JIT-related session events (sessions with JIT ticket numbers)
            var jitSessions = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= since && s.TicketNumber != null)
                .Select(s => new
                {
                    SessionId   = s.Id,
                    s.UserId,
                    s.DeviceId,
                    s.TicketNumber,
                    s.StartedAtUtc,
                    s.EndedAtUtc,
                    s.Status,
                    s.RiskScore
                })
                .OrderByDescending(s => s.StartedAtUtc)
                .Take(50)
                .ToListAsync();

            // Command-blocked sessions (sessions with at least one blocked command)
            var blockedCommandSessions = await db.CommandLogs
                .Where(c => c.Timestamp >= since && c.WasBlocked)
                .GroupBy(c => c.SessionId)
                .Select(g => new { SessionId = g.Key, BlockedCount = g.Count() })
                .OrderByDescending(g => g.BlockedCount)
                .Take(20)
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    periodDays         = days,
                    since,
                    adminTerminations  = adminTerminations.Count,
                    adminTerminatedSessions = adminTerminations,
                    realmDeniedCount   = realmDenied.Count,
                    realmDeniedEvents  = realmDenied,
                    jitSessionCount    = jitSessions.Count,
                    jitSessions,
                    commandBlockedSessions = blockedCommandSessions
                }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("Sessions");
    }
}
