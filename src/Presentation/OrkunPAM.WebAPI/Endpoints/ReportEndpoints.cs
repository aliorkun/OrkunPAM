using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ReportEndpoints
{
    public static void MapReportEndpoints(this WebApplication app)
    {
        var reports = app.MapGroup("/api/v1/reports").WithTags("Reports");

        // === Built-in Reports ===
        reports.MapGet("/", () =>
        {
            var builtIn = new[]
            {
                new { Id = "password-age", Name = "Password Age Report", Category = "Compliance", Description = "Credentials approaching expiry" },
                new { Id = "privileged-access", Name = "Privileged Access Report", Category = "Security", Description = "Who accessed what, when" },
                new { Id = "session-activity", Name = "Session Activity Report", Category = "Operational", Description = "Session count, duration, protocol breakdown" },
                new { Id = "failed-logins", Name = "Failed Login Report", Category = "Security", Description = "Failed auth attempts by user/IP" },
                new { Id = "checkout-history", Name = "Checkout History Report", Category = "Audit", Description = "Credential checkouts with reason/duration" },
                new { Id = "rotation-compliance", Name = "Rotation Compliance Report", Category = "Compliance", Description = "Passwords rotated vs overdue" },
                new { Id = "orphaned-accounts", Name = "Orphaned Account Report", Category = "Security", Description = "Discovered but unmanaged accounts" },
                new { Id = "user-access-matrix", Name = "User Access Matrix", Category = "Audit", Description = "User × resource permission matrix" },
                new { Id = "mfa-adoption", Name = "MFA Adoption Report", Category = "Security", Description = "Users with/without MFA" },
                new { Id = "device-inventory", Name = "Device Inventory Report", Category = "Operational", Description = "Devices by type/status" },
                new { Id = "session-risk", Name = "Session Risk Report", Category = "Security", Description = "Sessions by risk score" },
                new { Id = "break-glass", Name = "Break-Glass Usage Report", Category = "Audit", Description = "Emergency access usage" },
                new { Id = "group-membership", Name = "Group Membership Report", Category = "Operational", Description = "Users per group" },
                new { Id = "aapm-usage", Name = "AAPM Usage Report", Category = "Operational", Description = "API client credential retrievals" },
                new { Id = "compliance-summary", Name = "Compliance Summary", Category = "Compliance", Description = "Per-framework compliance status" },
            };
            return Results.Ok(new { success = true, data = builtIn });
        });

        // Run a built-in report
        reports.MapPost("/{reportId}/run", async (string reportId, ReportRunRequest? req,
            OrkunPamDbContext db) =>
        {
            var from = req?.From ?? DateTime.UtcNow.AddDays(-30);
            var to = req?.To ?? DateTime.UtcNow;

            object? result = reportId switch
            {
                "password-age" => await GetPasswordAgeReport(db),
                "session-activity" => await GetSessionActivityReport(db, from, to),
                "failed-logins" => await GetFailedLoginReport(db, from, to),
                "mfa-adoption" => await GetMfaAdoptionReport(db),
                "device-inventory" => await GetDeviceInventoryReport(db),
                "rotation-compliance" => await GetRotationComplianceReport(db),
                _ => null
            };

            if (result == null)
                return Results.NotFound(new { success = false, errors = new[] { $"Report '{reportId}' not found or not yet implemented" } });

            return Results.Ok(new { success = true, data = result, meta = new { reportId, from, to, generatedAt = DateTime.UtcNow } });
        });

        // === Dashboard Widgets ===
        var dashboard = app.MapGroup("/api/v1/dashboard").WithTags("Dashboard");

        dashboard.MapGet("/summary", async (OrkunPamDbContext db) =>
        {
            var totalUsers = await db.Users.CountAsync();
            var activeUsers = await db.Users.CountAsync(u => u.Status == UserStatus.Active);
            var totalDevices = await db.Devices.CountAsync();
            var totalCredentials = await db.Credentials.CountAsync();
            var checkedOut = await db.Credentials.CountAsync(c => c.Status == CredentialStatus.CheckedOut);
            var activeSessions = await db.ProxySessions.CountAsync(s => s.Status == SessionStatus.Active);
            var mfaEnabled = await db.Users.CountAsync(u => u.MfaEnabled);
            var pendingApprovals = await db.ApprovalRequests.CountAsync(a => a.Status == ApprovalStatus.Pending);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    users = new { total = totalUsers, active = activeUsers, mfaEnabled },
                    devices = new { total = totalDevices },
                    vault = new { totalCredentials, checkedOut },
                    sessions = new { active = activeSessions },
                    workflow = new { pendingApprovals },
                    timestamp = DateTime.UtcNow
                }
            });
        });

        dashboard.MapGet("/recent-activity", async (OrkunPamDbContext db, int count = 20) =>
        {
            var recentLogins = await db.Users
                .Where(u => u.LastLoginAtUtc != null)
                .OrderByDescending(u => u.LastLoginAtUtc)
                .Take(count)
                .Select(u => new { u.Username, u.LastLoginAtUtc, u.LastLoginIp })
                .ToListAsync();

            var recentSessions = await db.ProxySessions
                .OrderByDescending(s => s.StartedAtUtc)
                .Take(count)
                .Select(s => new
                {
                    s.Id, s.UserId, Type = s.SessionType.ToString(),
                    Status = s.Status.ToString(),
                    s.TargetIpAddress, s.StartedAtUtc, s.DurationSeconds
                }).ToListAsync();

            var recentCheckouts = await db.CheckOutHistories
                .OrderByDescending(h => h.CheckedOutAtUtc)
                .Take(count)
                .Select(h => new { h.CredentialId, h.UserId, h.CheckedOutAtUtc, h.CheckedInAtUtc, h.Reason })
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = new { recentLogins, recentSessions, recentCheckouts }
            });
        });
    }

    // === Report Implementations ===

    private static async Task<object> GetPasswordAgeReport(OrkunPamDbContext db)
    {
        var creds = await db.Credentials
            .Where(c => c.Status == CredentialStatus.Active)
            .Select(c => new
            {
                c.Id, c.Name, c.Username, c.DeviceId,
                c.LastRotatedAtUtc, c.NextRotationAtUtc,
                AgeDays = c.LastRotatedAtUtc.HasValue
                    ? (int)(DateTime.UtcNow - c.LastRotatedAtUtc.Value).TotalDays
                    : (int)(DateTime.UtcNow - c.CreatedAtUtc).TotalDays,
                IsOverdue = c.NextRotationAtUtc.HasValue && c.NextRotationAtUtc < DateTime.UtcNow
            }).OrderByDescending(c => c.AgeDays).ToListAsync();

        return new
        {
            totalCredentials = creds.Count,
            overdueCount = creds.Count(c => c.IsOverdue),
            averageAgeDays = creds.Any() ? creds.Average(c => c.AgeDays) : 0,
            credentials = creds
        };
    }

    private static async Task<object> GetSessionActivityReport(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var sessions = await db.ProxySessions
            .Where(s => s.StartedAtUtc >= from && s.StartedAtUtc <= to)
            .ToListAsync();

        var byType = sessions.GroupBy(s => s.SessionType).ToDictionary(g => g.Key.ToString(), g => g.Count());
        var byStatus = sessions.GroupBy(s => s.Status).ToDictionary(g => g.Key.ToString(), g => g.Count());

        return new
        {
            totalSessions = sessions.Count,
            byType,
            byStatus,
            averageDurationSeconds = sessions.Where(s => s.DurationSeconds.HasValue).Select(s => s.DurationSeconds!.Value).DefaultIfEmpty(0).Average(),
            terminatedCount = sessions.Count(s => s.Status == SessionStatus.Terminated)
        };
    }

    private static async Task<object> GetFailedLoginReport(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var usersWithFailures = await db.Users
            .Where(u => u.FailedLoginCount > 0)
            .Select(u => new { u.Username, u.FailedLoginCount, u.Status, u.LockoutEndUtc, u.LastLoginIp })
            .OrderByDescending(u => u.FailedLoginCount)
            .ToListAsync();

        return new
        {
            usersWithFailures = usersWithFailures.Count,
            lockedAccounts = usersWithFailures.Count(u => u.Status == UserStatus.Locked),
            details = usersWithFailures
        };
    }

    private static async Task<object> GetMfaAdoptionReport(OrkunPamDbContext db)
    {
        var total = await db.Users.CountAsync(u => u.Status == UserStatus.Active);
        var mfaEnabled = await db.Users.CountAsync(u => u.Status == UserStatus.Active && u.MfaEnabled);

        return new
        {
            totalActiveUsers = total,
            mfaEnabled,
            mfaDisabled = total - mfaEnabled,
            adoptionPercentage = total > 0 ? Math.Round((double)mfaEnabled / total * 100, 1) : 0
        };
    }

    private static async Task<object> GetDeviceInventoryReport(OrkunPamDbContext db)
    {
        var devices = await db.Devices.ToListAsync();
        var byType = devices.GroupBy(d => d.DeviceType).ToDictionary(g => g.Key.ToString(), g => g.Count());
        var byStatus = devices.GroupBy(d => d.Status).ToDictionary(g => g.Key.ToString(), g => g.Count());

        return new
        {
            totalDevices = devices.Count,
            byType,
            byStatus,
            unreachable = devices.Count(d => d.IsReachable == false),
            managed = devices.Count(d => d.IsManaged)
        };
    }

    private static async Task<object> GetRotationComplianceReport(OrkunPamDbContext db)
    {
        var creds = await db.Credentials
            .Where(c => c.RotationPolicyId != null && c.Status == CredentialStatus.Active)
            .Select(c => new
            {
                c.Id, c.Name, c.LastRotatedAtUtc, c.NextRotationAtUtc,
                IsOverdue = c.NextRotationAtUtc.HasValue && c.NextRotationAtUtc < DateTime.UtcNow
            }).ToListAsync();

        return new
        {
            totalManaged = creds.Count,
            compliant = creds.Count(c => !c.IsOverdue),
            overdue = creds.Count(c => c.IsOverdue),
            compliancePercentage = creds.Any() ? Math.Round((double)creds.Count(c => !c.IsOverdue) / creds.Count * 100, 1) : 100
        };
    }
}

public record ReportRunRequest(DateTime? From, DateTime? To);
