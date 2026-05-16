using System.Text;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ReportEndpoints
{
    public static void MapReportEndpoints(this IEndpointRouteBuilder app)
    {
        var reports = app.MapGroup("/api/v1/reports").WithTags("Reports");

        reports.MapGet("/", () =>
        {
            var builtIn = new[]
            {
                new { Id = "password-age", Name = "Password Age Report", Category = "Compliance", Description = "Credentials approaching expiry" },
                new { Id = "credential-expiry", Name = "Credential Expiry Report", Category = "Compliance", Description = "Credentials expiring soon" },
                new { Id = "privileged-access", Name = "Privileged Access Report", Category = "Security", Description = "Who accessed what, when" },
                new { Id = "session-activity", Name = "Session Activity Report", Category = "Operational", Description = "Session count, duration, protocol breakdown" },
                new { Id = "failed-logins", Name = "Failed Login Report", Category = "Security", Description = "Failed auth attempts by user/IP" },
                new { Id = "checkout-history", Name = "Checkout History Report", Category = "Audit", Description = "Credential checkouts with reason/duration" },
                new { Id = "rotation-compliance", Name = "Rotation Compliance Report", Category = "Compliance", Description = "Passwords rotated vs overdue" },
                new { Id = "policy-compliance", Name = "Policy Compliance Report", Category = "Compliance", Description = "Password policy compliance stats" },
                new { Id = "orphaned-accounts", Name = "Orphaned Account Report", Category = "Security", Description = "Discovered but unmanaged accounts" },
                new { Id = "user-access-matrix", Name = "User Access Matrix", Category = "Audit", Description = "User x resource permission matrix" },
                new { Id = "mfa-adoption", Name = "MFA Adoption Report", Category = "Security", Description = "Users with/without MFA" },
                new { Id = "mfa-usage", Name = "MFA Enrollment & Usage Report", Category = "Security", Description = "MFA adoption rate, bypass events, per-user enrollment status (RFP Reporting #37)" },
                new { Id = "account-lifecycle", Name = "Account Lifecycle & Privilege Change Report", Category = "Compliance", Description = "Account creation, role changes, disabling, deletion (RFP Reporting #35)" },
                new { Id = "device-inventory", Name = "Device Inventory Report", Category = "Operational", Description = "Devices by type/status" },
                new { Id = "session-risk", Name = "Session Risk Report", Category = "Security", Description = "Sessions by risk score" },
                new { Id = "break-glass", Name = "Break-Glass Usage Report", Category = "Audit", Description = "Emergency access usage" },
                new { Id = "group-membership", Name = "Group Membership Report", Category = "Operational", Description = "Users per group" },
                new { Id = "jit-access-summary", Name = "JIT Access Summary Report", Category = "Security", Description = "Just-in-time access requests summary" },
                new { Id = "privileged-account-inventory", Name = "Privileged Account Inventory", Category = "Audit", Description = "All privileged accounts inventory" },
                new { Id = "vendor-access-report", Name = "Vendor Access Report", Category = "Security", Description = "Vendor/temporary user access" },
                new { Id = "aapm-usage", Name = "AAPM Usage Report", Category = "Operational", Description = "API client credential retrievals" },
                new { Id = "compliance-summary", Name = "Compliance Summary", Category = "Compliance", Description = "Per-framework compliance status" },
            };
            return Results.Ok(new { success = true, data = builtIn });
        });

        reports.MapPost("/{reportId}/run", async (string reportId, ReportRunRequest? req,
            OrkunPamDbContext db) =>
        {
            var from = req?.From ?? DateTime.UtcNow.AddDays(-30);
            var to = req?.To ?? DateTime.UtcNow;

            object? result = reportId switch
            {
                "password-age" => await GetPasswordAgeReport(db),
                "credential-expiry" => await GetCredentialExpiryReport(db),
                "session-activity" => await GetSessionActivityReport(db, from, to),
                "failed-logins"      => await GetFailedLoginReport(db, from, to),
                "mfa-adoption"       => await GetMfaAdoptionReport(db),
                "mfa-usage"          => await GetMfaUsageReport(db, from, to),
                "account-lifecycle"  => await GetAccountLifecycleReport(db, from, to),
                "device-inventory" => await GetDeviceInventoryReport(db),
                "rotation-compliance" => await GetRotationComplianceReport(db),
                "group-membership" => await GetGroupMembershipReport(db),
                "policy-compliance" => await GetPolicyComplianceReport(db),
                "checkout-history" => await GetCheckoutHistoryReport(db, from, to),
                "break-glass" => await GetBreakGlassUsageReport(db, from, to),
                "jit-access-summary" => await GetJitAccessSummaryReport(db, from, to),
                "privileged-account-inventory" => await GetPrivilegedAccountInventoryReport(db),
                "vendor-access-report" => await GetVendorAccessReport(db),
                "compliance-summary" => await GetComplianceSummaryReport(db),
                _ => null
            };

            if (result == null)
                return Results.NotFound(new { success = false, errors = new[] { $"Report '{reportId}' not found or not yet implemented" } });

            return Results.Ok(new { success = true, data = result, meta = new { reportId, from, to, generatedAt = DateTime.UtcNow } });
        });

        // -----------------------------------------------------------------------
        // CSV Export endpoints (RFP Reporting #8, #9)
        // -----------------------------------------------------------------------

        reports.MapGet("/audit-log/export", async (OrkunPamDbContext db,
            string? format, DateTime? from, DateTime? to, Guid? userId) =>
        {
            format = (format ?? "csv").ToLowerInvariant();
            if (format != "csv")
                return Results.BadRequest(new { success = false, errors = new[] { "Supported formats: csv" } });

            var fromDate = from ?? DateTime.UtcNow.AddDays(-30);
            var toDate   = to   ?? DateTime.UtcNow;

            var query = db.AuditLogs
                .Where(a => a.Timestamp >= fromDate && a.Timestamp <= toDate);
            if (userId.HasValue)
                query = query.Where(a => a.ActorUserId == userId);

            var rows = await query
                .OrderBy(a => a.Timestamp)
                .Select(a => new
                {
                    a.Timestamp, a.EventCategory, a.EventType,
                    a.ActorUsername, a.ActorIpAddress,
                    a.TargetType, a.TargetId,
                    Outcome = a.Outcome.ToString(), a.Details
                }).ToListAsync();

            var sb = new StringBuilder();
            sb.AppendLine("Timestamp,EventCategory,EventType,ActorUsername,ActorIpAddress,TargetType,TargetId,Outcome,Details");
            foreach (var r in rows)
            {
                sb.AppendLine(string.Join(",",
                    CsvCell(r.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")),
                    CsvCell(r.EventCategory), CsvCell(r.EventType),
                    CsvCell(r.ActorUsername), CsvCell(r.ActorIpAddress),
                    CsvCell(r.TargetType), CsvCell(r.TargetId),
                    CsvCell(r.Outcome), CsvCell(r.Details)));
            }

            var filename = $"audit-log-{fromDate:yyyy-MM-dd}-{toDate:yyyy-MM-dd}.csv";
            return Results.File(Encoding.UTF8.GetBytes(sb.ToString()), "text/csv", filename);
        });

        reports.MapGet("/sessions/export", async (OrkunPamDbContext db,
            string? format, DateTime? from, DateTime? to, Guid? userId) =>
        {
            format = (format ?? "csv").ToLowerInvariant();
            if (format != "csv")
                return Results.BadRequest(new { success = false, errors = new[] { "Supported formats: csv" } });

            var fromDate = from ?? DateTime.UtcNow.AddDays(-30);
            var toDate   = to   ?? DateTime.UtcNow;

            var query = db.ProxySessions
                .Where(s => s.StartedAtUtc >= fromDate && s.StartedAtUtc <= toDate);
            if (userId.HasValue)
                query = query.Where(s => s.UserId == userId);

            var rows = await query
                .OrderBy(s => s.StartedAtUtc)
                .Select(s => new
                {
                    s.Id, s.UserId,
                    Type   = s.SessionType.ToString(),
                    Status = s.Status.ToString(),
                    s.TargetIpAddress, s.TargetPort,
                    s.StartedAtUtc, s.EndedAtUtc, s.DurationSeconds,
                    s.ClientIpAddress, s.RiskScore, s.Reason, s.TicketNumber
                }).ToListAsync();

            var sb = new StringBuilder();
            sb.AppendLine("SessionId,UserId,Type,Status,TargetIp,TargetPort,StartedAt,EndedAt,DurationSeconds,ClientIp,RiskScore,Reason,TicketNumber");
            foreach (var r in rows)
            {
                sb.AppendLine(string.Join(",",
                    CsvCell(r.Id.ToString()), CsvCell(r.UserId.ToString()),
                    CsvCell(r.Type), CsvCell(r.Status),
                    CsvCell(r.TargetIpAddress), CsvCell(r.TargetPort.ToString()),
                    CsvCell(r.StartedAtUtc.ToString("yyyy-MM-dd HH:mm:ss")),
                    CsvCell(r.EndedAtUtc?.ToString("yyyy-MM-dd HH:mm:ss")),
                    CsvCell(r.DurationSeconds?.ToString()),
                    CsvCell(r.ClientIpAddress), CsvCell(r.RiskScore.ToString()),
                    CsvCell(r.Reason), CsvCell(r.TicketNumber)));
            }

            var filename = $"sessions-{fromDate:yyyy-MM-dd}-{toDate:yyyy-MM-dd}.csv";
            return Results.File(Encoding.UTF8.GetBytes(sb.ToString()), "text/csv", filename);
        });

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
                .Select(u => new { u.Username, u.LastLoginAtUtc })
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
        // AuditLogs-based brute force analysis (RFP Reporting #25)
        var failedEvents = await db.AuditLogs
            .Where(a => a.Outcome == AuditOutcome.Failure &&
                        a.Timestamp >= from && a.Timestamp <= to &&
                        (a.EventCategory == "Auth" ||
                         a.EventType.Contains("Login") || a.EventType.Contains("Auth")))
            .Select(a => new { a.ActorUsername, a.ActorIpAddress, a.Timestamp })
            .ToListAsync();

        var byUser = failedEvents
            .GroupBy(e => e.ActorUsername ?? "unknown")
            .Select(g => new
            {
                username      = g.Key,
                failedCount   = g.Count(),
                firstAttempt  = g.Min(e => e.Timestamp),
                lastAttempt   = g.Max(e => e.Timestamp),
                uniqueIps     = g.Select(e => e.ActorIpAddress).Distinct().Count()
            })
            .OrderByDescending(x => x.failedCount)
            .ToList();

        var byIp = failedEvents
            .Where(e => !string.IsNullOrEmpty(e.ActorIpAddress))
            .GroupBy(e => e.ActorIpAddress!)
            .Select(g => new
            {
                ipAddress       = g.Key,
                failedCount     = g.Count(),
                targetedUsers   = g.Select(e => e.ActorUsername).Distinct().Count(),
                firstAttempt    = g.Min(e => e.Timestamp),
                lastAttempt     = g.Max(e => e.Timestamp)
            })
            .OrderByDescending(x => x.failedCount)
            .ToList();

        var lockedUsers = await db.Users
            .Where(u => u.Status == UserStatus.Locked)
            .Select(u => new { u.Username, u.FailedLoginCount, u.LockoutEndUtc })
            .OrderByDescending(u => u.FailedLoginCount)
            .ToListAsync();

        return new
        {
            totalFailedAttempts   = failedEvents.Count,
            lockedAccountsCount   = lockedUsers.Count,
            top5TargetedUsers     = byUser.Take(5),
            top5AttackingIps      = byIp.Take(5),
            currentlyLockedUsers  = lockedUsers,
            byUser,
            byIp
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

    // -----------------------------------------------------------------------
    // 1. Credential Expiry Report
    // -----------------------------------------------------------------------
    private static async Task<object> GetCredentialExpiryReport(OrkunPamDbContext db)
    {
        var now = DateTime.UtcNow;
        var creds = await db.Credentials
            .Where(c => c.Status == CredentialStatus.Active && c.NextRotationAtUtc != null)
            .Select(c => new
            {
                c.Id, c.Name, c.Username, c.DeviceId,
                c.NextRotationAtUtc,
                c.LastRotatedAtUtc,
                DaysUntilExpiry = c.NextRotationAtUtc.HasValue
                    ? (int)(c.NextRotationAtUtc.Value - now).TotalDays
                    : (int?)null
            })
            .OrderBy(c => c.NextRotationAtUtc)
            .ToListAsync();

        var expired = creds.Count(c => c.DaysUntilExpiry < 0);
        var expiringIn7 = creds.Count(c => c.DaysUntilExpiry >= 0 && c.DaysUntilExpiry <= 7);
        var expiringIn30 = creds.Count(c => c.DaysUntilExpiry > 7 && c.DaysUntilExpiry <= 30);
        var healthy = creds.Count(c => c.DaysUntilExpiry > 30);

        return new
        {
            totalCredentials = creds.Count,
            expired,
            expiringIn7Days = expiringIn7,
            expiringIn30Days = expiringIn30,
            healthy,
            credentials = creds
        };
    }

    // -----------------------------------------------------------------------
    // 2. Group Membership Report
    // -----------------------------------------------------------------------
    private static async Task<object> GetGroupMembershipReport(OrkunPamDbContext db)
    {
        var groups = await db.Groups
            .Select(g => new
            {
                g.Id,
                g.Name,
                g.Description,
                Source = g.GroupSource.ToString(),
                MemberCount = g.UserGroups.Count
            })
            .OrderByDescending(g => g.MemberCount)
            .ToListAsync();

        var totalGroups = groups.Count;
        var emptyGroups = groups.Count(g => g.MemberCount == 0);
        var totalMemberships = groups.Sum(g => g.MemberCount);

        return new
        {
            totalGroups,
            emptyGroups,
            totalMemberships,
            averageMembersPerGroup = totalGroups > 0 ? Math.Round((double)totalMemberships / totalGroups, 1) : 0,
            groups
        };
    }

    // -----------------------------------------------------------------------
    // 3. Policy Compliance Report
    // -----------------------------------------------------------------------
    private static async Task<object> GetPolicyComplianceReport(OrkunPamDbContext db)
    {
        var now = DateTime.UtcNow;
        var totalUsers = await db.Users.CountAsync(u => u.Status == UserStatus.Active);

        var passwordExpired = await db.Users.CountAsync(u =>
            u.Status == UserStatus.Active &&
            u.PasswordExpiresAt.HasValue && u.PasswordExpiresAt < now);

        var passwordNeverChanged = await db.Users.CountAsync(u =>
            u.Status == UserStatus.Active && u.PasswordLastChanged == null);

        var mustChangePassword = await db.Users.CountAsync(u =>
            u.Status == UserStatus.Active && u.MustChangePassword);

        var mfaEnabled = await db.Users.CountAsync(u =>
            u.Status == UserStatus.Active && u.MfaEnabled);

        var compliantUsers = totalUsers - passwordExpired - mustChangePassword;
        if (compliantUsers < 0) compliantUsers = 0;

        return new
        {
            totalActiveUsers = totalUsers,
            passwordExpired,
            passwordNeverChanged,
            mustChangePassword,
            mfaEnabled,
            mfaDisabled = totalUsers - mfaEnabled,
            compliantUsers,
            compliancePercentage = totalUsers > 0
                ? Math.Round((double)compliantUsers / totalUsers * 100, 1)
                : 100
        };
    }

    // -----------------------------------------------------------------------
    // 4. Checkout History Report
    // -----------------------------------------------------------------------
    private static async Task<object> GetCheckoutHistoryReport(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var history = await db.CheckOutHistories
            .Where(h => h.CheckedOutAtUtc >= from && h.CheckedOutAtUtc <= to)
            .OrderByDescending(h => h.CheckedOutAtUtc)
            .Select(h => new
            {
                h.Id, h.CredentialId, h.UserId,
                h.CheckedOutAtUtc, h.CheckedInAtUtc,
                h.Reason, h.TicketNumber, h.ApprovedBy,
                h.WasAutoCheckedIn,
                DurationMinutes = h.CheckedInAtUtc.HasValue
                    ? (int)(h.CheckedInAtUtc.Value - h.CheckedOutAtUtc).TotalMinutes
                    : (int?)null
            })
            .ToListAsync();

        var stillCheckedOut = history.Count(h => h.CheckedInAtUtc == null);
        var autoCheckedIn = history.Count(h => h.WasAutoCheckedIn);

        return new
        {
            totalCheckouts = history.Count,
            stillCheckedOut,
            autoCheckedIn,
            manualCheckedIn = history.Count - stillCheckedOut - autoCheckedIn,
            averageDurationMinutes = history
                .Where(h => h.DurationMinutes.HasValue)
                .Select(h => h.DurationMinutes!.Value)
                .DefaultIfEmpty(0)
                .Average(),
            checkouts = history
        };
    }

    // -----------------------------------------------------------------------
    // 5. Break-Glass Usage Report
    // -----------------------------------------------------------------------
    private static async Task<object> GetBreakGlassUsageReport(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var events = await db.BreakGlassEvents
            .Where(e => e.CreatedAtUtc >= from && e.CreatedAtUtc <= to)
            .OrderByDescending(e => e.CreatedAtUtc)
            .Select(e => new
            {
                e.Id, e.RequesterId, e.RequesterUsername,
                e.RequesterIpAddress, e.ResourceType,
                e.ResourceId, e.ResourceName,
                e.EmergencyReason, e.TicketNumber,
                Status = e.Status.ToString(),
                e.CreatedAtUtc, e.ExpiresAtUtc,
                e.AcknowledgedAtUtc, e.AcknowledgedByUsername,
                e.AcknowledgementNotes
            })
            .ToListAsync();

        var byStatus = events.GroupBy(e => e.Status).ToDictionary(g => g.Key, g => g.Count());
        var byResourceType = events.GroupBy(e => e.ResourceType).ToDictionary(g => g.Key, g => g.Count());

        return new
        {
            totalEvents = events.Count,
            byStatus,
            byResourceType,
            unacknowledged = events.Count(e => e.AcknowledgedAtUtc == null),
            events
        };
    }

    // -----------------------------------------------------------------------
    // 6. JIT Access Summary Report
    // -----------------------------------------------------------------------
    private static async Task<object> GetJitAccessSummaryReport(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var requests = await db.JitAccessRequests
            .Where(r => r.CreatedAtUtc >= from && r.CreatedAtUtc <= to)
            .OrderByDescending(r => r.CreatedAtUtc)
            .Select(r => new
            {
                r.Id, r.RequesterId, r.RequesterUsername,
                r.ResourceType, r.ResourceId, r.ResourceName,
                r.Reason, r.RequestedDurationMinutes,
                Status = r.Status.ToString(),
                r.CreatedAtUtc, r.ApprovedAtUtc, r.ApprovedByUsername,
                r.ActivatedAtUtc, r.ExpiresAtUtc,
                r.DenyReason, r.ExtensionRequested
            })
            .ToListAsync();

        var byStatus = requests.GroupBy(r => r.Status).ToDictionary(g => g.Key, g => g.Count());
        var byResourceType = requests.GroupBy(r => r.ResourceType).ToDictionary(g => g.Key, g => g.Count());
        var avgDuration = requests
            .Select(r => r.RequestedDurationMinutes)
            .DefaultIfEmpty(0)
            .Average();

        return new
        {
            totalRequests = requests.Count,
            byStatus,
            byResourceType,
            averageRequestedDurationMinutes = Math.Round(avgDuration, 1),
            extensionRequests = requests.Count(r => r.ExtensionRequested),
            requests
        };
    }

    // -----------------------------------------------------------------------
    // 7. Privileged Account Inventory Report
    // -----------------------------------------------------------------------
    private static async Task<object> GetPrivilegedAccountInventoryReport(OrkunPamDbContext db)
    {
        var credentials = await db.Credentials
            .Select(c => new
            {
                c.Id, c.Name, c.Username, c.DeviceId,
                CredentialType = c.CredentialType.ToString(),
                Status = c.Status.ToString(),
                c.IsDiscovered, c.IsTakenOver,
                c.RequiresApproval,
                c.LastRotatedAtUtc, c.NextRotationAtUtc,
                HasRotationPolicy = c.RotationPolicyId != null,
                c.CheckedOutByUserId,
                c.CreatedAtUtc
            })
            .OrderBy(c => c.Name)
            .ToListAsync();

        var byType = credentials.GroupBy(c => c.CredentialType).ToDictionary(g => g.Key, g => g.Count());
        var byStatus = credentials.GroupBy(c => c.Status).ToDictionary(g => g.Key, g => g.Count());

        return new
        {
            totalAccounts = credentials.Count,
            byType,
            byStatus,
            discovered = credentials.Count(c => c.IsDiscovered),
            takenOver = credentials.Count(c => c.IsTakenOver),
            withRotationPolicy = credentials.Count(c => c.HasRotationPolicy),
            requiresApproval = credentials.Count(c => c.RequiresApproval),
            currentlyCheckedOut = credentials.Count(c => c.CheckedOutByUserId != null),
            accounts = credentials
        };
    }

    // -----------------------------------------------------------------------
    // 8. Vendor Access Report
    // -----------------------------------------------------------------------
    private static async Task<object> GetVendorAccessReport(OrkunPamDbContext db)
    {
        var now = DateTime.UtcNow;
        var vendors = await db.Users
            .Where(u => u.IsTemporary)
            .Select(u => new
            {
                u.Id, u.Username, u.DisplayName, u.Email,
                Status = u.Status.ToString(),
                u.TemporaryExpiresUtc,
                IsExpired = u.TemporaryExpiresUtc.HasValue && u.TemporaryExpiresUtc < now,
                u.LastLoginAtUtc, u.MfaEnabled,
                u.CreatedAtUtc
            })
            .OrderBy(u => u.TemporaryExpiresUtc)
            .ToListAsync();

        var active = vendors.Count(v => v.Status == UserStatus.Active.ToString() && !v.IsExpired);
        var expired = vendors.Count(v => v.IsExpired);
        var neverLoggedIn = vendors.Count(v => v.LastLoginAtUtc == null);

        return new
        {
            totalVendorAccounts = vendors.Count,
            active,
            expired,
            neverLoggedIn,
            mfaEnabled = vendors.Count(v => v.MfaEnabled),
            vendors
        };
    }

    // -----------------------------------------------------------------------
    // 9. Compliance Summary Report
    // -----------------------------------------------------------------------
    private static async Task<object> GetComplianceSummaryReport(OrkunPamDbContext db)
    {
        var frameworks = await db.ComplianceFrameworks.ToListAsync();
        var assessments = await db.ControlAssessments.ToListAsync();

        var frameworkSummaries = frameworks.Select(f =>
        {
            var controls = assessments.Where(a => a.FrameworkId == f.Id).ToList();
            var total = controls.Count;
            var compliant = controls.Count(c => c.Status == 1);
            var partial = controls.Count(c => c.Status == 2);
            var nonCompliant = controls.Count(c => c.Status == 0);
            var notApplicable = controls.Count(c => c.Status == 3);
            var assessed = total - notApplicable;

            return new
            {
                frameworkId = f.Id,
                frameworkName = f.Name,
                version = f.Version,
                isBuiltIn = f.IsBuiltIn,
                totalControls = total,
                compliant,
                partial,
                nonCompliant,
                notApplicable,
                compliancePercentage = assessed > 0
                    ? Math.Round((double)compliant / assessed * 100, 1)
                    : 0,
                lastAssessedAtUtc = controls.Any()
                    ? controls.Max(c => c.AssessedAtUtc)
                    : (DateTime?)null
            };
        }).ToList();

        return new
        {
            totalFrameworks = frameworks.Count,
            overallCompliancePercentage = frameworkSummaries.Any()
                ? Math.Round(frameworkSummaries.Average(f => f.compliancePercentage), 1)
                : 0,
            frameworks = frameworkSummaries
        };
    }

    // -----------------------------------------------------------------------
    // 10. MFA Enrollment & Usage Report (RFP Reporting #37) — Issue #174
    // -----------------------------------------------------------------------
    private static async Task<object> GetMfaUsageReport(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var users = await db.Users
            .Where(u => u.Status == UserStatus.Active)
            .Select(u => new
            {
                u.Username, u.MfaEnabled, u.LastLoginAtUtc,
                u.DisplayName
            })
            .ToListAsync();

        var mfaEvents = await db.AuditLogs
            .Where(a => a.Timestamp >= from && a.Timestamp <= to &&
                        (a.EventType.Contains("Mfa") || a.EventType.Contains("MFA") ||
                         a.EventType.Contains("Totp") || a.EventType.Contains("Fido") ||
                         a.EventType.Contains("WebAuthn")))
            .OrderByDescending(a => a.Timestamp)
            .Select(a => new
            {
                a.Timestamp, a.EventType, a.ActorUsername,
                a.ActorIpAddress, Outcome = a.Outcome.ToString()
            })
            .ToListAsync();

        var notEnrolled = users
            .Where(u => !u.MfaEnabled)
            .Select(u => u.Username)
            .ToList();

        var totalUsers = users.Count;
        var enrolledCount = users.Count(u => u.MfaEnabled);

        return new
        {
            totalActiveUsers        = totalUsers,
            mfaEnrolled             = enrolledCount,
            mfaNotEnrolled          = totalUsers - enrolledCount,
            enrollmentPercentage    = totalUsers > 0 ? Math.Round((double)enrolledCount / totalUsers * 100, 1) : 0.0,
            totalMfaEvents          = mfaEvents.Count,
            successfulVerifications = mfaEvents.Count(e => e.Outcome == "Success"),
            failedAttempts          = mfaEvents.Count(e => e.Outcome == "Failure"),
            usersNotEnrolled        = notEnrolled,
            recentMfaEvents         = mfaEvents.Take(100)
        };
    }

    // -----------------------------------------------------------------------
    // 11. Account Lifecycle & Privilege Change Report (RFP Reporting #35) — Issue #173
    // -----------------------------------------------------------------------
    private static async Task<object> GetAccountLifecycleReport(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var events = await db.AuditLogs
            .Where(a => a.Timestamp >= from && a.Timestamp <= to &&
                        (a.EventCategory == "User" ||
                         a.EventType.Contains("User") ||
                         a.EventType.Contains("Role") ||
                         a.EventType.Contains("Password") ||
                         a.EventType.Contains("Lock")))
            .OrderByDescending(a => a.Timestamp)
            .Select(a => new
            {
                a.Timestamp,
                a.EventType,
                a.EventCategory,
                a.ActorUsername,
                a.TargetId,
                a.ActorIpAddress,
                a.Details,
                Outcome = a.Outcome.ToString()
            })
            .ToListAsync();

        var created     = events.Count(e => e.EventType.Contains("Created"));
        var deleted     = events.Count(e => e.EventType.Contains("Deleted") || e.EventType.Contains("Removed"));
        var locked      = events.Count(e => e.EventType.Contains("Lock") && !e.EventType.Contains("Unlock"));
        var roleChanges = events.Count(e => e.EventType.Contains("Role"));
        var pwResets    = events.Count(e => e.EventType.Contains("Password"));

        return new
        {
            totalEvents     = events.Count,
            newAccounts     = created,
            deletedAccounts = deleted,
            lockEvents      = locked,
            roleChangeEvents = roleChanges,
            passwordEvents  = pwResets,
            events
        };
    }

    // Wraps a value in CSV quotes, escaping embedded quotes
    private static string CsvCell(string? value)
    {
        if (value == null) return "";
        var s = value.Replace("\"", "\"\"");
        return s.Contains(',') || s.Contains('"') || s.Contains('\n') ? $"\"{ s}\"" : s;
    }
}

public record ReportRunRequest(DateTime? From, DateTime? To);
