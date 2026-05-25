using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class OperationalReportsEndpoints
{
    public static void MapOperationalReportsEndpoints(this IEndpointRouteBuilder app)
    {
        // GET /api/v1/reports/operational/capacity?months=3
        app.MapGet("/api/v1/reports/operational/capacity", async (
            OrkunPamDbContext db,
            int months = 3) =>
        {
            months = Math.Clamp(months, 1, 12);
            var since = DateTime.UtcNow.AddMonths(-months);

            // Build weekly bucket start dates
            var bucketStarts = new List<DateTime>();
            var current = since.Date;
            while (current < DateTime.UtcNow.Date)
            {
                bucketStarts.Add(current);
                current = current.AddDays(7);
            }

            var devices    = await db.Devices.Where(d => d.CreatedAtUtc >= since).Select(d => d.CreatedAtUtc.Date).ToListAsync();
            var creds      = await db.Credentials.Where(c => c.CreatedAtUtc >= since).Select(c => c.CreatedAtUtc.Date).ToListAsync();
            var users      = await db.Users.Where(u => u.CreatedAtUtc >= since && !u.IsServiceAccount).Select(u => u.CreatedAtUtc.Date).ToListAsync();
            var recordings = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= since && s.RecordingSizeBytes != null)
                .Select(s => new { s.StartedAtUtc.Date, s.RecordingSizeBytes })
                .ToListAsync();

            var devBase  = await db.Devices.CountAsync(d => d.CreatedAtUtc < since);
            var creBase  = await db.Credentials.CountAsync(c => c.CreatedAtUtc < since);
            var usrBase  = await db.Users.CountAsync(u => u.CreatedAtUtc < since && !u.IsServiceAccount);

            var devRunning = devBase;
            var creRunning = creBase;
            var usrRunning = usrBase;
            var devTotals  = new List<int>();
            var creTotals  = new List<int>();
            var usrTotals  = new List<int>();

            var deviceTrend = bucketStarts.Select(start =>
            {
                var end = start.AddDays(7);
                var n = devices.Count(d => d >= start && d < end);
                devRunning += n; devTotals.Add(devRunning);
                return new { week = start.ToString("yyyy-MM-dd"), newCount = n, total = devRunning };
            }).ToList();

            devRunning = devBase;
            var credentialTrend = bucketStarts.Select(start =>
            {
                var end = start.AddDays(7);
                var n = creds.Count(d => d >= start && d < end);
                creRunning += n; creTotals.Add(creRunning);
                return new { week = start.ToString("yyyy-MM-dd"), newCount = n, total = creRunning };
            }).ToList();

            creRunning = creBase;
            var userTrend = bucketStarts.Select(start =>
            {
                var end = start.AddDays(7);
                var n = users.Count(d => d >= start && d < end);
                usrRunning += n; usrTotals.Add(usrRunning);
                return new { week = start.ToString("yyyy-MM-dd"), newCount = n, total = usrRunning };
            }).ToList();

            var storageTrend = bucketStarts.Select(start =>
            {
                var end = start.AddDays(7);
                var wb = recordings.Where(r => r.Date >= start && r.Date < end).Sum(r => r.RecordingSizeBytes ?? 0);
                return new { week = start.ToString("yyyy-MM-dd"), newGb = Math.Round(wb / 1_073_741_824.0, 3) };
            }).ToList();

            var projection = new
            {
                devices = LinearProject90(devTotals),
                creds   = LinearProject90(creTotals),
                users   = LinearProject90(usrTotals)
            };

            return Results.Ok(new
            {
                success = true,
                data = new { months, since, deviceTrend, credentialTrend, userTrend, storageTrend, projection90Days = projection }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("Reports");

        // GET /api/v1/reports/operational/performance?from=&to=
        app.MapGet("/api/v1/reports/operational/performance", async (
            OrkunPamDbContext db,
            DateTime? from,
            DateTime? to) =>
        {
            var dateFrom = from ?? DateTime.UtcNow.AddDays(-30);
            var dateTo   = to   ?? DateTime.UtcNow;

            // Session success rate
            var sessions = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= dateFrom && s.StartedAtUtc <= dateTo)
                .Select(s => new { s.Status, s.SessionType, s.DeviceId, s.StartedAtUtc.Date })
                .ToListAsync();

            var totalSessions = sessions.Count;
            var completedSessions = sessions.Count(s => s.Status == SessionStatus.Completed);
            var sessionSuccessRate = totalSessions > 0
                ? Math.Round((double)completedSessions / totalSessions * 100, 1)
                : 100.0;

            // Credential rotation performance
            var credStats = await db.Credentials
                .Select(c => new
                {
                    c.LastRotatedAtUtc,
                    c.RotationFailureCount,
                    c.LastRotationFailedAtUtc
                })
                .ToListAsync();

            var totalCreds = credStats.Count;
            var rotated = credStats.Count(c => c.LastRotatedAtUtc != null);
            var rotationSuccessRate = totalCreds > 0
                ? Math.Round((double)rotated / totalCreds * 100, 1)
                : 0.0;
            var totalFailures = credStats.Sum(c => c.RotationFailureCount);

            // Proxy uptime by protocol (days with at least one session per protocol)
            var totalDays = Math.Max(1, (int)(dateTo - dateFrom).TotalDays);
            var proxyUptime = sessions
                .GroupBy(s => s.SessionType.ToString())
                .Select(g => new
                {
                    protocol  = g.Key,
                    activeDays = g.Select(s => s.Date).Distinct().Count(),
                    totalDays,
                    uptimePercent = Math.Round((double)g.Select(s => s.Date).Distinct().Count() / totalDays * 100, 1)
                })
                .OrderByDescending(p => p.activeDays)
                .ToList();

            // Top 5 devices with most failed/terminated sessions
            var terminatedSessions = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= dateFrom && s.StartedAtUtc <= dateTo
                         && s.Status == SessionStatus.Terminated)
                .GroupBy(s => s.DeviceId)
                .Select(g => new { DeviceId = g.Key, FailedCount = g.Count() })
                .OrderByDescending(g => g.FailedCount)
                .Take(5)
                .ToListAsync();

            var deviceIds = terminatedSessions.Select(d => d.DeviceId).ToList();
            var deviceNames = await db.Devices
                .Where(d => deviceIds.Contains(d.Id))
                .Select(d => new { d.Id, d.Hostname, d.IpAddress })
                .ToDictionaryAsync(d => d.Id);

            var topSlowDevices = terminatedSessions.Select(d => new
            {
                d.DeviceId,
                hostname = deviceNames.TryGetValue(d.DeviceId, out var dev) ? dev.Hostname : d.DeviceId.ToString()[..8],
                d.FailedCount
            }).ToList();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    periodFrom         = dateFrom,
                    periodTo           = dateTo,
                    totalSessions,
                    completedSessions,
                    sessionSuccessRate,
                    totalCredentials   = totalCreds,
                    credentialsRotated = rotated,
                    rotationSuccessRate,
                    totalRotationFailures = totalFailures,
                    proxyUptimeByProtocol = proxyUptime,
                    topTerminatedDevices  = topSlowDevices
                }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("Reports");

        // GET /api/v1/reports/operational/sla?from=&to=
        app.MapGet("/api/v1/reports/operational/sla", async (
            OrkunPamDbContext db,
            DateTime? from,
            DateTime? to) =>
        {
            var dateFrom = from ?? DateTime.UtcNow.AddDays(-30);
            var dateTo   = to   ?? DateTime.UtcNow;

            // 1. Credential rotation on-time rate
            //    On-time: credential has been rotated within the last IntervalDays of its policy
            var credRotation = await db.Credentials
                .Where(c => c.RotationPolicyId != null)
                .Join(db.RotationPolicies,
                    c => c.RotationPolicyId,
                    rp => rp.Id,
                    (c, rp) => new
                    {
                        c.LastRotatedAtUtc,
                        rp.IntervalDays
                    })
                .ToListAsync();

            var credWithPolicy = credRotation.Count;
            var onTimeRotations = credRotation.Count(c =>
                c.LastRotatedAtUtc != null &&
                (DateTime.UtcNow - c.LastRotatedAtUtc.Value).TotalDays <= c.IntervalDays);
            var rotationOnTimePercent = credWithPolicy > 0
                ? Math.Round((double)onTimeRotations / credWithPolicy * 100, 1)
                : 100.0;

            // 2. Session recording coverage
            var periodSessions = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= dateFrom && s.StartedAtUtc <= dateTo)
                .Select(s => new { s.RecordingPath })
                .ToListAsync();

            var totalPeriodSessions = periodSessions.Count;
            var recordedSessions = periodSessions.Count(s => s.RecordingPath != null);
            var recordingCoveragePercent = totalPeriodSessions > 0
                ? Math.Round((double)recordedSessions / totalPeriodSessions * 100, 1)
                : 0.0;

            // 3. Approval response time (average hours from request to completion)
            var approvals = await db.ApprovalRequests
                .Where(a => a.CreatedAtUtc >= dateFrom && a.CreatedAtUtc <= dateTo
                         && a.CompletedAtUtc != null)
                .Select(a => new { a.CreatedAtUtc, a.CompletedAtUtc })
                .ToListAsync();

            var avgApprovalHours = approvals.Count > 0
                ? Math.Round(approvals.Average(a => (a.CompletedAtUtc!.Value - a.CreatedAtUtc).TotalHours), 2)
                : 0.0;

            // 4. Checkout compliance (checked-in within credential MaxCheckoutMinutes)
            var checkoutRaw = await db.CheckOutHistories
                .Where(c => c.CheckedOutAtUtc >= dateFrom && c.CheckedOutAtUtc <= dateTo
                         && c.CheckedInAtUtc != null)
                .Join(db.Credentials,
                    ch => ch.CredentialId,
                    cr => cr.Id,
                    (ch, cr) => new
                    {
                        ch.CheckedOutAtUtc,
                        ch.CheckedInAtUtc,
                        cr.MaxCheckoutMinutes
                    })
                .ToListAsync();

            var totalCheckouts = checkoutRaw.Count;
            var compliantCheckouts = checkoutRaw.Count(c =>
                (c.CheckedInAtUtc!.Value - c.CheckedOutAtUtc).TotalMinutes <= c.MaxCheckoutMinutes);
            var checkoutCompliancePercent = totalCheckouts > 0
                ? Math.Round((double)compliantCheckouts / totalCheckouts * 100, 1)
                : 100.0;

            // 5. MFA enrollment coverage
            var totalActiveUsers = await db.Users
                .CountAsync(u => u.Status == UserStatus.Active && !u.IsServiceAccount);
            var mfaEnrolledUsers = await db.Users
                .CountAsync(u => u.Status == UserStatus.Active && !u.IsServiceAccount && u.MfaEnabled);
            var mfaEnrollmentPercent = totalActiveUsers > 0
                ? Math.Round((double)mfaEnrolledUsers / totalActiveUsers * 100, 1)
                : 0.0;

            // SLA breaches (metrics below target)
            const double rotationTarget = 90.0;
            const double recordingTarget = 95.0;
            const double checkoutTarget  = 95.0;
            const double mfaTarget       = 100.0;
            const double approvalMaxHours = 4.0;

            var breaches = new List<object>();
            if (rotationOnTimePercent < rotationTarget)
                breaches.Add(new { metric = "Rotation On-Time", actual = rotationOnTimePercent, target = rotationTarget });
            if (recordingCoveragePercent < recordingTarget)
                breaches.Add(new { metric = "Recording Coverage", actual = recordingCoveragePercent, target = recordingTarget });
            if (checkoutCompliancePercent < checkoutTarget)
                breaches.Add(new { metric = "Checkout Compliance", actual = checkoutCompliancePercent, target = checkoutTarget });
            if (mfaEnrollmentPercent < mfaTarget)
                breaches.Add(new { metric = "MFA Enrollment", actual = mfaEnrollmentPercent, target = mfaTarget });
            if (avgApprovalHours > approvalMaxHours)
                breaches.Add(new { metric = "Approval Response Time", actual = avgApprovalHours, target = approvalMaxHours, unit = "hours" });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    periodFrom             = dateFrom,
                    periodTo               = dateTo,
                    rotationOnTimePercent,
                    rotationTarget,
                    credentialsWithPolicy  = credWithPolicy,
                    onTimeRotations,
                    recordingCoveragePercent,
                    recordingTarget,
                    totalPeriodSessions,
                    recordedSessions,
                    avgApprovalHours,
                    approvalMaxHoursTarget = approvalMaxHours,
                    totalApprovals         = approvals.Count,
                    checkoutCompliancePercent,
                    checkoutTarget,
                    totalCheckouts,
                    compliantCheckouts,
                    mfaEnrollmentPercent,
                    mfaTarget,
                    totalActiveUsers,
                    mfaEnrolledUsers,
                    slaBreaches            = breaches
                }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("Reports");
    }

    private static int LinearProject90(List<int> totals)
    {
        if (totals.Count < 2) return totals.LastOrDefault();
        var recent = totals.TakeLast(4).ToList();
        var growth = (recent.Last() - recent.First()) / (double)(recent.Count - 1);
        return (int)Math.Max(recent.Last() + growth * 13, recent.Last());
    }
}
