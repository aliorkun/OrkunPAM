using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ComplianceReportEndpoints
{
    public static void MapComplianceReportEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/compliance").WithTags("ComplianceReports").RequireAuthorization();

        group.MapGet("/report-templates", () =>
        {
            var templates = new[]
            {
                new
                {
                    Id = "sox",
                    Name = "SOX PAM Controls",
                    Description = "Sarbanes-Oxley Act — privileged access review, SoD, credential rotation",
                    Version = "2002",
                    Controls = new[]
                    {
                        new { Code = "sox-01", Name = "Privileged Access Review (90 days)", Reference = "Section 302/404" },
                        new { Code = "sox-02", Name = "Separation of Duties",               Reference = "COBIT DS5.4" },
                        new { Code = "sox-03", Name = "Failed Access Attempts",             Reference = "IT General Controls" },
                        new { Code = "sox-04", Name = "Credential Rotation Compliance",     Reference = "IT General Controls" },
                    }
                },
                new
                {
                    Id = "pci-dss",
                    Name = "PCI-DSS PAM Controls",
                    Description = "Payment Card Industry Data Security Standard — Chapter 7, 8, 10",
                    Version = "4.0",
                    Controls = new[]
                    {
                        new { Code = "pci-01", Name = "MFA Enforcement Rate (Req 8.4)",           Reference = "PCI DSS v4 Req 8.4" },
                        new { Code = "pci-02", Name = "Privileged Account Access Control (Req 7)", Reference = "PCI DSS v4 Req 7" },
                        new { Code = "pci-03", Name = "Audit Log Integrity (Req 10.5)",            Reference = "PCI DSS v4 Req 10.5" },
                        new { Code = "pci-04", Name = "Inactive Account Lockout (Req 8.2)",        Reference = "PCI DSS v4 Req 8.2" },
                    }
                },
                new
                {
                    Id = "iso27001",
                    Name = "ISO 27001 PAM Controls",
                    Description = "ISO/IEC 27001:2022 — Access control (A.9) and Operations security (A.12)",
                    Version = "2022",
                    Controls = new[]
                    {
                        new { Code = "iso-01", Name = "Access Control Policy (A.9.1)",              Reference = "ISO 27001 A.9.1" },
                        new { Code = "iso-02", Name = "Privileged User Activity Monitoring (A.9.2)", Reference = "ISO 27001 A.9.2" },
                        new { Code = "iso-03", Name = "Access Rights Review (A.9.2.5)",             Reference = "ISO 27001 A.9.2.5" },
                        new { Code = "iso-04", Name = "Audit Log Monitoring (A.12.4)",              Reference = "ISO 27001 A.12.4" },
                    }
                }
            };
            return Results.Ok(new { success = true, data = templates });
        });

        group.MapGet("/report/{framework}/controls", async (string framework, DateTime? from, DateTime? to, OrkunPamDbContext db) =>
        {
            var dateFrom = from ?? DateTime.UtcNow.AddDays(-90);
            var dateTo   = to   ?? DateTime.UtcNow;

            var controls = await EvaluateControlsAsync(framework, dateFrom, dateTo, db);
            if (controls == null)
                return Results.NotFound(new { success = false, errors = new[] { $"Framework '{framework}' not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    framework,
                    dateFrom,
                    dateTo,
                    passCount    = controls.Count(c => c.Status == "pass"),
                    partialCount = controls.Count(c => c.Status == "partial"),
                    failCount    = controls.Count(c => c.Status == "fail"),
                    score        = controls.Count > 0
                        ? Math.Round((double)controls.Count(c => c.Status == "pass") / controls.Count * 100, 1)
                        : 0.0,
                    controls
                }
            });
        });

        group.MapPost("/report/generate", async (ComplianceReportRequest req, OrkunPamDbContext db,
                                                 HttpContext ctx, IAuditService audit) =>
        {
            var dateFrom = req.From ?? DateTime.UtcNow.AddDays(-90);
            var dateTo   = req.To   ?? DateTime.UtcNow;

            var controls = await EvaluateControlsAsync(req.Framework, dateFrom, dateTo, db);
            if (controls == null)
                return Results.BadRequest(new { success = false, errors = new[] { $"Unknown framework: {req.Framework}" } });

            if (req.IncludeControls is { Length: > 0 })
                controls = controls.Where(c => req.IncludeControls.Contains(c.Code)).ToList();

            var passed  = controls.Count(c => c.Status == "pass");
            var total   = controls.Count;
            var score   = total > 0 ? Math.Round((double)passed / total * 100, 1) : 0.0;

            var frameworkName = req.Framework switch
            {
                "sox"      => "SOX PAM Controls",
                "pci-dss"  => "PCI-DSS PAM Controls (Chapter 7/8/10)",
                "iso27001" => "ISO 27001 PAM Controls (A.9 / A.12)",
                _          => req.Framework
            };

            var actorId   = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown";
            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _ = audit.LogAsync("Compliance", "ComplianceReportGenerated",
                Guid.TryParse(actorId, out var aid) ? aid : Guid.Empty,
                actorName, ip, "ComplianceReport", req.Framework,
                new { framework = req.Framework, score, from = dateFrom, to = dateTo });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    reportId      = Guid.NewGuid(),
                    framework     = req.Framework,
                    frameworkName,
                    generatedAt   = DateTime.UtcNow,
                    period        = new { from = dateFrom, to = dateTo },
                    summary = new
                    {
                        totalControls   = total,
                        passed,
                        partial         = controls.Count(c => c.Status == "partial"),
                        failed          = controls.Count(c => c.Status == "fail"),
                        score,
                        overallStatus   = score >= 90 ? "Compliant" : score >= 70 ? "Partially Compliant" : "Non-Compliant"
                    },
                    controls
                }
            });
        });
    }

    private static async Task<List<ControlResult>?> EvaluateControlsAsync(
        string framework, DateTime from, DateTime to, OrkunPamDbContext db)
    {
        return framework switch
        {
            "sox"      => await EvaluateSoxAsync(from, to, db),
            "pci-dss"  => await EvaluatePciDssAsync(from, to, db),
            "iso27001" => await EvaluateIso27001Async(from, to, db),
            _          => null
        };
    }

    // ── SOX ──────────────────────────────────────────────────────────────────

    private static async Task<List<ControlResult>> EvaluateSoxAsync(
        DateTime from, DateTime to, OrkunPamDbContext db)
    {
        var results = new List<ControlResult>();

        // sox-01: Privileged Access Review
        var sessions  = await db.ProxySessions.CountAsync(s => s.StartedAtUtc >= from && s.StartedAtUtc <= to);
        var checkouts = await db.CheckOutHistories.CountAsync(c => c.CheckedOutAtUtc >= from && c.CheckedOutAtUtc <= to);
        results.Add(new ControlResult(
            "sox-01", "Privileged Access Review (90 days)", "Section 302/404",
            sessions > 0 || checkouts > 0 ? "pass" : "partial",
            sessions > 0 || checkouts > 0
                ? "Privileged access activity is being monitored and recorded."
                : "No privileged access sessions recorded in period.",
            new Dictionary<string, object>
            {
                ["sessionsRecorded"]    = sessions,
                ["credentialCheckouts"] = checkouts,
                ["periodDays"]          = (int)(to - from).TotalDays
            }));

        // sox-02: Separation of Duties
        var sodRules = await db.SodRules.Where(r => r.IsEnabled).ToListAsync();
        var totalViolations = 0;
        foreach (var rule in sodRules)
        {
            totalViolations += await db.UserRoles
                .Where(ur => ur.RoleId == rule.RoleA)
                .Select(ur => ur.UserId)
                .Intersect(db.UserRoles.Where(ur => ur.RoleId == rule.RoleB).Select(ur => ur.UserId))
                .CountAsync();
        }
        results.Add(new ControlResult(
            "sox-02", "Separation of Duties", "COBIT DS5.4",
            totalViolations == 0 ? "pass" : "fail",
            totalViolations == 0
                ? $"No SoD violations detected across {sodRules.Count} rule(s)."
                : $"{totalViolations} SoD violation(s) detected across {sodRules.Count} rule(s).",
            new Dictionary<string, object>
            {
                ["sodRulesConfigured"] = sodRules.Count,
                ["violations"]         = totalViolations
            }));

        // sox-03: Failed Access Attempts
        var failedLogins = await db.AuditLogs
            .CountAsync(a => a.Timestamp >= from && a.Timestamp <= to
                          && a.EventCategory == "Auth" && a.Outcome == AuditOutcome.Failure);
        var totalLogins = await db.AuditLogs
            .CountAsync(a => a.Timestamp >= from && a.Timestamp <= to && a.EventCategory == "Auth");
        var failRate = totalLogins > 0 ? Math.Round((double)failedLogins / totalLogins * 100, 1) : 0.0;
        results.Add(new ControlResult(
            "sox-03", "Failed Access Attempts", "IT General Controls",
            failRate <= 5 ? "pass" : failRate <= 15 ? "partial" : "fail",
            $"{failedLogins} failed auth attempts ({failRate}% failure rate) in period.",
            new Dictionary<string, object>
            {
                ["failedAttempts"] = failedLogins,
                ["totalAttempts"]  = totalLogins,
                ["failureRate"]    = failRate
            }));

        // sox-04: Credential Rotation Compliance
        var totalManaged = await db.Credentials.CountAsync(c => c.RotationPolicyId != null);
        var overdue      = await db.Credentials.CountAsync(c => c.RotationPolicyId != null && c.NextRotationAtUtc < DateTime.UtcNow);
        var rotRate      = totalManaged > 0 ? Math.Round((double)(totalManaged - overdue) / totalManaged * 100, 1) : 100.0;
        results.Add(new ControlResult(
            "sox-04", "Credential Rotation Compliance", "IT General Controls",
            rotRate >= 90 ? "pass" : rotRate >= 70 ? "partial" : "fail",
            $"{rotRate}% of managed credentials are rotation-compliant ({totalManaged - overdue}/{totalManaged}).",
            new Dictionary<string, object>
            {
                ["managedCredentials"] = totalManaged,
                ["overdueRotation"]    = overdue,
                ["complianceRate"]     = rotRate
            }));

        return results;
    }

    // ── PCI-DSS ──────────────────────────────────────────────────────────────

    private static async Task<List<ControlResult>> EvaluatePciDssAsync(
        DateTime from, DateTime to, OrkunPamDbContext db)
    {
        var results = new List<ControlResult>();

        // pci-01: MFA Enforcement Rate (Req 8.4)
        var totalActive = await db.Users.CountAsync(u => u.Status == UserStatus.Active);
        var mfaEnabled  = await db.Users.CountAsync(u => u.Status == UserStatus.Active && u.MfaEnabled);
        var mfaRate     = totalActive > 0 ? Math.Round((double)mfaEnabled / totalActive * 100, 1) : 0.0;
        results.Add(new ControlResult(
            "pci-01", "MFA Enforcement Rate (Req 8.4)", "PCI DSS v4 Req 8.4",
            mfaRate >= 90 ? "pass" : mfaRate >= 70 ? "partial" : "fail",
            $"{mfaRate}% of active users have MFA enabled ({mfaEnabled}/{totalActive}).",
            new Dictionary<string, object>
            {
                ["activeUsers"]     = totalActive,
                ["mfaEnabledUsers"] = mfaEnabled,
                ["mfaRate"]         = mfaRate
            }));

        // pci-02: Privileged Account Access Control (Req 7)
        var totalCreds   = await db.Credentials.CountAsync();
        var deviceLinked = await db.Credentials.CountAsync(c => c.DeviceId != null);
        results.Add(new ControlResult(
            "pci-02", "Privileged Account Access Control (Req 7)", "PCI DSS v4 Req 7",
            totalCreds > 0 ? "pass" : "partial",
            $"{totalCreds} privileged credentials in vault. {deviceLinked} linked to managed devices.",
            new Dictionary<string, object>
            {
                ["totalCredentials"] = totalCreds,
                ["deviceLinked"]     = deviceLinked
            }));

        // pci-03: Audit Log Integrity (Req 10.5)
        var tampered   = await db.AuditLogs.CountAsync(a => a.IsTampered);
        var auditCount = await db.AuditLogs.CountAsync(a => a.Timestamp >= from && a.Timestamp <= to);
        results.Add(new ControlResult(
            "pci-03", "Audit Log Integrity (Req 10.5)", "PCI DSS v4 Req 10.5",
            tampered == 0 ? "pass" : "fail",
            tampered == 0
                ? $"Audit log integrity verified. {auditCount} entries in period, no tampering detected."
                : $"WARNING: {tampered} tampered audit log entries detected!",
            new Dictionary<string, object>
            {
                ["auditEntriesInPeriod"] = auditCount,
                ["tamperedEntries"]      = tampered,
                ["integrityValid"]       = tampered == 0
            }));

        // pci-04: Inactive Account Controls (Req 8.2)
        var expiredActive = await db.Users.CountAsync(u =>
            u.PasswordExpiresAt != null && u.PasswordExpiresAt < DateTime.UtcNow
            && u.Status == UserStatus.Active);
        var lockedDisabled = await db.Users.CountAsync(u =>
            u.Status == UserStatus.Locked || u.Status == UserStatus.Disabled);
        results.Add(new ControlResult(
            "pci-04", "Inactive Account Lockout (Req 8.2)", "PCI DSS v4 Req 8.2",
            expiredActive == 0 ? "pass" : "fail",
            expiredActive == 0
                ? $"No expired accounts with Active status. {lockedDisabled} accounts properly locked/disabled."
                : $"{expiredActive} expired account(s) still have Active status.",
            new Dictionary<string, object>
            {
                ["lockedDisabledAccounts"]  = lockedDisabled,
                ["expiredActiveAccounts"]   = expiredActive
            }));

        return results;
    }

    // ── ISO 27001 ─────────────────────────────────────────────────────────────

    private static async Task<List<ControlResult>> EvaluateIso27001Async(
        DateTime from, DateTime to, OrkunPamDbContext db)
    {
        var results = new List<ControlResult>();

        // iso-01: Access Control Policy (A.9.1)
        var policyCount  = await db.Policies.CountAsync();
        var sessionPols  = await db.SessionPolicies.CountAsync();
        results.Add(new ControlResult(
            "iso-01", "Access Control Policy (A.9.1)", "ISO 27001 A.9.1",
            policyCount > 0 || sessionPols > 0 ? "pass" : "fail",
            $"{policyCount} access policies and {sessionPols} session policies configured.",
            new Dictionary<string, object>
            {
                ["accessPolicies"]  = policyCount,
                ["sessionPolicies"] = sessionPols
            }));

        // iso-02: Privileged User Activity Monitoring (A.9.2)
        var recordedSessions = await db.ProxySessions
            .CountAsync(s => s.StartedAtUtc >= from && s.StartedAtUtc <= to && s.Status == SessionStatus.Completed);
        var commandsLogged = await db.CommandLogs
            .CountAsync(c => c.Timestamp >= from && c.Timestamp <= to);
        results.Add(new ControlResult(
            "iso-02", "Privileged User Activity Monitoring (A.9.2)", "ISO 27001 A.9.2",
            recordedSessions > 0 ? "pass" : "partial",
            $"{recordedSessions} privileged sessions recorded. {commandsLogged} commands logged in period.",
            new Dictionary<string, object>
            {
                ["sessionsRecorded"] = recordedSessions,
                ["commandsLogged"]   = commandsLogged,
                ["periodDays"]       = (int)(to - from).TotalDays
            }));

        // iso-03: Access Rights Review (A.9.2.5)
        var completedCampaigns = await db.AttestationCampaigns
            .CountAsync(c => c.Status == 2 && c.CompletedAtUtc >= from && c.CompletedAtUtc <= to);
        var activeCampaigns = await db.AttestationCampaigns.CountAsync(c => c.Status == 1);
        results.Add(new ControlResult(
            "iso-03", "Access Rights Review (A.9.2.5)", "ISO 27001 A.9.2.5",
            completedCampaigns > 0 ? "pass" : activeCampaigns > 0 ? "partial" : "fail",
            completedCampaigns > 0
                ? $"{completedCampaigns} access certification campaign(s) completed in period."
                : activeCampaigns > 0
                    ? $"{activeCampaigns} active certification campaign(s) in progress."
                    : "No access certification campaigns completed in period.",
            new Dictionary<string, object>
            {
                ["completedCampaigns"] = completedCampaigns,
                ["activeCampaigns"]    = activeCampaigns
            }));

        // iso-04: Audit Log Monitoring (A.12.4)
        var auditInPeriod = await db.AuditLogs.CountAsync(a => a.Timestamp >= from && a.Timestamp <= to);
        var tamperedIso   = await db.AuditLogs.CountAsync(a => a.IsTampered);
        results.Add(new ControlResult(
            "iso-04", "Audit Log Monitoring (A.12.4)", "ISO 27001 A.12.4",
            auditInPeriod > 0 && tamperedIso == 0 ? "pass" : auditInPeriod > 0 ? "partial" : "fail",
            auditInPeriod > 0
                ? $"{auditInPeriod} audit events collected in period. Integrity: {(tamperedIso == 0 ? "OK — no tampering detected" : $"{tamperedIso} tampered entries detected")}."
                : "No audit log entries found in period.",
            new Dictionary<string, object>
            {
                ["auditEntriesInPeriod"] = auditInPeriod,
                ["tamperedEntries"]      = tamperedIso,
                ["integrityOk"]          = tamperedIso == 0
            }));

        return results;
    }
}

internal sealed record ControlResult(
    string Code,
    string Name,
    string Reference,
    string Status,
    string Finding,
    Dictionary<string, object> Evidence);

public record ComplianceReportRequest(
    string     Framework,
    DateTime?  From,
    DateTime?  To,
    string[]?  IncludeControls);
