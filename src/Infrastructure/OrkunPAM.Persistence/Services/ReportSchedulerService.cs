using System.Net;
using System.Net.Mail;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Compliance;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Scheduled Report Delivery (#159) — runs every 60 s to dispatch due report schedules.
/// </summary>
public sealed class ReportSchedulerService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ReportSchedulerService> _logger;
    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    public ReportSchedulerService(IServiceScopeFactory scopeFactory, ILogger<ReportSchedulerService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("ReportSchedulerService started");
        using var timer = new PeriodicTimer(Interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try { await TickAsync(stoppingToken); }
            catch (Exception ex) { _logger.LogError(ex, "ReportSchedulerService tick failed"); }
        }
    }

    private async Task TickAsync(CancellationToken ct)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var vault = scope.ServiceProvider.GetRequiredService<IVaultEncryptionService>();
        var now = DateTime.UtcNow;

        var due = await db.ReportSchedules
            .Where(s => s.IsActive && (s.NextRunAtUtc == null || s.NextRunAtUtc <= now))
            .ToListAsync(ct);

        foreach (var schedule in due)
            await RunScheduleAsync(db, vault, schedule, ct);
    }

    private async Task RunScheduleAsync(
        OrkunPamDbContext db, IVaultEncryptionService vault,
        ReportSchedule schedule, CancellationToken ct)
    {
        _logger.LogInformation("Running scheduled report '{Name}' type={Type}", schedule.Name, schedule.ReportType);
        var from = DateTime.UtcNow.AddDays(-30);
        var to = DateTime.UtcNow;

        try
        {
            var csv = await GenerateReportCsvAsync(db, schedule.ReportType, from, to, ct);
            if (csv == null)
            {
                schedule.LastRunStatus = "UnsupportedType";
            }
            else if (string.IsNullOrWhiteSpace(schedule.Recipients))
            {
                schedule.LastRunStatus = "NoRecipients";
            }
            else
            {
                var ok = await SendReportEmailAsync(db, vault, schedule, csv, from, to, ct);
                schedule.LastRunStatus = ok ? "Success" : "EmailFailed";
                if (ok)
                {
                    var recipientCount = schedule.Recipients.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries).Length;
                    db.AuditLogs.Add(new AuditLogEntry
                    {
                        EventCategory = "ReportSchedule",
                        EventType     = "ScheduledReportEmailed",
                        TargetType    = "ReportSchedule",
                        TargetId      = schedule.Id.ToString(),
                        Details       = $"name='{schedule.Name}' type={schedule.ReportType} recipients={recipientCount}",
                        Outcome       = AuditOutcome.Success
                    });
                }
            }
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Scheduled report '{Name}' failed", schedule.Name);
            schedule.LastRunStatus = "Error";
        }

        schedule.LastRunAtUtc = DateTime.UtcNow;
        schedule.NextRunAtUtc = CalculateNextRun(schedule);
        await db.SaveChangesAsync(ct);

        _logger.LogInformation("Report '{Name}' done: {Status}, next={Next:O}",
            schedule.Name, schedule.LastRunStatus, schedule.NextRunAtUtc);
    }

    // -----------------------------------------------------------------------
    // CSV generation
    // -----------------------------------------------------------------------

    private static async Task<byte[]?> GenerateReportCsvAsync(
        OrkunPamDbContext db, string reportType, DateTime from, DateTime to, CancellationToken ct)
    {
        var sb = new StringBuilder();

        switch (reportType)
        {
            case "checkout-history":
                sb.AppendLine($"# Checkout History Report — {from:yyyy-MM-dd} to {to:yyyy-MM-dd}");
                sb.AppendLine("CredentialId,UserId,CheckedOutAt,CheckedInAt,DurationMin,Reason,TicketNumber,ApprovedBy,AutoCheckedIn");
                var checkouts = await db.CheckOutHistories
                    .Where(h => h.CheckedOutAtUtc >= from && h.CheckedOutAtUtc <= to)
                    .OrderByDescending(h => h.CheckedOutAtUtc)
                    .Select(h => new { h.CredentialId, h.UserId, h.CheckedOutAtUtc, h.CheckedInAtUtc, h.Reason, h.TicketNumber, h.ApprovedBy, h.WasAutoCheckedIn })
                    .ToListAsync(ct);
                foreach (var r in checkouts)
                {
                    var dur = r.CheckedInAtUtc.HasValue
                        ? ((int)(r.CheckedInAtUtc.Value - r.CheckedOutAtUtc).TotalMinutes).ToString()
                        : "";
                    sb.AppendLine(string.Join(",",
                        Csv(r.CredentialId.ToString()), Csv(r.UserId.ToString()),
                        Csv(r.CheckedOutAtUtc.ToString("O")), Csv(r.CheckedInAtUtc?.ToString("O")),
                        Csv(dur), Csv(r.Reason), Csv(r.TicketNumber), Csv(r.ApprovedBy),
                        r.WasAutoCheckedIn ? "Yes" : "No"));
                }
                break;

            case "session-activity":
                sb.AppendLine($"# Session Activity Report — {from:yyyy-MM-dd} to {to:yyyy-MM-dd}");
                sb.AppendLine("SessionId,UserId,Type,Status,TargetIp,TargetPort,StartedAt,EndedAt,DurationSec,ClientIp,RiskScore");
                var sessions = await db.ProxySessions
                    .Where(s => s.StartedAtUtc >= from && s.StartedAtUtc <= to)
                    .OrderByDescending(s => s.StartedAtUtc)
                    .Select(s => new { s.Id, s.UserId, Type = s.SessionType.ToString(), Status = s.Status.ToString(), s.TargetIpAddress, s.TargetPort, s.StartedAtUtc, s.EndedAtUtc, s.DurationSeconds, s.ClientIpAddress, s.RiskScore })
                    .ToListAsync(ct);
                foreach (var r in sessions)
                {
                    sb.AppendLine(string.Join(",",
                        Csv(r.Id.ToString()), Csv(r.UserId.ToString()),
                        Csv(r.Type), Csv(r.Status),
                        Csv(r.TargetIpAddress), Csv(r.TargetPort.ToString()),
                        Csv(r.StartedAtUtc.ToString("O")), Csv(r.EndedAtUtc?.ToString("O")),
                        Csv(r.DurationSeconds?.ToString()), Csv(r.ClientIpAddress),
                        Csv(r.RiskScore.ToString())));
                }
                break;

            case "failed-logins":
                sb.AppendLine($"# Failed Login Report — {from:yyyy-MM-dd} to {to:yyyy-MM-dd}");
                sb.AppendLine("Username,FailedLoginCount,Status,LockoutEnd");
                var failures = await db.Users
                    .Where(u => u.FailedLoginCount > 0)
                    .OrderByDescending(u => u.FailedLoginCount)
                    .Select(u => new { u.Username, u.FailedLoginCount, Status = u.Status.ToString(), u.LockoutEndUtc })
                    .ToListAsync(ct);
                foreach (var r in failures)
                    sb.AppendLine(string.Join(",", Csv(r.Username), r.FailedLoginCount.ToString(), Csv(r.Status), Csv(r.LockoutEndUtc?.ToString("O"))));
                break;

            case "password-age":
                sb.AppendLine($"# Password Age Report — generated {DateTime.UtcNow:yyyy-MM-dd}");
                sb.AppendLine("CredentialId,Name,Username,LastRotatedAt,NextRotationAt,AgeDays,IsOverdue");
                var creds = await db.Credentials
                    .Where(c => c.Status == CredentialStatus.Active)
                    .Select(c => new { c.Id, c.Name, c.Username, c.LastRotatedAtUtc, c.NextRotationAtUtc, c.CreatedAtUtc })
                    .OrderBy(c => c.LastRotatedAtUtc)
                    .ToListAsync(ct);
                foreach (var r in creds)
                {
                    var age = r.LastRotatedAtUtc.HasValue
                        ? (int)(DateTime.UtcNow - r.LastRotatedAtUtc.Value).TotalDays
                        : (int)(DateTime.UtcNow - r.CreatedAtUtc).TotalDays;
                    var overdue = r.NextRotationAtUtc.HasValue && r.NextRotationAtUtc < DateTime.UtcNow;
                    sb.AppendLine(string.Join(",",
                        Csv(r.Id.ToString()), Csv(r.Name), Csv(r.Username),
                        Csv(r.LastRotatedAtUtc?.ToString("O")), Csv(r.NextRotationAtUtc?.ToString("O")),
                        age.ToString(), overdue ? "Yes" : "No"));
                }
                break;

            case "mfa-adoption":
                sb.AppendLine($"# MFA Adoption Report — generated {DateTime.UtcNow:yyyy-MM-dd}");
                sb.AppendLine("Username,DisplayName,Email,MfaEnabled,Status,LastLoginAt");
                var users = await db.Users
                    .Where(u => u.Status == UserStatus.Active)
                    .Select(u => new { u.Username, u.DisplayName, u.Email, u.MfaEnabled, Status = u.Status.ToString(), u.LastLoginAtUtc })
                    .OrderBy(u => u.MfaEnabled).ThenBy(u => u.Username)
                    .ToListAsync(ct);
                foreach (var r in users)
                    sb.AppendLine(string.Join(",",
                        Csv(r.Username), Csv(r.DisplayName), Csv(r.Email),
                        r.MfaEnabled ? "Yes" : "No", Csv(r.Status), Csv(r.LastLoginAtUtc?.ToString("O"))));
                break;

            case "rotation-compliance":
                sb.AppendLine($"# Rotation Compliance Report — generated {DateTime.UtcNow:yyyy-MM-dd}");
                sb.AppendLine("CredentialId,Name,LastRotatedAt,NextRotationAt,IsOverdue");
                var rotCreds = await db.Credentials
                    .Where(c => c.RotationPolicyId != null && c.Status == CredentialStatus.Active)
                    .Select(c => new { c.Id, c.Name, c.LastRotatedAtUtc, c.NextRotationAtUtc })
                    .ToListAsync(ct);
                foreach (var r in rotCreds)
                {
                    var overdue = r.NextRotationAtUtc.HasValue && r.NextRotationAtUtc < DateTime.UtcNow;
                    sb.AppendLine(string.Join(",",
                        Csv(r.Id.ToString()), Csv(r.Name),
                        Csv(r.LastRotatedAtUtc?.ToString("O")), Csv(r.NextRotationAtUtc?.ToString("O")),
                        overdue ? "Yes" : "No"));
                }
                break;

            case "policy-compliance":
                sb.AppendLine($"# Policy Compliance Report — generated {DateTime.UtcNow:yyyy-MM-dd}");
                sb.AppendLine("Username,Status,PasswordExpired,MustChangePassword,MfaEnabled");
                var policyUsers = await db.Users
                    .Where(u => u.Status == UserStatus.Active)
                    .Select(u => new { u.Username, Status = u.Status.ToString(), PasswordExpired = u.PasswordExpiresAt.HasValue && u.PasswordExpiresAt < DateTime.UtcNow, u.MustChangePassword, u.MfaEnabled })
                    .ToListAsync(ct);
                foreach (var r in policyUsers)
                    sb.AppendLine(string.Join(",",
                        Csv(r.Username), Csv(r.Status),
                        r.PasswordExpired ? "Yes" : "No",
                        r.MustChangePassword ? "Yes" : "No",
                        r.MfaEnabled ? "Yes" : "No"));
                break;

            default:
                return null;
        }

        return Encoding.UTF8.GetBytes(sb.ToString());
    }

    // -----------------------------------------------------------------------
    // Email delivery with attachment
    // -----------------------------------------------------------------------

    private async Task<bool> SendReportEmailAsync(
        OrkunPamDbContext db, IVaultEncryptionService vault,
        ReportSchedule schedule, byte[] csv, DateTime from, DateTime to, CancellationToken ct)
    {
        var configs = await db.SystemConfigs
            .Where(c => c.Category == "smtp")
            .ToDictionaryAsync(c => c.Key, c => c, ct);

        if (!configs.TryGetValue("smtp.host", out var hostCfg) || string.IsNullOrEmpty(hostCfg.Value))
        {
            _logger.LogWarning("SMTP not configured — skipping report delivery for '{Name}'", schedule.Name);
            return false;
        }

        var host = hostCfg.Value;
        var port = int.TryParse(configs.GetValueOrDefault("smtp.port")?.Value, out var p) ? p : 587;
        var useTls = configs.GetValueOrDefault("smtp.tls")?.Value == "true";
        var from2 = configs.GetValueOrDefault("smtp.from")?.Value ?? "noreply@orkunpam.local";
        var fromName = configs.GetValueOrDefault("smtp.fromname")?.Value ?? "OrkunPAM";

        try
        {
            using var client = new SmtpClient(host, port)
            {
                EnableSsl = useTls,
                Timeout = 15_000,
                DeliveryMethod = SmtpDeliveryMethod.Network
            };

            if (configs.TryGetValue("smtp.username", out var userCfg) && !string.IsNullOrEmpty(userCfg.Value))
            {
                var password = string.Empty;
                if (configs.TryGetValue("smtp.password", out var passCfg) && !string.IsNullOrEmpty(passCfg.Value))
                {
                    if (passCfg.IsEncrypted)
                    {
                        var dec = vault.DecryptString(Convert.FromBase64String(passCfg.Value));
                        password = dec.IsSuccess ? dec.Value : string.Empty;
                    }
                    else
                    {
                        password = passCfg.Value;
                    }
                }
                client.Credentials = new NetworkCredential(userCfg.Value, password);
            }

            var subject = $"OrkunPAM Report: {schedule.Name} — {from:yyyy-MM-dd} to {to:yyyy-MM-dd}";
            var attachmentName = $"{schedule.ReportType}-{from:yyyyMMdd}-{to:yyyyMMdd}.csv";

            using var msg = new MailMessage();
            msg.From = new MailAddress(from2, fromName);
            msg.Subject = subject;
            msg.IsBodyHtml = true;
            msg.Body = $"""
                <h3>OrkunPAM Scheduled Report</h3>
                <p><b>Report:</b> {System.Net.WebUtility.HtmlEncode(schedule.Name)}<br/>
                <b>Type:</b> {System.Net.WebUtility.HtmlEncode(schedule.ReportType)}<br/>
                <b>Period:</b> {from:yyyy-MM-dd} — {to:yyyy-MM-dd}<br/>
                <b>Generated:</b> {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC</p>
                <p>See attached CSV file for full data.</p>
                <hr/><small>Orkun PAM — Automated Report</small>
                """;

            var attachment = new Attachment(new MemoryStream(csv), attachmentName, "text/csv");
            msg.Attachments.Add(attachment);

            foreach (var recipient in schedule.Recipients.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                msg.To.Add(recipient);

            if (msg.To.Count == 0)
                return false;

            await client.SendMailAsync(msg, ct);
            _logger.LogInformation("Scheduled report '{Name}' emailed to {Count} recipients", schedule.Name, msg.To.Count);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMTP send failed for scheduled report '{Name}'", schedule.Name);
            return false;
        }
    }

    // -----------------------------------------------------------------------
    // Next-run calculation
    // -----------------------------------------------------------------------

    public static DateTime CalculateNextRun(ReportSchedule schedule)
    {
        var now = DateTime.UtcNow;
        var today = now.Date;

        return schedule.Frequency switch
        {
            "weekly"  => NextWeeklyRun(today, schedule.DayOfWeek, schedule.RunAtHourUtc, now),
            "monthly" => NextMonthlyRun(today, schedule.DayOfMonth, schedule.RunAtHourUtc, now),
            _         => NextDailyRun(today, schedule.RunAtHourUtc, now)
        };
    }

    private static DateTime NextDailyRun(DateTime today, int hour, DateTime now)
    {
        var candidate = today.AddHours(hour);
        return candidate > now ? candidate : candidate.AddDays(1);
    }

    private static DateTime NextWeeklyRun(DateTime today, int targetDow, int hour, DateTime now)
    {
        var candidate = today.AddHours(hour);
        var daysAdded = 0;
        while (daysAdded <= 7 && ((int)candidate.DayOfWeek != targetDow || candidate <= now))
        {
            candidate = candidate.AddDays(1);
            daysAdded++;
        }
        return candidate;
    }

    private static DateTime NextMonthlyRun(DateTime today, int targetDay, int hour, DateTime now)
    {
        var dom = Math.Clamp(targetDay, 1, 28);
        var candidate = new DateTime(today.Year, today.Month, dom, hour, 0, 0, DateTimeKind.Utc);
        if (candidate > now) return candidate;
        var nextMonth = today.AddMonths(1);
        return new DateTime(nextMonth.Year, nextMonth.Month, dom, hour, 0, 0, DateTimeKind.Utc);
    }

    private static string Csv(string? value)
    {
        if (value == null) return "";
        var s = value.Replace("\"", "\"\"");
        return s.Contains(',') || s.Contains('"') || s.Contains('\n') ? $"\"{s}\"" : s;
    }
}
