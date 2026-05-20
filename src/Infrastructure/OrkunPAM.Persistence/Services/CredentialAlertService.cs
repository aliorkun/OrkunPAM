using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Daily background service that alerts VaultAdmin/GlobalAdmin users about:
/// - Credentials expiring within 7 days
/// - Credentials at Critical risk level
/// Deduplicates via AuditLog — no extra migration needed. (#239)
/// </summary>
public sealed class CredentialAlertService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<CredentialAlertService> _logger;

    public CredentialAlertService(IServiceScopeFactory scopeFactory, ILogger<CredentialAlertService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Offset startup to avoid thundering-herd with other background services
        await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RunAlertsAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogError(ex, "CredentialAlertService cycle error"); }

            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }

    internal async Task RunAlertsAsync(CancellationToken ct)
    {
        using var scope  = _scopeFactory.CreateScope();
        var db           = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var emailService = scope.ServiceProvider.GetRequiredService<IEmailService>();

        var adminEmails = await GetAdminEmailsAsync(db, ct);
        if (adminEmails.Count == 0)
        {
            _logger.LogDebug("CredentialAlertService: no active VaultAdmin/GlobalAdmin emails found, skipping.");
            return;
        }

        var now = DateTime.UtcNow;

        await SendExpiryAlertsAsync(db, emailService, adminEmails, now, ct);
        await SendCriticalRiskAlertsAsync(db, emailService, adminEmails, now, ct);
    }

    private async Task SendExpiryAlertsAsync(
        OrkunPamDbContext db, IEmailService email,
        List<string> adminEmails, DateTime now, CancellationToken ct)
    {
        var window = now.AddDays(7);
        var expiring = await db.Credentials
            .Include(c => c.Folder)
            .Where(c => c.ExpiresAtUtc != null && c.ExpiresAtUtc >= now && c.ExpiresAtUtc <= window)
            .OrderBy(c => c.ExpiresAtUtc)
            .Take(50)
            .Select(c => new { c.Id, c.Name, c.Username, FolderName = c.Folder.Name, c.ExpiresAtUtc })
            .ToListAsync(ct);

        if (expiring.Count == 0) return;

        // Check if an expiry alert was already sent in the last 23 hours (deduplicate)
        var alertCutoff = now.AddHours(-23);
        var alreadySent = await db.AuditLogs
            .AnyAsync(a => a.EventType == "CREDENTIAL_EXPIRY_ALERT" && a.Timestamp >= alertCutoff, ct);
        if (alreadySent) return;

        var rows = string.Join("",
            expiring.Select(c =>
            {
                var daysLeft = (int)(c.ExpiresAtUtc!.Value - now).TotalDays;
                var color    = daysLeft <= 1 ? "#dc2626" : daysLeft <= 3 ? "#f59e0b" : "#2563eb";
                return $"<tr><td style='padding:4px 12px 4px 0'>{System.Net.WebUtility.HtmlEncode(c.Name)}</td>" +
                       $"<td style='padding:4px 12px 4px 0'>{System.Net.WebUtility.HtmlEncode(c.Username ?? "—")}</td>" +
                       $"<td style='padding:4px 12px 4px 0'>{System.Net.WebUtility.HtmlEncode(c.FolderName)}</td>" +
                       $"<td style='padding:4px 12px 4px 0'>{c.ExpiresAtUtc:yyyy-MM-dd}</td>" +
                       $"<td style='padding:4px 12px 4px 0;color:{color}'><strong>{daysLeft}d</strong></td></tr>";
            }));

        var body = $"""
            <h2 style="color:#d97706">&#x26A0; Credential Expiry Warning</h2>
            <p>{expiring.Count} credential(s) will expire within 7 days.</p>
            <table style="border-collapse:collapse;font-family:sans-serif;font-size:0.9em">
              <thead><tr style="background:#f3f4f6">
                <th style="padding:4px 12px 4px 0;text-align:left">Name</th>
                <th style="padding:4px 12px 4px 0;text-align:left">Username</th>
                <th style="padding:4px 12px 4px 0;text-align:left">Folder</th>
                <th style="padding:4px 12px 4px 0;text-align:left">Expires</th>
                <th style="padding:4px 12px 4px 0;text-align:left">Days Left</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>
            <p>Log in to <strong>OrkunPAM</strong> &gt; Vault &gt; Governance to review and renew.</p>
            """;

        foreach (var to in adminEmails)
            await email.SendAsync(to, $"[OrkunPAM] {expiring.Count} Credential(s) Expiring Soon", body, ct);

        // Write audit log to prevent duplicate alerts within 24h
        db.AuditLogs.Add(new Domain.Entities.System.AuditLogEntry
        {
            EventCategory  = "Vault",
            EventType      = "CREDENTIAL_EXPIRY_ALERT",
            ActorUserId    = Guid.Empty,
            ActorUsername  = "system",
            ActorIpAddress = "localhost",
            TargetType     = "Credential",
            TargetId       = "batch",
            Outcome        = Domain.Enums.AuditOutcome.Success,
            Timestamp      = DateTime.UtcNow,
            Details        = $"{{\"count\":{expiring.Count}}}"
        });
        await db.SaveChangesAsync(ct);

        _logger.LogInformation("CredentialAlertService: expiry alert sent for {Count} credentials", expiring.Count);
    }

    private async Task SendCriticalRiskAlertsAsync(
        OrkunPamDbContext db, IEmailService email,
        List<string> adminEmails, DateTime now, CancellationToken ct)
    {
        var critical = await db.Credentials
            .Include(c => c.Folder)
            .Where(c => c.RiskLevel == "Critical")
            .OrderByDescending(c => c.RiskScore)
            .Take(20)
            .Select(c => new { c.Id, c.Name, c.Username, FolderName = c.Folder.Name, c.RiskScore, c.RiskScoredAtUtc })
            .ToListAsync(ct);

        if (critical.Count == 0) return;

        // Only alert if not already sent in last 23h
        var alertCutoff = now.AddHours(-23);
        var alreadySent = await db.AuditLogs
            .AnyAsync(a => a.EventType == "CREDENTIAL_CRITICAL_RISK_ALERT" && a.Timestamp >= alertCutoff, ct);
        if (alreadySent) return;

        var rows = string.Join("",
            critical.Select(c =>
                $"<tr><td style='padding:4px 12px 4px 0'>{System.Net.WebUtility.HtmlEncode(c.Name)}</td>" +
                $"<td style='padding:4px 12px 4px 0'>{System.Net.WebUtility.HtmlEncode(c.Username ?? "—")}</td>" +
                $"<td style='padding:4px 12px 4px 0'>{System.Net.WebUtility.HtmlEncode(c.FolderName)}</td>" +
                $"<td style='padding:4px 12px 4px 0;color:#dc2626'><strong>{c.RiskScore}</strong></td></tr>"));

        var body = $"""
            <h2 style="color:#dc2626">&#x1F6A8; Critical Risk Credentials Detected</h2>
            <p>{critical.Count} credential(s) are at <strong>Critical</strong> risk level and require immediate attention.</p>
            <table style="border-collapse:collapse;font-family:sans-serif;font-size:0.9em">
              <thead><tr style="background:#f3f4f6">
                <th style="padding:4px 12px 4px 0;text-align:left">Name</th>
                <th style="padding:4px 12px 4px 0;text-align:left">Username</th>
                <th style="padding:4px 12px 4px 0;text-align:left">Folder</th>
                <th style="padding:4px 12px 4px 0;text-align:left">Risk Score</th>
              </tr></thead>
              <tbody>{rows}</tbody>
            </table>
            <p>Log in to <strong>OrkunPAM</strong> &gt; Vault &gt; Governance to review and remediate.</p>
            """;

        foreach (var to in adminEmails)
            await email.SendAsync(to, $"[OrkunPAM] {critical.Count} Critical Risk Credential(s) Detected", body, ct);

        db.AuditLogs.Add(new Domain.Entities.System.AuditLogEntry
        {
            EventCategory  = "Vault",
            EventType      = "CREDENTIAL_CRITICAL_RISK_ALERT",
            ActorUserId    = Guid.Empty,
            ActorUsername  = "system",
            ActorIpAddress = "localhost",
            TargetType     = "Credential",
            TargetId       = "batch",
            Outcome        = Domain.Enums.AuditOutcome.Success,
            Timestamp      = DateTime.UtcNow,
            Details        = $"{{\"count\":{critical.Count}}}"
        });
        await db.SaveChangesAsync(ct);

        _logger.LogInformation("CredentialAlertService: critical risk alert sent for {Count} credentials", critical.Count);
    }

    private static async Task<List<string>> GetAdminEmailsAsync(OrkunPamDbContext db, CancellationToken ct) =>
        await db.Users
            .Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
            .Where(u => u.Email != null && u.Status == UserStatus.Active &&
                        u.UserRoles.Any(ur => ur.Role.Name == "GlobalAdmin" || ur.Role.Name == "VaultAdmin"))
            .Select(u => u.Email!)
            .Distinct()
            .ToListAsync(ct);
}
