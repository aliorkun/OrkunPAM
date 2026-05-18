using System.Net.Sockets;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Analytics;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Runs every 5 minutes. Scans new sessions against user behavior baselines
/// and command logs to detect anomalies and calculate per-session risk scores.
/// </summary>
public sealed class AnomalyDetectionService : BackgroundService
{
    private const string LastScanKey = "anomaly.last_session_scan_utc";
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<AnomalyDetectionService> _logger;

    public AnomalyDetectionService(IServiceScopeFactory scopeFactory, ILogger<AnomalyDetectionService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RunDetectionCycleAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogError(ex, "Anomaly detection cycle error"); }
            await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken);
        }
    }

    private async Task RunDetectionCycleAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db         = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var vault      = scope.ServiceProvider.GetService<IVaultEncryptionService>();
        var email      = scope.ServiceProvider.GetService<IEmailService>();

        var lastScanCfg = await db.SystemConfigs.FindAsync([LastScanKey], ct);
        var lastScan = lastScanCfg != null && DateTime.TryParse(lastScanCfg.Value, out var dt)
            ? dt
            : DateTime.UtcNow.AddMinutes(-10);

        var now = DateTime.UtcNow;

        var sessions = await db.ProxySessions
            .Where(s => s.StartedAtUtc > lastScan && s.StartedAtUtc <= now)
            .ToListAsync(ct);

        await PersistLastScan(db, lastScanCfg, now, ct);

        if (sessions.Count == 0) return;

        var userIds = sessions.Select(s => s.UserId).Distinct().ToList();
        var baselines = await db.UserBehaviorBaselines
            .Where(b => userIds.Contains(b.UserId))
            .ToDictionaryAsync(b => b.UserId, ct);

        var alertRules = await db.AlertRules.Where(r => r.IsEnabled).ToListAsync(ct);

        var oneHourAgo = now.AddHours(-1);
        var recentCounts = await db.ProxySessions
            .Where(s => s.StartedAtUtc >= oneHourAgo)
            .GroupBy(s => s.UserId)
            .Select(g => new { UserId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.UserId, x => x.Count, ct);

        // Bulk-load IOC matches for session IPs (#206 Threat Intelligence Feed)
        var sessionIps = sessions
            .Where(s => !string.IsNullOrEmpty(s.ClientIpAddress))
            .Select(s => s.ClientIpAddress!)
            .Distinct()
            .ToList();
        var iocByIp = sessionIps.Count > 0
            ? await db.ThreatIndicators
                .Where(t => t.IndicatorType == "IP"
                         && sessionIps.Contains(t.Value)
                         && (t.ExpiresAtUtc == null || t.ExpiresAtUtc > now))
                .ToDictionaryAsync(t => t.Value, ct)
            : new Dictionary<string, ThreatIndicator>();

        var anomaliesToAdd = new List<Anomaly>();

        foreach (var session in sessions)
        {
            baselines.TryGetValue(session.UserId, out var baseline);
            decimal sessionRisk = 0;

            // Off-hours check
            if (baseline?.TypicalHoursJson != null)
            {
                var typicalHours = JsonSerializer.Deserialize<List<int>>(baseline.TypicalHoursJson) ?? [];
                if (typicalHours.Count > 0 && !typicalHours.Contains(session.StartedAtUtc.Hour))
                {
                    anomaliesToAdd.Add(MakeAnomaly(session.UserId, session.Id, "OffHours", 1,
                        $"Session at {session.StartedAtUtc.Hour:D2}:00 UTC outside typical hours"));
                    sessionRisk += 25;
                }
            }

            // Unusual source IP — decrypt baseline if needed
            if (baseline?.KnownIpsJson != null && session.ClientIpAddress != null)
            {
                var decryptedIps = BehaviorBaselineService.DecryptOrDeserialize(vault, baseline.KnownIpsJson);
                var knownIps = decryptedIps != null
                    ? JsonSerializer.Deserialize<List<string>>(decryptedIps) ?? []
                    : [];
                if (knownIps.Count > 0 && !knownIps.Contains(session.ClientIpAddress))
                {
                    anomaliesToAdd.Add(MakeAnomaly(session.UserId, session.Id, "UnusualIP", 2,
                        $"Connection from unknown IP: {session.ClientIpAddress}"));
                    sessionRisk += 50;
                }
            }

            // Unusual device — decrypt baseline if needed
            if (baseline?.KnownDevicesJson != null)
            {
                var decryptedDevices = BehaviorBaselineService.DecryptOrDeserialize(vault, baseline.KnownDevicesJson);
                var knownDevices = decryptedDevices != null
                    ? JsonSerializer.Deserialize<List<string>>(decryptedDevices) ?? []
                    : [];
                if (knownDevices.Count > 0 && !knownDevices.Contains(session.DeviceId.ToString()))
                {
                    anomaliesToAdd.Add(MakeAnomaly(session.UserId, session.Id, "UnusualDevice", 1,
                        $"Access to previously unseen device {session.DeviceId}"));
                    sessionRisk += 25;
                }
            }

            // Frequency spike (>5 sessions in last hour)
            if (recentCounts.TryGetValue(session.UserId, out var hourCount) && hourCount > 5)
            {
                anomaliesToAdd.Add(MakeAnomaly(session.UserId, session.Id, "FrequencySpike", 2,
                    $"{hourCount} sessions in the last hour (threshold: 5)"));
                sessionRisk += 50;
            }

            // IOC check — Threat Intelligence Feed (#206)
            if (!string.IsNullOrEmpty(session.ClientIpAddress) &&
                iocByIp.TryGetValue(session.ClientIpAddress, out var ioc))
            {
                anomaliesToAdd.Add(MakeAnomaly(session.UserId, session.Id, "KnownMaliciousIP", 3,
                    $"Source IP {session.ClientIpAddress} matched threat feed: {ioc.Source}"));
                sessionRisk += 80;
            }

            session.RiskScore = Math.Min(100, sessionRisk);
        }

        // High-risk commands
        var sessionIds = sessions.Select(s => s.Id).ToList();
        var cmdGroups = await db.CommandLogs
            .Where(c => sessionIds.Contains(c.SessionId) && c.RiskScore >= 7.0m)
            .GroupBy(c => c.SessionId)
            .Select(g => new { SessionId = g.Key, MaxRisk = g.Max(c => c.RiskScore), Count = g.Count() })
            .ToListAsync(ct);

        foreach (var cg in cmdGroups)
        {
            var session = sessions.FirstOrDefault(s => s.Id == cg.SessionId);
            if (session == null) continue;
            byte severity = cg.MaxRisk >= 9.0m ? (byte)3 : (byte)2;
            anomaliesToAdd.Add(MakeAnomaly(session.UserId, session.Id, "HighRiskCommand", severity,
                $"{cg.Count} high-risk command(s), max score: {cg.MaxRisk:F1}"));
            session.RiskScore = Math.Min(100, session.RiskScore + cg.MaxRisk * 10);
        }

        if (anomaliesToAdd.Count > 0)
        {
            db.Anomalies.AddRange(anomaliesToAdd);
            await FireAlertRulesAsync(db, anomaliesToAdd, alertRules, email, ct);
            _logger.LogInformation("Anomaly detection: {Count} anomalies in this cycle", anomaliesToAdd.Count);
        }

        await db.SaveChangesAsync(ct);
    }

    private static Anomaly MakeAnomaly(Guid userId, Guid sessionId, string type, byte severity, string details)
        => new() { UserId = userId, SessionId = sessionId, AnomalyType = type, Severity = severity, Details = details };

    private async Task FireAlertRulesAsync(
        OrkunPamDbContext db, List<Anomaly> newAnomalies, List<AlertRule> rules,
        IEmailService? emailService, CancellationToken ct)
    {
        if (rules.Count == 0) return;
        var now = DateTime.UtcNow;

        foreach (var rule in rules)
        {
            var condition = JsonSerializer.Deserialize<AlertRuleCondition>(rule.ConditionJson)
                ?? new AlertRuleCondition();

            var matching = newAnomalies.Where(a =>
                (condition.AnomalyType == null || a.AnomalyType == condition.AnomalyType) &&
                a.Severity >= condition.MinSeverity).ToList();

            if (matching.Count == 0) continue;

            // Cooldown check
            var lastFired = await db.AlertHistories
                .Where(h => h.AlertRuleId == rule.Id)
                .OrderByDescending(h => h.TriggeredAtUtc)
                .Select(h => (DateTime?)h.TriggeredAtUtc)
                .FirstOrDefaultAsync(ct);

            if (lastFired.HasValue && (now - lastFired.Value).TotalMinutes < rule.CooldownMinutes)
                continue;

            var action = TryParseAction(rule.ActionJson);
            var actionsTaken = new List<string>();

            // SIEM forwarding
            if (action.SendSiem)
            {
                try
                {
                    await SendAlertToSiemAsync(db, rule, matching, ct);
                    actionsTaken.Add("siem");
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Alert SIEM forward failed for rule {RuleId}", rule.Id);
                }
            }

            // Email notification
            if (action.SendEmail && !string.IsNullOrWhiteSpace(action.EmailTo) && emailService != null)
            {
                try
                {
                    var subject = $"[PAM ALERT] {rule.Name} triggered ({matching.Count} anomal{(matching.Count == 1 ? "y" : "ies")})";
                    var body    = BuildAlertEmailBody(rule, matching);
                    await emailService.SendAsync(action.EmailTo, subject, body, ct);
                    actionsTaken.Add("email:" + action.EmailTo);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Alert email failed for rule {RuleId}", rule.Id);
                }
            }

            db.AlertHistories.Add(new AlertHistory
            {
                AlertRuleId  = rule.Id,
                Details      = $"Rule '{rule.Name}' triggered: {matching.Count} matching anomal{(matching.Count == 1 ? "y" : "ies")}",
                ActionsTaken = actionsTaken.Count > 0 ? string.Join(", ", actionsTaken) : "none"
            });
        }
    }

    private static AlertRuleAction TryParseAction(string json)
    {
        try { return JsonSerializer.Deserialize<AlertRuleAction>(json, new JsonSerializerOptions { PropertyNameCaseInsensitive = true }) ?? new(); }
        catch { return new(); }
    }

    private static async Task SendAlertToSiemAsync(
        OrkunPamDbContext db, AlertRule rule, List<Anomaly> matching, CancellationToken ct)
    {
        var targets = await db.SiemTargets.Where(t => t.IsEnabled).ToListAsync(ct);
        if (targets.Count == 0) return;

        var hostname = Environment.MachineName;
        var ts       = DateTime.UtcNow.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var pri      = (16 * 8) + 4; // facility:local0, severity:warning
        var msg      = $"<{pri}>1 {ts} {hostname} OrkunPAM - ALERT001 - "
                     + $"CEF:0|OrkunPAM|PAM|1.0|ALERT001|PAM Alert Rule Triggered|7|"
                     + $"ruleName={EscapeCef(rule.Name)} "
                     + $"anomalyCount={matching.Count} "
                     + $"types={EscapeCef(string.Join(",", matching.Select(a => a.AnomalyType).Distinct()))} "
                     + $"maxSeverity={matching.Max(a => a.Severity)}";
        var bytes = Encoding.UTF8.GetBytes(msg + "\n");

        foreach (var target in targets)
        {
            try
            {
                using var udp = new UdpClient();
                await udp.SendAsync(bytes, bytes.Length, target.Host, target.Port);
            }
            catch { /* individual target failure is non-fatal */ }
        }
    }

    private static string BuildAlertEmailBody(AlertRule rule, List<Anomaly> matching)
    {
        var rows = string.Join("", matching.Take(20).Select(a =>
            $"<tr><td>{a.UserId}</td><td>{a.AnomalyType}</td><td>{a.Severity}</td><td>{a.Details}</td></tr>"));
        return $"""
            <html><body>
            <h2>PAM Alert: {System.Net.WebUtility.HtmlEncode(rule.Name)}</h2>
            <p><b>{matching.Count}</b> anomal{(matching.Count == 1 ? "y" : "ies")} matched rule conditions at {DateTime.UtcNow:u}.</p>
            <table border="1" cellpadding="4"><thead><tr><th>UserId</th><th>Type</th><th>Severity</th><th>Details</th></tr></thead>
            <tbody>{rows}</tbody></table>
            </body></html>
            """;
    }

    private static string EscapeCef(string v) =>
        v.Replace("\\", "\\\\").Replace("|", "\\|").Replace("=", "\\=").Replace("\n", "\\n");

    private static async Task PersistLastScan(OrkunPamDbContext db, SystemConfig? cfg, DateTime now, CancellationToken ct)
    {
        if (cfg == null)
            db.SystemConfigs.Add(new SystemConfig { Key = LastScanKey, Value = now.ToString("O"), Category = "Analytics" });
        else
        {
            cfg.Value = now.ToString("O");
            cfg.UpdatedAtUtc = now;
        }
        await db.SaveChangesAsync(ct);
    }
}

internal sealed record AlertRuleCondition(string? AnomalyType = null, byte MinSeverity = 0);

internal sealed record AlertRuleAction(
    bool SendSiem    = false,
    bool SendEmail   = false,
    string? EmailTo  = null);
