using System.Net.Security;
using System.Net.Sockets;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

public interface ISiemForwarderService
{
    Task<(bool Success, string? Error, long Ms)> TestTargetAsync(Guid targetId, CancellationToken ct = default);
}

/// <summary>
/// Polls the audit log every 30s and forwards new entries to all enabled SIEM targets.
/// Supports RFC 5424 Syslog framing with CEF or Key-Value payload over UDP, TCP, or TLS.
/// Tracks forwarding cursor in SystemConfig (key: siem.last_audit_id).
/// </summary>
public sealed class SiemForwarderService : BackgroundService, ISiemForwarderService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<SiemForwarderService> _logger;
    private readonly string _hostname = Environment.MachineName;

    public SiemForwarderService(IServiceScopeFactory scopeFactory, ILogger<SiemForwarderService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromSeconds(20), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await ForwardPendingAsync(stoppingToken);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _logger.LogError(ex, "SIEM forwarding cycle error");
            }
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);
        }
    }

    private async Task ForwardPendingAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();

        var targets = await db.SiemTargets.Where(t => t.IsEnabled).ToListAsync(ct);
        if (targets.Count == 0) return;

        const string cursorKey = "siem.last_audit_id";
        var cursorCfg = await db.SystemConfigs.FindAsync(new object[] { cursorKey }, ct);
        long lastId = cursorCfg != null && long.TryParse(cursorCfg.Value, out var v) ? v : 0;

        var entries = await db.AuditLogs
            .Where(a => a.Id > lastId)
            .OrderBy(a => a.Id)
            .Take(500)
            .ToListAsync(ct);

        if (entries.Count == 0) return;

        long maxId = lastId;
        foreach (var entry in entries)
        {
            foreach (var target in targets)
            {
                if (!MatchesFilter(target, entry.EventType)) continue;
                try
                {
                    await SendToTargetAsync(target, entry, ct);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "SIEM send failed to {Name} ({Host}:{Port})", target.Name, target.Host, target.Port);
                    target.LastError = ex.Message.Length > 500 ? ex.Message[..500] : ex.Message;
                }
            }
            if (entry.Id > maxId) maxId = entry.Id;
        }

        if (cursorCfg == null)
            db.SystemConfigs.Add(new SystemConfig { Key = cursorKey, Value = maxId.ToString(), Category = "siem" });
        else
        {
            cursorCfg.Value = maxId.ToString();
            cursorCfg.UpdatedAtUtc = DateTime.UtcNow;
        }

        await db.SaveChangesAsync(ct);
    }

    private static bool MatchesFilter(SiemTarget target, string eventType)
    {
        if (string.IsNullOrEmpty(target.EventFilterJson) || target.EventFilterJson == "[]")
            return true;
        try
        {
            var filters = JsonSerializer.Deserialize<string[]>(target.EventFilterJson);
            if (filters == null || filters.Length == 0) return true;
            return filters.Any(f => eventType.StartsWith(f, StringComparison.OrdinalIgnoreCase));
        }
        catch { return true; }
    }

    private async Task SendToTargetAsync(SiemTarget target, AuditLogEntry entry, CancellationToken ct)
    {
        var message = target.Format == "CEF"
            ? BuildCefMessage(target, entry)
            : BuildKvMessage(target, entry);

        await SendMessageAsync(target, message, ct);

        target.LastSentAtUtc = DateTime.UtcNow;
        target.TotalEventsSent++;
        target.LastError = null;
    }

    private string BuildSyslogHeader(int facility, int severity, DateTime timestamp, string msgId)
    {
        int pri = (facility * 8) + severity;
        var ts = timestamp.ToString("yyyy-MM-ddTHH:mm:ss.fffZ");
        var safeMsgId = msgId.Length > 32 ? msgId[..32] : msgId;
        return $"<{pri}>1 {ts} {_hostname} OrkunPAM - {safeMsgId} -";
    }

    private string BuildCefMessage(SiemTarget target, AuditLogEntry entry)
    {
        int syslogSeverity = GetSyslogSeverity(entry);
        int cefSeverity = GetCefSeverity(entry);
        var (classId, eventName) = GetEventClassInfo(entry.EventType);

        var ext = new StringBuilder();
        if (!string.IsNullOrEmpty(entry.ActorUsername)) ext.Append("suser=").Append(EscapeCef(entry.ActorUsername)).Append(' ');
        if (!string.IsNullOrEmpty(entry.ActorIpAddress)) ext.Append("src=").Append(EscapeCef(entry.ActorIpAddress)).Append(' ');
        if (!string.IsNullOrEmpty(entry.TargetType)) ext.Append("cs1=").Append(EscapeCef(entry.TargetType)).Append(' ');
        if (!string.IsNullOrEmpty(entry.TargetId)) ext.Append("cs2=").Append(EscapeCef(entry.TargetId)).Append(' ');
        if (entry.Outcome != AuditOutcome.Success) ext.Append("outcome=failure ");
        if (!string.IsNullOrEmpty(entry.Details))
        {
            var details = entry.Details.Length > 200 ? entry.Details[..200] : entry.Details;
            ext.Append("msg=").Append(EscapeCef(details));
        }

        var cefBody = $"CEF:0|OrkunPAM|PAM|1.0|{classId}|{eventName}|{cefSeverity}|{ext.ToString().TrimEnd()}";
        var header = BuildSyslogHeader(target.Facility, syslogSeverity, entry.Timestamp, classId);
        return header + " " + cefBody;
    }

    private string BuildKvMessage(SiemTarget target, AuditLogEntry entry)
    {
        int syslogSeverity = GetSyslogSeverity(entry);
        var header = BuildSyslogHeader(target.Facility, syslogSeverity, entry.Timestamp, entry.EventType);

        var kv = new StringBuilder();
        kv.Append("event_type=\"").Append(entry.EventType).Append("\" ");
        if (!string.IsNullOrEmpty(entry.ActorUsername)) kv.Append("user=\"").Append(entry.ActorUsername).Append("\" ");
        if (!string.IsNullOrEmpty(entry.ActorIpAddress)) kv.Append("src_ip=\"").Append(entry.ActorIpAddress).Append("\" ");
        if (!string.IsNullOrEmpty(entry.TargetType)) kv.Append("target_type=\"").Append(entry.TargetType).Append("\" ");
        if (!string.IsNullOrEmpty(entry.TargetId)) kv.Append("target_id=\"").Append(entry.TargetId).Append("\" ");
        kv.Append("outcome=\"").Append(entry.Outcome).Append("\" ");
        kv.Append("category=\"").Append(entry.EventCategory).Append('"');

        return header + " " + kv.ToString().TrimEnd();
    }

    private static int GetSyslogSeverity(AuditLogEntry entry)
    {
        if (entry.EventType.Contains("BreakGlass") || entry.EventType.Contains("Emergency")) return 2;
        if (entry.Outcome != AuditOutcome.Success
            || entry.EventType.Contains("Failed") || entry.EventType.Contains("Violation")
            || entry.EventType.Contains("Blocked") || entry.EventType.Contains("Denied"))
            return 4;
        return 6;
    }

    private static int GetCefSeverity(AuditLogEntry entry)
    {
        if (entry.EventType.Contains("BreakGlass") || entry.EventType.Contains("Emergency")) return 9;
        if (entry.Outcome != AuditOutcome.Success
            || entry.EventType.Contains("Failed") || entry.EventType.Contains("Violation")
            || entry.EventType.Contains("Blocked") || entry.EventType.Contains("Denied"))
            return 6;
        return 3;
    }

    private static (string ClassId, string Name) GetEventClassInfo(string eventType) => eventType switch
    {
        _ when eventType.Contains("LOGIN_SUCCESS") || eventType.Contains("Login.Success") => ("AUTH001", "Authentication Success"),
        _ when eventType.Contains("LOGIN_FAILED") || eventType.Contains("Login.Failed") => ("AUTH002", "Authentication Failure"),
        _ when eventType.Contains("SESSION_STARTED") || eventType.Contains("Session.Started") => ("SESS001", "Session Started"),
        _ when eventType.Contains("SESSION_TERMINATED") || eventType.Contains("Session.Terminated") => ("SESS002", "Session Terminated"),
        _ when eventType.Contains("CREDENTIAL_CHECKOUT") || eventType.Contains("Credential.CheckedOut") => ("VAULT001", "Credential Checked Out"),
        _ when eventType.Contains("CREDENTIAL_CHECKIN") || eventType.Contains("Credential.CheckedIn") => ("VAULT002", "Credential Checked In"),
        _ when eventType.Contains("PASSWORD_ROTATED") || eventType.Contains("Password.Rotated") => ("VAULT003", "Password Rotated"),
        _ when eventType.Contains("BreakGlass") => ("SEC001", "Break-Glass Activated"),
        _ when eventType.Contains("Violation") => ("POL001", "Policy Violation"),
        _ when eventType.Contains("Blocked") => ("SESS003", "Command Blocked"),
        _ when eventType.Contains("JIT") => ("JIT001", "JIT Access Event"),
        _ => ("GEN001", "PAM Event")
    };

    private static string EscapeCef(string value) =>
        value.Replace("\\", "\\\\").Replace("|", "\\|").Replace("=", "\\=")
             .Replace("\n", "\\n").Replace("\r", "\\r");

    private static async Task SendMessageAsync(SiemTarget target, string message, CancellationToken ct)
    {
        var bytes = Encoding.UTF8.GetBytes(message + "\n");

        switch (target.Protocol.ToUpperInvariant())
        {
            case "UDP":
                using (var udp = new UdpClient())
                    await udp.SendAsync(bytes, bytes.Length, target.Host, target.Port);
                break;

            case "TCP":
                using (var tcp = new TcpClient())
                {
                    await tcp.ConnectAsync(target.Host, target.Port, ct);
                    await tcp.GetStream().WriteAsync(bytes, ct);
                }
                break;

            case "TLS":
                using (var tcp = new TcpClient())
                {
                    await tcp.ConnectAsync(target.Host, target.Port, ct);
                    RemoteCertificateValidationCallback? validationCallback = null;
                    if (!string.IsNullOrEmpty(target.CaCertThumbprint))
                    {
                        var expectedThumbprint = target.CaCertThumbprint.Replace(":", "").Replace(" ", "").ToUpperInvariant();
                        validationCallback = (_, cert, _, errors) =>
                            cert != null &&
                            cert.GetCertHashString().Equals(expectedThumbprint, StringComparison.OrdinalIgnoreCase);
                    }
                    else if (target.AllowSelfSigned)
                    {
                        validationCallback = (_, _, _, errors) =>
                            (errors & ~(SslPolicyErrors.RemoteCertificateChainErrors)) == SslPolicyErrors.None;
                    }
                    using var ssl = new SslStream(tcp.GetStream(), leaveInnerStreamOpen: false);
                    await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
                    {
                        TargetHost = target.Host,
                        EnabledSslProtocols = System.Security.Authentication.SslProtocols.Tls12 | System.Security.Authentication.SslProtocols.Tls13,
                        RemoteCertificateValidationCallback = validationCallback
                    });
                    await ssl.WriteAsync(bytes, ct);
                }
                break;

            default:
                throw new InvalidOperationException($"Unknown SIEM protocol: {target.Protocol}");
        }
    }

    public async Task<(bool Success, string? Error, long Ms)> TestTargetAsync(Guid targetId, CancellationToken ct = default)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();

        var target = await db.SiemTargets.FindAsync(new object[] { targetId }, ct);
        if (target == null) return (false, "Target not found", 0);

        var testEntry = new AuditLogEntry
        {
            Timestamp = DateTime.UtcNow,
            EventCategory = "Test",
            EventType = "SIEM.Test",
            ActorUsername = "system",
            ActorIpAddress = "127.0.0.1",
            Outcome = AuditOutcome.Success,
            Details = "OrkunPAM SIEM connectivity test"
        };

        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var message = target.Format == "CEF"
                ? BuildCefMessage(target, testEntry)
                : BuildKvMessage(target, testEntry);
            await SendMessageAsync(target, message, ct);
            sw.Stop();
            return (true, null, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            sw.Stop();
            return (false, ex.Message, sw.ElapsedMilliseconds);
        }
    }
}
