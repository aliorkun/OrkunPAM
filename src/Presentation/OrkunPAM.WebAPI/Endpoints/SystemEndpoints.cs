using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SystemEndpoints
{
    public static void MapSystemEndpoints(this IEndpointRouteBuilder app)
    {
        var config = app.MapGroup("/api/v1/system/config").WithTags("System").RequireAuthorization("AdminPolicy");

        config.MapGet("/", async (OrkunPamDbContext db, string? category) =>
        {
            var query = db.SystemConfigs.AsQueryable();
            if (!string.IsNullOrEmpty(category))
                query = query.Where(c => c.Category == category);

            var list = await query
                .OrderBy(c => c.Category).ThenBy(c => c.Key)
                .Select(c => new { c.Key, c.Value, c.IsEncrypted, c.Category, c.Description, c.UpdatedAtUtc })
                .ToListAsync();

            var masked = list.Select(c => new
            {
                c.Key, Value = c.IsEncrypted ? "********" : c.Value,
                c.IsEncrypted, c.Category, c.Description, c.UpdatedAtUtc
            });

            return Results.Ok(new { success = true, data = masked });
        });

        config.MapPut("/{key}", async (string key, UpdateConfigRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault) =>
        {
            string? storedValue = req.Value;
            bool isEncrypted = false;
            if (req.IsEncrypted && !string.IsNullOrEmpty(req.Value))
            {
                var encResult = vault.EncryptString(req.Value, "SystemConfig");
                if (encResult.IsFailure)
                    return Results.Problem("Failed to encrypt config value");
                storedValue = Convert.ToBase64String(encResult.Value);
                isEncrypted = true;
            }

            var cfg = await db.SystemConfigs.FindAsync(key);
            if (cfg == null)
            {
                cfg = new SystemConfig
                {
                    Key = key,
                    Value = storedValue,
                    IsEncrypted = isEncrypted,
                    Category = req.Category,
                    Description = req.Description
                };
                db.SystemConfigs.Add(cfg);
            }
            else
            {
                cfg.Value = storedValue;
                cfg.IsEncrypted = isEncrypted;
                cfg.UpdatedAtUtc = DateTime.UtcNow;
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        var audit = app.MapGroup("/api/v1/audit-logs").WithTags("Audit").RequireAuthorization("AdminPolicy");

        audit.MapGet("/", async (OrkunPamDbContext db, string? category, string? eventType,
            Guid? userId, string? targetType, DateTime? from, DateTime? to,
            int page = 1, int pageSize = 50) =>
        {
            var query = db.AuditLogs.AsQueryable();

            if (!string.IsNullOrEmpty(category)) query = query.Where(a => a.EventCategory == category);
            if (!string.IsNullOrEmpty(eventType)) query = query.Where(a => a.EventType.Contains(eventType));
            if (userId.HasValue) query = query.Where(a => a.ActorUserId == userId.Value);
            if (!string.IsNullOrEmpty(targetType)) query = query.Where(a => a.TargetType == targetType);
            if (from.HasValue) query = query.Where(a => a.Timestamp >= from.Value);
            if (to.HasValue) query = query.Where(a => a.Timestamp <= to.Value);

            var total = await query.CountAsync();
            var logs = await query
                .OrderByDescending(a => a.Timestamp)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(a => new
                {
                    a.Id, a.Timestamp, a.EventCategory, a.EventType,
                    a.ActorUserId, a.ActorUsername, a.ActorIpAddress,
                    a.TargetType, a.TargetId, a.Details,
                    Outcome = a.Outcome.ToString(),
                    a.TraceId, a.IsTampered
                }).ToListAsync();

            return Results.Ok(new { success = true, data = logs, meta = new { page, pageSize, totalCount = total } });
        });

        audit.MapGet("/verify", async (OrkunPamDbContext db) =>
        {
            const int batchSize = 1000;
            long lastId = 0;
            byte[]? previousHash = null;
            int checkedCount = 0, tamperedCount = 0;
            long? firstTamperedId = null;
            var setTampered = new List<long>();
            var clearTampered = new List<long>();

            while (true)
            {
                var batch = await db.AuditLogs
                    .AsNoTracking()
                    .Where(a => a.Id > lastId)
                    .OrderBy(a => a.Id)
                    .Take(batchSize)
                    .ToListAsync();

                if (batch.Count == 0) break;

                foreach (var log in batch)
                {
                    if (previousHash != null && log.PreviousHash != null)
                    {
                        if (!previousHash.SequenceEqual(log.PreviousHash))
                        {
                            if (!log.IsTampered) { tamperedCount++; firstTamperedId ??= log.Id; setTampered.Add(log.Id); }
                        }
                        else if (log.IsTampered)
                        {
                            clearTampered.Add(log.Id);
                        }
                    }
                    previousHash = log.EntryHash;
                    checkedCount++;
                }

                lastId = batch[^1].Id;
                if (batch.Count < batchSize) break;
            }

            if (setTampered.Count > 0 || clearTampered.Count > 0)
            {
                var toUpdate = await db.AuditLogs
                    .Where(a => setTampered.Contains(a.Id) || clearTampered.Contains(a.Id))
                    .ToListAsync();
                foreach (var log in toUpdate)
                    log.IsTampered = setTampered.Contains(log.Id);
                await db.SaveChangesAsync();
            }

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    integrityValid = tamperedCount == 0,
                    entriesChecked = checkedCount,
                    tamperedCount,
                    firstTamperedId,
                    message = tamperedCount == 0
                        ? "Audit log integrity verified"
                        : $"TAMPERING DETECTED — {tamperedCount} record(s) marked as tampered"
                }
            });
        });

        var jobs = app.MapGroup("/api/v1/system/jobs").WithTags("System").RequireAuthorization("AdminPolicy");

        jobs.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.BackgroundJobs
                .Select(j => new
                {
                    j.Id, j.JobType, j.CronExpression,
                    j.LastRunAtUtc, j.NextRunAtUtc, j.LastRunResult, j.IsEnabled
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        // === SMTP Configuration ===
        var emailGroup = app.MapGroup("/api/v1/system/email").WithTags("System").RequireAuthorization("AdminPolicy");

        emailGroup.MapGet("/config", async (OrkunPamDbContext db) =>
        {
            var configs = await db.SystemConfigs.Where(c => c.Category == "smtp").ToListAsync();
            var dict = configs.ToDictionary(
                c => c.Key,
                c => c.IsEncrypted ? "********" : (c.Value ?? string.Empty));
            return Results.Ok(new { success = true, data = dict });
        });

        emailGroup.MapPut("/config", async (SmtpConfigRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault) =>
        {
            var updates = new Dictionary<string, (string Value, bool IsEncrypted)>
            {
                ["smtp.host"]     = (req.Host ?? string.Empty, false),
                ["smtp.port"]     = ((req.Port ?? 587).ToString(), false),
                ["smtp.from"]     = (req.From ?? string.Empty, false),
                ["smtp.fromname"] = (req.FromName ?? string.Empty, false),
                ["smtp.tls"]      = (req.UseTls ? "true" : "false", false),
                ["smtp.username"] = (req.Username ?? string.Empty, false)
            };

            if (!string.IsNullOrEmpty(req.Password))
            {
                var enc = vault.EncryptString(req.Password, "SystemConfig");
                if (enc.IsSuccess)
                    updates["smtp.password"] = (Convert.ToBase64String(enc.Value), true);
            }

            foreach (var (key, (value, isEncrypted)) in updates)
            {
                var cfg = await db.SystemConfigs.FindAsync(key);
                if (cfg == null)
                {
                    db.SystemConfigs.Add(new SystemConfig
                    {
                        Key = key, Value = value, IsEncrypted = isEncrypted, Category = "smtp"
                    });
                }
                else
                {
                    cfg.Value = value;
                    cfg.IsEncrypted = isEncrypted;
                    cfg.UpdatedAtUtc = DateTime.UtcNow;
                }
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = "SMTP configuration saved" });
        });

        emailGroup.MapPost("/test", async (TestEmailRequest req, IEmailService email) =>
        {
            if (string.IsNullOrWhiteSpace(req.To) || !System.Net.Mail.MailAddress.TryCreate(req.To, out _))
                return Results.BadRequest(new { success = false, message = "Invalid email address" });

            var ok = await email.SendAsync(
                req.To,
                "OrkunPAM SMTP Test",
                "<h3>OrkunPAM SMTP Test</h3><p>If you receive this email, your SMTP configuration is working correctly.</p>");

            return Results.Ok(new
            {
                success = ok,
                message = ok ? "Test email sent successfully" : "Failed — check SMTP configuration and logs"
            });
        });

        // === Account Lifecycle Policy ===
        var accountGroup = app.MapGroup("/api/v1/system/account-policy").WithTags("System").RequireAuthorization("AdminPolicy");

        accountGroup.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var configs = await db.SystemConfigs
                .Where(c => c.Category == "account")
                .ToDictionaryAsync(c => c.Key, c => c.Value ?? string.Empty);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    maxPasswordAgeDays = int.TryParse(configs.GetValueOrDefault("account.maxPasswordAgeDays"), out var pa) ? pa : 0,
                    maxInactivityDays  = int.TryParse(configs.GetValueOrDefault("account.maxInactivityDays"),  out var ia) ? ia : 0,
                    warnDaysBefore     = int.TryParse(configs.GetValueOrDefault("account.warnDaysBefore"),     out var wb) ? wb : 7
                }
            });
        });

        accountGroup.MapPut("/", async (AccountPolicyRequest req, OrkunPamDbContext db) =>
        {
            var entries = new[]
            {
                ("account.maxPasswordAgeDays", req.MaxPasswordAgeDays.ToString()),
                ("account.maxInactivityDays",  req.MaxInactivityDays.ToString()),
                ("account.warnDaysBefore",     req.WarnDaysBefore.ToString())
            };

            foreach (var (key, value) in entries)
            {
                var cfg = await db.SystemConfigs.FindAsync(key);
                if (cfg == null)
                    db.SystemConfigs.Add(new OrkunPAM.Domain.Entities.System.SystemConfig
                        { Key = key, Value = value, Category = "account" });
                else
                { cfg.Value = value; cfg.UpdatedAtUtc = DateTime.UtcNow; }
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = "Account policy saved" });
        });

        // === System Health Monitoring (#138) ===
        var healthGroup = app.MapGroup("/api/v1/system/health").WithTags("System").RequireAuthorization("AdminPolicy");

        healthGroup.MapGet("/", async (OrkunPamDbContext db, CancellationToken ct) =>
        {
            var snapshot = await SystemHealthMonitorService.CollectSnapshotAsync(db, ct);
            return Results.Ok(new { success = true, data = snapshot });
        });

        healthGroup.MapGet("/alarms", async (OrkunPamDbContext db, string? status,
            string? severity, int page = 1, int pageSize = 50, CancellationToken ct = default) =>
        {
            var query = db.SystemAlarmLogs.AsQueryable();
            if (!string.IsNullOrEmpty(status))   query = query.Where(a => a.Status == status);
            if (!string.IsNullOrEmpty(severity))  query = query.Where(a => a.Severity == severity);

            var total = await query.CountAsync(ct);
            var alarms = await query
                .OrderByDescending(a => a.OccurredAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(a => new
                {
                    a.Id, a.OccurredAtUtc, a.MetricName, a.Severity,
                    a.MetricValue, a.Threshold, a.Message, a.Status, a.EmailSent
                }).ToListAsync(ct);

            return Results.Ok(new { success = true, data = alarms,
                meta = new { page, pageSize, totalCount = total } });
        });

        healthGroup.MapGet("/config", async (OrkunPamDbContext db, CancellationToken ct) =>
        {
            var keys = new[] { "health.cpu.warn_pct", "health.mem.warn_mb",
                "health.disk.free_warn_pct", "health.alarm.recipients" };
            var configs = await db.SystemConfigs
                .Where(c => keys.Contains(c.Key))
                .ToDictionaryAsync(c => c.Key, c => c.Value ?? string.Empty, ct);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    cpuWarningPct  = configs.GetValueOrDefault("health.cpu.warn_pct") ?? "80",
                    memoryWarningMb= configs.GetValueOrDefault("health.mem.warn_mb") ?? "2048",
                    diskFreeWarningPct = configs.GetValueOrDefault("health.disk.free_warn_pct") ?? "10",
                    alarmRecipients    = configs.GetValueOrDefault("health.alarm.recipients") ?? string.Empty
                }
            });
        });

        healthGroup.MapPut("/config", async (HealthAlarmConfigRequest req, OrkunPamDbContext db,
            CancellationToken ct) =>
        {
            var entries = new[]
            {
                ("health.cpu.warn_pct",        req.CpuWarningPct.ToString()),
                ("health.mem.warn_mb",         req.MemoryWarningMb.ToString()),
                ("health.disk.free_warn_pct",  req.DiskFreeWarningPct.ToString()),
                ("health.alarm.recipients",    req.AlarmRecipients ?? string.Empty)
            };

            foreach (var (key, value) in entries)
            {
                var cfg = await db.SystemConfigs.FindAsync([key], ct);
                if (cfg == null)
                    db.SystemConfigs.Add(new SystemConfig { Key = key, Value = value, Category = "health" });
                else
                { cfg.Value = value; cfg.UpdatedAtUtc = DateTime.UtcNow; }
            }

            await db.SaveChangesAsync(ct);
            return Results.Ok(new { success = true, message = "Health alarm configuration saved" });
        });

        healthGroup.MapPost("/alarms/{id}/clear", async (long id, OrkunPamDbContext db, CancellationToken ct) =>
        {
            var alarm = await db.SystemAlarmLogs.FindAsync([id], ct);
            if (alarm == null) return Results.NotFound();
            alarm.Status = "Cleared";
            alarm.ClearedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync(ct);
            return Results.Ok(new { success = true });
        });

        // === System Log Viewer (#160) ===
        var sysLogsGroup = app.MapGroup("/api/v1/system/logs").WithTags("System").RequireAuthorization("AdminPolicy");

        sysLogsGroup.MapGet("/", async (
            OrkunPamDbContext db, IAuditService audit, HttpContext ctx,
            string source = "api",
            string? level = null,
            DateTime? from = null,
            DateTime? to = null,
            string? search = null,
            int page = 1,
            int pageSize = 100,
            CancellationToken ct = default) =>
        {
            var userIdClaim = ctx.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            var usernameClaim = ctx.User.FindFirst(System.Security.Claims.ClaimTypes.Name)?.Value;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            _ = Guid.TryParse(userIdClaim, out var actorId);
            _ = audit.LogAsync("System", "SystemLog.View",
                actorId == Guid.Empty ? null : actorId, usernameClaim, ip,
                "SystemLogs", source, $"source={source}", AuditOutcome.Success, ct);

            if (source == "audit" || source == "security")
            {
                var query = db.AuditLogs.AsQueryable();

                if (source == "security")
                    query = query.Where(a =>
                        a.EventCategory == "Auth" ||
                        a.EventType.Contains("lock") ||
                        a.EventType.Contains("Lock") ||
                        a.EventType.Contains("Role") ||
                        a.Outcome != AuditOutcome.Success);

                if (from.HasValue)  query = query.Where(a => a.Timestamp >= from.Value);
                if (to.HasValue)    query = query.Where(a => a.Timestamp <= to.Value);
                if (!string.IsNullOrEmpty(level))
                {
                    if (level.Equals("ERR", StringComparison.OrdinalIgnoreCase))
                        query = query.Where(a => a.Outcome == AuditOutcome.Failure);
                    else if (level.Equals("WRN", StringComparison.OrdinalIgnoreCase))
                        query = query.Where(a => a.Outcome == AuditOutcome.Denied);
                    else if (level.Equals("INF", StringComparison.OrdinalIgnoreCase))
                        query = query.Where(a => a.Outcome == AuditOutcome.Success);
                }
                if (!string.IsNullOrEmpty(search))
                    query = query.Where(a =>
                        a.EventType.Contains(search) ||
                        (a.Details != null && a.Details.Contains(search)) ||
                        (a.ActorUsername != null && a.ActorUsername.Contains(search)) ||
                        (a.ActorIpAddress != null && a.ActorIpAddress.Contains(search)));

                var total = await query.CountAsync(ct);
                var items = await query
                    .OrderByDescending(a => a.Timestamp)
                    .Skip((page - 1) * pageSize)
                    .Take(pageSize)
                    .Select(a => new
                    {
                        Timestamp = a.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                        Level = a.Outcome == AuditOutcome.Success ? "INF" :
                                a.Outcome == AuditOutcome.Denied  ? "WRN" : "ERR",
                        Source = source,
                        Message = a.EventCategory + " / " + a.EventType,
                        Username = a.ActorUsername,
                        IpAddress = a.ActorIpAddress,
                        Details = a.Details
                    })
                    .ToListAsync(ct);

                return Results.Ok(new { success = true, data = items, meta = new { page, pageSize, totalCount = total } });
            }

            // source == "api" — read Serilog rolling log files
            var logDir = "logs";
            if (!Directory.Exists(logDir))
                logDir = Path.Combine(AppContext.BaseDirectory, "logs");

            var entries = new List<(string Timestamp, string Level, string Message)>();

            if (Directory.Exists(logDir))
            {
                var files = Directory.GetFiles(logDir, "orkunpam-*.log")
                    .OrderByDescending(f => f)
                    .Take(7)
                    .ToList();

                foreach (var file in files)
                {
                    var fname    = Path.GetFileNameWithoutExtension(file);
                    var datePart = fname.Length > 9 ? fname[9..] : string.Empty;
                    DateTime fileDate = DateTime.UtcNow.Date;
                    if (datePart.Length == 8 &&
                        DateTime.TryParseExact(datePart, "yyyyMMdd",
                            System.Globalization.CultureInfo.InvariantCulture,
                            System.Globalization.DateTimeStyles.None, out var pd))
                        fileDate = pd;

                    string[] lines;
                    try { lines = await File.ReadAllLinesAsync(file, ct); }
                    catch { continue; }

                    foreach (var line in lines)
                    {
                        if (string.IsNullOrEmpty(line) || line[0] != '[') continue;
                        var close = line.IndexOf(']');
                        if (close < 5) continue;
                        var header = line[1..close].Split(' ');
                        if (header.Length < 2) continue;
                        var lvl = header[1];
                        var msg = line[(close + 1)..].TrimStart();

                        if (!TimeSpan.TryParse(header[0], out var ts)) continue;
                        var entryTime = fileDate.Add(ts);

                        if (from.HasValue && entryTime < from.Value) continue;
                        if (to.HasValue   && entryTime > to.Value)   continue;
                        if (!string.IsNullOrEmpty(level) &&
                            !lvl.Equals(level, StringComparison.OrdinalIgnoreCase)) continue;
                        if (!string.IsNullOrEmpty(search) &&
                            !msg.Contains(search, StringComparison.OrdinalIgnoreCase)) continue;

                        entries.Add((entryTime.ToString("yyyy-MM-dd HH:mm:ss"), lvl, msg));
                    }
                }
            }

            var totalApi = entries.Count;
            var pageItems = entries
                .OrderByDescending(e => e.Timestamp)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(e => new
                {
                    e.Timestamp, e.Level, Source = "api", Message = e.Message,
                    Username = (string?)null, IpAddress = (string?)null, Details = (string?)null
                })
                .ToList();

            return Results.Ok(new { success = true, data = pageItems,
                meta = new { page, pageSize, totalCount = totalApi } });
        });

        // === Windows / Kerberos Auth Settings (#126) ===
        var winAuthGroup = app.MapGroup("/api/v1/system/windows-auth").WithTags("System").RequireAuthorization("AdminPolicy");

        winAuthGroup.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var configs = await db.SystemConfigs
                .Where(c => c.Category == "windows_auth")
                .ToDictionaryAsync(c => c.Key, c => c.Value ?? string.Empty);
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    enabled = configs.GetValueOrDefault("windows.auth.enabled") == "true",
                    autoProvision = configs.GetValueOrDefault("windows.auth.auto_provision") == "true",
                    mfaBypass = configs.GetValueOrDefault("windows.auth.mfa_bypass") == "true",
                    trustedDomains = configs.GetValueOrDefault("windows.auth.trusted_domains") ?? string.Empty
                }
            });
        });

        winAuthGroup.MapPut("/", async (WindowsAuthSettingsRequest req, OrkunPamDbContext db) =>
        {
            var entries = new[]
            {
                ("windows.auth.enabled", req.Enabled ? "true" : "false"),
                ("windows.auth.auto_provision", req.AutoProvision ? "true" : "false"),
                ("windows.auth.mfa_bypass", req.MfaBypass ? "true" : "false"),
                ("windows.auth.trusted_domains", req.TrustedDomains ?? string.Empty)
            };

            foreach (var (key, value) in entries)
            {
                var cfg = await db.SystemConfigs.FindAsync(key);
                if (cfg == null)
                    db.SystemConfigs.Add(new OrkunPAM.Domain.Entities.System.SystemConfig
                        { Key = key, Value = value, Category = "windows_auth" });
                else
                { cfg.Value = value; cfg.UpdatedAtUtc = DateTime.UtcNow; }
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = "Windows Auth settings saved" });
        });
    }
}

public record UpdateConfigRequest(string Value, string? Category, string? Description, bool IsEncrypted = false);
public record SmtpConfigRequest(string? Host, int? Port, string? From, string? FromName,
    string? Username, string? Password, bool UseTls = true);
public record TestEmailRequest(string To);
public record AccountPolicyRequest(int MaxPasswordAgeDays, int MaxInactivityDays, int WarnDaysBefore = 7);
public record WindowsAuthSettingsRequest(bool Enabled, bool AutoProvision, bool MfaBypass, string? TrustedDomains);
public record HealthAlarmConfigRequest(double CpuWarningPct, double MemoryWarningMb,
    double DiskFreeWarningPct, string? AlarmRecipients);
