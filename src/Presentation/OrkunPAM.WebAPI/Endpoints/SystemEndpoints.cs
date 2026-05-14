using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SystemEndpoints
{
    public static void MapSystemEndpoints(this IEndpointRouteBuilder app)
    {
        var config = app.MapGroup("/api/v1/system/config").WithTags("System");

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

        var audit = app.MapGroup("/api/v1/audit-logs").WithTags("Audit");

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
            var logs = await db.AuditLogs.OrderBy(a => a.Id).ToListAsync();

            byte[]? previousHash = null;
            int checkedCount = 0, tamperedCount = 0;
            long? firstTamperedId = null;

            foreach (var log in logs)
            {
                if (previousHash != null && log.PreviousHash != null)
                {
                    if (!previousHash.SequenceEqual(log.PreviousHash))
                    {
                        if (!log.IsTampered)
                        {
                            log.IsTampered = true;
                            tamperedCount++;
                            firstTamperedId ??= log.Id;
                        }
                    }
                    else if (log.IsTampered)
                    {
                        log.IsTampered = false;
                    }
                }
                previousHash = log.EntryHash;
                checkedCount++;
            }

            if (tamperedCount > 0)
                await db.SaveChangesAsync();

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

        var jobs = app.MapGroup("/api/v1/system/jobs").WithTags("System");

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
        var emailGroup = app.MapGroup("/api/v1/system/email").WithTags("System");

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
        var accountGroup = app.MapGroup("/api/v1/system/account-policy").WithTags("System");

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
    }
}

public record UpdateConfigRequest(string Value, string? Category, string? Description, bool IsEncrypted = false);
public record SmtpConfigRequest(string? Host, int? Port, string? From, string? FromName,
    string? Username, string? Password, bool UseTls = true);
public record TestEmailRequest(string To);
public record AccountPolicyRequest(int MaxPasswordAgeDays, int MaxInactivityDays, int WarnDaysBefore = 7);
