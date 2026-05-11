using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SystemEndpoints
{
    public static void MapSystemEndpoints(this WebApplication app)
    {
        // === System Config ===
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

            // Mask encrypted values
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

        // === Audit Logs (enhanced) ===
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
                    a.TraceId
                }).ToListAsync();

            return Results.Ok(new { success = true, data = logs, meta = new { page, pageSize, totalCount = total } });
        });

        // Verify audit log integrity
        audit.MapGet("/verify", async (OrkunPamDbContext db) =>
        {
            var logs = await db.AuditLogs.OrderBy(a => a.Id).Take(1000).ToListAsync();

            var valid = true;
            byte[]? previousHash = null;
            var checkedCount = 0;

            foreach (var log in logs)
            {
                if (previousHash != null && log.PreviousHash != null)
                {
                    if (!previousHash.SequenceEqual(log.PreviousHash))
                    {
                        valid = false;
                        break;
                    }
                }
                previousHash = log.EntryHash;
                checkedCount++;
            }

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    integrityValid = valid,
                    entriesChecked = checkedCount,
                    message = valid ? "Audit log integrity verified" : "TAMPERING DETECTED - hash chain broken"
                }
            });
        });

        // === Background Jobs ===
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
    }
}

public record UpdateConfigRequest(string Value, string? Category, string? Description, bool IsEncrypted = false);
