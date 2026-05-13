using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class BackupEndpoints
{
    public static void MapBackupEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/system/backup").WithTags("Backup");

        // GET /api/v1/system/backup — list backups
        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.BackupRecords
                .OrderByDescending(b => b.CreatedAtUtc)
                .Select(b => new
                {
                    b.Id, b.FileName, b.Scope, b.FileSizeBytes,
                    b.IntegrityHash, b.IntegrityVerified,
                    b.Status, b.ErrorMessage,
                    b.CompletedAtUtc, b.CreatedAtUtc, b.InitiatedBy
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        // POST /api/v1/system/backup — trigger backup
        group.MapPost("/", async (CreateBackupRequest req, IBackupService backupSvc,
            ILogger<Program> logger) =>
        {
            if (string.IsNullOrWhiteSpace(req.Passphrase) || req.Passphrase.Length < 8)
                return Results.BadRequest(new { success = false, errors = new[] { "Passphrase must be at least 8 characters" } });

            var validScopes = new[] { "All", "VaultOnly", "UsersOnly", "PoliciesOnly" };
            var scope = req.Scope ?? "All";
            if (!validScopes.Contains(scope))
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid scope" } });

            logger.LogInformation("Manual backup triggered by user (scope: {Scope})", scope);

            try
            {
                var record = await backupSvc.CreateBackupAsync(scope, req.Passphrase, req.InitiatedBy ?? "admin");
                return Results.Ok(new
                {
                    success = true,
                    data = new
                    {
                        record.Id, record.FileName, record.Scope,
                        record.FileSizeBytes, record.IntegrityHash,
                        record.Status, record.CompletedAtUtc
                    }
                });
            }
            catch (Exception ex)
            {
                return Results.Problem($"Backup failed: {ex.Message}");
            }
        });

        // GET /api/v1/system/backup/{id}/download — download backup file
        group.MapGet("/{id:guid}/download", async (Guid id, OrkunPamDbContext db) =>
        {
            var record = await db.BackupRecords.FindAsync(id);
            if (record == null)
                return Results.NotFound(new { success = false, errors = new[] { "Backup not found" } });
            if (!File.Exists(record.FilePath))
                return Results.NotFound(new { success = false, errors = new[] { "Backup file not found on disk" } });

            var bytes = await File.ReadAllBytesAsync(record.FilePath);
            return Results.File(bytes, "application/octet-stream", record.FileName);
        });

        // DELETE /api/v1/system/backup/{id} — delete backup record + file
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var record = await db.BackupRecords.FindAsync(id);
            if (record == null)
                return Results.NotFound(new { success = false, errors = new[] { "Backup not found" } });

            if (File.Exists(record.FilePath))
            {
                File.Delete(record.FilePath);
                logger.LogInformation("Deleted backup file {File}", record.FilePath);
            }

            db.BackupRecords.Remove(record);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // POST /api/v1/system/backup/{id}/verify — verify integrity
        group.MapPost("/{id:guid}/verify", async (Guid id, IBackupService backupSvc) =>
        {
            var valid = await backupSvc.VerifyIntegrityAsync(id);
            return Results.Ok(new
            {
                success = true,
                data = new { backupId = id, integrityValid = valid }
            });
        });

        // POST /api/v1/system/backup/restore — restore from uploaded file
        group.MapPost("/restore", async (HttpRequest req, IBackupService backupSvc, ILogger<Program> logger) =>
        {
            if (!req.Form.Files.Any())
                return Results.BadRequest(new { success = false, errors = new[] { "No file uploaded" } });

            var file = req.Form.Files[0];
            var passphrase = req.Form["passphrase"].ToString();
            var conflictStrategy = req.Form["conflictStrategy"].FirstOrDefault() ?? "SkipExisting";

            if (string.IsNullOrWhiteSpace(passphrase))
                return Results.BadRequest(new { success = false, errors = new[] { "Passphrase is required" } });

            using var ms = new MemoryStream();
            await file.CopyToAsync(ms);
            var fileBytes = ms.ToArray();

            logger.LogWarning("Backup restore initiated from file {FileName} (strategy: {Strategy})",
                file.FileName, conflictStrategy);

            var (success, error, restoredCount) = await backupSvc.RestoreBackupAsync(fileBytes, passphrase, conflictStrategy);

            if (!success)
                return Results.BadRequest(new { success = false, errors = new[] { error } });

            return Results.Ok(new
            {
                success = true,
                data = new { restoredCount, message = $"Restore completed — {restoredCount} objects restored" }
            });
        }).DisableAntiforgery();

        // GET /api/v1/system/backup/schedule — get schedule config
        group.MapGet("/schedule", async (OrkunPamDbContext db) =>
        {
            var keys = new[] { "backup.schedule.enabled", "backup.schedule.hourUtc", "backup.schedule.scope" };
            var cfgs = await db.SystemConfigs.Where(c => keys.Contains(c.Key)).ToListAsync();
            var dict = cfgs.ToDictionary(c => c.Key, c => c.Value ?? string.Empty);
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    enabled = dict.GetValueOrDefault("backup.schedule.enabled") == "true",
                    hourUtc = int.TryParse(dict.GetValueOrDefault("backup.schedule.hourUtc"), out var h) ? h : 2,
                    scope = dict.GetValueOrDefault("backup.schedule.scope") ?? "All"
                }
            });
        });

        // PUT /api/v1/system/backup/schedule — update schedule config
        group.MapPut("/schedule", async (BackupScheduleRequest req, OrkunPamDbContext db) =>
        {
            var updates = new Dictionary<string, string>
            {
                ["backup.schedule.enabled"] = req.Enabled ? "true" : "false",
                ["backup.schedule.hourUtc"] = req.HourUtc.ToString(),
                ["backup.schedule.scope"] = req.Scope ?? "All"
            };
            if (!string.IsNullOrEmpty(req.Passphrase))
                updates["backup.schedule.passphrase"] = req.Passphrase;

            foreach (var (key, value) in updates)
            {
                var cfg = await db.SystemConfigs.FindAsync(key);
                if (cfg == null)
                    db.SystemConfigs.Add(new SystemConfig { Key = key, Value = value, Category = "backup" });
                else
                {
                    cfg.Value = value;
                    cfg.UpdatedAtUtc = DateTime.UtcNow;
                }
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = "Backup schedule saved" });
        });
    }
}

public record CreateBackupRequest(string? Scope, string Passphrase, string? InitiatedBy);
public record BackupScheduleRequest(bool Enabled, int HourUtc, string? Scope, string? Passphrase);
