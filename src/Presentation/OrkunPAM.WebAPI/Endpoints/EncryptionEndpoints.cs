using System.Security.Claims;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class EncryptionEndpoints
{
    public static void MapEncryptionEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/api/v1/system/encryption").WithTags("System").RequireAuthorization();

        // GET /api/v1/system/encryption/status
        grp.MapGet("/status", (IKeyStore keyStore) =>
        {
            var s = keyStore.GetKeyStatus();
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    s.Version,
                    s.InitializedAtUtc,
                    s.RotationCount,
                    s.IsInitialized,
                    DekCacheTtlMinutes = 15
                }
            });
        });

        // POST /api/v1/system/encryption/rotate
        grp.MapPost("/rotate", async (RotateMasterKeyRequest req, IKeyStore keyStore,
            IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.NewPassphrase) || req.NewPassphrase.Length < 16)
                return Results.BadRequest(new { success = false, error = "New passphrase must be at least 16 characters." });

            if (req.NewPassphrase != req.ConfirmPassphrase)
                return Results.BadRequest(new { success = false, error = "Passphrases do not match." });

            var result = keyStore.RotateMasterKey(req.NewPassphrase);
            if (result.IsFailure)
                return Results.Problem(result.Error.Message);

            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userId = Guid.TryParse(userIdStr, out var g) ? g : (Guid?)null;
            var username = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            _ = audit.LogAsync("Security", "MasterKeyRotated", userId, username, ip,
                "KeyStore", null,
                new { newVersion = keyStore.GetKeyStatus().Version },
                AuditOutcome.Success);

            return Results.Ok(new
            {
                success = true,
                message = $"Master key rotated to version {keyStore.GetKeyStatus().Version}. New passphrase is now active."
            });
        });

        // POST /api/v1/system/encryption/backup  → returns encrypted JSON file download
        grp.MapPost("/backup", async (ExportKeyBackupRequest req, IKeyStore keyStore,
            IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.BackupPassphrase) || req.BackupPassphrase.Length < 12)
                return Results.BadRequest(new { success = false, error = "Backup passphrase must be at least 12 characters." });

            var result = keyStore.ExportEncryptedBackup(req.BackupPassphrase);
            if (result.IsFailure)
                return Results.Problem(result.Error.Message);

            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var userId = Guid.TryParse(userIdStr, out var g) ? g : (Guid?)null;
            var username = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            _ = audit.LogAsync("Security", "KeyBackupExported", userId, username, ip,
                "KeyStore", null,
                new { version = keyStore.GetKeyStatus().Version },
                AuditOutcome.Success);

            var filename = $"orkunpam-keybackup-v{keyStore.GetKeyStatus().Version}-{DateTime.UtcNow:yyyyMMdd}.json";
            return Results.File(result.Value, "application/json", filename);
        });
    }
}

public record RotateMasterKeyRequest(string NewPassphrase, string ConfirmPassphrase);
public record ExportKeyBackupRequest(string BackupPassphrase);
