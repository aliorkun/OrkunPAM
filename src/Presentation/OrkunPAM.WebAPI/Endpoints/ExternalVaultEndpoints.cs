using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ExternalVaultEndpoints
{
    public static void MapExternalVaultEndpoints(this IEndpointRouteBuilder app)
    {
        var vaults = app.MapGroup("/api/v1/system/external-vaults").WithTags("ExternalVaults")
            .RequireAuthorization("AdminPolicy");

        // GET list
        vaults.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.ExternalVaultConnections
                .OrderBy(v => v.Name)
                .Select(v => new
                {
                    v.Id, v.Name, v.VaultType, v.Endpoint, v.AuthMethod,
                    v.KeyVaultName, v.Namespace, v.MountPath,
                    v.TenantId, v.ClientId,
                    v.SyncEnabled, v.SyncIntervalMinutes, v.IsEnabled,
                    v.LastSyncAtUtc, v.LastSyncError,
                    v.CreatedAtUtc,
                    MappingCount = db.ExternalCredentialMappings.Count(m => m.ConnectionId == v.Id)
                })
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        // GET single
        vaults.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var v = await db.ExternalVaultConnections
                .Include(x => x.Mappings)
                .FirstOrDefaultAsync(x => x.Id == id);
            if (v == null) return Results.NotFound(new { success = false, errors = new[] { "Not found" } });
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    v.Id, v.Name, v.VaultType, v.Endpoint, v.AuthMethod,
                    v.KeyVaultName, v.Namespace, v.MountPath,
                    v.TenantId, v.ClientId,
                    v.SyncEnabled, v.SyncIntervalMinutes, v.IsEnabled,
                    v.LastSyncAtUtc, v.LastSyncError, v.CreatedAtUtc,
                    Mappings = v.Mappings.Select(m => new
                    {
                        m.Id, m.ExternalPath, m.UsernameField, m.PasswordField,
                        m.MappedCredentialId, m.SyncMode, m.SyncStatus,
                        m.LastFetchedAtUtc, m.LastSyncedAtUtc, m.LastError
                    })
                }
            });
        });

        // POST create
        vaults.MapPost("/", async (CreateExternalVaultRequest req, OrkunPamDbContext db,
            IAuditService audit, IVaultEncryptionService encryption, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });
            if (string.IsNullOrWhiteSpace(req.Endpoint))
                return Results.BadRequest(new { success = false, errors = new[] { "Endpoint is required" } });
            if (await db.ExternalVaultConnections.AnyAsync(v => v.Name == req.Name))
                return Results.Conflict(new { success = false, errors = new[] { "Name already exists" } });

            byte[]? authSecretEnc = null;
            if (!string.IsNullOrEmpty(req.AuthSecret))
            {
                var enc = encryption.EncryptString(req.AuthSecret);
                if (enc.IsSuccess) authSecretEnc = enc.Value;
            }

            var conn = new ExternalVaultConnection
            {
                Name                = req.Name.Trim(),
                VaultType           = req.VaultType,
                Endpoint            = req.Endpoint.Trim(),
                AuthMethod          = req.AuthMethod,
                AuthSecretEnc       = authSecretEnc,
                Namespace           = req.Namespace?.Trim(),
                MountPath           = req.MountPath?.Trim(),
                KeyVaultName        = req.KeyVaultName?.Trim(),
                TenantId            = req.TenantId?.Trim(),
                ClientId            = req.ClientId?.Trim(),
                SyncEnabled         = req.SyncEnabled,
                SyncIntervalMinutes = req.SyncIntervalMinutes > 0 ? req.SyncIntervalMinutes : 60,
                IsEnabled           = true
            };
            db.ExternalVaultConnections.Add(conn);
            await db.SaveChangesAsync();

            var userId = ctx.User.FindFirst("sub")?.Value;
            var userName = ctx.User.FindFirst("name")?.Value ?? ctx.User.FindFirst("sub")?.Value;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            if (userId != null)
                await audit.LogAsync("Integration", "EXTERNAL_VAULT_CONNECTED",
                    Guid.Parse(userId), userName, ip,
                    "ExternalVaultConnection", conn.Id.ToString(),
                    new { conn.Name, conn.VaultType });

            return Results.Created($"/api/v1/system/external-vaults/{conn.Id}",
                new { success = true, data = new { conn.Id, conn.Name } });
        });

        // PUT update
        vaults.MapPut("/{id:guid}", async (Guid id, UpdateExternalVaultRequest req, OrkunPamDbContext db,
            IAuditService audit, IVaultEncryptionService encryption, HttpContext ctx) =>
        {
            var conn = await db.ExternalVaultConnections.FindAsync(id);
            if (conn == null) return Results.NotFound(new { success = false, errors = new[] { "Not found" } });

            if (!string.IsNullOrEmpty(req.Name)) conn.Name = req.Name.Trim();
            if (!string.IsNullOrEmpty(req.Endpoint)) conn.Endpoint = req.Endpoint.Trim();
            conn.Namespace           = req.Namespace?.Trim();
            conn.MountPath           = req.MountPath?.Trim();
            conn.KeyVaultName        = req.KeyVaultName?.Trim();
            conn.TenantId            = req.TenantId?.Trim();
            conn.ClientId            = req.ClientId?.Trim();
            conn.SyncEnabled         = req.SyncEnabled;
            conn.SyncIntervalMinutes = req.SyncIntervalMinutes > 0 ? req.SyncIntervalMinutes : conn.SyncIntervalMinutes;
            conn.IsEnabled           = req.IsEnabled;

            if (!string.IsNullOrEmpty(req.AuthSecret))
            {
                var enc = encryption.EncryptString(req.AuthSecret);
                if (enc.IsSuccess) conn.AuthSecretEnc = enc.Value;
            }

            conn.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            var userId = ctx.User.FindFirst("sub")?.Value;
            var userName = ctx.User.FindFirst("name")?.Value ?? userId;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            if (userId != null)
                await audit.LogAsync("Integration", "EXTERNAL_VAULT_UPDATED",
                    Guid.Parse(userId), userName, ip,
                    "ExternalVaultConnection", id.ToString(), new { conn.Name });

            return Results.Ok(new { success = true, data = new { conn.Id, conn.Name } });
        });

        // DELETE
        vaults.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var conn = await db.ExternalVaultConnections.FindAsync(id);
            if (conn == null) return Results.NotFound(new { success = false, errors = new[] { "Not found" } });

            db.ExternalVaultConnections.Remove(conn);
            await db.SaveChangesAsync();

            var userId = ctx.User.FindFirst("sub")?.Value;
            var userName = ctx.User.FindFirst("name")?.Value ?? userId;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            if (userId != null)
                await audit.LogAsync("Integration", "EXTERNAL_VAULT_DELETED",
                    Guid.Parse(userId), userName, ip,
                    "ExternalVaultConnection", id.ToString(), new { conn.Name });

            return Results.Ok(new { success = true });
        });

        // POST test connection
        vaults.MapPost("/{id:guid}/test", async (Guid id, TestExternalVaultRequest? req, OrkunPamDbContext db,
            IExternalVaultService svc, IVaultEncryptionService encryption, IAuditService audit,
            HttpContext ctx) =>
        {
            var conn = await db.ExternalVaultConnections.FindAsync(id);
            if (conn == null) return Results.NotFound(new { success = false, errors = new[] { "Not found" } });

            // Use provided plain secret for test, or decrypt stored one
            string? plainSecret = req?.AuthSecret;
            if (string.IsNullOrEmpty(plainSecret) && conn.AuthSecretEnc != null)
                plainSecret = encryption.DecryptString(conn.AuthSecretEnc).Value;

            var result = await svc.TestConnectionAsync(conn, plainSecret);

            var userId = ctx.User.FindFirst("sub")?.Value;
            var userName = ctx.User.FindFirst("name")?.Value ?? userId;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            if (userId != null)
                await audit.LogAsync("Integration", "EXTERNAL_VAULT_TEST",
                    Guid.Parse(userId), userName, ip,
                    "ExternalVaultConnection", id.ToString(),
                    new { conn.Name, result.Success, result.LatencyMs, result.Error },
                    result.Success ? AuditOutcome.Success : AuditOutcome.Failure);

            return Results.Ok(new { success = result.Success, data = result });
        });

        // POST trigger sync
        vaults.MapPost("/{id:guid}/sync", async (Guid id, OrkunPamDbContext db,
            IExternalVaultService svc, IAuditService audit, HttpContext ctx) =>
        {
            var conn = await db.ExternalVaultConnections
                .Include(c => c.Mappings)
                .FirstOrDefaultAsync(c => c.Id == id);
            if (conn == null) return Results.NotFound(new { success = false, errors = new[] { "Not found" } });
            if (!conn.IsEnabled) return Results.BadRequest(new { success = false, errors = new[] { "Connection is disabled" } });

            var syncMappings = conn.Mappings.Where(m => m.SyncMode == ExternalSyncMode.Sync).ToList();
            var syncResults = new List<(bool Success, string? Error, string Path)>();
            foreach (var mapping in syncMappings)
            {
                var r = await svc.SyncMappingAsync(conn, mapping, db);
                syncResults.Add((r.Success, r.Error, mapping.ExternalPath));
            }

            conn.LastSyncAtUtc = DateTime.UtcNow;
            conn.LastSyncError = syncResults.Any(r => !r.Success) ? "Some mappings failed" : null;
            await db.SaveChangesAsync();

            var userId = ctx.User.FindFirst("sub")?.Value;
            var userName = ctx.User.FindFirst("name")?.Value ?? userId;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            if (userId != null)
                await audit.LogAsync("Integration", "EXTERNAL_VAULT_SYNC_COMPLETED",
                    Guid.Parse(userId), userName, ip,
                    "ExternalVaultConnection", id.ToString(),
                    new { conn.Name, MappingCount = syncMappings.Count, Results = syncResults.Count });

            var resultObjects = syncResults.Select(r => new { Path = r.Path, r.Success, r.Error }).ToList();
            return Results.Ok(new { success = true, data = new { SyncedCount = syncMappings.Count, Results = resultObjects } });
        });

        // GET browse secrets
        vaults.MapGet("/{id:guid}/secrets", async (Guid id, string? path, OrkunPamDbContext db,
            IExternalVaultService svc) =>
        {
            var conn = await db.ExternalVaultConnections.FindAsync(id);
            if (conn == null) return Results.NotFound(new { success = false, errors = new[] { "Not found" } });

            var secrets = await svc.ListSecretsAsync(conn, path);
            return Results.Ok(new { success = true, data = secrets });
        });

        // POST add mapping
        vaults.MapPost("/{id:guid}/mappings", async (Guid id, CreateMappingRequest req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var conn = await db.ExternalVaultConnections.FindAsync(id);
            if (conn == null) return Results.NotFound(new { success = false, errors = new[] { "Not found" } });
            if (string.IsNullOrWhiteSpace(req.ExternalPath))
                return Results.BadRequest(new { success = false, errors = new[] { "ExternalPath is required" } });

            var mapping = new ExternalCredentialMapping
            {
                ConnectionId       = id,
                ExternalPath       = req.ExternalPath.Trim(),
                UsernameField      = req.UsernameField?.Trim(),
                PasswordField      = req.PasswordField?.Trim(),
                MappedCredentialId = req.MappedCredentialId,
                SyncMode           = req.SyncMode,
                SyncStatus         = ExternalSyncStatus.Pending
            };
            db.ExternalCredentialMappings.Add(mapping);
            await db.SaveChangesAsync();

            var userId = ctx.User.FindFirst("sub")?.Value;
            var userName = ctx.User.FindFirst("name")?.Value ?? userId;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            if (userId != null)
                await audit.LogAsync("Integration", "EXTERNAL_VAULT_MAPPING_ADDED",
                    Guid.Parse(userId), userName, ip,
                    "ExternalCredentialMapping", mapping.Id.ToString(),
                    new { mapping.ExternalPath, mapping.SyncMode });

            return Results.Created($"/api/v1/system/external-vaults/{id}/mappings/{mapping.Id}",
                new { success = true, data = new { mapping.Id, mapping.ExternalPath, mapping.SyncMode } });
        });

        // DELETE mapping
        vaults.MapDelete("/{id:guid}/mappings/{mappingId:guid}", async (Guid id, Guid mappingId,
            OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var mapping = await db.ExternalCredentialMappings
                .FirstOrDefaultAsync(m => m.ConnectionId == id && m.Id == mappingId);
            if (mapping == null) return Results.NotFound(new { success = false, errors = new[] { "Mapping not found" } });

            db.ExternalCredentialMappings.Remove(mapping);
            await db.SaveChangesAsync();

            var userId = ctx.User.FindFirst("sub")?.Value;
            var userName = ctx.User.FindFirst("name")?.Value ?? userId;
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            if (userId != null)
                await audit.LogAsync("Integration", "EXTERNAL_VAULT_MAPPING_REMOVED",
                    Guid.Parse(userId), userName, ip,
                    "ExternalCredentialMapping", mappingId.ToString(),
                    new { mapping.ExternalPath });

            return Results.Ok(new { success = true });
        });
    }
}

public record CreateExternalVaultRequest(
    string Name,
    ExternalVaultType VaultType,
    string Endpoint,
    ExternalVaultAuthMethod AuthMethod,
    string? AuthSecret,
    string? Namespace,
    string? MountPath,
    string? KeyVaultName,
    string? TenantId,
    string? ClientId,
    bool SyncEnabled,
    int SyncIntervalMinutes);

public record UpdateExternalVaultRequest(
    string? Name,
    string? Endpoint,
    string? AuthSecret,
    string? Namespace,
    string? MountPath,
    string? KeyVaultName,
    string? TenantId,
    string? ClientId,
    bool SyncEnabled,
    int SyncIntervalMinutes,
    bool IsEnabled);

public record TestExternalVaultRequest(string? AuthSecret);

public record CreateMappingRequest(
    string ExternalPath,
    string? UsernameField,
    string? PasswordField,
    Guid? MappedCredentialId,
    ExternalSyncMode SyncMode);
