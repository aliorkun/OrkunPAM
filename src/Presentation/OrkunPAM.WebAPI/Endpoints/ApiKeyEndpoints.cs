using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ApiKeyEndpoints
{
    public static void MapApiKeyEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/system/api-keys")
            .WithTags("ApiKeys")
            .RequireAuthorization("AdminPolicy");

        // List all API keys
        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var keys = await db.ApiKeys
                .Include(k => k.ServiceAccountUser)
                .OrderByDescending(k => k.CreatedAtUtc)
                .Select(k => new
                {
                    id                   = k.Id,
                    name                 = k.Name,
                    description          = k.Description,
                    prefix               = k.Prefix,
                    serviceAccountUserId = k.ServiceAccountUserId,
                    serviceAccountName   = k.ServiceAccountUser.Username,
                    allowedIpCidrs       = k.AllowedIpCidrsJson,
                    allowedScopes        = k.AllowedScopesJson,
                    expiresAtUtc         = k.ExpiresAtUtc,
                    lastUsedAtUtc        = k.LastUsedAtUtc,
                    usageCount           = k.UsageCount,
                    isActive             = k.IsActive,
                    createdAtUtc         = k.CreatedAtUtc
                })
                .ToListAsync();
            return Results.Ok(new { success = true, data = keys });
        });

        // Create API key (returns one-time key material)
        group.MapPost("/", async (CreateApiKeyRequest req, OrkunPamDbContext db,
            IVaultEncryptionService vault, IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            var actorId = ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // Create or find service account user
            var saUsername = SanitizeUsername(req.ServiceAccountName ?? req.Name);
            if (await db.Users.AnyAsync(u => u.NormalizedUsername == saUsername.ToUpperInvariant()))
                saUsername += "-" + Guid.NewGuid().ToString("N")[..6];

            // Find ReadOnly role for service accounts
            var readOnlyRole = await db.Roles.FirstOrDefaultAsync(r => r.Name == "ReadOnly");

            var saUser = new User
            {
                Username           = saUsername,
                NormalizedUsername = saUsername.ToUpperInvariant(),
                DisplayName        = req.Name,
                IsServiceAccount   = true,
                AuthSource         = AuthSource.Local,
                Status             = UserStatus.Active
            };
            db.Users.Add(saUser);
            await db.SaveChangesAsync();

            if (readOnlyRole != null)
            {
                db.UserRoles.Add(new UserRole { UserId = saUser.Id, RoleId = readOnlyRole.Id });
                await db.SaveChangesAsync();
            }

            // Generate 32-byte raw key → prefix (8 hex chars) + raw key (base64)
            var rawKeyBytes = RandomNumberGenerator.GetBytes(32);
            var rawKeyB64   = Convert.ToBase64String(rawKeyBytes);
            var prefix      = Convert.ToHexString(rawKeyBytes[..4]).ToLowerInvariant();

            // SHA-256 hash of raw key for storage (NEVER store plaintext)
            var keyHash = SHA256.HashData(Encoding.UTF8.GetBytes(rawKeyB64));

            // Generate 32-byte HMAC secret
            var hmacSecret    = RandomNumberGenerator.GetBytes(32);
            var hmacSecretB64 = Convert.ToBase64String(hmacSecret);

            // Encrypt HMAC secret for storage
            var encResult = vault.Encrypt(hmacSecret, "ApiKeyHmacSecret");
            CryptographicOperations.ZeroMemory(hmacSecret);
            if (encResult.IsFailure)
                return Results.Problem("Failed to protect HMAC secret");

            DateTime? expiresAt = req.ExpiresAfterDays.HasValue
                ? DateTime.UtcNow.AddDays(req.ExpiresAfterDays.Value)
                : null;

            var apiKey = new ApiKey
            {
                Name                 = req.Name.Trim(),
                Description          = req.Description?.Trim(),
                Prefix               = prefix,
                KeyHash              = keyHash,
                HmacSecretEnc        = encResult.Value,
                ServiceAccountUserId = saUser.Id,
                AllowedIpCidrsJson   = req.AllowedIpCidrs?.Count > 0
                    ? JsonSerializer.Serialize(req.AllowedIpCidrs) : null,
                AllowedScopesJson    = req.AllowedScopes?.Count > 0
                    ? JsonSerializer.Serialize(req.AllowedScopes) : null,
                ExpiresAtUtc         = expiresAt,
                IsActive             = true
            };
            db.ApiKeys.Add(apiKey);
            await db.SaveChangesAsync();

            if (Guid.TryParse(actorId, out var actorGuid))
                await audit.LogAsync("ApiKey", "API_KEY_CREATED", actorGuid, null, ip,
                    "ApiKey", apiKey.Id.ToString(), new { apiKey.Name, saUsername });

            return Results.Created($"/api/v1/system/api-keys/{apiKey.Id}", new
            {
                success = true,
                data = new
                {
                    id           = apiKey.Id,
                    name         = apiKey.Name,
                    prefix       = prefix,
                    rawKey       = prefix + "." + rawKeyB64,  // one-time
                    hmacSecret   = hmacSecretB64,               // one-time
                    expiresAtUtc = expiresAt
                }
            });
        });

        // Get single API key
        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var k = await db.ApiKeys
                .Include(k => k.ServiceAccountUser)
                .FirstOrDefaultAsync(k => k.Id == id);
            if (k == null) return Results.NotFound();
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    id                   = k.Id,
                    name                 = k.Name,
                    description          = k.Description,
                    prefix               = k.Prefix,
                    serviceAccountUserId = k.ServiceAccountUserId,
                    serviceAccountName   = k.ServiceAccountUser.Username,
                    allowedIpCidrs       = k.AllowedIpCidrsJson,
                    allowedScopes        = k.AllowedScopesJson,
                    expiresAtUtc         = k.ExpiresAtUtc,
                    lastUsedAtUtc        = k.LastUsedAtUtc,
                    usageCount           = k.UsageCount,
                    isActive             = k.IsActive,
                    createdAtUtc         = k.CreatedAtUtc
                }
            });
        });

        // Revoke (soft-delete) an API key
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var apiKey = await db.ApiKeys.FindAsync(id);
            if (apiKey == null) return Results.NotFound();

            apiKey.IsActive = false;
            await db.SaveChangesAsync();

            var actorId = ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            if (Guid.TryParse(actorId, out var actorGuid))
                await audit.LogAsync("ApiKey", "API_KEY_REVOKED", actorGuid, null, ip,
                    "ApiKey", id.ToString(), new { apiKey.Name });

            return Results.Ok(new { success = true });
        });

        // Rotate an API key — returns new one-time key material
        group.MapPost("/{id:guid}/rotate", async (Guid id, OrkunPamDbContext db,
            IVaultEncryptionService vault, IAuditService audit, HttpContext ctx) =>
        {
            var apiKey = await db.ApiKeys.FindAsync(id);
            if (apiKey == null) return Results.NotFound();
            if (!apiKey.IsActive)
                return Results.BadRequest(new { success = false, errors = new[] { "API key is revoked" } });

            var rawKeyBytes = RandomNumberGenerator.GetBytes(32);
            var rawKeyB64   = Convert.ToBase64String(rawKeyBytes);
            var newPrefix   = Convert.ToHexString(rawKeyBytes[..4]).ToLowerInvariant();
            var newKeyHash  = SHA256.HashData(Encoding.UTF8.GetBytes(rawKeyB64));

            var hmacSecret    = RandomNumberGenerator.GetBytes(32);
            var hmacSecretB64 = Convert.ToBase64String(hmacSecret);
            var encResult     = vault.Encrypt(hmacSecret, "ApiKeyHmacSecret");
            CryptographicOperations.ZeroMemory(hmacSecret);
            if (encResult.IsFailure)
                return Results.Problem("Failed to protect HMAC secret");

            apiKey.Prefix       = newPrefix;
            apiKey.KeyHash      = newKeyHash;
            apiKey.HmacSecretEnc = encResult.Value;
            apiKey.UsageCount   = 0;
            await db.SaveChangesAsync();

            var actorId = ctx.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            if (Guid.TryParse(actorId, out var actorGuid))
                await audit.LogAsync("ApiKey", "API_KEY_ROTATED", actorGuid, null, ip,
                    "ApiKey", id.ToString(), new { apiKey.Name });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    id         = apiKey.Id,
                    prefix     = newPrefix,
                    rawKey     = newPrefix + "." + rawKeyB64,
                    hmacSecret = hmacSecretB64
                }
            });
        });
    }

    private static string SanitizeUsername(string name) =>
        new string(name.ToLowerInvariant()
            .Select(c => char.IsLetterOrDigit(c) ? c : '-')
            .ToArray())
            .Trim('-');
}

public record CreateApiKeyRequest(
    string         Name,
    string?        Description,
    string?        ServiceAccountName,
    List<string>?  AllowedIpCidrs,
    List<string>?  AllowedScopes,
    int?           ExpiresAfterDays);
