using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Aapm;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class AapmEndpoints
{
    public static void MapAapmEndpoints(this IEndpointRouteBuilder app)
    {
        var clients = app.MapGroup("/api/v1/aapm/clients").WithTags("AAPM");

        clients.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.ApiClients
                .Select(c => new
                {
                    c.Id, c.Name, c.ClientId, c.AllowedIpRanges,
                    c.RateLimitPerMinute, c.IsEnabled, c.LastUsedAtUtc,
                    CredentialCount = c.CredentialAccess.Count
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        clients.MapPost("/", async (CreateApiClientRequest req, OrkunPamDbContext db, IPasswordHasher hasher) =>
        {
            var clientId = $"opam_{Guid.NewGuid():N}"[..24];
            var clientSecret = Convert.ToBase64String(RandomNumberGenerator.GetBytes(48));

            var client = new ApiClient
            {
                Name = req.Name,
                ClientId = clientId,
                ClientSecretHash = hasher.Hash(clientSecret),
                AllowedIpRanges = req.AllowedIpRanges,
                RateLimitPerMinute = req.RateLimitPerMinute ?? 60,
                ServiceAccountId = req.ServiceAccountId
            };

            if (req.CredentialIds != null)
            {
                foreach (var credId in req.CredentialIds)
                    client.CredentialAccess.Add(new ApiClientCredentialAccess { ApiClientId = client.Id, CredentialId = credId });
            }

            db.ApiClients.Add(client);
            await db.SaveChangesAsync();

            return Results.Created($"/api/v1/aapm/clients/{client.Id}", new
            {
                success = true,
                data = new
                {
                    client.Id, client.Name,
                    clientId,
                    clientSecret,
                    message = "SAVE THIS SECRET NOW - it will not be shown again"
                }
            });
        });

        clients.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var c = await db.ApiClients
                .Include(c => c.CredentialAccess)
                .FirstOrDefaultAsync(c => c.Id == id);
            if (c == null) return Results.NotFound(new { success = false, errors = new[] { "API client not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    c.Id, c.Name, c.ClientId, c.AllowedIpRanges,
                    c.RateLimitPerMinute, c.IsEnabled, c.LastUsedAtUtc, c.CreatedAtUtc,
                    Credentials = c.CredentialAccess.Select(ca => ca.CredentialId)
                }
            });
        });

        clients.MapPut("/{id:guid}", async (Guid id, UpdateApiClientRequest req, OrkunPamDbContext db) =>
        {
            var c = await db.ApiClients.FindAsync(id);
            if (c == null) return Results.NotFound(new { success = false, errors = new[] { "API client not found" } });

            if (req.Name != null) c.Name = req.Name;
            if (req.AllowedIpRanges != null) c.AllowedIpRanges = req.AllowedIpRanges;
            if (req.RateLimitPerMinute.HasValue) c.RateLimitPerMinute = req.RateLimitPerMinute.Value;
            if (req.IsEnabled.HasValue) c.IsEnabled = req.IsEnabled.Value;

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        clients.MapGet("/{id:guid}/access-log", async (Guid id, OrkunPamDbContext db, int page = 1, int pageSize = 50) =>
        {
            var total = await db.ApiAccessLogs.Where(l => l.ApiClientId == id).CountAsync();
            var logs = await db.ApiAccessLogs
                .Where(l => l.ApiClientId == id)
                .OrderByDescending(l => l.RequestedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .ToListAsync();
            return Results.Ok(new { success = true, data = logs, meta = new { page, pageSize, totalCount = total } });
        });

        app.MapPost("/api/v1/aapm/token", async (AapmTokenRequest req, OrkunPamDbContext db,
            IPasswordHasher hasher, IJwtTokenService jwt, ILogger<Program> logger) =>
        {
            var client = await db.ApiClients.FirstOrDefaultAsync(c => c.ClientId == req.ClientId);
            if (client == null || !client.IsEnabled)
                return Results.Json(new { error = "invalid_client" }, statusCode: 401);

            if (!hasher.Verify(req.ClientSecret, client.ClientSecretHash))
            {
                logger.LogWarning("AAPM: invalid client secret for client '{ClientId}'", req.ClientId);
                return Results.Json(new { error = "invalid_client" }, statusCode: 401);
            }

            client.LastUsedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            var tokenResult = jwt.GenerateTokens(
                client.Id, client.ClientId, client.Name,
                "aapm", ["AAPM"], ["aapm.credential.retrieve"]);

            if (tokenResult.IsFailure)
                return Results.Problem("Token generation failed");

            logger.LogInformation("AAPM token issued for client '{ClientId}'", req.ClientId);

            return Results.Ok(new
            {
                access_token = tokenResult.Value.AccessToken,
                token_type = "Bearer",
                expires_in = (int)(tokenResult.Value.AccessTokenExpiry - DateTime.UtcNow).TotalSeconds
            });
        }).WithTags("AAPM").AllowAnonymous();

        app.MapGet("/api/v1/aapm/credentials/{credId:guid}", async (Guid credId, OrkunPamDbContext db,
            IVaultEncryptionService vault, ILogger<Program> logger, HttpContext ctx) =>
        {
            var clientIdClaim = ctx.User?.FindFirst("sub")?.Value ?? ctx.User?.FindFirst("client_id")?.Value;
            if (string.IsNullOrEmpty(clientIdClaim) || !Guid.TryParse(clientIdClaim, out var apiClientId))
            {
                logger.LogWarning("AAPM credential access denied: missing or invalid client_id claim");
                return Results.Json(new { error = "unauthorized", message = "Valid AAPM token required" }, statusCode: 401);
            }

            var apiClient = await db.ApiClients
                .Include(c => c.CredentialAccess)
                .FirstOrDefaultAsync(c => c.Id == apiClientId && c.IsEnabled);

            if (apiClient == null)
            {
                logger.LogWarning("AAPM credential access denied: client {ClientId} not found or disabled", apiClientId);
                return Results.Json(new { error = "forbidden", message = "API client not found or disabled" }, statusCode: 403);
            }

            var hasAccess = apiClient.CredentialAccess.Any(ca => ca.CredentialId == credId);
            if (!hasAccess)
            {
                logger.LogWarning("AAPM client {ClientId} attempted to access credential {CredId} without permission",
                    apiClient.ClientId, credId);
                return Results.Json(new { error = "forbidden", message = "Client does not have access to this credential" }, statusCode: 403);
            }

            var cred = await db.Credentials.FindAsync(credId);
            if (cred == null)
                return Results.NotFound(new { error = "credential_not_found" });

            string? password = null;
            if (cred.PasswordEnc != null)
            {
                var decResult = vault.DecryptString(cred.PasswordEnc);
                if (decResult.IsFailure)
                    return Results.Problem("Credential decryption failed");
                password = decResult.Value;
            }

            db.ApiAccessLogs.Add(new ApiAccessLog
            {
                CredentialId = credId,
                ApiClientId = apiClientId,
                ClientIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                Outcome = 0
            });
            apiClient.LastUsedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            logger.LogInformation("AAPM credential {CredId} retrieved by client {ClientId} from {Ip}",
                credId, apiClient.ClientId, ctx.Connection.RemoteIpAddress);

            return Results.Ok(new
            {
                credentialId = cred.Id,
                username = cred.Username,
                password,
                credentialType = cred.CredentialType.ToString()
            });
        }).WithTags("AAPM");
    }
}

public record CreateApiClientRequest(string Name, string? AllowedIpRanges, int? RateLimitPerMinute,
    Guid? ServiceAccountId, Guid[]? CredentialIds);
public record UpdateApiClientRequest(string? Name, string? AllowedIpRanges, int? RateLimitPerMinute, bool? IsEnabled);
public record AapmTokenRequest(string ClientId, string ClientSecret);
