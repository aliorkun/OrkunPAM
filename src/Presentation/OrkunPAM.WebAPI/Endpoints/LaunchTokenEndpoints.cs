using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Cryptography;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class LaunchTokenEndpoints
{
    private const int TokenTtlSeconds = 30;

    public static void MapLaunchTokenEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/sessions").WithTags("Sessions");

        // ── Generate a one-time launch token (authenticated users only) ──────
        group.MapPost("/launch-token", async (
            LaunchTokenRequest req,
            OrkunPamDbContext db,
            HttpContext ctx,
            ILogger<Program> logger) =>
        {
            var userIdClaim = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username    = ctx.User.FindFirstValue(ClaimTypes.Name);
            if (userIdClaim == null || !Guid.TryParse(userIdClaim, out var userId))
                return Results.Unauthorized();

            var device = await db.Devices.FindAsync(req.DeviceId);
            if (device == null)
                return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            var cred = await db.Credentials.FindAsync(req.CredentialId);
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var protocol = req.Protocol?.ToLowerInvariant() switch
            {
                "rdp" => "rdp",
                "ssh" => "ssh",
                _     => device.ConnectionProtocol.ToString().ToLowerInvariant() == "rdp" ? "rdp" : "ssh"
            };

            var targetHost = device.IpAddress ?? device.Fqdn ?? device.Hostname;
            var targetPort = device.ConnectionPort ?? (protocol == "rdp" ? 3389 : 22);

            // Purge stale tokens (best-effort, not critical)
            await db.LaunchTokens
                .Where(t => t.ExpiresAtUtc < DateTime.UtcNow.AddMinutes(-5))
                .ExecuteDeleteAsync();

            var token = new LaunchToken
            {
                UserId            = userId,
                DeviceId          = req.DeviceId,
                CredentialId      = req.CredentialId,
                Protocol          = protocol,
                TargetHost        = targetHost,
                TargetPort        = targetPort,
                ExpiresAtUtc      = DateTime.UtcNow.AddSeconds(TokenTtlSeconds),
                CreatedByUsername = username
            };
            db.LaunchTokens.Add(token);
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory = "Session",
                EventType     = "LaunchTokenGenerated",
                ActorUsername = username,
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType    = "Device",
                TargetId      = req.DeviceId.ToString(),
                Details       = $"protocol={protocol} host={targetHost}:{targetPort}",
                Outcome       = AuditOutcome.Success
            });
            await db.SaveChangesAsync();

            var launchUri = $"orkunpam://launch?token={token.Id}&protocol={protocol}";
            return Results.Ok(new
            {
                success = true,
                data    = new { token = token.Id, launchUri, expiresAt = token.ExpiresAtUtc }
            });
        }).RequireAuthorization().RequireRateLimiting("auth");

        // ── Redeem launch token (called by LaunchHelper, no user auth) ──────
        // Returns device connection info + credential for immediate use.
        // Token is one-time: second call returns 410 Gone.
        group.MapGet("/launch-token/{tokenId:guid}/redeem", async (
            Guid tokenId,
            OrkunPamDbContext db,
            IVaultEncryptionService vault,
            HttpContext ctx,
            ILogger<Program> logger) =>
        {
            var token = await db.LaunchTokens.FindAsync(tokenId);

            if (token == null)
                return Results.NotFound(new { success = false, errors = new[] { "Token not found" } });

            if (token.IsUsed)
            {
                logger.LogWarning("LaunchToken {Id} already redeemed", tokenId);
                return Results.Json(new { success = false, errors = new[] { "Token already used" } },
                    statusCode: 410);
            }

            if (token.ExpiresAtUtc < DateTime.UtcNow)
            {
                db.AuditLogs.Add(AuditEntry("LaunchTokenExpired", token, ctx));
                await db.SaveChangesAsync();
                return Results.Json(new { success = false, errors = new[] { "Token expired" } },
                    statusCode: 410);
            }

            // Mark used before returning credential (idempotency)
            token.IsUsed         = true;
            token.RedeemedAtUtc  = DateTime.UtcNow;
            token.RedeemedFromIp = ctx.Connection.RemoteIpAddress?.ToString();

            var cred = await db.Credentials.FindAsync(token.CredentialId);
            if (cred == null)
            {
                db.AuditLogs.Add(AuditEntry("LaunchTokenFailed", token, ctx, "credential missing"));
                await db.SaveChangesAsync();
                return Results.Problem("Credential no longer exists");
            }

            string? password = null;
            if (cred.PasswordEnc != null)
            {
                var dec = vault.DecryptString(cred.PasswordEnc);
                if (dec.IsFailure)
                {
                    logger.LogError("LaunchToken redeem: decrypt failed for credential {CredId}", cred.Id);
                    db.AuditLogs.Add(AuditEntry("LaunchTokenFailed", token, ctx, "decrypt error"));
                    await db.SaveChangesAsync();
                    return Results.Problem("Decryption failed");
                }
                password = dec.Value;
            }

            string? privateKey = null;
            if (cred.PrivateKeyEnc != null)
            {
                var pkDec = vault.DecryptString(cred.PrivateKeyEnc);
                if (pkDec.IsSuccess) privateKey = pkDec.Value;
            }

            db.AuditLogs.Add(AuditEntry("LaunchTokenRedeemed", token, ctx));
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    protocol   = token.Protocol,
                    host       = token.TargetHost,
                    port       = token.TargetPort,
                    username   = cred.Username,
                    password,
                    privateKey
                }
            });
        }).RequireRateLimiting("auth");
    }

    private static AuditLogEntry AuditEntry(
        string eventType, LaunchToken token, HttpContext ctx, string? extra = null)
        => new()
        {
            EventCategory  = "Session",
            EventType      = eventType,
            ActorUsername  = token.CreatedByUsername,
            ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
            TargetType     = "LaunchToken",
            TargetId       = token.Id.ToString(),
            Details        = extra ?? $"protocol={token.Protocol} host={token.TargetHost}:{token.TargetPort}",
            Outcome        = eventType.EndsWith("Failed") || eventType.EndsWith("Expired")
                ? AuditOutcome.Failure
                : AuditOutcome.Success
        };
}

public record LaunchTokenRequest(Guid DeviceId, Guid CredentialId, string? Protocol);
