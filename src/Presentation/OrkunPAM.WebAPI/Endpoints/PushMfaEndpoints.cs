using System.Collections.Concurrent;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

/// <summary>
/// Push Notification MFA (#196) — polling-based, enterprise on-prem, no FCM/APNs required.
/// Challenges are stored in-memory (single-node); devices are stored in SystemConfig.
/// </summary>
public static class PushMfaEndpoints
{
    // In-memory challenge store: ChallengeId → state. Cleaned up on expiry.
    private static readonly ConcurrentDictionary<string, PushChallengeState> _challenges = new();

    public static void MapPushMfaEndpoints(this IEndpointRouteBuilder app)
    {
        var push = app.MapGroup("/api/v1/auth/push").WithTags("Auth");

        // === Device Enrollment ===
        push.MapPost("/enroll", async (EnrollDeviceRequest req, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var deviceId = Guid.NewGuid().ToString("N");
            var rawToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32));
            var tokenHash = HashToken(rawToken);

            var deviceRecord = new { id = deviceId, name = req.DeviceName, registeredAt = DateTime.UtcNow, tokenHash };
            var configKey = $"push:device:{userId}:{deviceId}";

            var existing = await db.SystemConfigs.FindAsync(configKey);
            if (existing != null)
            {
                existing.Value = JsonSerializer.Serialize(deviceRecord);
                existing.UpdatedAtUtc = DateTime.UtcNow;
            }
            else
            {
                db.SystemConfigs.Add(new SystemConfig
                {
                    Key = configKey,
                    Value = JsonSerializer.Serialize(deviceRecord),
                    Category = "PushMfa",
                    IsEncrypted = false,
                    UpdatedAtUtc = DateTime.UtcNow,
                    UpdatedBy = userId
                });
            }
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = true,
                data = new { deviceId, deviceToken = rawToken, deviceName = req.DeviceName,
                    message = "Store this device token securely — it will not be shown again." }
            });
        }).RequireAuthorization();

        // === List Devices ===
        push.MapGet("/devices", async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var prefix = $"push:device:{userId}:";
            var configs = await db.SystemConfigs
                .Where(c => c.Key.StartsWith(prefix))
                .ToListAsync();

            var devices = configs.Select(c =>
            {
                try
                {
                    var doc = JsonSerializer.Deserialize<JsonElement>(c.Value ?? "{}");
                    return new
                    {
                        id = doc.TryGetProperty("id", out var id) ? id.GetString() : null,
                        name = doc.TryGetProperty("name", out var n) ? n.GetString() : null,
                        registeredAt = doc.TryGetProperty("registeredAt", out var r) ? r.GetDateTime() : (DateTime?)null
                    };
                }
                catch { return (object?)null; }
            }).Where(d => d != null).ToList();

            return Results.Ok(new { success = true, data = devices });
        }).RequireAuthorization();

        // === Remove Device ===
        push.MapDelete("/devices/{deviceId}", async (string deviceId, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var configKey = $"push:device:{userId}:{deviceId}";
            var config = await db.SystemConfigs.FindAsync(configKey);
            if (config == null) return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            db.SystemConfigs.Remove(config);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = "Device removed" });
        }).RequireAuthorization();

        // === Initiate Push Challenge (web login step) ===
        // Called after username/password verified, before JWT returned.
        push.MapPost("/initiate", async (InitiatePushRequest req, OrkunPamDbContext db, HttpContext ctx) =>
        {
            // Cleanup expired challenges
            var expired = _challenges.Where(kv => kv.Value.ExpiresAt < DateTime.UtcNow).Select(kv => kv.Key).ToList();
            foreach (var k in expired) _challenges.TryRemove(k, out _);

            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var challengeId = Guid.NewGuid().ToString("N");
            var state = new PushChallengeState
            {
                ChallengeId = challengeId,
                UserId = userId,
                CreatedAt = DateTime.UtcNow,
                ExpiresAt = DateTime.UtcNow.AddMinutes(2),
                Status = "Pending"
            };
            _challenges[challengeId] = state;

            return Results.Ok(new
            {
                success = true,
                data = new { challengeId, expiresAt = state.ExpiresAt,
                    message = "Approve this login from your registered mobile device." }
            });
        }).RequireAuthorization();

        // === Poll Challenge Status (web browser polls this) ===
        push.MapGet("/{challengeId}/status", (string challengeId, HttpContext ctx) =>
        {
            if (!_challenges.TryGetValue(challengeId, out var state))
                return Results.NotFound(new { success = false, errors = new[] { "Challenge not found or expired" } });

            if (state.ExpiresAt < DateTime.UtcNow)
            {
                state.Status = "Expired";
                _challenges.TryRemove(challengeId, out _);
            }

            return Results.Ok(new
            {
                success = true,
                data = new { challengeId, state.Status, state.ExpiresAt }
            });
        }).AllowAnonymous();

        // === Mobile Device Responds (approve or deny) ===
        // Mobile app sends X-Device-Token header for authentication.
        push.MapPost("/{challengeId}/respond", async (string challengeId, PushRespondRequest req,
            OrkunPamDbContext db, HttpContext ctx) =>
        {
            var deviceToken = ctx.Request.Headers["X-Device-Token"].FirstOrDefault();
            if (string.IsNullOrEmpty(deviceToken))
                return Results.Unauthorized();

            if (!_challenges.TryGetValue(challengeId, out var state))
                return Results.NotFound(new { success = false, errors = new[] { "Challenge not found or expired" } });

            if (state.ExpiresAt < DateTime.UtcNow)
            {
                _challenges.TryRemove(challengeId, out _);
                return Results.BadRequest(new { success = false, errors = new[] { "Challenge expired" } });
            }

            if (state.Status != "Pending")
                return Results.BadRequest(new { success = false, errors = new[] { "Challenge already resolved" } });

            // Verify device token belongs to this user
            var tokenHash = HashToken(deviceToken);
            var prefix = $"push:device:{state.UserId}:";
            var deviceExists = await db.SystemConfigs
                .Where(c => c.Key.StartsWith(prefix) && c.Value != null && c.Value.Contains(tokenHash))
                .AnyAsync();

            if (!deviceExists)
                return Results.Forbid();

            state.Status = req.Approved ? "Approved" : "Denied";

            if (!req.Approved)
                _challenges.TryRemove(challengeId, out _);

            return Results.Ok(new { success = true, data = new { challengeId, status = state.Status } });
        }).AllowAnonymous();
    }

    private static string HashToken(string raw)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(raw));
        return Convert.ToHexString(bytes).ToLowerInvariant();
    }
}

internal sealed class PushChallengeState
{
    public string ChallengeId { get; set; } = string.Empty;
    public Guid UserId { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime ExpiresAt { get; set; }
    public string Status { get; set; } = "Pending"; // Pending | Approved | Denied | Expired
}

public record EnrollDeviceRequest(string DeviceName);
public record InitiatePushRequest(string? Hint);
public record PushRespondRequest(bool Approved);
