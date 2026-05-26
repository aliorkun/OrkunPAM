using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class DeviceMfaPolicyEndpoints
{
    public static void MapDeviceMfaPolicyEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/policies/device-mfa")
            .WithTags("DeviceMfaPolicy")
            .RequireAuthorization("AdminPolicy");

        // GET — list all device MFA policies
        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var policies = await db.DeviceMfaPolicies
                .OrderBy(p => p.Name)
                .Select(p => new
                {
                    p.Id, p.Name, p.Description, p.IsEnabled,
                    p.DeviceGroupId, p.DeviceId,
                    p.RequiredMfaLevel, p.EnforceAtSessionStart,
                    p.CreatedAtUtc, p.UpdatedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = policies });
        });

        // POST — create policy
        group.MapPost("/", async (CreateDeviceMfaPolicyRequest req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            var validLevels = new[] { "None", "Totp", "Fido2", "HardwareToken", "Any" };
            var level = req.RequiredMfaLevel ?? "Any";
            if (!validLevels.Contains(level))
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid RequiredMfaLevel. Use: None, Totp, Fido2, HardwareToken, or Any" } });

            var policy = new DeviceMfaPolicy
            {
                Id                    = Guid.NewGuid(),
                Name                  = req.Name.Trim(),
                Description           = req.Description?.Trim(),
                DeviceGroupId         = req.DeviceGroupId,
                DeviceId              = req.DeviceId,
                RequiredMfaLevel      = level,
                EnforceAtSessionStart = req.EnforceAtSessionStart ?? true,
                IsEnabled             = req.IsEnabled ?? true
            };

            db.DeviceMfaPolicies.Add(policy);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "DEVICE_MFA_POLICY_CREATED", null, null, ip,
                "DeviceMfaPolicy", policy.Id.ToString(), new { policy.Name, policy.RequiredMfaLevel });

            return Results.Created($"/api/v1/policies/device-mfa/{policy.Id}",
                new { success = true, data = new { policy.Id, policy.Name } });
        });

        // GET {id}
        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var policy = await db.DeviceMfaPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            return Results.Ok(new { success = true, data = policy });
        });

        // PUT {id}
        group.MapPut("/{id:guid}", async (Guid id, UpdateDeviceMfaPolicyRequest req,
            OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var policy = await db.DeviceMfaPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            if (req.Name != null) policy.Name = req.Name.Trim();
            if (req.Description != null) policy.Description = req.Description.Trim();
            if (req.IsEnabled.HasValue) policy.IsEnabled = req.IsEnabled.Value;
            if (req.EnforceAtSessionStart.HasValue) policy.EnforceAtSessionStart = req.EnforceAtSessionStart.Value;
            if (req.DeviceGroupId.HasValue) policy.DeviceGroupId = req.DeviceGroupId;
            if (req.DeviceId.HasValue) policy.DeviceId = req.DeviceId;

            if (req.RequiredMfaLevel != null)
            {
                var validLevels = new[] { "None", "Totp", "Fido2", "HardwareToken", "Any" };
                if (!validLevels.Contains(req.RequiredMfaLevel))
                    return Results.BadRequest(new { success = false, errors = new[] { "Invalid RequiredMfaLevel" } });
                policy.RequiredMfaLevel = req.RequiredMfaLevel;
            }

            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "DEVICE_MFA_POLICY_UPDATED", null, null, ip,
                "DeviceMfaPolicy", policy.Id.ToString(), new { policy.Name, policy.IsEnabled, policy.RequiredMfaLevel });

            return Results.Ok(new { success = true, data = new { policy.Id, policy.Name } });
        });

        // DELETE {id}
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var policy = await db.DeviceMfaPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            db.DeviceMfaPolicies.Remove(policy);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "DEVICE_MFA_POLICY_DELETED", null, null, ip,
                "DeviceMfaPolicy", id.ToString(), null);

            return Results.Ok(new { success = true });
        });

        // GET /effective?deviceId=... — called by session start to find active policy
        app.MapGet("/api/v1/policies/device-mfa/effective",
            async (Guid? deviceId, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null) return Results.Unauthorized();

            if (!deviceId.HasValue)
                return Results.Ok(new { success = true, data = (object?)null });

            var policy = await GetEffectivePolicyAsync(db, deviceId.Value);
            return Results.Ok(new { success = true, data = policy == null ? null : new
            {
                policy.Id, policy.Name, policy.RequiredMfaLevel,
                policy.EnforceAtSessionStart, policy.IsEnabled
            }});
        }).WithTags("DeviceMfaPolicy").RequireAuthorization();

        // POST /step-up-verify — user completes step-up MFA before session start
        app.MapPost("/api/v1/sessions/step-up-verify",
            async (StepUpVerifyRequest req, OrkunPamDbContext db, IMemoryCache cache,
                ITotpService totp, IVaultEncryptionService vault,
                IAuditService audit, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            // Verify the step-up token exists in cache (issued at session start 403)
            var tokenCacheKey = $"stepup-token:{req.StepUpToken}";
            if (!cache.TryGetValue(tokenCacheKey, out StepUpTokenData? tokenData) || tokenData == null)
                return Results.BadRequest(new { success = false, errors = new[] { "Step-up token invalid or expired" } });

            if (tokenData.UserId != userId)
                return Results.Forbid();

            // Verify MFA code based on user's enrolled MFA
            var user = await db.Users.FindAsync(userId);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            bool verified = false;

            if (!string.IsNullOrEmpty(req.TotpCode) && user.MfaSecret != null && user.MfaEnabled)
            {
                var decResult = vault.Decrypt(user.MfaSecret);
                if (decResult.IsSuccess)
                {
                    try { verified = totp.ValidateCode(decResult.Value, req.TotpCode); }
                    finally { CryptographicOperations.ZeroMemory(decResult.Value); }
                }
            }
            else if (tokenData.RequiredMfaLevel == "None")
            {
                // Policy requires no MFA — auto-pass
                verified = true;
            }

            if (!verified)
            {
                await audit.LogAsync("Session", "SESSION_MFA_STEP_UP_FAILED", userId, null, ip,
                    "Device", tokenData.DeviceId.ToString(), new { tokenData.RequiredMfaLevel });
                return Results.BadRequest(new { success = false, errors = new[] { "MFA verification failed" } });
            }

            // Store step-up completion for 15 minutes
            cache.Remove(tokenCacheKey);
            cache.Set($"stepup:{userId}:{tokenData.DeviceId}", true,
                new MemoryCacheEntryOptions { AbsoluteExpirationRelativeToNow = TimeSpan.FromMinutes(15) });

            await audit.LogAsync("Session", "SESSION_MFA_STEP_UP_COMPLETED", userId, null, ip,
                "Device", tokenData.DeviceId.ToString(), new { tokenData.RequiredMfaLevel });

            return Results.Ok(new { success = true, message = "Step-up MFA verified. Proceed with session creation." });
        }).WithTags("DeviceMfaPolicy").RequireAuthorization();
    }

    internal static async Task<DeviceMfaPolicy?> GetEffectivePolicyAsync(OrkunPamDbContext db, Guid deviceId)
    {
        // First: exact device match
        var byDevice = await db.DeviceMfaPolicies
            .Where(p => p.IsEnabled && p.DeviceId == deviceId)
            .FirstOrDefaultAsync();
        if (byDevice != null) return byDevice;

        // Second: device group match (find which group the device belongs to)
        var deviceGroupId = await db.DeviceGroupMembers
            .Where(m => m.DeviceId == deviceId)
            .Select(m => (Guid?)m.DeviceGroupId)
            .FirstOrDefaultAsync();

        if (deviceGroupId.HasValue)
        {
            var byGroup = await db.DeviceMfaPolicies
                .Where(p => p.IsEnabled && p.DeviceGroupId == deviceGroupId)
                .FirstOrDefaultAsync();
            if (byGroup != null) return byGroup;
        }

        // Third: global policy (no device/group scope)
        return await db.DeviceMfaPolicies
            .Where(p => p.IsEnabled && p.DeviceId == null && p.DeviceGroupId == null)
            .FirstOrDefaultAsync();
    }
}

public record CreateDeviceMfaPolicyRequest(
    string  Name,
    string? Description,
    Guid?   DeviceGroupId,
    Guid?   DeviceId,
    string? RequiredMfaLevel,
    bool?   EnforceAtSessionStart,
    bool?   IsEnabled);

public record UpdateDeviceMfaPolicyRequest(
    string? Name,
    string? Description,
    Guid?   DeviceGroupId,
    Guid?   DeviceId,
    string? RequiredMfaLevel,
    bool?   EnforceAtSessionStart,
    bool?   IsEnabled);

public record StepUpVerifyRequest(string StepUpToken, string? TotpCode);

public record StepUpTokenData(Guid UserId, Guid DeviceId, string RequiredMfaLevel);
