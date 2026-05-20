using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

/// <summary>
/// MFA Device Management (RFP MFA #12) — unified list + revoke for all enrolled MFA methods.
/// Methods: TOTP, Email OTP, SMS, FIDO2, Push.
/// </summary>
public static class MfaDeviceEndpoints
{
    private static readonly JsonSerializerOptions _jsonOpts = new() { PropertyNameCaseInsensitive = true };

    public static void MapMfaDeviceEndpoints(this IEndpointRouteBuilder app)
    {
        // === User self-service: list all enrolled MFA methods ===
        app.MapGet("/api/v1/my/mfa-devices", async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userId = GetUserId(ctx);
            if (userId == null) return Results.Unauthorized();

            var user = await db.Users.FindAsync(userId.Value);
            if (user == null) return Results.NotFound();

            var devices = await BuildDeviceListAsync(db, userId.Value, user);
            return Results.Ok(new { success = true, data = devices });
        }).RequireAuthorization();

        // === User self-service: revoke TOTP / Email OTP / SMS enrollment ===
        app.MapDelete("/api/v1/my/mfa-devices/by-type/{type}", async (
            string type, OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var userId = GetUserId(ctx);
            if (userId == null) return Results.Unauthorized();

            var user = await db.Users.FindAsync(userId.Value);
            if (user == null) return Results.NotFound();

            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            switch (type.ToLowerInvariant())
            {
                case "totp":
                    if (!user.MfaEnabled || user.MfaType != MfaType.Totp || user.MfaSecret == null)
                        return Results.BadRequest(new { success = false, errors = new[] { "TOTP is not your active MFA method" } });
                    user.MfaEnabled = false;
                    user.MfaSecret = null;
                    await db.SaveChangesAsync();
                    _ = audit.LogAsync("MFA", "MFA_TOTP_REVOKED", userId.Value, actorName, ip, "User", userId.Value.ToString(), null);
                    return Results.Ok(new { success = true, data = "TOTP enrollment revoked" });

                case "email_otp":
                    if (!user.MfaEnabled || user.MfaType != MfaType.EmailOtp)
                        return Results.BadRequest(new { success = false, errors = new[] { "Email OTP is not your active MFA method" } });
                    user.MfaEnabled = false;
                    await db.SaveChangesAsync();
                    _ = audit.LogAsync("MFA", "MFA_EMAIL_OTP_REVOKED", userId.Value, actorName, ip, "User", userId.Value.ToString(), null);
                    return Results.Ok(new { success = true, data = "Email OTP enrollment revoked" });

                case "sms":
                    if (!user.MfaEnabled || user.MfaType != MfaType.Sms)
                        return Results.BadRequest(new { success = false, errors = new[] { "SMS OTP is not your active MFA method" } });
                    user.MfaEnabled = false;
                    await db.SaveChangesAsync();
                    _ = audit.LogAsync("MFA", "MFA_SMS_REVOKED", userId.Value, actorName, ip, "User", userId.Value.ToString(), null);
                    return Results.Ok(new { success = true, data = "SMS OTP enrollment revoked" });

                default:
                    return Results.BadRequest(new { success = false, errors = new[] { "Unknown type. Valid: totp, email_otp, sms" } });
            }
        }).RequireAuthorization();

        // === User self-service: revoke a FIDO2 security key ===
        app.MapDelete("/api/v1/my/mfa-devices/fido2/{credId:guid}", async (
            Guid credId, OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var userId = GetUserId(ctx);
            if (userId == null) return Results.Unauthorized();

            var cred = await db.Fido2Credentials
                .FirstOrDefaultAsync(f => f.Id == credId && f.UserId == userId.Value && f.IsActive);
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Security key not found" } });

            cred.IsActive = false;
            await db.SaveChangesAsync();

            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _ = audit.LogAsync("MFA", "MFA_FIDO2_REVOKED", userId.Value, actorName, ip,
                "Fido2Credential", credId.ToString(), new { credId });

            return Results.Ok(new { success = true, data = "Security key revoked" });
        }).RequireAuthorization();

        // === User self-service: revoke a Push MFA device ===
        app.MapDelete("/api/v1/my/mfa-devices/push/{deviceId}", async (
            string deviceId, OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var userId = GetUserId(ctx);
            if (userId == null) return Results.Unauthorized();

            var configKey = "push:device:" + userId.Value + ":" + deviceId;
            var config = await db.SystemConfigs.FindAsync(configKey);
            if (config == null)
                return Results.NotFound(new { success = false, errors = new[] { "Push device not found" } });

            db.SystemConfigs.Remove(config);
            await db.SaveChangesAsync();

            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _ = audit.LogAsync("MFA", "MFA_PUSH_REVOKED", userId.Value, actorName, ip,
                "PushDevice", deviceId, new { deviceId });

            return Results.Ok(new { success = true, data = "Push device revoked" });
        }).RequireAuthorization();

        // === Admin: list any user's enrolled MFA methods ===
        app.MapGet("/api/v1/admin/users/{userId:guid}/mfa-devices", async (
            Guid userId, OrkunPamDbContext db) =>
        {
            var user = await db.Users.FindAsync(userId);
            if (user == null)
                return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            var devices = await BuildDeviceListAsync(db, userId, user);
            return Results.Ok(new { success = true, data = devices });
        }).RequireAuthorization("AdminPolicy");

        // === Admin: revoke a user's TOTP / Email OTP / SMS enrollment ===
        app.MapDelete("/api/v1/admin/users/{userId:guid}/mfa-devices/by-type/{type}", async (
            Guid userId, string type, OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var user = await db.Users.FindAsync(userId);
            if (user == null)
                return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            var adminId = GetUserId(ctx);
            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var details = new { TargetUserId = userId };

            switch (type.ToLowerInvariant())
            {
                case "totp":
                    user.MfaEnabled = false;
                    user.MfaSecret = null;
                    await db.SaveChangesAsync();
                    _ = audit.LogAsync("MFA", "ADMIN_MFA_TOTP_REVOKED", adminId, actorName, ip, "User", userId.ToString(), details);
                    return Results.Ok(new { success = true, data = "TOTP revoked by admin" });

                case "email_otp":
                    if (user.MfaType == MfaType.EmailOtp) user.MfaEnabled = false;
                    await db.SaveChangesAsync();
                    _ = audit.LogAsync("MFA", "ADMIN_MFA_EMAIL_OTP_REVOKED", adminId, actorName, ip, "User", userId.ToString(), details);
                    return Results.Ok(new { success = true, data = "Email OTP revoked by admin" });

                case "sms":
                    if (user.MfaType == MfaType.Sms) user.MfaEnabled = false;
                    await db.SaveChangesAsync();
                    _ = audit.LogAsync("MFA", "ADMIN_MFA_SMS_REVOKED", adminId, actorName, ip, "User", userId.ToString(), details);
                    return Results.Ok(new { success = true, data = "SMS OTP revoked by admin" });

                default:
                    return Results.BadRequest(new { success = false, errors = new[] { "Unknown type" } });
            }
        }).RequireAuthorization("AdminPolicy");

        // === Admin: revoke a user's FIDO2 key ===
        app.MapDelete("/api/v1/admin/users/{userId:guid}/mfa-devices/fido2/{credId:guid}", async (
            Guid userId, Guid credId, OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var cred = await db.Fido2Credentials
                .FirstOrDefaultAsync(f => f.Id == credId && f.UserId == userId);
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Security key not found" } });

            cred.IsActive = false;
            await db.SaveChangesAsync();

            var adminId = GetUserId(ctx);
            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _ = audit.LogAsync("MFA", "ADMIN_MFA_FIDO2_REVOKED", adminId, actorName, ip,
                "Fido2Credential", credId.ToString(), new { TargetUserId = userId, credId });

            return Results.Ok(new { success = true, data = "Security key revoked by admin" });
        }).RequireAuthorization("AdminPolicy");
    }

    private static Guid? GetUserId(HttpContext ctx)
    {
        var s = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(s, out var id) ? id : null;
    }

    private static string? MaskPhone(string? phone)
    {
        if (string.IsNullOrEmpty(phone)) return null;
        return "****" + phone[^Math.Min(4, phone.Length)..];
    }

    private static async Task<List<object>> BuildDeviceListAsync(OrkunPamDbContext db, Guid userId, User user)
    {
        var result = new List<object>();

        if (user.MfaEnabled)
        {
            switch (user.MfaType)
            {
                case MfaType.Totp when user.MfaSecret != null:
                    result.Add(new { type = "totp", name = "TOTP Authenticator App", status = "Active", deviceId = (string?)null, detail = (string?)null });
                    break;
                case MfaType.EmailOtp:
                    result.Add(new { type = "email_otp", name = "Email One-Time Password", status = "Active", deviceId = (string?)null, detail = user.Email });
                    break;
                case MfaType.Sms:
                    result.Add(new { type = "sms", name = "SMS One-Time Password", status = "Active", deviceId = (string?)null, detail = MaskPhone(user.Phone) });
                    break;
            }
        }

        var fido2Keys = await db.Fido2Credentials
            .Where(f => f.UserId == userId && f.IsActive)
            .OrderBy(f => f.RegisteredAtUtc)
            .ToListAsync();
        foreach (var k in fido2Keys)
            result.Add(new
            {
                type = "fido2",
                name = k.FriendlyName,
                status = "Active",
                deviceId = k.Id.ToString(),
                detail = k.LastUsedAtUtc.HasValue ? "Last used " + k.LastUsedAtUtc.Value.ToString("yyyy-MM-dd") : "Never used"
            });

        var pushConfigs = await db.SystemConfigs
            .Where(c => c.Key.StartsWith("push:device:" + userId + ":"))
            .ToListAsync();
        foreach (var cfg in pushConfigs)
        {
            try
            {
                var rec = JsonSerializer.Deserialize<PushDeviceRecord>(cfg.Value, _jsonOpts);
                if (rec != null)
                    result.Add(new
                    {
                        type = "push",
                        name = rec.Name ?? "Push Device",
                        status = "Active",
                        deviceId = rec.Id,
                        detail = "Registered " + rec.RegisteredAt.ToString("yyyy-MM-dd")
                    });
            }
            catch { }
        }

        return result;
    }

    private record PushDeviceRecord(string? Id, string? Name, DateTime RegisteredAt, string? TokenHash);
}
