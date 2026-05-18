using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class DeviceTrustEndpoints
{
    public static void MapDeviceTrustEndpoints(this IEndpointRouteBuilder app)
    {
        // ── User: own trusted devices ──────────────────────────────────────────
        var mine = app.MapGroup("/api/v1/my/trusted-devices")
            .WithTags("DeviceTrust")
            .RequireAuthorization();

        mine.MapGet("/", async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            if (!TryGetUserId(ctx, out var userId)) return Results.Unauthorized();

            var list = await db.TrustedDevices
                .Where(d => d.UserId == userId)
                .OrderByDescending(d => d.LastSeenAtUtc)
                .Select(d => new
                {
                    d.Id,
                    d.DeviceName,
                    TrustLevel = d.TrustLevel.ToString(),
                    d.IsRevoked,
                    d.UserAgent,
                    d.RegisteredAtUtc,
                    d.LastSeenAtUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list });
        });

        mine.MapPut("/{id:guid}/rename", async (Guid id, RenameTrustedDeviceRequest req,
            OrkunPamDbContext db, HttpContext ctx) =>
        {
            if (!TryGetUserId(ctx, out var userId)) return Results.Unauthorized();

            var device = await db.TrustedDevices.FirstOrDefaultAsync(d => d.Id == id && d.UserId == userId);
            if (device == null) return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            device.DeviceName = req.DeviceName?.Trim();
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        mine.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (!TryGetUserId(ctx, out var userId)) return Results.Unauthorized();

            var device = await db.TrustedDevices.FirstOrDefaultAsync(d => d.Id == id && d.UserId == userId);
            if (device == null) return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            device.IsRevoked = true;
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("DeviceTrust", "DEVICE_REVOKED", userId, null, ip,
                "TrustedDevice", id.ToString(), new { deviceName = device.DeviceName });

            return Results.Ok(new { success = true });
        });

        // ── Admin: all trusted devices ──────────────────────────────────────────
        var admin = app.MapGroup("/api/v1/admin/trusted-devices")
            .WithTags("DeviceTrust")
            .RequireAuthorization("AdminPolicy");

        admin.MapGet("/", async (OrkunPamDbContext db,
            Guid? userId, string? trustLevel, bool? revoked, int page = 1, int pageSize = 50) =>
        {
            var query = db.TrustedDevices.AsQueryable();

            if (userId.HasValue) query = query.Where(d => d.UserId == userId.Value);
            if (revoked.HasValue) query = query.Where(d => d.IsRevoked == revoked.Value);
            if (!string.IsNullOrEmpty(trustLevel) && Enum.TryParse<TrustLevel>(trustLevel, true, out var tl))
                query = query.Where(d => d.TrustLevel == tl);

            var total = await query.CountAsync();
            var list = await query
                .OrderByDescending(d => d.LastSeenAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(d => new
                {
                    d.Id,
                    d.UserId,
                    d.DeviceName,
                    d.DeviceFingerprint,
                    TrustLevel = d.TrustLevel.ToString(),
                    d.IsRevoked,
                    d.UserAgent,
                    d.RegisteredAtUtc,
                    d.LastSeenAtUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        admin.MapPut("/{id:guid}/trust", async (Guid id, SetTrustLevelRequest req,
            OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var device = await db.TrustedDevices.FindAsync(id);
            if (device == null) return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            if (!Enum.TryParse<TrustLevel>(req.TrustLevel, true, out var newLevel))
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid trust level. Valid values: Unknown, UserRegistered, AdminApproved, ManagedDevice" } });

            var oldLevel = device.TrustLevel;
            device.TrustLevel = newLevel;
            device.IsRevoked = false;
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            Guid? actorId = Guid.TryParse(ctx.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsed) ? parsed : null;
            await audit.LogAsync("DeviceTrust", "DEVICE_TRUST_UPDATED", actorId, null, ip,
                "TrustedDevice", id.ToString(), new { deviceId = id, from = oldLevel.ToString(), to = newLevel.ToString() });

            return Results.Ok(new { success = true });
        });

        admin.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var device = await db.TrustedDevices.FindAsync(id);
            if (device == null) return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            device.IsRevoked = true;
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            Guid? actorId = Guid.TryParse(ctx.User.FindFirstValue(ClaimTypes.NameIdentifier), out var parsedAdmin) ? parsedAdmin : null;
            await audit.LogAsync("DeviceTrust", "DEVICE_REVOKED_BY_ADMIN", actorId, null, ip,
                "TrustedDevice", id.ToString(), new { deviceId = id, userId = device.UserId });

            return Results.Ok(new { success = true });
        });
    }

    private static bool TryGetUserId(HttpContext ctx, out Guid userId)
    {
        var str = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
        return Guid.TryParse(str, out userId);
    }
}

public record RenameTrustedDeviceRequest(string? DeviceName);
public record SetTrustLevelRequest(string TrustLevel);
