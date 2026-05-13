using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Security;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class JitEndpoints
{
    public static void MapJitEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/api/v1/jit").WithTags("JIT").RequireAuthorization();

        // POST /api/v1/jit/requests — submit JIT access request
        grp.MapPost("/requests", async (JitAccessRequestBody req, OrkunPamDbContext db,
            HttpContext ctx, IAuditService audit) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var username = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            if (string.IsNullOrWhiteSpace(req.Reason) || req.Reason.Trim().Length < 10)
                return Results.BadRequest(new { success = false, error = "Reason must be at least 10 characters." });

            var validDurations = new[] { 30, 60, 120, 240, 480 };
            if (!validDurations.Contains(req.DurationMinutes))
                return Results.BadRequest(new { success = false, error = "Invalid duration. Choose 30, 60, 120, 240, or 480 minutes." });

            var jit = new JitAccessRequest
            {
                RequesterId = userId,
                RequesterUsername = username,
                RequesterIpAddress = ip,
                ResourceType = req.ResourceType,
                ResourceId = req.ResourceId,
                ResourceName = req.ResourceName ?? string.Empty,
                Reason = req.Reason.Trim(),
                RequestedDurationMinutes = req.DurationMinutes,
                Status = JitAccessStatus.Pending
            };

            db.JitAccessRequests.Add(jit);
            await db.SaveChangesAsync();

            _ = audit.LogAsync("JIT", "JitAccessRequested", userId, username, ip,
                req.ResourceType, req.ResourceId?.ToString(),
                new { durationMinutes = req.DurationMinutes, resourceName = req.ResourceName, reason = req.Reason });

            return Results.Ok(new { success = true, data = MapDto(jit) });
        });

        // GET /api/v1/jit/requests — list all requests (admin)
        grp.MapGet("/requests", async (OrkunPamDbContext db,
            string? status = null, int page = 1, int pageSize = 50) =>
        {
            var query = db.JitAccessRequests.AsQueryable();
            if (!string.IsNullOrEmpty(status) && Enum.TryParse<JitAccessStatus>(status, out var parsedStatus))
                query = query.Where(r => r.Status == parsedStatus);

            var total = await query.CountAsync();
            var items = await query
                .OrderByDescending(r => r.CreatedAtUtc)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = items.Select(MapDto),
                meta = new { page, pageSize, totalCount = total }
            });
        });

        // GET /api/v1/jit/requests/active — active sessions for dashboard
        grp.MapGet("/requests/active", async (OrkunPamDbContext db) =>
        {
            var now = DateTime.UtcNow;
            var items = await db.JitAccessRequests
                .Where(r => r.Status == JitAccessStatus.Active)
                .OrderBy(r => r.ExpiresAtUtc)
                .ToListAsync();

            return Results.Ok(new { success = true, data = items.Select(MapDto) });
        });

        // GET /api/v1/jit/requests/my — caller's own requests
        grp.MapGet("/requests/my", async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            if (!Guid.TryParse(ctx.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
                return Results.Unauthorized();

            var items = await db.JitAccessRequests
                .Where(r => r.RequesterId == userId)
                .OrderByDescending(r => r.CreatedAtUtc)
                .ToListAsync();

            return Results.Ok(new { success = true, data = items.Select(MapDto) });
        });

        // POST /api/v1/jit/requests/{id}/approve
        grp.MapPost("/requests/{id:guid}/approve", async (Guid id, OrkunPamDbContext db,
            HttpContext ctx, IAuditService audit) =>
        {
            var req = await db.JitAccessRequests.FindAsync(id);
            if (req == null) return Results.NotFound();
            if (req.Status != JitAccessStatus.Pending)
                return Results.BadRequest(new { success = false, error = "Request is not in Pending state." });

            var adminIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(adminIdStr, out var adminId);
            var adminName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var now = DateTime.UtcNow;
            req.Status = JitAccessStatus.Active;
            req.ApprovedAtUtc = now;
            req.ApprovedByUserId = adminId;
            req.ApprovedByUsername = adminName;
            req.ActivatedAtUtc = now;
            req.ExpiresAtUtc = now.AddMinutes(req.RequestedDurationMinutes);

            await db.SaveChangesAsync();

            _ = audit.LogAsync("JIT", "JitAccessApproved", adminId, adminName, ip,
                req.ResourceType, req.ResourceId?.ToString(),
                new { requesterId = req.RequesterId, requesterUsername = req.RequesterUsername,
                      durationMinutes = req.RequestedDurationMinutes, expiresAt = req.ExpiresAtUtc });

            return Results.Ok(new { success = true, data = MapDto(req) });
        });

        // POST /api/v1/jit/requests/{id}/deny
        grp.MapPost("/requests/{id:guid}/deny", async (Guid id, JitDenyBody body,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var req = await db.JitAccessRequests.FindAsync(id);
            if (req == null) return Results.NotFound();
            if (req.Status != JitAccessStatus.Pending)
                return Results.BadRequest(new { success = false, error = "Request is not in Pending state." });

            var adminIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(adminIdStr, out var adminId);
            var adminName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            req.Status = JitAccessStatus.Denied;
            req.DenyReason = body.Reason;
            req.ApprovedByUserId = adminId;
            req.ApprovedByUsername = adminName;

            await db.SaveChangesAsync();

            _ = audit.LogAsync("JIT", "JitAccessDenied", adminId, adminName, ip,
                req.ResourceType, req.ResourceId?.ToString(),
                new { requesterId = req.RequesterId, reason = body.Reason });

            return Results.Ok(new { success = true });
        });

        // POST /api/v1/jit/requests/{id}/revoke
        grp.MapPost("/requests/{id:guid}/revoke", async (Guid id, JitRevokeBody body,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var req = await db.JitAccessRequests.FindAsync(id);
            if (req == null) return Results.NotFound();
            if (req.Status != JitAccessStatus.Active)
                return Results.BadRequest(new { success = false, error = "Request is not Active." });

            var adminIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(adminIdStr, out var adminId);
            var adminName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            req.Status = JitAccessStatus.Revoked;
            req.RevokeReason = body.Reason;
            req.RevokedByUserId = adminId;
            req.RevokedByUsername = adminName;

            await db.SaveChangesAsync();

            _ = audit.LogAsync("JIT", "JitAccessRevoked", adminId, adminName, ip,
                req.ResourceType, req.ResourceId?.ToString(),
                new { requesterId = req.RequesterId, reason = body.Reason });

            return Results.Ok(new { success = true });
        });

        // POST /api/v1/jit/requests/{id}/extend
        grp.MapPost("/requests/{id:guid}/extend", async (Guid id, JitExtendBody body,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var req = await db.JitAccessRequests.FindAsync(id);
            if (req == null) return Results.NotFound();
            if (req.Status != JitAccessStatus.Active)
                return Results.BadRequest(new { success = false, error = "Request is not Active." });
            if (req.ExtensionRequested)
                return Results.BadRequest(new { success = false, error = "Extension already requested." });

            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(userIdStr, out var userId);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            req.ExtensionRequested = true;
            req.ExtensionRequestedMinutes = body.AdditionalMinutes;
            req.ExtensionReason = body.Reason;

            await db.SaveChangesAsync();

            _ = audit.LogAsync("JIT", "JitExtensionRequested", userId, username, ip,
                req.ResourceType, req.ResourceId?.ToString(),
                new { additionalMinutes = body.AdditionalMinutes, reason = body.Reason });

            return Results.Ok(new { success = true, message = "Extension request submitted. Awaiting admin approval." });
        });

        // POST /api/v1/jit/requests/{id}/approve-extension — admin approves extension
        grp.MapPost("/requests/{id:guid}/approve-extension", async (Guid id,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var req = await db.JitAccessRequests.FindAsync(id);
            if (req == null) return Results.NotFound();
            if (req.Status != JitAccessStatus.Active || !req.ExtensionRequested)
                return Results.BadRequest(new { success = false, error = "No pending extension request." });

            var adminIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(adminIdStr, out var adminId);
            var adminName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var extraMinutes = req.ExtensionRequestedMinutes ?? 60;
            req.ExpiresAtUtc = (req.ExpiresAtUtc ?? DateTime.UtcNow).AddMinutes(extraMinutes);
            req.ExtensionRequested = false;

            await db.SaveChangesAsync();

            _ = audit.LogAsync("JIT", "JitExtensionApproved", adminId, adminName, ip,
                req.ResourceType, req.ResourceId?.ToString(),
                new { extraMinutes, newExpiry = req.ExpiresAtUtc });

            return Results.Ok(new { success = true, data = MapDto(req) });
        });
    }

    private static object MapDto(JitAccessRequest r) => new
    {
        Id = r.Id.ToString(),
        r.RequesterUsername,
        r.RequesterIpAddress,
        r.ResourceType,
        ResourceId = r.ResourceId?.ToString(),
        r.ResourceName,
        r.Reason,
        r.RequestedDurationMinutes,
        Status = r.Status.ToString(),
        r.CreatedAtUtc,
        r.ApprovedAtUtc,
        r.ApprovedByUsername,
        r.ActivatedAtUtc,
        r.ExpiresAtUtc,
        r.DenyReason,
        r.RevokeReason,
        r.RevokedByUsername,
        r.ExtensionRequested,
        r.ExtensionRequestedMinutes,
        r.ExtensionReason
    };
}

public record JitAccessRequestBody(
    string ResourceType,
    Guid? ResourceId,
    string? ResourceName,
    string Reason,
    int DurationMinutes);

public record JitDenyBody(string? Reason);
public record JitRevokeBody(string? Reason);
public record JitExtendBody(int AdditionalMinutes, string? Reason);
