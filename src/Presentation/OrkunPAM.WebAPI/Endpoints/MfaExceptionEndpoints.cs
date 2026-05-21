using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class MfaExceptionEndpoints
{
    private const int MaxExpiryHours = 72;

    public static void MapMfaExceptionEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/api/v1/mfa/exceptions")
            .WithTags("MfaExceptions")
            .RequireAuthorization("AdminPolicy");

        // List all exceptions
        admin.MapGet("/", async (OrkunPamDbContext db, string? status) =>
        {
            var query = db.MfaExceptions.Include(e => e.User).AsQueryable();
            if (!string.IsNullOrEmpty(status) && Enum.TryParse<MfaExceptionStatus>(status, true, out var s))
                query = query.Where(e => e.Status == s);

            var list = await query
                .OrderByDescending(e => e.CreatedAtUtc)
                .Select(e => new
                {
                    id                = e.Id,
                    userId            = e.UserId,
                    username          = e.User.Username,
                    displayName       = e.User.DisplayName,
                    requestedByUserId = e.RequestedByUserId,
                    approvedByUserId  = e.ApprovedByUserId,
                    reason            = e.Reason,
                    status            = e.Status.ToString(),
                    expiresAtUtc      = e.ExpiresAtUtc,
                    revokedAtUtc      = e.RevokedAtUtc,
                    maxUsageCount     = e.MaxUsageCount,
                    usageCount        = e.UsageCount,
                    ipCidrRestriction = e.IpCidrRestriction,
                    createdAtUtc      = e.CreatedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = list });
        });

        // Admin directly creates + approves an exception (no pending step)
        admin.MapPost("/", async (CreateMfaExceptionRequest req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (req.ExpiresInHours < 1 || req.ExpiresInHours > MaxExpiryHours)
                return Results.BadRequest(new { success = false, errors = new[] { $"ExpiresInHours must be 1–{MaxExpiryHours}" } });
            if (string.IsNullOrWhiteSpace(req.Reason))
                return Results.BadRequest(new { success = false, errors = new[] { "Reason is required" } });

            var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(actorStr, out var actorId))
                return Results.Unauthorized();

            if (!await db.Users.AnyAsync(u => u.Id == req.UserId && !u.IsDeleted))
                return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            var exc = new MfaException
            {
                UserId            = req.UserId,
                RequestedByUserId = actorId,
                ApprovedByUserId  = actorId,
                Reason            = req.Reason.Trim(),
                Status            = MfaExceptionStatus.Approved,
                ExpiresAtUtc      = DateTime.UtcNow.AddHours(req.ExpiresInHours),
                MaxUsageCount     = req.MaxUsageCount < 1 ? 1 : req.MaxUsageCount,
                IpCidrRestriction = req.IpCidrRestriction?.Trim()
            };
            db.MfaExceptions.Add(exc);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("MfaException", "MFA_EXCEPTION_CREATED", actorId, null, ip,
                "MfaException", exc.Id.ToString(), new { exc.UserId, exc.ExpiresAtUtc, exc.MaxUsageCount });

            return Results.Created($"/api/v1/mfa/exceptions/{exc.Id}", new { success = true, data = new { exc.Id } });
        });

        // Approve a pending exception
        admin.MapPut("/{id:guid}/approve", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var exc = await db.MfaExceptions.FindAsync(id);
            if (exc == null) return Results.NotFound();
            if (exc.Status != MfaExceptionStatus.Pending)
                return Results.BadRequest(new { success = false, errors = new[] { "Exception is not in Pending state" } });

            var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(actorStr, out var actorId);

            exc.Status           = MfaExceptionStatus.Approved;
            exc.ApprovedByUserId = actorId;
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("MfaException", "MFA_EXCEPTION_APPROVED", actorId, null, ip,
                "MfaException", id.ToString(), new { exc.UserId });

            return Results.Ok(new { success = true });
        });

        // Deny a pending exception
        admin.MapPut("/{id:guid}/deny", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var exc = await db.MfaExceptions.FindAsync(id);
            if (exc == null) return Results.NotFound();
            if (exc.Status != MfaExceptionStatus.Pending)
                return Results.BadRequest(new { success = false, errors = new[] { "Exception is not in Pending state" } });

            var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(actorStr, out var actorId);

            exc.Status = MfaExceptionStatus.Denied;
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("MfaException", "MFA_EXCEPTION_DENIED", actorId, null, ip,
                "MfaException", id.ToString(), new { exc.UserId });

            return Results.Ok(new { success = true });
        });

        // Revoke an approved exception
        admin.MapDelete("/{id:guid}/revoke", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var exc = await db.MfaExceptions.FindAsync(id);
            if (exc == null) return Results.NotFound();
            if (exc.Status != MfaExceptionStatus.Approved)
                return Results.BadRequest(new { success = false, errors = new[] { "Only approved exceptions can be revoked" } });

            var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(actorStr, out var actorId);

            exc.Status       = MfaExceptionStatus.Revoked;
            exc.RevokedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("MfaException", "MFA_EXCEPTION_REVOKED", actorId, null, ip,
                "MfaException", id.ToString(), new { exc.UserId });

            return Results.Ok(new { success = true });
        });

        // Self-service: user requests exception for themselves
        app.MapPost("/api/v1/mfa/exceptions/request",
            async (RequestMfaExceptionRequest req, OrkunPamDbContext db,
                IAuditService audit, HttpContext ctx) =>
            {
                var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (!Guid.TryParse(actorStr, out var actorId))
                    return Results.Unauthorized();

                if (string.IsNullOrWhiteSpace(req.Reason))
                    return Results.BadRequest(new { success = false, errors = new[] { "Reason is required" } });

                var expiresHours = Math.Clamp(req.ExpiresInHours, 1, MaxExpiryHours);

                var exc = new MfaException
                {
                    UserId            = actorId,
                    RequestedByUserId = actorId,
                    Reason            = req.Reason.Trim(),
                    Status            = MfaExceptionStatus.Pending,
                    ExpiresAtUtc      = DateTime.UtcNow.AddHours(expiresHours),
                    MaxUsageCount     = 1
                };
                db.MfaExceptions.Add(exc);
                await db.SaveChangesAsync();

                var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
                await audit.LogAsync("MfaException", "MFA_EXCEPTION_REQUESTED", actorId, null, ip,
                    "MfaException", exc.Id.ToString(), new { exc.ExpiresAtUtc });

                return Results.Created($"/api/v1/mfa/exceptions/{exc.Id}",
                    new { success = true, message = "Exception request submitted. Pending admin approval.", data = new { exc.Id } });
            })
            .RequireAuthorization()
            .WithTags("MfaExceptions");

        // Self-service: my active exceptions
        app.MapGet("/api/v1/mfa/exceptions/my",
            async (OrkunPamDbContext db, HttpContext ctx) =>
            {
                var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (!Guid.TryParse(actorStr, out var userId))
                    return Results.Unauthorized();

                var list = await db.MfaExceptions
                    .Where(e => e.UserId == userId)
                    .OrderByDescending(e => e.CreatedAtUtc)
                    .Select(e => new
                    {
                        id            = e.Id,
                        reason        = e.Reason,
                        status        = e.Status.ToString(),
                        expiresAtUtc  = e.ExpiresAtUtc,
                        maxUsageCount = e.MaxUsageCount,
                        usageCount    = e.UsageCount,
                        createdAtUtc  = e.CreatedAtUtc
                    })
                    .ToListAsync();

                return Results.Ok(new { success = true, data = list });
            })
            .RequireAuthorization()
            .WithTags("MfaExceptions");
    }
}

public record CreateMfaExceptionRequest(Guid UserId, string Reason, int ExpiresInHours, int MaxUsageCount, string? IpCidrRestriction);
public record RequestMfaExceptionRequest(string Reason, int ExpiresInHours);
