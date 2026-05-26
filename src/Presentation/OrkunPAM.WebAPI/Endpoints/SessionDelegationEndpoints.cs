using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SessionDelegationEndpoints
{
    public static void MapSessionDelegationEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/sessions/delegations")
            .WithTags("Sessions")
            .RequireAuthorization("AdminPolicy");

        // Grant a delegation — SessionAdmin or GlobalAdmin only
        group.MapPost("", async (
            CreateDelegationBody body,
            OrkunPamDbContext db,
            IAuditService audit,
            HttpContext ctx) =>
        {
            var userId   = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip       = ctx.Connection.RemoteIpAddress?.ToString();
            if (!Guid.TryParse(userId, out var uid)) return Results.Unauthorized();

            if (body.DeviceId == null && body.DeviceGroupId == null)
                return Results.BadRequest(new { success = false, errors = new[] { "Either DeviceId or DeviceGroupId is required" } });

            if (body.ExpiresAtUtc <= DateTime.UtcNow)
                return Results.BadRequest(new { success = false, errors = new[] { "ExpiresAtUtc must be in the future" } });

            var delegateUser = await db.Users.FindAsync(body.DelegateUserId);
            if (delegateUser is null)
                return Results.BadRequest(new { success = false, errors = new[] { "Delegate user not found" } });

            var delegation = new SessionDelegation
            {
                DelegatorUserId   = uid,
                DelegatorUsername = username,
                DelegateUserId    = body.DelegateUserId,
                DelegateUsername  = delegateUser.Username,
                DeviceId          = body.DeviceId,
                DeviceGroupId     = body.DeviceGroupId,
                CredentialId      = body.CredentialId,
                ExpiresAtUtc      = body.ExpiresAtUtc,
                MaxSessionCount   = body.MaxSessionCount > 0 ? body.MaxSessionCount : 1,
                DelegationNote    = body.Note?.Trim()
            };
            db.SessionDelegations.Add(delegation);
            await db.SaveChangesAsync();

            await audit.LogAsync("Session", "SESSION_DELEGATION_GRANTED", uid, username, ip,
                "SessionDelegation", delegation.Id.ToString(),
                $"Delegation {delegation.Id} granted to {delegateUser.Username} — expires {body.ExpiresAtUtc:u}");

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    delegation.Id,
                    delegation.DelegateUserId,
                    delegation.DelegateUsername,
                    delegation.DeviceId,
                    delegation.DeviceGroupId,
                    delegation.CredentialId,
                    delegation.ExpiresAtUtc,
                    delegation.MaxSessionCount,
                    delegation.Status
                }
            });
        });

        // List all delegations (admin view — all) / user sees own
        group.MapGet("", async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(userId, out var uid)) return Results.Unauthorized();

            var now = DateTime.UtcNow;

            // Auto-expire stale Active delegations
            var stale = await db.SessionDelegations
                .Where(d => d.Status == "Active" && d.ExpiresAtUtc < now)
                .ToListAsync();
            if (stale.Count > 0)
            {
                foreach (var s in stale) s.Status = "Expired";
                await db.SaveChangesAsync();
            }

            var isGlobalAdmin = ctx.User.HasClaim("role", "GlobalAdmin");

            var query = isGlobalAdmin
                ? db.SessionDelegations.AsQueryable()
                : db.SessionDelegations.Where(d => d.DelegatorUserId == uid || d.DelegateUserId == uid);

            var list = await query
                .OrderByDescending(d => d.GrantedAtUtc)
                .Select(d => new
                {
                    d.Id,
                    d.DelegatorUsername,
                    d.DelegateUsername,
                    d.DeviceId,
                    d.DeviceGroupId,
                    d.CredentialId,
                    d.GrantedAtUtc,
                    d.ExpiresAtUtc,
                    d.RevokedAtUtc,
                    d.Status,
                    d.MaxSessionCount,
                    d.UsageCount,
                    d.DelegationNote
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { count = list.Count } });
        });

        // My delegations — received (as delegate) + granted (as delegator)
        group.MapGet("/my", async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(userId, out var uid)) return Results.Unauthorized();

            var now = DateTime.UtcNow;

            var received = await db.SessionDelegations
                .Where(d => d.DelegateUserId == uid && d.Status == "Active" && d.ExpiresAtUtc > now)
                .OrderBy(d => d.ExpiresAtUtc)
                .Select(d => new
                {
                    d.Id,
                    d.DelegatorUsername,
                    d.DeviceId,
                    d.DeviceGroupId,
                    d.CredentialId,
                    d.ExpiresAtUtc,
                    d.MaxSessionCount,
                    d.UsageCount,
                    d.DelegationNote
                })
                .ToListAsync();

            var granted = await db.SessionDelegations
                .Where(d => d.DelegatorUserId == uid)
                .OrderByDescending(d => d.GrantedAtUtc)
                .Take(50)
                .Select(d => new
                {
                    d.Id,
                    d.DelegateUsername,
                    d.DeviceId,
                    d.DeviceGroupId,
                    d.CredentialId,
                    d.GrantedAtUtc,
                    d.ExpiresAtUtc,
                    d.Status,
                    d.MaxSessionCount,
                    d.UsageCount
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = new { received, granted } });
        });

        // Revoke a delegation (delegator or GlobalAdmin)
        group.MapDelete("/{id:guid}", async (
            Guid id,
            OrkunPamDbContext db,
            IAuditService audit,
            HttpContext ctx) =>
        {
            var userId   = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip       = ctx.Connection.RemoteIpAddress?.ToString();
            if (!Guid.TryParse(userId, out var uid)) return Results.Unauthorized();

            var delegation = await db.SessionDelegations.FindAsync(id);
            if (delegation is null)
                return Results.NotFound(new { success = false, errors = new[] { "Delegation not found" } });

            var isGlobalAdmin = ctx.User.HasClaim("role", "GlobalAdmin");
            if (delegation.DelegatorUserId != uid && !isGlobalAdmin)
                return Results.Forbid();

            if (delegation.Status != "Active")
                return Results.BadRequest(new { success = false, errors = new[] { $"Delegation is already {delegation.Status}" } });

            delegation.Status      = "Revoked";
            delegation.RevokedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            await audit.LogAsync("Session", "SESSION_DELEGATION_REVOKED", uid, username, ip,
                "SessionDelegation", id.ToString(),
                $"Delegation {id} revoked (delegate: {delegation.DelegateUsername})");

            return Results.Ok(new { success = true });
        });

        // Check active delegation for a device (called at session-start authorization)
        group.MapGet("/check", async (
            Guid? deviceId,
            OrkunPamDbContext db,
            HttpContext ctx) =>
        {
            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(userId, out var uid)) return Results.Unauthorized();

            if (deviceId == null)
                return Results.BadRequest(new { success = false, errors = new[] { "deviceId is required" } });

            var now = DateTime.UtcNow;

            // Find any Active delegation for this user to this device (direct or via group)
            // Device group lookup is approximated: check delegations with the device's group
            // Full realm-based check is done by the session service; this is a fast pre-check.
            var active = await db.SessionDelegations
                .Where(d => d.DelegateUserId == uid
                         && d.Status == "Active"
                         && d.ExpiresAtUtc > now
                         && d.UsageCount < d.MaxSessionCount
                         && (d.DeviceId == deviceId || d.DeviceId == null))
                .OrderBy(d => d.ExpiresAtUtc)
                .FirstOrDefaultAsync();

            if (active == null)
                return Results.Ok(new { success = true, data = new { hasDelegation = false } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    hasDelegation  = true,
                    delegationId   = active.Id,
                    delegatorName  = active.DelegatorUsername,
                    credentialId   = active.CredentialId,
                    expiresAtUtc   = active.ExpiresAtUtc,
                    remainingUses  = active.MaxSessionCount - active.UsageCount
                }
            });
        });
    }
}

public record CreateDelegationBody(
    Guid      DelegateUserId,
    Guid?     DeviceId,
    Guid?     DeviceGroupId,
    Guid?     CredentialId,
    DateTime  ExpiresAtUtc,
    int       MaxSessionCount,
    string?   Note);
