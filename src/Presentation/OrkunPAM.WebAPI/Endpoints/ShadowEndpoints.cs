using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Persistence;
using OrkunPAM.WebAPI.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ShadowEndpoints
{
    public static void MapShadowEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/sessions")
            .WithTags("Sessions")
            .RequireAuthorization("AdminPolicy");

        // Start shadowing a session — creates SessionShadow record + increments observer count
        group.MapPost("/{id:guid}/shadow", async (
            Guid id, OrkunPamDbContext db, SessionChunkStore chunks,
            IAuditService audit, HttpContext ctx) =>
        {
            var session = await db.ProxySessions.FindAsync(id);
            if (session == null)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            var userId   = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip       = ctx.Connection.RemoteIpAddress?.ToString();
            if (userId == null || !Guid.TryParse(userId, out var uid))
                return Results.Unauthorized();

            // Close any existing active shadow for this user+session (idempotent)
            var existing = await db.SessionShadows
                .Where(s => s.SessionId == id && s.ShadowByUserId == uid && s.IsActive)
                .FirstOrDefaultAsync();
            if (existing != null)
            {
                existing.IsActive    = false;
                existing.EndedAtUtc  = DateTime.UtcNow;
                chunks.DecrementObservers(id);
            }

            var shadow = new SessionShadow
            {
                SessionId        = id,
                ShadowByUserId   = uid,
                ShadowByUsername = username,
                ShadowIp         = ip
            };
            db.SessionShadows.Add(shadow);
            chunks.IncrementObservers(id);

            // Inject "being monitored" banner into the live stream so observers can see it
            var banner = $"\r\n\x1b[36m[PAM] Session is now being monitored by {username ?? "an admin"}.\x1b[0m\r\n";
            chunks.Append(id, banner);

            await db.SaveChangesAsync();

            if (Guid.TryParse(userId, out var actorGuid))
                await audit.LogAsync("Session", "SESSION_SHADOW_STARTED", actorGuid, username, ip,
                    "ProxySession", id.ToString(),
                    $"Shadow started for session {id}");

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    shadowId     = shadow.Id,
                    sessionId    = id,
                    streamUrl    = $"/api/v1/sessions/live/{id}/stream",
                    statusUrl    = $"/api/v1/sessions/live/{id}/status",
                    terminateUrl = $"/api/v1/sessions/{id}/terminate",
                    startedAtUtc = shadow.StartedAtUtc
                }
            });
        });

        // Stop shadowing a session
        group.MapDelete("/{id:guid}/shadow", async (
            Guid id, OrkunPamDbContext db, SessionChunkStore chunks,
            IAuditService audit, HttpContext ctx) =>
        {
            var userId   = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip       = ctx.Connection.RemoteIpAddress?.ToString();
            if (userId == null || !Guid.TryParse(userId, out var uid))
                return Results.Unauthorized();

            var shadow = await db.SessionShadows
                .Where(s => s.SessionId == id && s.ShadowByUserId == uid && s.IsActive)
                .FirstOrDefaultAsync();

            if (shadow != null)
            {
                shadow.IsActive   = false;
                shadow.EndedAtUtc = DateTime.UtcNow;
                chunks.DecrementObservers(id);
                await db.SaveChangesAsync();

                if (Guid.TryParse(userId, out var actorGuid2))
                    await audit.LogAsync("Session", "SESSION_SHADOW_ENDED", actorGuid2, username, ip,
                        "ProxySession", id.ToString(),
                        $"Shadow ended for session {id}");
            }

            return Results.Ok(new { success = true });
        });

        // List active shadows for a session (admin oversight)
        group.MapGet("/{id:guid}/shadows", async (Guid id, OrkunPamDbContext db) =>
        {
            var shadows = await db.SessionShadows
                .Where(s => s.SessionId == id && s.IsActive)
                .OrderBy(s => s.StartedAtUtc)
                .Select(s => new
                {
                    s.Id,
                    s.ShadowByUserId,
                    s.ShadowByUsername,
                    s.StartedAtUtc,
                    s.ShadowIp
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = shadows, meta = new { count = shadows.Count } });
        });

        // Admin revokes all active shadows for a session
        group.MapPost("/{id:guid}/shadow/revoke-all", async (
            Guid id, OrkunPamDbContext db, SessionChunkStore chunks,
            IAuditService audit, HttpContext ctx) =>
        {
            var userId   = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip       = ctx.Connection.RemoteIpAddress?.ToString();

            var actives = await db.SessionShadows
                .Where(s => s.SessionId == id && s.IsActive)
                .ToListAsync();

            foreach (var s in actives)
            {
                s.IsActive   = false;
                s.EndedAtUtc = DateTime.UtcNow;
                chunks.DecrementObservers(id);
            }

            if (actives.Count > 0)
            {
                await db.SaveChangesAsync();
                if (Guid.TryParse(userId, out var actorGuid))
                    await audit.LogAsync("Session", "SESSION_SHADOW_REVOKED", actorGuid, username, ip,
                        "ProxySession", id.ToString(),
                        $"All shadows revoked for session {id} ({actives.Count} observer(s))");
            }

            return Results.Ok(new { success = true, revokedCount = actives.Count });
        });
    }
}