using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SessionRestorationEndpoints
{
    private const int RestoreWindowMinutes = 15;

    public static void MapSessionRestorationEndpoints(this IEndpointRouteBuilder app)
    {
        // ── Proxy-facing: mark session as disconnected + issue restore token ──────
        // Called by SSH/RDP/VNC proxy on unexpected disconnect (not planned exit).
        app.MapPost("/api/v1/sessions/{id:guid}/mark-disconnected",
            async (Guid id, OrkunPamDbContext db, IConfiguration config, HttpContext ctx) =>
        {
            var secret = config["ProxyService:Secret"] ?? "";
            if (secret.Length < 32 || ctx.Request.Headers["X-Proxy-Secret"] != secret)
                return Results.Unauthorized();

            var session = await db.ProxySessions.FindAsync(id);
            if (session is null)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            if (session.Status != SessionStatus.Active)
                return Results.Ok(new { success = true, message = "Session already ended" });

            session.Disconnect();

            var token = new SessionRestoreToken
            {
                OriginalSessionId = id,
                UserId            = session.UserId,
                DeviceId          = session.DeviceId,
                CredentialId      = session.CredentialId,
                Protocol          = session.SessionType.ToString(),
                ExpiresAtUtc      = DateTime.UtcNow.AddMinutes(RestoreWindowMinutes)
            };
            db.SessionRestoreTokens.Add(token);
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, data = new { tokenId = token.Id, expiresAtUtc = token.ExpiresAtUtc } });
        }).WithTags("Sessions").AllowAnonymous();

        // ── User-facing: list restorable sessions (active tokens) ──────────────
        app.MapGet("/api/v1/sessions/restorable",
            async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            if (!Guid.TryParse(ctx.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
                return Results.Unauthorized();

            var now = DateTime.UtcNow;
            var tokens = await db.SessionRestoreTokens
                .Where(t => t.UserId == userId && !t.IsUsed && t.ExpiresAtUtc > now)
                .OrderByDescending(t => t.ExpiresAtUtc)
                .Select(t => new
                {
                    t.Id,
                    t.OriginalSessionId,
                    t.Protocol,
                    t.DeviceId,
                    t.CredentialId,
                    t.CreatedAtUtc,
                    t.ExpiresAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = tokens });
        }).WithTags("Sessions").RequireAuthorization();

        // ── Restore: reconnect using a restore token ──────────────────────────
        app.MapPost("/api/v1/sessions/restore/{tokenId:guid}",
            async (Guid tokenId, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            if (!Guid.TryParse(ctx.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
                return Results.Unauthorized();

            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip = ctx.Connection.RemoteIpAddress?.ToString();
            var now = DateTime.UtcNow;

            var token = await db.SessionRestoreTokens.FindAsync(tokenId);
            if (token is null || token.UserId != userId)
                return Results.NotFound(new { success = false, errors = new[] { "Restore token not found" } });

            if (token.IsUsed)
                return Results.Conflict(new { success = false, errors = new[] { "Restore token already used" } });

            if (token.ExpiresAtUtc <= now)
                return Results.BadRequest(new { success = false, errors = new[] { "Restore token has expired" } });

            // Validate the original session still exists
            var original = await db.ProxySessions.FindAsync(token.OriginalSessionId);
            if (original is null)
                return Results.NotFound(new { success = false, errors = new[] { "Original session not found" } });

            // Create new proxy session using original parameters
            var newSession = new ProxySession
            {
                UserId          = token.UserId,
                DeviceId        = token.DeviceId,
                CredentialId    = token.CredentialId ?? original.CredentialId,
                SessionType     = original.SessionType,
                SessionPolicyId = original.SessionPolicyId,
                ClientIpAddress = ip,
                TargetIpAddress = original.TargetIpAddress,
                TargetPort      = original.TargetPort,
                Reason          = $"Restored from session {token.OriginalSessionId}",
                Status          = SessionStatus.Active
            };
            db.ProxySessions.Add(newSession);

            token.IsUsed            = true;
            token.RestoredSessionId = newSession.Id;

            await db.SaveChangesAsync();

            await audit.LogAsync("Session", "SESSION_RESTORE_INITIATED", userId, username, ip,
                $"Session restore initiated from token {tokenId} (original: {token.OriginalSessionId})",
                newSession.Id.ToString());

            await audit.LogAsync("Session", "SESSION_RESTORE_COMPLETED", userId, username, ip,
                $"New session {newSession.Id} created from restore token {tokenId}",
                newSession.Id.ToString());

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    newSessionId    = newSession.Id,
                    protocol        = newSession.SessionType.ToString(),
                    targetIpAddress = newSession.TargetIpAddress,
                    targetPort      = newSession.TargetPort
                }
            });
        }).WithTags("Sessions").RequireAuthorization();

        // ── Cancel a restore token ────────────────────────────────────
        app.MapDelete("/api/v1/sessions/restore/{tokenId:guid}",
            async (Guid tokenId, OrkunPamDbContext db, HttpContext ctx) =>
        {
            if (!Guid.TryParse(ctx.User.FindFirstValue(ClaimTypes.NameIdentifier), out var userId))
                return Results.Unauthorized();

            var token = await db.SessionRestoreTokens.FindAsync(tokenId);
            if (token is null || token.UserId != userId)
                return Results.NotFound(new { success = false, errors = new[] { "Restore token not found" } });

            token.IsUsed = true; // mark consumed so cleanup skips it
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true });
        }).WithTags("Sessions").RequireAuthorization();
    }
}
