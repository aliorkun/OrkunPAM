using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SessionRestorationEndpoints
{
    private const int RestoreWindowMinutes = 15;

    private static bool ValidateProxySecret(IConfiguration config, HttpContext ctx)
    {
        var secret = config["ProxyService:Secret"] ?? "";
        if (secret.Length < 32) return false;
        var header = ctx.Request.Headers["X-Proxy-Secret"].FirstOrDefault() ?? "";
        var secretBytes = Encoding.UTF8.GetBytes(secret);
        var headerBytes = Encoding.UTF8.GetBytes(header);
        return CryptographicOperations.FixedTimeEquals(secretBytes, headerBytes);
    }

    public static void MapSessionRestorationEndpoints(this IEndpointRouteBuilder app)
    {
        // ── Proxy-facing: mark session as disconnected + issue restore token ──────
        // Called by SSH/RDP/VNC proxy on unexpected disconnect (not planned exit).
        app.MapPost("/api/v1/sessions/{id:guid}/mark-disconnected",
            async (Guid id, OrkunPamDbContext db, IConfiguration config, HttpContext ctx) =>
        {
            if (!ValidateProxySecret(config, ctx))
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

            // Re-check current authorization (CWE-285): user account must still be active
            var user = await db.Users.FindAsync(userId);
            if (user is null || user.Status != UserStatus.Active)
                return Results.Forbid();

            // Re-check credential is still assigned to this user (direct or via group)
            var credentialId = token.CredentialId ?? original.CredentialId;
            if (credentialId != Guid.Empty)
            {
                var userGroupIds = await db.UserGroups
                    .Where(ug => ug.UserId == userId)
                    .Select(ug => ug.GroupId)
                    .ToListAsync();

                var hasAccess = await db.AssignedCredentials
                    .AnyAsync(a => a.CredentialId == credentialId && a.IsEnabled &&
                        ((a.PrincipalType == PrincipalType.User  && a.PrincipalId == userId) ||
                         (a.PrincipalType == PrincipalType.Group && userGroupIds.Contains(a.PrincipalId))));

                if (!hasAccess)
                    return Results.Forbid();
            }

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
                "ProxySession", newSession.Id.ToString(),
                $"Session restore initiated from token {tokenId} (original: {token.OriginalSessionId})");

            await audit.LogAsync("Session", "SESSION_RESTORE_COMPLETED", userId, username, ip,
                "ProxySession", newSession.Id.ToString(),
                $"New session {newSession.Id} created from restore token {tokenId}");

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
