using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.WebAPI.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SessionHandoffEndpoints
{
    public static void MapSessionHandoffEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/sessions")
            .WithTags("Sessions")
            .RequireAuthorization("AdminPolicy");

        // Request a handoff of an active session to another admin
        group.MapPost("/{id:guid}/handoff", async (
            Guid id,
            HandoffRequestBody body,
            OrkunPamDbContext db,
            SessionChunkStore chunks,
            IAuditService audit,
            HttpContext ctx) =>
        {
            var userId   = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip       = ctx.Connection.RemoteIpAddress?.ToString();
            if (!Guid.TryParse(userId, out var uid)) return Results.Unauthorized();

            var session = await db.ProxySessions.FindAsync(id);
            if (session is null)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            if (session.Status != SessionStatus.Active)
                return Results.BadRequest(new { success = false, errors = new[] { "Session is not active" } });

            // Resolve target user
            var targetUser = await db.Users.FindAsync(body.TargetUserId);
            if (targetUser is null)
                return Results.BadRequest(new { success = false, errors = new[] { "Target user not found" } });

            // Cancel any pending handoff for this session (one at a time)
            var existing = await db.SessionHandoffs
                .Where(h => h.SessionId == id && h.Status == "Pending")
                .ToListAsync();
            foreach (var h in existing)
                h.Status = "Expired";

            var handoff = new SessionHandoff
            {
                SessionId           = id,
                RequestedByUserId   = uid,
                RequestedByUsername = username,
                RequestedToUserId   = body.TargetUserId,
                RequestedToUsername = targetUser.Username,
                TransferNotes       = body.Notes?.Trim()
            };
            db.SessionHandoffs.Add(handoff);

            // Notify via live stream
            var banner = $"\r\n\x1b[33m[PAM] Session handoff requested by {username ?? "admin"} → {targetUser.Username}. Awaiting acceptance.\x1b[0m\r\n";
            chunks.Append(id, banner);

            await db.SaveChangesAsync();
            await audit.LogAsync("Session", "SESSION_HANDOFF_REQUESTED", uid, username, ip,
                $"Handoff requested for session {id} → user {targetUser.Username}", id.ToString());

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    handoffId       = handoff.Id,
                    sessionId       = id,
                    requestedToUser = targetUser.Username,
                    expiresAtUtc    = handoff.ExpiresAtUtc,
                    status          = handoff.Status
                }
            });
        });

        // Accept a pending handoff (called by the target admin)
        group.MapPost("/{id:guid}/handoff/accept", async (
            Guid id,
            HandoffActionBody body,
            OrkunPamDbContext db,
            SessionChunkStore chunks,
            IAuditService audit,
            HttpContext ctx) =>
        {
            var userId   = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip       = ctx.Connection.RemoteIpAddress?.ToString();
            if (!Guid.TryParse(userId, out var uid)) return Results.Unauthorized();

            var handoff = await db.SessionHandoffs
                .Where(h => h.Id == body.HandoffId && h.SessionId == id && h.RequestedToUserId == uid)
                .FirstOrDefaultAsync();

            if (handoff is null)
                return Results.NotFound(new { success = false, errors = new[] { "Handoff request not found" } });

            if (handoff.Status != "Pending")
                return Results.BadRequest(new { success = false, errors = new[] { $"Handoff is {handoff.Status}" } });

            // Expire stale handoffs before checking TTL
            if (handoff.ExpiresAtUtc < DateTime.UtcNow)
            {
                handoff.Status = "Expired";
                await db.SaveChangesAsync();
                return Results.BadRequest(new { success = false, errors = new[] { "Handoff request has expired" } });
            }

            // Transfer session ownership in DB
            var session = await db.ProxySessions.FindAsync(id);
            if (session is not null)
                session.UserId = uid;

            handoff.Status        = "Accepted";
            handoff.AcceptedAtUtc = DateTime.UtcNow;

            // Notify live stream: transfer complete
            var banner = $"\r\n\x1b[32m[PAM] Session ownership transferred to {username ?? "admin"}. Original owner disconnected from PAM audit.\x1b[0m\r\n";
            chunks.Append(id, banner);

            await db.SaveChangesAsync();

            await audit.LogAsync("Session", "SESSION_HANDOFF_ACCEPTED", uid, username, ip,
                $"Handoff accepted for session {id} (from {handoff.RequestedByUsername})", id.ToString());
            await audit.LogAsync("Session", "SESSION_TRANSFERRED", uid, username, ip,
                $"Session {id} ownership transferred from {handoff.RequestedByUsername} to {username}", id.ToString());

            return Results.Ok(new
            {
                success = true,
                data = new { sessionId = id, newOwner = username, transferredAtUtc = handoff.AcceptedAtUtc }
            });
        });

        // Decline a pending handoff
        group.MapPost("/{id:guid}/handoff/decline", async (
            Guid id,
            HandoffActionBody body,
            OrkunPamDbContext db,
            IAuditService audit,
            HttpContext ctx) =>
        {
            var userId   = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            var ip       = ctx.Connection.RemoteIpAddress?.ToString();
            if (!Guid.TryParse(userId, out var uid)) return Results.Unauthorized();

            var handoff = await db.SessionHandoffs
                .Where(h => h.Id == body.HandoffId && h.SessionId == id && h.RequestedToUserId == uid)
                .FirstOrDefaultAsync();

            if (handoff is null)
                return Results.NotFound(new { success = false, errors = new[] { "Handoff request not found" } });

            if (handoff.Status != "Pending")
                return Results.BadRequest(new { success = false, errors = new[] { $"Handoff is {handoff.Status}" } });

            handoff.Status = "Declined";
            await db.SaveChangesAsync();

            await audit.LogAsync("Session", "SESSION_HANDOFF_DECLINED", uid, username, ip,
                $"Handoff declined for session {id} (requested by {handoff.RequestedByUsername})", id.ToString());

            return Results.Ok(new { success = true });
        });

        // List pending handoffs targeting the current user
        group.MapGet("/handoff/pending", async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(userId, out var uid)) return Results.Unauthorized();

            var now = DateTime.UtcNow;

            // Expire overdue entries
            var stale = await db.SessionHandoffs
                .Where(h => h.Status == "Pending" && h.ExpiresAtUtc < now)
                .ToListAsync();
            if (stale.Count > 0)
            {
                foreach (var h in stale) h.Status = "Expired";
                await db.SaveChangesAsync();
            }

            var pending = await db.SessionHandoffs
                .Where(h => h.RequestedToUserId == uid && h.Status == "Pending")
                .OrderBy(h => h.RequestedAtUtc)
                .Select(h => new
                {
                    h.Id,
                    h.SessionId,
                    h.RequestedByUsername,
                    h.RequestedAtUtc,
                    h.ExpiresAtUtc,
                    h.TransferNotes
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = pending, meta = new { count = pending.Count } });
        });

        // List all handoffs for a session (admin oversight)
        group.MapGet("/{id:guid}/handoffs", async (Guid id, OrkunPamDbContext db) =>
        {
            var handoffs = await db.SessionHandoffs
                .Where(h => h.SessionId == id)
                .OrderByDescending(h => h.RequestedAtUtc)
                .Select(h => new
                {
                    h.Id,
                    h.RequestedByUsername,
                    h.RequestedToUsername,
                    h.RequestedAtUtc,
                    h.AcceptedAtUtc,
                    h.Status,
                    h.TransferNotes,
                    h.ExpiresAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = handoffs, meta = new { count = handoffs.Count } });
        });
    }
}

public record HandoffRequestBody(Guid TargetUserId, string? Notes);
public record HandoffActionBody(Guid HandoffId);
