using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.WebAPI.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class LiveSessionEndpoints
{
    public static void MapLiveSessionEndpoints(this IEndpointRouteBuilder app)
    {
        var live = app.MapGroup("/api/v1/sessions/live")
            .WithTags("Sessions")
            .RequireAuthorization("AdminPolicy");

        // Active sessions list for live monitor dashboard
        live.MapGet("/", async (OrkunPamDbContext db, SessionChunkStore chunks) =>
        {
            var active = await db.ProxySessions
                .Where(s => s.Status == SessionStatus.Active)
                .OrderBy(s => s.StartedAtUtc)
                .Select(s => new
                {
                    s.Id,
                    s.UserId,
                    s.DeviceId,
                    Type = s.SessionType.ToString(),
                    s.StartedAtUtc,
                    DurationMinutes = (int)(DateTime.UtcNow - s.StartedAtUtc).TotalMinutes,
                    s.ClientIpAddress,
                    s.TargetIpAddress,
                    s.TargetPort,
                    s.RiskScore,
                    s.Reason,
                    s.TicketNumber,
                    ObserverCount = chunks.GetObserverCount(s.Id)
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = active, meta = new { count = active.Count } });
        });

        // Per-session observer count + metadata
        live.MapGet("/{id:guid}/status", async (Guid id, OrkunPamDbContext db, SessionChunkStore chunks) =>
        {
            var s = await db.ProxySessions.FindAsync(id);
            if (s == null)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            var observers = await db.SessionObserverLogs
                .Where(o => o.SessionId == id && o.LeftAtUtc == null)
                .Select(o => new { o.ObserverUsername, o.JoinedAtUtc })
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    sessionId = id,
                    status = s.Status.ToString(),
                    sessionType = s.SessionType.ToString(),
                    startedAtUtc = s.StartedAtUtc,
                    targetIp = s.TargetIpAddress,
                    riskScore = s.RiskScore,
                    activeObservers = chunks.GetObserverCount(id),
                    observers
                }
            });
        });

        // Poll for new terminal output (offset-based paging to avoid re-sending old data)
        live.MapGet("/{id:guid}/stream", (Guid id, int offset, SessionChunkStore chunks) =>
        {
            var (text, newOffset) = chunks.Read(id, offset);
            return Results.Ok(new { success = true, data = new { text, newOffset } });
        });

        // Admin joins / starts observing a session -> audit log
        live.MapPost("/{id:guid}/join", async (Guid id, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var s = await db.ProxySessions.FindAsync(id);
            if (s == null)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name);
            if (userId == null || !Guid.TryParse(userId, out var uid))
                return Results.Unauthorized();

            // Close any existing open observation for this user+session
            var existing = await db.SessionObserverLogs
                .Where(o => o.SessionId == id && o.ObserverUserId == uid && o.LeftAtUtc == null)
                .FirstOrDefaultAsync();
            if (existing != null)
                existing.LeftAtUtc = DateTime.UtcNow;

            db.SessionObserverLogs.Add(new SessionObserverLog
            {
                SessionId = id,
                ObserverUserId = uid,
                ObserverUsername = username
            });
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, message = "Observation started" });
        });

        // Admin leaves / stops observing
        live.MapPost("/{id:guid}/leave", async (Guid id, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null || !Guid.TryParse(userId, out var uid))
                return Results.Unauthorized();

            var log = await db.SessionObserverLogs
                .Where(o => o.SessionId == id && o.ObserverUserId == uid && o.LeftAtUtc == null)
                .FirstOrDefaultAsync();
            if (log != null)
            {
                log.LeftAtUtc = DateTime.UtcNow;
                await db.SaveChangesAsync();
            }

            return Results.Ok(new { success = true });
        });

        // Admin broadcast message to session (injected into SSH/Telnet stream as a banner)
        live.MapPost("/{id:guid}/message", async (Guid id,
            BroadcastMessageRequest req, OrkunPamDbContext db,
            SessionChunkStore chunks, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Message) || req.Message.Length > 500)
                return Results.BadRequest(new { success = false, errors = new[] { "Message must be 1-500 characters" } });

            var s = await db.ProxySessions.FindAsync(id);
            if (s == null)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            var adminUser = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "Admin";

            // Inject visible banner into live stream buffer so admin observers can also see it
            var banner = $"\r\n\x1b[33m[PAM ADMIN MESSAGE from {adminUser}]: {req.Message}\x1b[0m\r\n";
            chunks.Append(id, banner);

            return Results.Ok(new { success = true, message = "Message broadcast" });
        });

        // Proxy-side chunk submission (X-Proxy-Secret, not JWT)
        app.MapPost("/api/v1/sessions/{id:guid}/live/chunk",
            (Guid id, LiveChunkRequest req, SessionChunkStore chunks,
             IConfiguration config, HttpContext ctx) =>
        {
            var secret = config["ProxyService:Secret"] ?? "";
            if (secret.Length < 32 || ctx.Request.Headers["X-Proxy-Secret"] != secret)
                return Results.Unauthorized();

            if (!string.IsNullOrEmpty(req.Text))
                chunks.Append(id, req.Text);

            return Results.Ok(new { success = true });
        }).WithTags("Sessions").AllowAnonymous();
    }
}

public record BroadcastMessageRequest(string Message);
public record LiveChunkRequest(string Text);
