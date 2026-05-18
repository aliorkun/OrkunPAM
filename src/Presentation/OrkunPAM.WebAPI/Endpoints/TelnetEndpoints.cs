using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class TelnetEndpoints
{
    public static void MapTelnetEndpoints(this IEndpointRouteBuilder app)
    {
        // ── Admin / UI endpoints (JWT + AdminPolicy) ──────────────────────

        var telnet = app.MapGroup("/api/v1/telnet")
            .WithTags("Telnet")
            .RequireAuthorization("AdminPolicy");

        // GET /api/v1/telnet/sessions — list active and recent Telnet sessions
        telnet.MapGet("/sessions", async (OrkunPamDbContext db, int page = 1, int pageSize = 50) =>
        {
            pageSize = Math.Clamp(pageSize, 1, 200);

            var sessions = await db.ProxySessions
                .Where(s => s.SessionType == SessionType.Telnet)
                .OrderByDescending(s => s.StartedAtUtc)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .Select(s => new
                {
                    s.Id,
                    s.UserId,
                    s.DeviceId,
                    s.ClientIpAddress,
                    s.TargetIpAddress,
                    s.TargetPort,
                    s.StartedAtUtc,
                    s.EndedAtUtc,
                    s.DurationSeconds,
                    Status = s.Status.ToString(),
                    s.RecordingSizeBytes
                })
                .ToListAsync();

            var total = await db.ProxySessions
                .CountAsync(s => s.SessionType == SessionType.Telnet);

            return Results.Ok(new
            {
                success = true,
                data = sessions,
                meta = new { page, pageSize, total }
            });
        });

        // DELETE /api/v1/telnet/sessions/{id} — admin terminate
        telnet.MapDelete("/sessions/{id:guid}", async (
            Guid id, TerminateReasonRequest? req, OrkunPamDbContext db, HttpContext context) =>
        {
            var session = await db.ProxySessions.FindAsync(id);
            if (session == null || session.SessionType != SessionType.Telnet)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            if (session.Status != SessionStatus.Active)
                return Results.BadRequest(new { success = false, errors = new[] { "Session is not active" } });

            session.Terminate(Guid.Empty, req?.Reason ?? "Admin terminated via UI");
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, data = new { terminated = true } });
        });

        // ── Proxy-internal endpoints (X-Proxy-Secret, AllowAnonymous) ─────

        // POST /api/v1/telnet/proxy/session-start — register a new Telnet session
        app.MapPost("/api/v1/telnet/proxy/session-start",
            async (TelnetSessionStartRequest req, OrkunPamDbContext db,
                   IConfiguration config, HttpContext context) =>
        {
            if (!ValidateProxySecret(context, config)) return Results.Unauthorized();

            var session = new ProxySession
            {
                SessionType    = SessionType.Telnet,
                ClientIpAddress = req.ClientIp,
                TargetIpAddress = req.TargetIp,
                TargetPort      = req.TargetPort,
                Status          = SessionStatus.Active,
                HasKeystrokeLog = true
            };

            // Map user/device/credential IDs if provided
            if (Guid.TryParse(req.UserId,       out var uid))  session.UserId       = uid;
            if (Guid.TryParse(req.DeviceId,     out var did))  session.DeviceId     = did;
            if (Guid.TryParse(req.CredentialId, out var crid)) session.CredentialId = crid;

            db.ProxySessions.Add(session);
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                success = true,
                data = new { sessionId = session.Id.ToString() }
            });
        }).WithTags("Telnet").AllowAnonymous();

        // POST /api/v1/telnet/proxy/session-end — close session + store recording
        app.MapPost("/api/v1/telnet/proxy/session-end",
            async (TelnetSessionEndRequest req, OrkunPamDbContext db,
                   IConfiguration config, HttpContext context, ILogger<Program> logger) =>
        {
            if (!ValidateProxySecret(context, config)) return Results.Unauthorized();

            if (!Guid.TryParse(req.SessionId, out var sessionId))
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid sessionId" } });

            var session = await db.ProxySessions.FindAsync(sessionId);
            if (session == null)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            if (session.Status == SessionStatus.Active)
            {
                session.EndedAtUtc      = DateTime.UtcNow;
                session.DurationSeconds = req.DurationSeconds;
                session.Status          = SessionStatus.Completed;
            }

            // Persist recording to disk
            if (!string.IsNullOrEmpty(req.RecordingBase64))
            {
                try
                {
                    var bytes = Convert.FromBase64String(req.RecordingBase64);
                    var dir   = Path.Combine("recordings", "telnet");
                    Directory.CreateDirectory(dir);
                    var path = Path.Combine(dir, $"{sessionId}.telnet.rec");
                    await File.WriteAllBytesAsync(path, bytes);
                    session.RecordingPath      = path;
                    session.RecordingSizeBytes = bytes.Length;
                    logger.LogInformation("Telnet recording saved: {Path} ({Bytes} bytes)", path, bytes.Length);
                }
                catch (Exception ex)
                {
                    logger.LogWarning(ex, "Failed to save Telnet recording for session {Id}", sessionId);
                }
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        }).WithTags("Telnet").AllowAnonymous();

        // GET /api/v1/telnet/proxy/sessions/{id}/status — proxy polls for termination
        app.MapGet("/api/v1/telnet/proxy/sessions/{id:guid}/status",
            async (Guid id, OrkunPamDbContext db, IConfiguration config, HttpContext context) =>
        {
            if (!ValidateProxySecret(context, config)) return Results.Unauthorized();

            var session = await db.ProxySessions
                .Where(s => s.Id == id && s.SessionType == SessionType.Telnet)
                .Select(s => new { s.Status })
                .FirstOrDefaultAsync();

            if (session == null) return Results.NotFound();

            return Results.Ok(new
            {
                success = true,
                data = new { terminated = session.Status == SessionStatus.Terminated }
            });
        }).WithTags("Telnet").AllowAnonymous();
    }

    private static bool ValidateProxySecret(HttpContext context, IConfiguration config)
    {
        var expected = config["ProxyService:Secret"] ?? config["PamApi:ProxySecret"] ?? "";
        if (expected.Length < 32) return false;
        var provided = context.Request.Headers["X-Proxy-Secret"].FirstOrDefault() ?? "";
        return provided == expected;
    }

    private sealed record TelnetSessionStartRequest(
        string? UserId, string? DeviceId, string? CredentialId,
        string ClientIp, string TargetIp, int TargetPort, string? SessionType);

    private sealed record TelnetSessionEndRequest(
        string SessionId, int DurationSeconds, string? RecordingBase64);

    private sealed record TerminateReasonRequest(string? Reason);
}
