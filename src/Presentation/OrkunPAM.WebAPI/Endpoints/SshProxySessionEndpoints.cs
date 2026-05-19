using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SshProxySessionEndpoints
{
    public static void MapSshProxySessionEndpoints(this IEndpointRouteBuilder app)
    {
        // POST /api/v1/ssh/proxy/session-start — register a new SSH session in the DB
        app.MapPost("/api/v1/ssh/proxy/session-start",
            async (SshSessionStartRequest req, OrkunPamDbContext db,
                   IConfiguration config, HttpContext context, ILogger<Program> logger) =>
        {
            if (!ValidateProxySecret(context, config)) return Results.Unauthorized();

            var session = new ProxySession
            {
                SessionType     = SessionType.Ssh,
                ClientIpAddress = req.ClientIp,
                TargetIpAddress = req.TargetIp,
                TargetPort      = req.TargetPort,
                Status          = SessionStatus.Active,
                HasKeystrokeLog = false
            };

            if (Guid.TryParse(req.UserId,       out var uid))  session.UserId       = uid;
            if (Guid.TryParse(req.DeviceId,     out var did))  session.DeviceId     = did;
            if (Guid.TryParse(req.CredentialId, out var crid)) session.CredentialId = crid;

            db.ProxySessions.Add(session);
            await db.SaveChangesAsync();

            logger.LogInformation(
                "[AUDIT] SSH_SESSION_STARTED userId={UserId} deviceId={DeviceId} clientIp={ClientIp} targetIp={TargetIp}:{TargetPort} sessionId={SessionId}",
                req.UserId, req.DeviceId, req.ClientIp, req.TargetIp, req.TargetPort, session.Id);

            return Results.Ok(new { success = true, data = new { sessionId = session.Id.ToString() } });
        }).WithTags("SSH").AllowAnonymous();

        // POST /api/v1/ssh/proxy/session-end — mark session complete + record path
        app.MapPost("/api/v1/ssh/proxy/session-end",
            async (SshSessionEndRequest req, OrkunPamDbContext db,
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

            if (!string.IsNullOrEmpty(req.RecordingPath))
            {
                session.RecordingPath = req.RecordingPath;
                logger.LogInformation("SSH session {Id} recording: {Path}", sessionId, req.RecordingPath);
            }

            await db.SaveChangesAsync();

            logger.LogInformation(
                "[AUDIT] SSH_SESSION_ENDED sessionId={SessionId} duration={Duration}s recordingPath={Path} status={Status}",
                sessionId, req.DurationSeconds, req.RecordingPath ?? "none", session.Status);

            return Results.Ok(new { success = true });
        }).WithTags("SSH").AllowAnonymous();

        // GET /api/v1/ssh/proxy/sessions/{id}/status — proxy polls to detect admin termination
        app.MapGet("/api/v1/ssh/proxy/sessions/{id:guid}/status",
            async (Guid id, OrkunPamDbContext db, IConfiguration config, HttpContext context) =>
        {
            if (!ValidateProxySecret(context, config)) return Results.Unauthorized();

            var session = await db.ProxySessions
                .Where(s => s.Id == id && s.SessionType == SessionType.Ssh)
                .Select(s => new { s.Status })
                .FirstOrDefaultAsync();

            if (session == null) return Results.NotFound();

            return Results.Ok(new
            {
                success = true,
                data = new { terminated = session.Status == SessionStatus.Terminated }
            });
        }).WithTags("SSH").AllowAnonymous();
    }

    private static bool ValidateProxySecret(HttpContext context, IConfiguration config)
    {
        var expected = config["ProxyService:Secret"] ?? config["PamApi:ProxySecret"] ?? "";
        if (expected.Length < 32) return false;
        var provided = context.Request.Headers["X-Proxy-Secret"].FirstOrDefault() ?? "";
        // CWE-208: constant-time comparison prevents timing side-channel attacks
        var expectedBytes = System.Text.Encoding.UTF8.GetBytes(expected);
        var providedBytes = System.Text.Encoding.UTF8.GetBytes(provided);
        return CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
    }

    private sealed record SshSessionStartRequest(
        string? UserId, string? DeviceId, string? CredentialId,
        string ClientIp, string TargetIp, int TargetPort);

    private sealed record SshSessionEndRequest(
        string SessionId, int DurationSeconds, string? RecordingPath);
}
