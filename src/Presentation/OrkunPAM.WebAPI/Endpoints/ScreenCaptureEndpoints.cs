using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ScreenCaptureEndpoints
{
    public static void MapScreenCaptureEndpoints(this IEndpointRouteBuilder app)
    {
        // GET /api/v1/sessions/{id}/screen-captures — list frames for a session
        app.MapGet("/api/v1/sessions/{id:guid}/screen-captures",
            async (Guid id, OrkunPamDbContext db, int? limit) =>
        {
            var cap = limit is > 0 and <= 500 ? limit.Value : 200;
            var frames = await db.ScreenCaptureFrames
                .Where(f => f.SessionId == id)
                .OrderBy(f => f.FrameIndex)
                .Take(cap)
                .Select(f => new
                {
                    f.Id, f.SessionId, f.FrameIndex,
                    f.CapturedAtUtc, f.Width, f.Height,
                    f.SessionType,
                    HasData = f.DataBase64 != null
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = frames, meta = new { totalCount = frames.Count } });
        }).RequireAuthorization("AdminPolicy").WithTags("Sessions");

        // GET /api/v1/sessions/{id}/screen-captures/{frameIndex} — single frame with data
        app.MapGet("/api/v1/sessions/{id:guid}/screen-captures/{frameIndex:int}",
            async (Guid id, int frameIndex, OrkunPamDbContext db) =>
        {
            var frame = await db.ScreenCaptureFrames
                .FirstOrDefaultAsync(f => f.SessionId == id && f.FrameIndex == frameIndex);

            if (frame == null)
                return Results.NotFound(new { success = false, errors = new[] { "Frame not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    frame.Id, frame.SessionId, frame.FrameIndex,
                    frame.CapturedAtUtc, frame.Width, frame.Height,
                    frame.SessionType, frame.DataBase64
                }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("Sessions");

        // POST /api/v1/sessions/screen-captures — called by proxy services (X-Proxy-Secret)
        app.MapPost("/api/v1/sessions/screen-captures",
            async (ScreenCaptureRequest req, OrkunPamDbContext db,
                   IAuditService audit, IConfiguration config, HttpContext ctx) =>
        {
            var secret = config["ProxyService:Secret"] ?? "";
            if (secret.Length < 32 || ctx.Request.Headers["X-Proxy-Secret"] != secret)
                return Results.Unauthorized();

            if (!Guid.TryParse(req.SessionId, out var sessionId))
                return Results.BadRequest(new { success = false, errors = new[] { "Invalid SessionId" } });

            // Deduplicate: skip if this frame index already exists
            var exists = await db.ScreenCaptureFrames
                .AnyAsync(f => f.SessionId == sessionId && f.FrameIndex == req.FrameIndex);
            if (exists)
                return Results.Ok(new { success = true, duplicate = true });

            var frame = new ScreenCaptureFrame
            {
                SessionId     = sessionId,
                FrameIndex    = req.FrameIndex,
                CapturedAtUtc = req.CapturedAtUtc != default ? req.CapturedAtUtc : DateTime.UtcNow,
                Width         = req.Width,
                Height        = req.Height,
                DataBase64    = req.DataBase64,
                SessionType   = req.SessionType ?? "Unknown"
            };

            db.ScreenCaptureFrames.Add(frame);
            await db.SaveChangesAsync();

            await audit.LogAsync("Session", "SCREEN_CAPTURE_RECORDED", null, "proxy-service", "127.0.0.1",
                "Session", req.SessionId,
                new { req.FrameIndex, req.Width, req.Height, req.SessionType },
                AuditOutcome.Success);

            return Results.Ok(new { success = true, data = new { frame.Id } });
        }).AllowAnonymous().WithTags("Sessions");
    }
}

internal record ScreenCaptureRequest(
    string   SessionId,
    int      FrameIndex,
    DateTime CapturedAtUtc,
    int?     Width,
    int?     Height,
    string?  DataBase64,
    string?  SessionType);
