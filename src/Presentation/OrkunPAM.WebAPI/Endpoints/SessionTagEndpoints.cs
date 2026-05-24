using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class SessionTagEndpoints
{
    public static void MapSessionTagEndpoints(this IEndpointRouteBuilder app)
    {
        // === Session Tagging & Annotation (#216) ===

        // PUT /api/v1/sessions/{id}/tags — update comma-separated tags string
        app.MapPut("/api/v1/sessions/{id}/tags", async (
            Guid id, UpdateTagsRequest req, OrkunPamDbContext db,
            IAuditService audit, ICurrentUserService currentUser) =>
        {
            var session = await db.ProxySessions.FindAsync(id);
            if (session == null)
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            session.Tags = req.Tags?.Trim();
            await db.SaveChangesAsync();

            if (currentUser.UserId.HasValue)
                await audit.LogAsync("Session", "SESSION_TAGS_UPDATED", currentUser.UserId.Value, null,
                    currentUser.IpAddress ?? "", "Session", id.ToString(),
                    new { tags = session.Tags });

            return Results.Ok(new { success = true, data = new { id, tags = session.Tags } });
        }).RequireAuthorization().WithTags("Sessions");

        // GET /api/v1/sessions/{id}/annotations — list annotations for a session
        app.MapGet("/api/v1/sessions/{id}/annotations", async (Guid id, OrkunPamDbContext db) =>
        {
            var annotations = await db.SessionAnnotations
                .Where(a => a.SessionId == id)
                .OrderBy(a => a.CreatedAtUtc)
                .Select(a => new
                {
                    a.Id,
                    a.SessionId,
                    a.AuthorUserId,
                    a.AuthorUsername,
                    a.Note,
                    a.CreatedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = annotations });
        }).RequireAuthorization().WithTags("Sessions");

        // POST /api/v1/sessions/{id}/annotations — add an annotation to a session
        app.MapPost("/api/v1/sessions/{id}/annotations", async (
            Guid id, AddAnnotationRequest req, OrkunPamDbContext db,
            IAuditService audit, ICurrentUserService currentUser) =>
        {
            if (string.IsNullOrWhiteSpace(req.Note))
                return Results.BadRequest(new { success = false, errors = new[] { "Note cannot be empty" } });

            if (!await db.ProxySessions.AnyAsync(s => s.Id == id))
                return Results.NotFound(new { success = false, errors = new[] { "Session not found" } });

            var authorId = currentUser.UserId ?? Guid.Empty;
            var annotation = new SessionAnnotation
            {
                SessionId      = id,
                AuthorUserId   = authorId,
                AuthorUsername = currentUser.Username,
                Note           = req.Note.Trim()
            };
            db.SessionAnnotations.Add(annotation);
            await db.SaveChangesAsync();

            if (currentUser.UserId.HasValue)
                await audit.LogAsync("Session", "SESSION_ANNOTATION_ADDED", currentUser.UserId.Value, null,
                    currentUser.IpAddress ?? "", "Session", id.ToString(),
                    new { annotationId = annotation.Id });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    annotation.Id,
                    annotation.SessionId,
                    annotation.AuthorUserId,
                    annotation.AuthorUsername,
                    annotation.Note,
                    annotation.CreatedAtUtc
                }
            });
        }).RequireAuthorization().WithTags("Sessions");

        // DELETE /api/v1/sessions/{sessionId}/annotations/{annotationId} — delete own annotation
        app.MapDelete("/api/v1/sessions/{sessionId}/annotations/{annotationId}", async (
            Guid sessionId, Guid annotationId, OrkunPamDbContext db,
            IAuditService audit, ICurrentUserService currentUser) =>
        {
            var annotation = await db.SessionAnnotations
                .FirstOrDefaultAsync(a => a.Id == annotationId && a.SessionId == sessionId);

            if (annotation == null)
                return Results.NotFound(new { success = false, errors = new[] { "Annotation not found" } });

            // Only author or admin can delete
            var isAdmin = currentUser.HasPermission("sessions.admin");
            if (!isAdmin && annotation.AuthorUserId != currentUser.UserId)
                return Results.Forbid();

            db.SessionAnnotations.Remove(annotation);
            await db.SaveChangesAsync();

            if (currentUser.UserId.HasValue)
                await audit.LogAsync("Session", "SESSION_ANNOTATION_DELETED", currentUser.UserId.Value, null,
                    currentUser.IpAddress ?? "", "Session", sessionId.ToString(),
                    new { annotationId });

            return Results.Ok(new { success = true });
        }).RequireAuthorization().WithTags("Sessions");
    }
}

internal record UpdateTagsRequest(string? Tags);
internal record AddAnnotationRequest(string Note);
