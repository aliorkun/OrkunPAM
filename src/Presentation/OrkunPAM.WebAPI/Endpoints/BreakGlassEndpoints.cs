using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Security;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.WebAPI.Endpoints;

public static class BreakGlassEndpoints
{
    public static void MapBreakGlassEndpoints(this IEndpointRouteBuilder app)
    {
        var bg = app.MapGroup("/api/v1/break-glass").WithTags("BreakGlass");

        // Submit emergency access request — grants immediate access, fully audited
        bg.MapPost("/", async (BreakGlassRequest req, OrkunPamDbContext db,
            HttpContext ctx, IEmailService? email, ILogger<Program> logger) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            if (string.IsNullOrWhiteSpace(req.EmergencyReason) || req.EmergencyReason.Trim().Length < 10)
                return Results.BadRequest(new { success = false, errors = new[] { "EmergencyReason must be at least 10 characters" } });

            var evt = new BreakGlassEvent
            {
                RequesterId = userId,
                RequesterUsername = username,
                RequesterIpAddress = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown",
                ResourceType = req.ResourceType,
                ResourceId = req.ResourceId,
                ResourceName = req.ResourceName ?? string.Empty,
                EmergencyReason = req.EmergencyReason.Trim(),
                TicketNumber = req.TicketNumber,
                Status = BreakGlassStatus.Active,
                ExpiresAtUtc = DateTime.UtcNow.AddMinutes(req.ExpiresInMinutes ?? 60)
            };

            db.BreakGlassEvents.Add(evt);
            await db.SaveChangesAsync();

            logger.LogCritical("[BREAK-GLASS] User={User} IP={Ip} Resource={ResourceType}/{ResourceId} Reason={Reason}",
                username, evt.RequesterIpAddress, req.ResourceType, req.ResourceId, req.EmergencyReason);

            if (email != null)
                _ = NotifyAdminsAsync(email, db, evt, logger);

            return Results.Created($"/api/v1/break-glass/{evt.Id}",
                new { success = true, data = new { evt.Id, Status = evt.Status.ToString(), evt.ExpiresAtUtc } });
        }).RequireAuthorization();

        // List all break-glass events (paginated, admin view)
        bg.MapGet("/", async (OrkunPamDbContext db, string? status, int page = 1, int pageSize = 50) =>
        {
            // Auto-expire stale active events
            var now = DateTime.UtcNow;
            var stale = await db.BreakGlassEvents
                .Where(e => e.Status == BreakGlassStatus.Active && e.ExpiresAtUtc < now)
                .ToListAsync();
            if (stale.Count > 0)
            {
                foreach (var s in stale) s.Status = BreakGlassStatus.Expired;
                await db.SaveChangesAsync();
            }

            var query = db.BreakGlassEvents.AsQueryable();
            if (!string.IsNullOrEmpty(status) && Enum.TryParse<BreakGlassStatus>(status, true, out var parsed))
                query = query.Where(e => e.Status == parsed);

            var total = await query.CountAsync();
            var list = await query
                .OrderByDescending(e => e.CreatedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(e => new
                {
                    e.Id, e.RequesterUsername, e.RequesterIpAddress,
                    e.ResourceType, e.ResourceId, e.ResourceName,
                    e.EmergencyReason, e.TicketNumber,
                    Status = e.Status.ToString(),
                    e.CreatedAtUtc, e.ExpiresAtUtc,
                    e.AcknowledgedAtUtc, e.AcknowledgedByUsername, e.AcknowledgementNotes
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        }).RequireAuthorization();

        // My break-glass events
        bg.MapGet("/my", async (OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var list = await db.BreakGlassEvents
                .Where(e => e.RequesterId == userId)
                .OrderByDescending(e => e.CreatedAtUtc)
                .Take(50)
                .Select(e => new
                {
                    e.Id, e.ResourceType, e.ResourceId, e.ResourceName,
                    e.EmergencyReason, e.TicketNumber,
                    Status = e.Status.ToString(),
                    e.CreatedAtUtc, e.ExpiresAtUtc,
                    e.AcknowledgedAtUtc, e.AcknowledgedByUsername
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list });
        }).RequireAuthorization();

        // Acknowledge — admin confirms they have reviewed the event post-facto
        bg.MapPost("/{id:guid}/acknowledge", async (Guid id, AcknowledgeBreakGlassRequest req,
            OrkunPamDbContext db, HttpContext ctx, ILogger<Program> logger) =>
        {
            var adminIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var adminName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            if (adminIdStr == null || !Guid.TryParse(adminIdStr, out var adminId))
                return Results.Unauthorized();

            var evt = await db.BreakGlassEvents.FindAsync(id);
            if (evt == null)
                return Results.NotFound(new { success = false, errors = new[] { "Event not found" } });
            if (evt.RequesterId == adminId)
                return Results.BadRequest(new { success = false, errors = new[] { "Cannot self-acknowledge break-glass events" } });

            evt.Status = BreakGlassStatus.Acknowledged;
            evt.AcknowledgedAtUtc = DateTime.UtcNow;
            evt.AcknowledgedByUserId = adminId;
            evt.AcknowledgedByUsername = adminName;
            evt.AcknowledgementNotes = req.Notes;

            await db.SaveChangesAsync();
            logger.LogInformation("[BREAK-GLASS] Event {Id} acknowledged by {Admin}", id, adminName);
            return Results.Ok(new { success = true });
        }).RequireAuthorization();

        // Revoke — admin immediately terminates an active break-glass session
        bg.MapPost("/{id:guid}/revoke", async (Guid id, AcknowledgeBreakGlassRequest req,
            OrkunPamDbContext db, HttpContext ctx, ILogger<Program> logger) =>
        {
            var adminIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var adminName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            if (adminIdStr == null || !Guid.TryParse(adminIdStr, out var adminId))
                return Results.Unauthorized();

            var evt = await db.BreakGlassEvents.FindAsync(id);
            if (evt == null)
                return Results.NotFound(new { success = false, errors = new[] { "Event not found" } });
            if (evt.Status != BreakGlassStatus.Active)
                return Results.Conflict(new { success = false, errors = new[] { $"Event is already {evt.Status}" } });

            evt.Status = BreakGlassStatus.Revoked;
            evt.AcknowledgedAtUtc = DateTime.UtcNow;
            evt.AcknowledgedByUserId = adminId;
            evt.AcknowledgedByUsername = adminName;
            evt.AcknowledgementNotes = req.Notes ?? "Revoked by administrator";

            await db.SaveChangesAsync();
            logger.LogWarning("[BREAK-GLASS] Event {Id} REVOKED by {Admin}", id, adminName);
            return Results.Ok(new { success = true });
        }).RequireAuthorization();
    }

    private static async Task NotifyAdminsAsync(IEmailService email, OrkunPamDbContext db,
        BreakGlassEvent evt, ILogger logger)
    {
        try
        {
            var adminEmails = await db.Users
                .Where(u => u.Status == UserStatus.Active && u.Email != null)
                .Join(db.UserRoles, u => u.Id, ur => ur.UserId, (u, ur) => new { u.Email, ur.RoleId })
                .Join(db.Roles.Where(r => r.Name == "Administrator" || r.Name == "Security Admin"),
                      x => x.RoleId, r => r.Id, (x, _) => x.Email!)
                .Distinct().Take(10).ToListAsync();

            if (adminEmails.Count == 0) return;

            var subject = $"[BREAK-GLASS ALERT] {evt.RequesterUsername} — {evt.ResourceType}";
            var body = $"""
                <h3 style="color:#c00">Break-Glass Emergency Access Activated</h3>
                <table style="border-collapse:collapse;font-family:sans-serif">
                  <tr><td style="padding:4px 12px"><b>User</b></td><td>{evt.RequesterUsername}</td></tr>
                  <tr><td style="padding:4px 12px"><b>IP Address</b></td><td>{evt.RequesterIpAddress}</td></tr>
                  <tr><td style="padding:4px 12px"><b>Resource</b></td><td>{evt.ResourceType} / {evt.ResourceName}</td></tr>
                  <tr><td style="padding:4px 12px"><b>Reason</b></td><td>{evt.EmergencyReason}</td></tr>
                  <tr><td style="padding:4px 12px"><b>Ticket</b></td><td>{evt.TicketNumber ?? "—"}</td></tr>
                  <tr><td style="padding:4px 12px"><b>Expires</b></td><td>{evt.ExpiresAtUtc:u}</td></tr>
                </table>
                <p><b>Action required:</b> Please acknowledge or revoke this event in the PAM console immediately.</p>
                """;

            foreach (var adminEmail in adminEmails)
                await email.SendAsync(adminEmail, subject, body);
        }
        catch (Exception ex)
        {
            logger.LogError(ex, "[BREAK-GLASS] Failed to send admin notifications for event {Id}", evt.Id);
        }
    }
}

public record BreakGlassRequest(
    string ResourceType,
    Guid? ResourceId,
    string? ResourceName,
    string EmergencyReason,
    string? TicketNumber,
    int? ExpiresInMinutes);

public record AcknowledgeBreakGlassRequest(string? Notes);
