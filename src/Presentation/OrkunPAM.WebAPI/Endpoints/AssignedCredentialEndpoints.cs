using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Access;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class AssignedCredentialEndpoints
{
    public static void MapAssignedCredentialEndpoints(this IEndpointRouteBuilder app)
    {
        var admin = app.MapGroup("/api/v1/assigned-credentials")
            .WithTags("AssignedCredential")
            .RequireAuthorization("AdminPolicy");

        // List all (admin, paginated)
        admin.MapGet("/", async (OrkunPamDbContext db,
            Guid? credentialId, Guid? principalId, int page = 1, int pageSize = 100) =>
        {
            var query = db.AssignedCredentials
                .Include(a => a.Credential)
                .AsQueryable();
            if (credentialId.HasValue) query = query.Where(a => a.CredentialId == credentialId.Value);
            if (principalId.HasValue)  query = query.Where(a => a.PrincipalId  == principalId.Value);

            var total = await query.CountAsync();
            var list = await query
                .OrderByDescending(a => a.CreatedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(a => new
                {
                    a.Id,
                    a.CredentialId,
                    CredentialName = a.Credential.Name,
                    PrincipalType  = a.PrincipalType.ToString(),
                    a.PrincipalId,
                    a.DeviceGroupId,
                    a.IsEnabled,
                    a.Notes,
                    a.CreatedAtUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        // Create assignment (admin)
        admin.MapPost("/", async (CreateAssignedCredentialRequest req, OrkunPamDbContext db) =>
        {
            if (!await db.Credentials.AnyAsync(c => c.Id == req.CredentialId))
                return Results.BadRequest(new { success = false, errors = new[] { "Credential not found" } });

            var a = new AssignedCredential
            {
                CredentialId  = req.CredentialId,
                PrincipalType = req.PrincipalType,
                PrincipalId   = req.PrincipalId,
                DeviceGroupId = req.DeviceGroupId,
                IsEnabled     = true,
                Notes         = req.Notes
            };
            db.AssignedCredentials.Add(a);
            await db.SaveChangesAsync();

            return Results.Created($"/api/v1/assigned-credentials/{a.Id}",
                new { success = true, data = new { a.Id } });
        });

        // Delete assignment (admin)
        admin.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var a = await db.AssignedCredentials.FindAsync(id);
            if (a == null)
                return Results.NotFound(new { success = false, errors = new[] { "Assignment not found" } });
            db.AssignedCredentials.Remove(a);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Toggle enable/disable (admin)
        admin.MapPost("/{id:guid}/toggle", async (Guid id, OrkunPamDbContext db) =>
        {
            var a = await db.AssignedCredentials.FindAsync(id);
            if (a == null)
                return Results.NotFound(new { success = false, errors = new[] { "Assignment not found" } });
            a.IsEnabled = !a.IsEnabled;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { a.Id, a.IsEnabled } });
        });

        // Who can use a specific credential (admin)
        admin.MapGet("/by-credential/{credentialId:guid}", async (Guid credentialId, OrkunPamDbContext db) =>
        {
            var list = await db.AssignedCredentials
                .Where(a => a.CredentialId == credentialId)
                .Select(a => new
                {
                    a.Id,
                    PrincipalType = a.PrincipalType.ToString(),
                    a.PrincipalId,
                    a.DeviceGroupId,
                    a.IsEnabled,
                    a.Notes,
                    a.CreatedAtUtc
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        // My assigned credentials (all authenticated users)
        app.MapGet("/api/v1/assigned-credentials/my-credentials", async (
            OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var groupIds = await db.UserGroups
                .Where(ug => ug.UserId == userId)
                .Select(ug => ug.GroupId)
                .ToListAsync();

            var list = await db.AssignedCredentials
                .Include(a => a.Credential)
                .Where(a => a.IsEnabled
                    && ((a.PrincipalType == PrincipalType.User  && a.PrincipalId == userId)
                    ||  (a.PrincipalType == PrincipalType.Group && groupIds.Contains(a.PrincipalId))))
                .Select(a => new
                {
                    a.Id,
                    a.CredentialId,
                    CredentialName = a.Credential.Name,
                    CredentialType = a.Credential.CredentialType.ToString(),
                    Username       = a.Credential.Username,
                    a.DeviceGroupId,
                    a.Notes
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list });
        }).RequireAuthorization();
    }
}

public record CreateAssignedCredentialRequest(
    Guid CredentialId,
    PrincipalType PrincipalType,
    Guid PrincipalId,
    Guid? DeviceGroupId,
    string? Notes);
