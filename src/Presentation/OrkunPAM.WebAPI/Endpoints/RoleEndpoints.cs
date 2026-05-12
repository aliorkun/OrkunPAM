using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class RoleEndpoints
{
    public static void MapRoleEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/roles").WithTags("Roles");

        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var roles = await db.Roles
                .Select(r => new
                {
                    r.Id, r.Name, r.Description, r.IsSystemRole,
                    PermissionCount = r.RolePermissions.Count
                }).ToListAsync();
            return Results.Ok(new { success = true, data = roles });
        });

        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var role = await db.Roles
                .Include(r => r.RolePermissions).ThenInclude(rp => rp.Permission)
                .FirstOrDefaultAsync(r => r.Id == id);

            if (role == null) return Results.NotFound(new { success = false, errors = new[] { "Role not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    role.Id, role.Name, role.Description, role.IsSystemRole,
                    Permissions = role.RolePermissions.Select(rp => new
                    {
                        rp.PermissionCode,
                        rp.Permission.Module,
                        rp.Permission.Description
                    })
                }
            });
        });

        group.MapPost("/", async (CreateRoleRequest req, OrkunPamDbContext db) =>
        {
            if (await db.Roles.AnyAsync(r => r.Name == req.Name))
                return Results.Conflict(new { success = false, errors = new[] { $"Role '{req.Name}' already exists" } });

            var role = new Role { Name = req.Name, Description = req.Description, IsSystemRole = false };
            db.Roles.Add(role);

            if (req.PermissionCodes?.Length > 0)
            {
                foreach (var code in req.PermissionCodes)
                {
                    if (await db.Permissions.AnyAsync(p => p.Code == code))
                        db.RolePermissions.Add(new RolePermission { RoleId = role.Id, PermissionCode = code });
                }
            }

            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/roles/{role.Id}", new { success = true, data = new { role.Id, role.Name } });
        });

        group.MapPut("/{id:guid}/permissions", async (Guid id, UpdateRolePermissionsRequest req, OrkunPamDbContext db) =>
        {
            var role = await db.Roles.FindAsync(id);
            if (role == null) return Results.NotFound(new { success = false, errors = new[] { "Role not found" } });
            if (role.IsSystemRole) return Results.BadRequest(new { success = false, errors = new[] { "Cannot modify system role permissions" } });

            var existing = await db.RolePermissions.Where(rp => rp.RoleId == id).ToListAsync();
            db.RolePermissions.RemoveRange(existing);

            foreach (var code in req.PermissionCodes)
            {
                if (await db.Permissions.AnyAsync(p => p.Code == code))
                    db.RolePermissions.Add(new RolePermission { RoleId = id, PermissionCode = code });
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = $"Permissions updated ({req.PermissionCodes.Length} codes)" });
        });

        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var role = await db.Roles.FindAsync(id);
            if (role == null) return Results.NotFound(new { success = false, errors = new[] { "Role not found" } });
            if (role.IsSystemRole) return Results.BadRequest(new { success = false, errors = new[] { "Cannot delete system role" } });

            db.Roles.Remove(role);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        app.MapGet("/api/v1/permissions", async (OrkunPamDbContext db) =>
        {
            var perms = await db.Permissions
                .OrderBy(p => p.Module).ThenBy(p => p.Code)
                .Select(p => new { p.Code, p.Module, p.Description })
                .ToListAsync();

            var grouped = perms.GroupBy(p => p.Module).ToDictionary(g => g.Key, g => g.Select(p => new { p.Code, p.Description }));
            return Results.Ok(new { success = true, data = grouped });
        }).WithTags("Roles");
    }
}

public record CreateRoleRequest(string Name, string? Description, string[]? PermissionCodes);
public record UpdateRolePermissionsRequest(string[] PermissionCodes);
