using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class GroupEndpoints
{
    public static void MapGroupEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/v1/groups").WithTags("Groups");

        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var groups = await db.Groups
                .Include(g => g.ChildGroups)
                .Select(g => new
                {
                    g.Id, g.Name, g.Description,
                    Source = g.GroupSource.ToString(),
                    g.ParentGroupId,
                    MemberCount = g.UserGroups.Count,
                    RoleCount = g.GroupRoles.Count
                }).ToListAsync();

            return Results.Ok(new { success = true, data = groups });
        });

        group.MapPost("/", async (CreateGroupRequest req, OrkunPamDbContext db) =>
        {
            if (await db.Groups.AnyAsync(g => g.Name == req.Name))
                return Results.Conflict(new { success = false, errors = new[] { $"Group '{req.Name}' already exists" } });

            var g = new Group
            {
                Name = req.Name,
                Description = req.Description,
                GroupSource = GroupSource.Local,
                ParentGroupId = req.ParentGroupId
            };

            db.Groups.Add(g);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/groups/{g.Id}", new { success = true, data = new { g.Id, g.Name } });
        });

        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var g = await db.Groups
                .Include(g => g.UserGroups).ThenInclude(ug => ug.User)
                .Include(g => g.GroupRoles).ThenInclude(gr => gr.Role)
                .Include(g => g.ChildGroups)
                .FirstOrDefaultAsync(g => g.Id == id);

            if (g == null) return Results.NotFound(new { success = false, errors = new[] { "Group not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    g.Id, g.Name, g.Description,
                    Source = g.GroupSource.ToString(),
                    g.ParentGroupId, g.CreatedAtUtc,
                    Members = g.UserGroups.Select(ug => new { ug.User.Id, ug.User.Username, ug.User.DisplayName }),
                    Roles = g.GroupRoles.Select(gr => new { gr.Role.Id, gr.Role.Name }),
                    ChildGroups = g.ChildGroups.Select(cg => new { cg.Id, cg.Name })
                }
            });
        });

        group.MapPut("/{id:guid}", async (Guid id, UpdateGroupRequest req, OrkunPamDbContext db) =>
        {
            var g = await db.Groups.FindAsync(id);
            if (g == null) return Results.NotFound(new { success = false, errors = new[] { "Group not found" } });

            if (req.Name != null) g.Name = req.Name;
            if (req.Description != null) g.Description = req.Description;

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { g.Id, g.Name } });
        });

        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var g = await db.Groups.FindAsync(id);
            if (g == null) return Results.NotFound(new { success = false, errors = new[] { "Group not found" } });

            db.Groups.Remove(g);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Members
        group.MapGet("/{id:guid}/members", async (Guid id, OrkunPamDbContext db) =>
        {
            var members = await db.UserGroups
                .Where(ug => ug.GroupId == id)
                .Select(ug => new { ug.User.Id, ug.User.Username, ug.User.DisplayName, ug.User.Email })
                .ToListAsync();
            return Results.Ok(new { success = true, data = members });
        });

        group.MapPost("/{id:guid}/members", async (Guid id, AddMembersRequest req, OrkunPamDbContext db) =>
        {
            if (!await db.Groups.AnyAsync(g => g.Id == id))
                return Results.NotFound(new { success = false, errors = new[] { "Group not found" } });

            var added = 0;
            foreach (var userId in req.UserIds)
            {
                if (await db.UserGroups.AnyAsync(ug => ug.GroupId == id && ug.UserId == userId))
                    continue;

                db.UserGroups.Add(new UserGroup { GroupId = id, UserId = userId });
                added++;
            }

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = $"{added} member(s) added" });
        });

        group.MapDelete("/{id:guid}/members/{userId:guid}", async (Guid id, Guid userId, OrkunPamDbContext db) =>
        {
            var ug = await db.UserGroups.FindAsync(userId, id);
            if (ug == null) return Results.NotFound(new { success = false, errors = new[] { "Membership not found" } });

            db.UserGroups.Remove(ug);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Group Roles
        group.MapPost("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, OrkunPamDbContext db) =>
        {
            if (!await db.Groups.AnyAsync(g => g.Id == id))
                return Results.NotFound(new { success = false, errors = new[] { "Group not found" } });

            if (await db.GroupRoles.AnyAsync(gr => gr.GroupId == id && gr.RoleId == roleId))
                return Results.Conflict(new { success = false, errors = new[] { "Role already assigned" } });

            db.GroupRoles.Add(new GroupRole { GroupId = id, RoleId = roleId });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = "Role assigned to group" });
        });

        group.MapDelete("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, OrkunPamDbContext db) =>
        {
            var gr = await db.GroupRoles.FindAsync(id, roleId);
            if (gr == null) return Results.NotFound(new { success = false, errors = new[] { "Assignment not found" } });

            db.GroupRoles.Remove(gr);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });
    }
}

public record CreateGroupRequest(string Name, string? Description, Guid? ParentGroupId);
public record UpdateGroupRequest(string? Name, string? Description);
public record AddMembersRequest(Guid[] UserIds);
