using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class UserEndpoints
{
    public static void MapUserEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/users").WithTags("Users");

        group.MapGet("/", async (OrkunPamDbContext db, string? search, string? status, int page = 1, int pageSize = 50) =>
        {
            var query = db.Users.AsQueryable();

            if (!string.IsNullOrEmpty(search))
                query = query.Where(u => u.Username.Contains(search) || u.DisplayName!.Contains(search) || u.Email!.Contains(search));

            if (!string.IsNullOrEmpty(status) && Enum.TryParse<UserStatus>(status, true, out var s))
                query = query.Where(u => u.Status == s);

            var total = await query.CountAsync();
            var users = await query
                .OrderBy(u => u.Username)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(u => new
                {
                    u.Id, u.Username, u.DisplayName, u.Email,
                    AuthSource = u.AuthSource.ToString(),
                    Status = u.Status.ToString(),
                    u.MfaEnabled, u.IsTemporary,
                    u.LastLoginAtUtc, u.CreatedAtUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = users, meta = new { page, pageSize, totalCount = total } });
        });

        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var user = await db.Users
                .Include(u => u.UserGroups).ThenInclude(ug => ug.Group)
                .Include(u => u.UserRoles).ThenInclude(ur => ur.Role)
                .FirstOrDefaultAsync(u => u.Id == id);

            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    user.Id, user.Username, user.DisplayName, user.Email,
                    AuthSource = user.AuthSource.ToString(),
                    Status = user.Status.ToString(),
                    user.MfaEnabled, user.IsTemporary, user.TemporaryExpiresUtc,
                    user.LastLoginAtUtc,
                    LastLoginIp = MaskIp(user.LastLoginIp),
                    user.Language, user.Timezone,
                    user.FailedLoginCount, user.LockoutEndUtc, user.PasswordLastChanged,
                    user.CreatedAtUtc, user.UpdatedAtUtc,
                    Groups = user.UserGroups.Select(ug => new { ug.Group.Id, ug.Group.Name }),
                    Roles = user.UserRoles.Select(ur => new { ur.Role.Id, ur.Role.Name })
                }
            });
        });

        group.MapPut("/{id:guid}", async (Guid id, UpdateUserRequest req, OrkunPamDbContext db,
            IAuditService audit, HttpContext context) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            if (req.DisplayName != null) user.DisplayName = req.DisplayName;
            if (req.Email != null) user.Email = req.Email;
            if (req.Language != null) user.Language = req.Language;
            if (req.Timezone != null) user.Timezone = req.Timezone;
            if (req.Status.HasValue) user.Status = req.Status.Value;

            await db.SaveChangesAsync();

            await audit.LogAsync("User", "User.Updated", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(), new { targetUsername = user.Username });

            return Results.Ok(new { success = true, data = new { user.Id, user.Username } });
        });

        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext context) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            user.IsDeleted = true;
            user.DeletedAtUtc = DateTime.UtcNow;
            user.Status = UserStatus.Disabled;
            await db.SaveChangesAsync();

            await audit.LogAsync("User", "User.Deleted", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(), new { targetUsername = user.Username });

            return Results.Ok(new { success = true });
        });

        group.MapPost("/{id:guid}/lock", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext context) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            user.Status = UserStatus.Locked;
            user.LockoutEndUtc = DateTime.UtcNow.AddYears(100);
            await db.SaveChangesAsync();

            await audit.LogAsync("User", "User.Locked", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(), new { targetUsername = user.Username });

            return Results.Ok(new { success = true, message = $"User '{user.Username}' locked" });
        });

        group.MapPost("/{id:guid}/unlock", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext context) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            user.Status = UserStatus.Active;
            user.LockoutEndUtc = null;
            user.FailedLoginCount = 0;
            await db.SaveChangesAsync();

            await audit.LogAsync("User", "User.Unlocked", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(), new { targetUsername = user.Username });

            return Results.Ok(new { success = true, message = $"User '{user.Username}' unlocked" });
        });

        group.MapPost("/{id:guid}/reset-password", async (Guid id, ResetPasswordRequest req,
            OrkunPamDbContext db, IPasswordHasher hasher, IAuditService audit, HttpContext context) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });
            if (user.AuthSource != AuthSource.Local)
                return Results.BadRequest(new { success = false, errors = new[] { $"Cannot reset password for {user.AuthSource} user" } });

            user.PasswordHash = hasher.Hash(req.NewPassword);
            user.PasswordLastChanged = DateTime.UtcNow;
            await db.SaveChangesAsync();

            await audit.LogAsync("User", "User.PasswordReset", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(), new { targetUsername = user.Username, adminReset = true });

            return Results.Ok(new { success = true, message = "Password reset successfully" });
        });

        group.MapGet("/{id:guid}/permissions", async (Guid id, IPermissionService perms) =>
        {
            var roles = await perms.GetEffectiveRolesAsync(id);
            var permissions = await perms.GetEffectivePermissionsAsync(id);
            return Results.Ok(new { success = true, data = new { roles, permissions } });
        });

        group.MapPost("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, OrkunPamDbContext db,
            IAuditService audit, HttpContext context) =>
        {
            if (!await db.Users.AnyAsync(u => u.Id == id))
                return Results.NotFound(new { success = false, errors = new[] { "User not found" } });
            if (!await db.Roles.AnyAsync(r => r.Id == roleId))
                return Results.NotFound(new { success = false, errors = new[] { "Role not found" } });
            if (await db.UserRoles.AnyAsync(ur => ur.UserId == id && ur.RoleId == roleId))
                return Results.Conflict(new { success = false, errors = new[] { "Role already assigned" } });

            db.UserRoles.Add(new UserRole { UserId = id, RoleId = roleId });
            await db.SaveChangesAsync();

            await audit.LogAsync("User", "User.RoleAssigned", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(), new { roleId });

            return Results.Ok(new { success = true, message = "Role assigned" });
        });

        group.MapDelete("/{id:guid}/roles/{roleId:guid}", async (Guid id, Guid roleId, OrkunPamDbContext db,
            IAuditService audit, HttpContext context) =>
        {
            var ur = await db.UserRoles.FindAsync(id, roleId);
            if (ur == null) return Results.NotFound(new { success = false, errors = new[] { "Assignment not found" } });

            db.UserRoles.Remove(ur);
            await db.SaveChangesAsync();

            await audit.LogAsync("User", "User.RoleRemoved", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(), new { roleId });

            return Results.Ok(new { success = true, message = "Role removed" });
        });
    }

    private static Guid? ParseActorId(HttpContext context)
        => Guid.TryParse(context.User.FindFirstValue(ClaimTypes.NameIdentifier), out var g) ? g : null;

    private static string? MaskIp(string? ip)
    {
        if (ip == null) return null;
        var lastDot = ip.LastIndexOf('.');
        return lastDot > 0 ? ip[..lastDot] + ".***" : "***";
    }
}

public record UpdateUserRequest(string? DisplayName, string? Email, string? Language, string? Timezone, UserStatus? Status);
public record ResetPasswordRequest(string NewPassword);
