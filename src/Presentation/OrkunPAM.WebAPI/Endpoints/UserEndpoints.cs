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
            user.LockoutEndUtc = DateTime.UtcNow.AddYears(100); // Manual lock = indefinite
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

        group.MapPost("/{id:guid}/reset-password", async (Guid id, AdminResetPasswordRequest req,
            OrkunPamDbContext db, IPasswordHasher hasher, IPasswordPolicyService policy,
            IAuditService audit, HttpContext context) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });
            if (user.AuthSource != AuthSource.Local)
                return Results.BadRequest(new { success = false, errors = new[] { $"Cannot reset password for {user.AuthSource} user" } });

            var validation = await policy.ValidateAsync(req.NewPassword, ct: context.RequestAborted);
            if (validation.IsFailure)
                return Results.BadRequest(new { success = false, errors = new[] { validation.Error.Message } });

            var newHash = hasher.Hash(req.NewPassword);
            user.PasswordHash = newHash;
            user.PasswordLastChanged = DateTime.UtcNow;
            user.PasswordExpiresAt = policy.ComputeExpiry();
            user.MustChangePassword = true;
            await db.SaveChangesAsync();

            await policy.RecordPasswordAsync(user.Id, newHash, context.RequestAborted);

            await audit.LogAsync("User", "User.PasswordReset", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(), new { targetUsername = user.Username, adminReset = true });

            return Results.Ok(new { success = true, message = "Password reset successfully" });
        });

        // Admin MFA management
        group.MapPost("/{id:guid}/mfa/reset", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext context) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            user.MfaEnabled = false;
            user.MfaSecret = null;
            user.MfaEnrollmentToken = null;
            user.MfaEnrollmentTokenExpiry = null;
            await db.SaveChangesAsync();

            await audit.LogAsync("User", "User.MfaReset", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(), new { targetUsername = user.Username });

            return Results.Ok(new { success = true, message = $"MFA reset for '{user.Username}'. User must re-enroll." });
        });

        group.MapPost("/{id:guid}/mfa/send-setup", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext context) =>
        {
            var user = await db.Users.FindAsync(id);
            if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });

            var token = Guid.NewGuid();
            user.MfaEnrollmentToken = token;
            user.MfaEnrollmentTokenExpiry = DateTime.UtcNow.AddHours(24);
            await db.SaveChangesAsync();

            await audit.LogAsync("User", "User.MfaEnrollmentLinkGenerated", ParseActorId(context),
                context.User.FindFirstValue("username"),
                context.Connection.RemoteIpAddress?.ToString(),
                "User", id.ToString(),
                new { targetUsername = user.Username, expiry = user.MfaEnrollmentTokenExpiry });

            return Results.Ok(new
            {
                success = true,
                data = new { enrollmentToken = token.ToString(), expiresAt = user.MfaEnrollmentTokenExpiry }
            });
        });

        group.MapGet("/{id:guid}/permissions", async (Guid id, IPermissionService perms) =>
        {
            var roles = await perms.GetEffectiveRolesAsync(id);
            var permissions = await perms.GetEffectivePermissionsAsync(id);
            return Results.Ok(new { success = true, data = new { roles, permissions } });
        });

        // Role assignment
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

        // -----------------------------------------------------------------------
        // Bulk User Import (CSV)
        // -----------------------------------------------------------------------

        group.MapGet("/import/template", () =>
        {
            const string csv = "username,displayName,email,department,role,groupName\n" +
                               "jdoe,Jane Doe,jdoe@example.com,IT,Operator,Linux-Admins\n" +
                               "asmith,Alan Smith,asmith@example.com,Finance,,\n";
            return Results.File(System.Text.Encoding.UTF8.GetBytes(csv),
                "text/csv", "users-import-template.csv");
        });

        group.MapPost("/import", async (HttpRequest req, OrkunPamDbContext db,
            IAuthenticationService auth, IAuditService audit, HttpContext context) =>
        {
            if (!req.HasFormContentType || !req.Form.Files.Any())
                return Results.BadRequest(new { success = false, errors = new[] { "No file uploaded" } });

            var file = req.Form.Files[0];
            if (file.Length > 5 * 1024 * 1024)
                return Results.BadRequest(new { success = false, errors = new[] { "File too large (max 5 MB)" } });

            using var reader = new System.IO.StreamReader(file.OpenReadStream());
            var lines = new List<string>();
            while (!reader.EndOfStream)
            {
                var line = await reader.ReadLineAsync();
                if (line != null) lines.Add(line);
            }

            if (lines.Count < 2)
                return Results.BadRequest(new { success = false, errors = new[] { "CSV must have a header row and at least one data row" } });

            // Pre-fetch roles and groups once to avoid N+1 queries
            var allRoles  = await db.Roles.ToListAsync();
            var allGroups = await db.Groups.ToListAsync();

            int successCount = 0;
            var errors = new List<object>();

            for (int i = 1; i < lines.Count; i++)
            {
                var line = lines[i].Trim();
                if (string.IsNullOrEmpty(line)) continue;

                var cols = line.Split(',');
                if (cols.Length < 2)
                {
                    errors.Add(new { row = i + 1, username = "", reason = "Too few columns" });
                    continue;
                }

                var username    = cols[0].Trim();
                var displayName = cols.Length > 1 ? cols[1].Trim() : null;
                var email       = cols.Length > 2 && !string.IsNullOrEmpty(cols[2].Trim()) ? cols[2].Trim() : null;
                var roleName    = cols.Length > 4 && !string.IsNullOrEmpty(cols[4].Trim()) ? cols[4].Trim() : null;
                var groupName   = cols.Length > 5 && !string.IsNullOrEmpty(cols[5].Trim()) ? cols[5].Trim() : null;

                if (string.IsNullOrEmpty(username))
                {
                    errors.Add(new { row = i + 1, username = "", reason = "Username is required" });
                    continue;
                }

                // Generate a temporary random password — user must change on first login
                var tempPassword = Convert.ToBase64String(System.Security.Cryptography.RandomNumberGenerator.GetBytes(18));

                var result = await auth.CreateLocalUserAsync(username, tempPassword, displayName, email);
                if (result.IsFailure)
                {
                    errors.Add(new { row = i + 1, username, reason = result.Error.Message });
                    continue;
                }

                var user = result.Value;
                user.MustChangePassword = true;

                // Assign role if specified
                if (roleName != null)
                {
                    var role = allRoles.FirstOrDefault(r => r.Name.Equals(roleName, StringComparison.OrdinalIgnoreCase));
                    if (role != null && !await db.UserRoles.AnyAsync(ur => ur.UserId == user.Id && ur.RoleId == role.Id))
                        db.UserRoles.Add(new UserRole { UserId = user.Id, RoleId = role.Id });
                }

                // Assign group if specified
                if (groupName != null)
                {
                    var group = allGroups.FirstOrDefault(g => g.Name.Equals(groupName, StringComparison.OrdinalIgnoreCase));
                    if (group != null && !await db.UserGroups.AnyAsync(ug => ug.UserId == user.Id && ug.GroupId == group.Id))
                        db.UserGroups.Add(new UserGroup { UserId = user.Id, GroupId = group.Id });
                }

                await db.SaveChangesAsync();
                successCount++;
            }

            var ip = context.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("User", "BULK_IMPORT", ParseActorId(context),
                context.User.FindFirstValue("username"), ip,
                "User", "bulk", new { successCount, failedCount = errors.Count, totalRows = lines.Count - 1 });

            return Results.Ok(new
            {
                success = true,
                data = new { imported = successCount, failed = errors.Count, errors }
            });
        }).DisableAntiforgery();
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
public record AdminResetPasswordRequest(string NewPassword);
