using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Identity.Services;

public interface IPermissionService
{
    Task<IReadOnlySet<string>> GetEffectivePermissionsAsync(Guid userId, CancellationToken ct = default);
    Task<IReadOnlySet<string>> GetEffectiveRolesAsync(Guid userId, CancellationToken ct = default);
    Task<bool> HasPermissionAsync(Guid userId, string permissionCode, CancellationToken ct = default);
}

/// <summary>
/// Resolves effective permissions by merging: direct user roles + group roles.
/// Permission code format: "module.resource.action" e.g. "vault.credential.checkout"
/// </summary>
public sealed class PermissionService : IPermissionService
{
    private readonly OrkunPamDbContext _db;

    public PermissionService(OrkunPamDbContext db) => _db = db;

    public async Task<IReadOnlySet<string>> GetEffectivePermissionsAsync(Guid userId, CancellationToken ct = default)
    {
        // Direct user role permissions
        var userPerms = await _db.UserRoles
            .Where(ur => ur.UserId == userId)
            .SelectMany(ur => ur.Role.RolePermissions)
            .Select(rp => rp.PermissionCode)
            .ToListAsync(ct);

        // Group role permissions
        var groupPerms = await _db.UserGroups
            .Where(ug => ug.UserId == userId)
            .SelectMany(ug => ug.Group.GroupRoles)
            .SelectMany(gr => gr.Role.RolePermissions)
            .Select(rp => rp.PermissionCode)
            .ToListAsync(ct);

        var all = new HashSet<string>(userPerms);
        all.UnionWith(groupPerms);
        return all;
    }

    public async Task<IReadOnlySet<string>> GetEffectiveRolesAsync(Guid userId, CancellationToken ct = default)
    {
        var userRoles = await _db.UserRoles
            .Where(ur => ur.UserId == userId)
            .Select(ur => ur.Role.Name)
            .ToListAsync(ct);

        var groupRoles = await _db.UserGroups
            .Where(ug => ug.UserId == userId)
            .SelectMany(ug => ug.Group.GroupRoles)
            .Select(gr => gr.Role.Name)
            .ToListAsync(ct);

        var all = new HashSet<string>(userRoles);
        all.UnionWith(groupRoles);
        return all;
    }

    public async Task<bool> HasPermissionAsync(Guid userId, string permissionCode, CancellationToken ct = default)
    {
        var perms = await GetEffectivePermissionsAsync(userId, ct);

        // GlobalAdmin has all permissions
        var roles = await GetEffectiveRolesAsync(userId, ct);
        if (roles.Contains("GlobalAdmin")) return true;

        // Check wildcard: "vault.*" matches "vault.credential.checkout"
        return perms.Contains(permissionCode) ||
               perms.Any(p => p.EndsWith(".*") && permissionCode.StartsWith(p[..^2]));
    }
}
