using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Access;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class DeviceRealmEndpoints
{
    public static void MapDeviceRealmEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/device-realms")
            .WithTags("DeviceRealm")
            .RequireAuthorization("AdminPolicy");

        // List all realms
        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var realms = await db.DeviceRealms
                .Include(r => r.UserGroups).ThenInclude(ug => ug.UserGroup)
                .Include(r => r.DeviceGroups).ThenInclude(dg => dg.DeviceGroup)
                .OrderBy(r => r.Name)
                .Select(r => new
                {
                    r.Id, r.Name, r.Description, r.IsEnabled, r.SessionPolicyId,
                    r.CreatedAtUtc, r.UpdatedAtUtc,
                    UserGroups = r.UserGroups.Select(ug => new { ug.UserGroupId, ug.UserGroup.Name }).ToList(),
                    DeviceGroups = r.DeviceGroups.Select(dg => new { dg.DeviceGroupId, dg.DeviceGroup.Name }).ToList()
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = realms });
        });

        // Get single realm
        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var realm = await db.DeviceRealms
                .Include(r => r.UserGroups).ThenInclude(ug => ug.UserGroup)
                .Include(r => r.DeviceGroups).ThenInclude(dg => dg.DeviceGroup)
                .Where(r => r.Id == id)
                .Select(r => new
                {
                    r.Id, r.Name, r.Description, r.IsEnabled, r.SessionPolicyId,
                    r.CreatedAtUtc, r.UpdatedAtUtc,
                    UserGroups = r.UserGroups.Select(ug => new { ug.UserGroupId, ug.UserGroup.Name }).ToList(),
                    DeviceGroups = r.DeviceGroups.Select(dg => new { dg.DeviceGroupId, dg.DeviceGroup.Name }).ToList()
                })
                .FirstOrDefaultAsync();

            if (realm == null)
                return Results.NotFound(new { success = false, errors = new[] { "Realm not found" } });

            return Results.Ok(new { success = true, data = realm });
        });

        // Create realm
        group.MapPost("/", async (CreateDeviceRealmRequest req, OrkunPamDbContext db) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            if (await db.DeviceRealms.AnyAsync(r => r.Name == req.Name))
                return Results.Conflict(new { success = false, errors = new[] { "Realm name already exists" } });

            var realm = new DeviceRealm
            {
                Name = req.Name.Trim(),
                Description = req.Description,
                IsEnabled = true,
                SessionPolicyId = req.SessionPolicyId
            };

            db.DeviceRealms.Add(realm);
            await db.SaveChangesAsync();

            return Results.Created("/api/v1/device-realms/" + realm.Id,
                new { success = true, data = new { realm.Id, realm.Name } });
        });

        // Update realm
        group.MapPut("/{id:guid}", async (Guid id, UpdateDeviceRealmRequest req, OrkunPamDbContext db) =>
        {
            var realm = await db.DeviceRealms.FindAsync(id);
            if (realm == null)
                return Results.NotFound(new { success = false, errors = new[] { "Realm not found" } });

            if (!string.IsNullOrWhiteSpace(req.Name) && req.Name != realm.Name
                && await db.DeviceRealms.AnyAsync(r => r.Name == req.Name && r.Id != id))
                return Results.Conflict(new { success = false, errors = new[] { "Realm name already exists" } });

            if (!string.IsNullOrWhiteSpace(req.Name)) realm.Name = req.Name.Trim();
            realm.Description = req.Description;
            realm.SessionPolicyId = req.SessionPolicyId;

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Toggle enable/disable
        group.MapPost("/{id:guid}/toggle", async (Guid id, OrkunPamDbContext db) =>
        {
            var realm = await db.DeviceRealms.FindAsync(id);
            if (realm == null)
                return Results.NotFound(new { success = false, errors = new[] { "Realm not found" } });

            realm.IsEnabled = !realm.IsEnabled;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { realm.Id, realm.IsEnabled } });
        });

        // Delete realm
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var realm = await db.DeviceRealms.FindAsync(id);
            if (realm == null)
                return Results.NotFound(new { success = false, errors = new[] { "Realm not found" } });

            db.DeviceRealms.Remove(realm);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Add user group to realm
        group.MapPost("/{id:guid}/user-groups", async (Guid id, AddGroupToRealmRequest req, OrkunPamDbContext db) =>
        {
            if (!await db.DeviceRealms.AnyAsync(r => r.Id == id))
                return Results.NotFound(new { success = false, errors = new[] { "Realm not found" } });

            if (!await db.Groups.AnyAsync(g => g.Id == req.GroupId))
                return Results.NotFound(new { success = false, errors = new[] { "Group not found" } });

            if (await db.DeviceRealmUserGroups.AnyAsync(rg => rg.DeviceRealmId == id && rg.UserGroupId == req.GroupId))
                return Results.Ok(new { success = true }); // already member

            db.DeviceRealmUserGroups.Add(new DeviceRealmUserGroup
            {
                DeviceRealmId = id,
                UserGroupId = req.GroupId
            });

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Remove user group from realm
        group.MapDelete("/{id:guid}/user-groups/{groupId:guid}", async (Guid id, Guid groupId, OrkunPamDbContext db) =>
        {
            var link = await db.DeviceRealmUserGroups
                .FirstOrDefaultAsync(rg => rg.DeviceRealmId == id && rg.UserGroupId == groupId);
            if (link == null)
                return Results.NotFound(new { success = false, errors = new[] { "Membership not found" } });

            db.DeviceRealmUserGroups.Remove(link);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Add device group to realm
        group.MapPost("/{id:guid}/device-groups", async (Guid id, AddGroupToRealmRequest req, OrkunPamDbContext db) =>
        {
            if (!await db.DeviceRealms.AnyAsync(r => r.Id == id))
                return Results.NotFound(new { success = false, errors = new[] { "Realm not found" } });

            if (!await db.DeviceGroups.AnyAsync(g => g.Id == req.GroupId))
                return Results.NotFound(new { success = false, errors = new[] { "Device group not found" } });

            if (await db.DeviceRealmDeviceGroups.AnyAsync(rg => rg.DeviceRealmId == id && rg.DeviceGroupId == req.GroupId))
                return Results.Ok(new { success = true }); // already member

            db.DeviceRealmDeviceGroups.Add(new DeviceRealmDeviceGroup
            {
                DeviceRealmId = id,
                DeviceGroupId = req.GroupId
            });

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Remove device group from realm
        group.MapDelete("/{id:guid}/device-groups/{groupId:guid}", async (Guid id, Guid groupId, OrkunPamDbContext db) =>
        {
            var link = await db.DeviceRealmDeviceGroups
                .FirstOrDefaultAsync(rg => rg.DeviceRealmId == id && rg.DeviceGroupId == groupId);
            if (link == null)
                return Results.NotFound(new { success = false, errors = new[] { "Membership not found" } });

            db.DeviceRealmDeviceGroups.Remove(link);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // My accessible realms — realms where the current user's group membership grants access
        app.MapGet("/api/v1/device-realms/my-access", async (OrkunPamDbContext db, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var userGroupIds = await db.UserGroups
                .Where(ug => ug.UserId == userId)
                .Select(ug => ug.GroupId)
                .ToListAsync();

            var realms = await db.DeviceRealms
                .Where(r => r.IsEnabled && r.UserGroups.Any(ug => userGroupIds.Contains(ug.UserGroupId)))
                .Include(r => r.DeviceGroups).ThenInclude(dg => dg.DeviceGroup)
                .Select(r => new
                {
                    r.Id, r.Name, r.Description, r.SessionPolicyId,
                    DeviceGroups = r.DeviceGroups.Select(dg => new { dg.DeviceGroupId, dg.DeviceGroup.Name }).ToList()
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = realms });
        }).RequireAuthorization();

        // Accessible devices — devices in realm-accessible device groups for the current user.
        // Admins see all devices. Non-admins see only devices in device groups covered by their realm membership.
        // Falls back to all devices when no realm covers any device (empty realm configuration).
        app.MapGet("/api/v1/device-realms/accessible-devices", async (OrkunPamDbContext db, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var isAdmin = context.User.IsInRole("GlobalAdmin")
                       || context.User.IsInRole("VaultAdmin")
                       || context.User.IsInRole("SessionAdmin");

            IQueryable<OrkunPAM.Domain.Entities.Device.Device> query;

            if (isAdmin)
            {
                query = db.Devices;
            }
            else
            {
                // Check if any realm has device group assignments (realm feature is in use)
                var anyRealmDeviceGroup = await db.DeviceRealms
                    .AnyAsync(r => r.IsEnabled && r.DeviceGroups.Any());

                if (!anyRealmDeviceGroup)
                {
                    // Realm not configured yet — show all devices (backward compatible)
                    query = db.Devices;
                }
                else
                {
                    var userGroupIds = await db.UserGroups
                        .Where(ug => ug.UserId == userId)
                        .Select(ug => ug.GroupId)
                        .ToListAsync();

                    var realmDeviceGroupIds = await db.DeviceRealms
                        .Where(r => r.IsEnabled && r.UserGroups.Any(ug => userGroupIds.Contains(ug.UserGroupId)))
                        .SelectMany(r => r.DeviceGroups.Select(dg => dg.DeviceGroupId))
                        .Distinct()
                        .ToListAsync();

                    var accessibleDeviceIds = await db.DeviceGroupMembers
                        .Where(dgm => realmDeviceGroupIds.Contains(dgm.DeviceGroupId))
                        .Select(dgm => dgm.DeviceId)
                        .Distinct()
                        .ToListAsync();

                    query = db.Devices.Where(d => accessibleDeviceIds.Contains(d.Id));
                }
            }

            var devices = await query
                .OrderBy(d => d.Hostname)
                .Select(d => new
                {
                    Id       = d.Id.ToString(),
                    d.Hostname,
                    d.Fqdn,
                    d.IpAddress,
                    Type     = d.DeviceType.ToString(),
                    Protocol = d.ConnectionProtocol.ToString(),
                    d.ConnectionPort,
                    d.OperatingSystem,
                    Status   = d.Status.ToString(),
                    d.IsReachable,
                    d.IsManaged,
                    CredentialCount = db.Credentials.Count(c => c.DeviceId == d.Id),
                    d.NetworkZoneId,
                    NetworkZoneName = d.NetworkZone != null ? d.NetworkZone.Name : null
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = devices });
        }).RequireAuthorization();
    }

    /// <summary>
    /// Returns true if any enabled realm contains a device group that the given device belongs to.
    /// When false, the realm feature is not covering this device → fall back to legacy AccessAssignment.
    /// </summary>
    public static async Task<bool> IsDeviceCoveredByRealmAsync(OrkunPamDbContext db, Guid deviceId)
    {
        var deviceGroupIds = await db.DeviceGroupMembers
            .Where(dgm => dgm.DeviceId == deviceId)
            .Select(dgm => dgm.DeviceGroupId)
            .ToListAsync();

        if (deviceGroupIds.Count == 0) return false;

        return await db.DeviceRealms
            .AnyAsync(r => r.IsEnabled && r.DeviceGroups.Any(dg => deviceGroupIds.Contains(dg.DeviceGroupId)));
    }

    /// <summary>
    /// Returns true if the user's group membership grants access to the device via an enabled realm.
    /// </summary>
    public static async Task<bool> HasRealmAccessAsync(OrkunPamDbContext db, Guid userId, Guid deviceId)
    {
        var userGroupIds = await db.UserGroups
            .Where(ug => ug.UserId == userId)
            .Select(ug => ug.GroupId)
            .ToListAsync();

        var deviceGroupIds = await db.DeviceGroupMembers
            .Where(dgm => dgm.DeviceId == deviceId)
            .Select(dgm => dgm.DeviceGroupId)
            .ToListAsync();

        if (deviceGroupIds.Count == 0 || userGroupIds.Count == 0) return false;

        return await db.DeviceRealms
            .AnyAsync(r => r.IsEnabled
                && r.UserGroups.Any(ug => userGroupIds.Contains(ug.UserGroupId))
                && r.DeviceGroups.Any(dg => deviceGroupIds.Contains(dg.DeviceGroupId)));
    }
}

public record CreateDeviceRealmRequest(string Name, string? Description, Guid? SessionPolicyId);
public record UpdateDeviceRealmRequest(string? Name, string? Description, Guid? SessionPolicyId);
public record AddGroupToRealmRequest(Guid GroupId);
