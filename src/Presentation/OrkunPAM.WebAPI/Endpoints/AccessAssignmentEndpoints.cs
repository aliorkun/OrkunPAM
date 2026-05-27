using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Access;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class AccessAssignmentEndpoints
{
    public static void MapAccessAssignmentEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/access-assignments").WithTags("AccessAssignment").RequireAuthorization();

        // List all access assignments (admin)
        group.MapGet("/", async (OrkunPamDbContext db, PrincipalType? principalType,
            Guid? principalId, Guid? targetId, int page = 1, int pageSize = 50) =>
        {
            var query = db.AccessAssignments.AsQueryable();
            if (principalType.HasValue) query = query.Where(a => a.PrincipalType == principalType.Value);
            if (principalId.HasValue) query = query.Where(a => a.PrincipalId == principalId.Value);
            if (targetId.HasValue) query = query.Where(a => a.TargetId == targetId.Value);

            var total = await query.CountAsync();
            var list = await query
                .OrderByDescending(a => a.CreatedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(a => new
                {
                    a.Id,
                    PrincipalType = a.PrincipalType.ToString(),
                    a.PrincipalId,
                    TargetType = a.TargetType.ToString(),
                    a.TargetId,
                    a.CredentialId,
                    Protocol = a.Protocol.HasValue ? a.Protocol.Value.ToString() : null,
                    a.TimeWindowJson,
                    a.ValidFromUtc, a.ValidUntilUtc,
                    a.SessionPolicyId,
                    a.IsEnabled,
                    a.Description,
                    a.CreatedAtUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        // Create access assignment
        group.MapPost("/", async (CreateAccessAssignmentRequest req, OrkunPamDbContext db) =>
        {
            var assignment = new AccessAssignment
            {
                PrincipalType = req.PrincipalType,
                PrincipalId = req.PrincipalId,
                TargetType = req.TargetType,
                TargetId = req.TargetId,
                CredentialId = req.CredentialId,
                Protocol = req.Protocol,
                TimeWindowJson = req.TimeWindowJson,
                ValidFromUtc = req.ValidFromUtc,
                ValidUntilUtc = req.ValidUntilUtc,
                SessionPolicyId = req.SessionPolicyId,
                IsEnabled = true,
                Description = req.Description
            };

            db.AccessAssignments.Add(assignment);
            await db.SaveChangesAsync();

            return Results.Created($"/api/v1/access-assignments/{assignment.Id}",
                new { success = true, data = new { assignment.Id } });
        });

        // Delete access assignment
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var assignment = await db.AccessAssignments.FindAsync(id);
            if (assignment == null)
                return Results.NotFound(new { success = false, errors = new[] { "Access assignment not found" } });

            db.AccessAssignments.Remove(assignment);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Toggle enable/disable
        group.MapPost("/{id:guid}/toggle", async (Guid id, OrkunPamDbContext db) =>
        {
            var assignment = await db.AccessAssignments.FindAsync(id);
            if (assignment == null)
                return Results.NotFound(new { success = false, errors = new[] { "Access assignment not found" } });

            assignment.IsEnabled = !assignment.IsEnabled;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { assignment.Id, assignment.IsEnabled } });
        });

        // My accessible devices — what the current user can connect to
        group.MapGet("/my-devices", async (OrkunPamDbContext db, HttpContext context) =>
        {
            var userIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userIdStr == null || !Guid.TryParse(userIdStr, out var userId))
                return Results.Unauthorized();

            var userGroupIds = await db.UserGroups
                .Where(ug => ug.UserId == userId)
                .Select(ug => ug.GroupId)
                .ToListAsync();

            var now = DateTime.UtcNow;
            var assignments = await db.AccessAssignments
                .Where(a => a.IsEnabled
                    && (a.ValidFromUtc == null || a.ValidFromUtc <= now)
                    && (a.ValidUntilUtc == null || a.ValidUntilUtc >= now)
                    && ((a.PrincipalType == PrincipalType.User && a.PrincipalId == userId)
                        || (a.PrincipalType == PrincipalType.Group && userGroupIds.Contains(a.PrincipalId))))
                .ToListAsync();

            // Resolve device IDs from assignments
            var directDeviceIds = assignments
                .Where(a => a.TargetType == AccessTargetType.Device)
                .Select(a => a.TargetId)
                .ToHashSet();

            var deviceGroupIds = assignments
                .Where(a => a.TargetType == AccessTargetType.DeviceGroup)
                .Select(a => a.TargetId)
                .ToHashSet();

            var groupDeviceIds = await db.DeviceGroupMembers
                .Where(dgm => deviceGroupIds.Contains(dgm.DeviceGroupId))
                .Select(dgm => dgm.DeviceId)
                .ToListAsync();

            var allDeviceIds = directDeviceIds.Union(groupDeviceIds).ToList();

            var devices = await db.Devices
                .Where(d => allDeviceIds.Contains(d.Id) && d.Status == DeviceStatus.Active)
                .Select(d => new
                {
                    d.Id,
                    d.Hostname,
                    d.Fqdn,
                    d.IpAddress,
                    Type = d.DeviceType.ToString(),
                    Protocol = d.ConnectionProtocol.ToString(),
                    d.ConnectionPort,
                    d.OperatingSystem,
                    Status = d.Status.ToString(),
                    d.IsReachable,
                    d.IsManaged
                }).ToListAsync();

            // Enrich with available credentials per device (in-memory)
            var result = devices.Select(d => new
            {
                d.Id, d.Hostname, d.Fqdn, d.IpAddress, d.Type, d.Protocol,
                d.ConnectionPort, d.OperatingSystem, d.Status, d.IsReachable, d.IsManaged,
                Credentials = assignments
                    .Where(a =>
                        (a.TargetType == AccessTargetType.Device && a.TargetId == d.Id)
                        || (a.TargetType == AccessTargetType.DeviceGroup && deviceGroupIds.Contains(a.TargetId)))
                    .Select(a => new { a.CredentialId, Protocol = a.Protocol?.ToString(), a.SessionPolicyId })
                    .Distinct()
                    .ToList()
            }).ToList();

            return Results.Ok(new { success = true, data = result });
        });
    }

    /// <summary>
    /// Checks whether a user has an active AccessAssignment for a given device + credential.
    /// Called from SessionEndpoints during session creation.
    /// </summary>
    public static async Task<bool> HasAccessAssignmentAsync(
        OrkunPamDbContext db, Guid userId, Guid deviceId, Guid credentialId)
    {
        var userGroupIds = await db.UserGroups
            .Where(ug => ug.UserId == userId)
            .Select(ug => ug.GroupId)
            .ToListAsync();

        // Find device's group memberships
        var deviceGroupIds = await db.DeviceGroupMembers
            .Where(dgm => dgm.DeviceId == deviceId)
            .Select(dgm => dgm.DeviceGroupId)
            .ToListAsync();

        var now = DateTime.UtcNow;

        // Fetch matching assignments without TimeWindowJson filter (EF Core cannot translate it).
        var candidates = await db.AccessAssignments
            .Where(a =>
                a.IsEnabled
                && a.CredentialId == credentialId
                && (a.ValidFromUtc == null || a.ValidFromUtc <= now)
                && (a.ValidUntilUtc == null || a.ValidUntilUtc >= now)
                && ((a.PrincipalType == PrincipalType.User && a.PrincipalId == userId)
                    || (a.PrincipalType == PrincipalType.Group && userGroupIds.Contains(a.PrincipalId)))
                && ((a.TargetType == AccessTargetType.Device && a.TargetId == deviceId)
                    || (a.TargetType == AccessTargetType.DeviceGroup && deviceGroupIds.Contains(a.TargetId))))
            .ToListAsync();

        // Enforce per-assignment time-window restrictions in memory.
        return candidates.Any(a =>
            string.IsNullOrEmpty(a.TimeWindowJson)
            || AccessPolicyEngine.IsWithinTimeWindowsJson(now, a.TimeWindowJson));
    }
}

public record CreateAccessAssignmentRequest(
    PrincipalType PrincipalType, Guid PrincipalId,
    AccessTargetType TargetType, Guid TargetId,
    Guid CredentialId,
    ConnectionProtocol? Protocol,
    string? TimeWindowJson,
    DateTime? ValidFromUtc, DateTime? ValidUntilUtc,
    Guid? SessionPolicyId,
    string? Description);
