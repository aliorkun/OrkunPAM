using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class DeviceEndpoints
{
    public static void MapDeviceEndpoints(this IEndpointRouteBuilder app)
    {
        var devices = app.MapGroup("/api/v1/devices").WithTags("Devices");

        devices.MapGet("/", async (OrkunPamDbContext db, HttpContext context, string? search, string? type, int page = 1, int pageSize = 50) =>
        {
            var callerIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isAdmin = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("VaultAdmin")
                || context.User.IsInRole("SessionAdmin") || context.User.IsInRole("DeviceAdmin");

            var query = db.Devices.AsQueryable();

            if (!isAdmin)
            {
                if (callerIdStr == null || !Guid.TryParse(callerIdStr, out var callerId))
                    return Results.Unauthorized();
                var accessibleIds = await DeviceRealmEndpoints.GetAccessibleDeviceIdsAsync(db, callerId);
                query = query.Where(d => accessibleIds.Contains(d.Id));
            }

            if (!string.IsNullOrEmpty(search))
                query = query.Where(d => d.Hostname.Contains(search) || d.IpAddress!.Contains(search) || d.Fqdn!.Contains(search));

            if (!string.IsNullOrEmpty(type) && Enum.TryParse<DeviceType>(type, true, out var dt))
                query = query.Where(d => d.DeviceType == dt);

            var total = await query.CountAsync();
            var list = await query
                .OrderBy(d => d.Hostname)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(d => new
                {
                    d.Id, d.Hostname, d.Fqdn, d.IpAddress,
                    Type = d.DeviceType.ToString(),
                    Protocol = d.ConnectionProtocol.ToString(),
                    d.ConnectionPort, d.OperatingSystem,
                    Status = d.Status.ToString(),
                    d.IsReachable, d.LastReachableCheck,
                    d.Tags, d.IsManaged,
                    d.SshHostKeyFingerprint,
                    CredentialCount = d.DeviceCredentials.Count,
                    d.NetworkZoneId,
                    NetworkZoneName = d.NetworkZone != null ? d.NetworkZone.Name : null,
                    JumpHostAddress = d.NetworkZone != null ? d.NetworkZone.JumpHostAddress : null,
                    JumpHostCredentialId = d.NetworkZone != null ? d.NetworkZone.JumpHostCredentialId : null,
                    JumpHostFingerprint = d.NetworkZone != null ? d.NetworkZone.JumpHostFingerprint : null
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        devices.MapPost("/", async (CreateDeviceRequest req, OrkunPamDbContext db) =>
        {
            var device = new Device
            {
                Hostname = req.Hostname,
                Fqdn = req.Fqdn,
                IpAddress = req.IpAddress,
                DeviceType = req.DeviceType,
                ConnectionProtocol = req.Protocol,
                ConnectionPort = req.Port,
                OperatingSystem = req.OperatingSystem,
                Tags = req.Tags,
                Notes = req.Notes,
                PlatformId = req.PlatformId,
                NetworkZoneId = req.NetworkZoneId
            };

            db.Devices.Add(device);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/devices/{device.Id}",
                new { success = true, data = new { device.Id, device.Hostname, device.IpAddress } });
        }).RequireAuthorization("AdminPolicy");

        devices.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db, HttpContext context) =>
        {
            var d = await db.Devices
                .Include(d => d.DeviceCredentials)
                .Include(d => d.DeviceGroupMembers).ThenInclude(m => m.DeviceGroup)
                .FirstOrDefaultAsync(d => d.Id == id);

            if (d == null) return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            var isAdmin = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("VaultAdmin")
                || context.User.IsInRole("SessionAdmin") || context.User.IsInRole("DeviceAdmin");
            if (!isAdmin)
            {
                var callerIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
                if (callerIdStr == null || !Guid.TryParse(callerIdStr, out var callerId))
                    return Results.Unauthorized();
                var accessible = await DeviceRealmEndpoints.GetAccessibleDeviceIdsAsync(db, callerId);
                if (!accessible.Contains(id))
                    return Results.Forbid();
            }

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    d.Id, d.Hostname, d.Fqdn, d.IpAddress,
                    Type = d.DeviceType.ToString(),
                    Protocol = d.ConnectionProtocol.ToString(),
                    d.ConnectionPort, d.OperatingSystem,
                    Status = d.Status.ToString(),
                    d.IsReachable, d.LastReachableCheck,
                    d.Tags, d.Notes, d.IsManaged,
                    ImportSource = d.ImportSource.ToString(),
                    d.CreatedAtUtc, d.UpdatedAtUtc,
                    Groups = d.DeviceGroupMembers.Select(m => new { m.DeviceGroup.Id, m.DeviceGroup.Name }),
                    Credentials = d.DeviceCredentials.Select(dc => new
                    {
                        dc.CredentialId,
                        Purpose = dc.Purpose.ToString(),
                        dc.IsPrimary
                    })
                }
            });
        });

        devices.MapPut("/{id:guid}", async (Guid id, UpdateDeviceRequest req, OrkunPamDbContext db) =>
        {
            var d = await db.Devices.FindAsync(id);
            if (d == null) return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            if (req.Hostname != null) d.Hostname = req.Hostname;
            if (req.IpAddress != null) d.IpAddress = req.IpAddress;
            if (req.Fqdn != null) d.Fqdn = req.Fqdn;
            if (req.OperatingSystem != null) d.OperatingSystem = req.OperatingSystem;
            if (req.Tags != null) d.Tags = req.Tags;
            if (req.Notes != null) d.Notes = req.Notes;
            if (req.Port.HasValue) d.ConnectionPort = req.Port.Value;
            if (req.Status.HasValue) d.Status = req.Status.Value;
            if (req.NetworkZoneId.HasValue) d.NetworkZoneId = req.NetworkZoneId == Guid.Empty ? null : req.NetworkZoneId;

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { d.Id, d.Hostname } });
        }).RequireAuthorization("AdminPolicy");

        devices.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var d = await db.Devices.FindAsync(id);
            if (d == null) return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });
            db.Devices.Remove(d);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminPolicy");

        devices.MapGet("/{id:guid}/credentials", async (Guid id, OrkunPamDbContext db, HttpContext context) =>
        {
            if (!await db.Devices.AnyAsync(d => d.Id == id))
                return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            var callerIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isAdmin = context.User.IsInRole("GlobalAdmin") || context.User.IsInRole("VaultAdmin")
                || context.User.IsInRole("SessionAdmin") || context.User.IsInRole("DeviceAdmin");

            if (!isAdmin)
            {
                if (callerIdStr == null || !Guid.TryParse(callerIdStr, out var callerId))
                    return Results.Unauthorized();

                var isRealmCovered = await DeviceRealmEndpoints.IsDeviceCoveredByRealmAsync(db, id);
                if (isRealmCovered)
                {
                    if (!await DeviceRealmEndpoints.HasRealmAccessAsync(db, callerId, id))
                        return Results.Forbid();
                }
                else
                {
                    var credIds = await db.DeviceCredentials
                        .Where(dc => dc.DeviceId == id)
                        .Select(dc => dc.CredentialId)
                        .ToListAsync();

                    var hasAnyAccess = false;
                    foreach (var credId in credIds)
                    {
                        if (await AccessAssignmentEndpoints.HasAccessAssignmentAsync(db, callerId, id, credId))
                        {
                            hasAnyAccess = true;
                            break;
                        }
                    }

                    if (!hasAnyAccess)
                        return Results.Forbid();
                }
            }

            var list = await db.DeviceCredentials
                .Where(dc => dc.DeviceId == id)
                .Join(db.Credentials, dc => dc.CredentialId, c => c.Id, (dc, c) => new
                {
                    c.Id,
                    c.Name,
                    c.Username,
                    Type = c.CredentialType.ToString(),
                    Purpose = dc.Purpose.ToString(),
                    dc.IsPrimary
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list });
        });

        devices.MapPost("/{id:guid}/credentials", async (Guid id, LinkCredentialRequest req, OrkunPamDbContext db) =>
        {
            if (!await db.Devices.AnyAsync(d => d.Id == id))
                return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            if (await db.DeviceCredentials.AnyAsync(dc => dc.DeviceId == id && dc.CredentialId == req.CredentialId))
                return Results.Conflict(new { success = false, errors = new[] { "Credential already linked" } });

            db.DeviceCredentials.Add(new DeviceCredential
            {
                DeviceId = id,
                CredentialId = req.CredentialId,
                Purpose = req.Purpose,
                IsPrimary = req.IsPrimary
            });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminPolicy");

        devices.MapDelete("/{id:guid}/credentials/{credentialId:guid}", async (Guid id, Guid credentialId, OrkunPamDbContext db) =>
        {
            var dc = await db.DeviceCredentials
                .FirstOrDefaultAsync(dc => dc.DeviceId == id && dc.CredentialId == credentialId);
            if (dc == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential assignment not found" } });

            db.DeviceCredentials.Remove(dc);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        }).RequireAuthorization("AdminPolicy");

        // Proxy-only endpoint: store SSH host key fingerprint (TOFU) — requires X-Proxy-Secret
        devices.MapPost("/{id:guid}/ssh-fingerprint", async (Guid id, SshFingerprintRequest req,
            OrkunPamDbContext db, IConfiguration config, HttpContext context) =>
        {
            var expectedSecret = config["ProxyService:Secret"];
            var providedSecret = context.Request.Headers["X-Proxy-Secret"].FirstOrDefault();
            if (string.IsNullOrEmpty(expectedSecret) || providedSecret != expectedSecret)
                return Results.Forbid();

            var d = await db.Devices.FindAsync(id);
            if (d == null)
                return Results.NotFound(new { success = false, errors = new[] { "Device not found" } });

            d.SshHostKeyFingerprint = req.Fingerprint;
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        }).AllowAnonymous(); // auth replaced by X-Proxy-Secret header check above

        var groups = app.MapGroup("/api/v1/device-groups").WithTags("Devices");

        groups.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.DeviceGroups
                .Select(g => new
                {
                    g.Id, g.Name,
                    Type = g.GroupType.ToString(),
                    g.VlanId, g.SubnetCidr, g.ParentGroupId,
                    MemberCount = g.Members.Count
                }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        groups.MapPost("/", async (CreateDeviceGroupRequest req, OrkunPamDbContext db) =>
        {
            var g = new DeviceGroup
            {
                Name = req.Name,
                GroupType = req.GroupType,
                VlanId = req.VlanId,
                SubnetCidr = req.SubnetCidr,
                ParentGroupId = req.ParentGroupId
            };
            db.DeviceGroups.Add(g);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/device-groups/{g.Id}", new { success = true, data = new { g.Id, g.Name } });
        }).RequireAuthorization("AdminPolicy");

        groups.MapPost("/{id:guid}/members", async (Guid id, AddDeviceGroupMembersRequest req, OrkunPamDbContext db) =>
        {
            var added = 0;
            foreach (var deviceId in req.DeviceIds)
            {
                if (await db.DeviceGroupMembers.AnyAsync(m => m.DeviceGroupId == id && m.DeviceId == deviceId))
                    continue;
                db.DeviceGroupMembers.Add(new DeviceGroupMember { DeviceGroupId = id, DeviceId = deviceId });
                added++;
            }
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, message = $"{added} device(s) added" });
        }).RequireAuthorization("AdminPolicy");

        var platforms = app.MapGroup("/api/v1/platforms").WithTags("Devices");

        platforms.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.Platforms.Select(p => new
            {
                p.Id, p.Name,
                Protocol = p.DefaultProtocol.ToString(),
                p.DefaultPort, p.RotationConnector
            }).ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        platforms.MapPost("/", async (CreatePlatformRequest req, OrkunPamDbContext db) =>
        {
            var p = new Platform
            {
                Name = req.Name,
                DefaultProtocol = req.Protocol,
                DefaultPort = req.Port,
                RotationConnector = req.RotationConnector,
                ConnectionTemplateJson = req.ConnectionTemplate
            };
            db.Platforms.Add(p);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/platforms/{p.Id}", new { success = true, data = new { p.Id, p.Name } });
        }).RequireAuthorization("AdminPolicy");
    }
}

public record CreateDeviceRequest(string Hostname, string? Fqdn, string? IpAddress,
    DeviceType DeviceType, ConnectionProtocol Protocol, int? Port,
    string? OperatingSystem, string? Tags, string? Notes, Guid? PlatformId, Guid? NetworkZoneId);
public record UpdateDeviceRequest(string? Hostname, string? IpAddress, string? Fqdn,
    string? OperatingSystem, string? Tags, string? Notes, int? Port, DeviceStatus? Status, Guid? NetworkZoneId);
public record LinkCredentialRequest(Guid CredentialId, CredentialPurpose Purpose, bool IsPrimary);
public record CreateDeviceGroupRequest(string Name, DeviceGroupType GroupType, int? VlanId, string? SubnetCidr, Guid? ParentGroupId);
public record AddDeviceGroupMembersRequest(Guid[] DeviceIds);
public record CreatePlatformRequest(string Name, ConnectionProtocol Protocol, int Port, string? RotationConnector, string? ConnectionTemplate);
public record SshFingerprintRequest(string Fingerprint);
