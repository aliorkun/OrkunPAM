using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class NetworkZoneEndpoints
{
    public static void MapNetworkZoneEndpoints(this IEndpointRouteBuilder app)
    {
        var zones = app.MapGroup("/api/v1/system/network-zones").WithTags("NetworkZones")
            .RequireAuthorization("AdminPolicy");

        zones.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.NetworkZones
                .Select(z => new
                {
                    z.Id, z.Name, z.Description, z.IpRangesJson,
                    z.JumpHostAddress, z.JumpHostCredentialId, z.JumpHostFingerprint,
                    z.ProxyBindAddress, z.IsDefault, z.Notes,
                    DeviceCount = db.Devices.Count(d => d.NetworkZoneId == z.Id)
                })
                .OrderBy(z => z.Name)
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        zones.MapPost("/", async (CreateNetworkZoneRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            if (await db.NetworkZones.AnyAsync(z => z.Name == req.Name))
                return Results.Conflict(new { success = false, errors = new[] { "Zone name already exists" } });

            if (req.IsDefault)
                await db.NetworkZones.Where(z => z.IsDefault).ForEachAsync(z => z.IsDefault = false);

            var zone = new NetworkZone
            {
                Name                = req.Name.Trim(),
                Description         = req.Description?.Trim(),
                IpRangesJson        = req.IpRangesJson,
                JumpHostAddress     = req.JumpHostAddress?.Trim(),
                JumpHostCredentialId = req.JumpHostCredentialId,
                JumpHostFingerprint = req.JumpHostFingerprint?.Trim(),
                ProxyBindAddress    = req.ProxyBindAddress?.Trim(),
                IsDefault           = req.IsDefault,
                Notes               = req.Notes?.Trim()
            };
            db.NetworkZones.Add(zone);
            await db.SaveChangesAsync();

            var userId = ctx.User.FindFirst("sub")?.Value;
            if (userId != null)
                await audit.LogAsync("System", "NETWORK_ZONE_CREATED", Guid.TryParse(userId, out var uid) ? uid : null, null, ctx.Connection.RemoteIpAddress?.ToString(),
                    "NetworkZone", zone.Id.ToString(), $"Zone '{zone.Name}' created");

            return Results.Created($"/api/v1/system/network-zones/{zone.Id}",
                new { success = true, data = new { zone.Id, zone.Name } });
        });

        zones.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var z = await db.NetworkZones.FindAsync(id);
            if (z == null) return Results.NotFound(new { success = false, errors = new[] { "Zone not found" } });
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    z.Id, z.Name, z.Description, z.IpRangesJson,
                    z.JumpHostAddress, z.JumpHostCredentialId, z.JumpHostFingerprint,
                    z.ProxyBindAddress, z.IsDefault, z.Notes,
                    z.CreatedAtUtc, z.UpdatedAtUtc
                }
            });
        });

        zones.MapPut("/{id:guid}", async (Guid id, UpdateNetworkZoneRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var z = await db.NetworkZones.FindAsync(id);
            if (z == null) return Results.NotFound(new { success = false, errors = new[] { "Zone not found" } });

            if (!string.IsNullOrWhiteSpace(req.Name)) z.Name = req.Name.Trim();
            if (req.Description != null) z.Description = req.Description.Trim();
            if (req.IpRangesJson != null) z.IpRangesJson = req.IpRangesJson;
            if (req.JumpHostAddress != null) z.JumpHostAddress = string.IsNullOrWhiteSpace(req.JumpHostAddress) ? null : req.JumpHostAddress.Trim();
            if (req.JumpHostCredentialId.HasValue) z.JumpHostCredentialId = req.JumpHostCredentialId;
            if (req.JumpHostFingerprint != null) z.JumpHostFingerprint = string.IsNullOrWhiteSpace(req.JumpHostFingerprint) ? null : req.JumpHostFingerprint.Trim();
            if (req.ProxyBindAddress != null) z.ProxyBindAddress = req.ProxyBindAddress.Trim();
            if (req.Notes != null) z.Notes = req.Notes.Trim();
            if (req.IsDefault.HasValue && req.IsDefault.Value)
            {
                await db.NetworkZones.Where(x => x.IsDefault && x.Id != id).ForEachAsync(x => x.IsDefault = false);
                z.IsDefault = true;
            }

            await db.SaveChangesAsync();

            var userId = ctx.User.FindFirst("sub")?.Value;
            if (userId != null)
                await audit.LogAsync("System", "NETWORK_ZONE_UPDATED", Guid.TryParse(userId, out var uid2) ? uid2 : null, null, ctx.Connection.RemoteIpAddress?.ToString(),
                    "NetworkZone", z.Id.ToString(), $"Zone '{z.Name}' updated");

            return Results.Ok(new { success = true, data = new { z.Id, z.Name } });
        });

        zones.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var z = await db.NetworkZones.FindAsync(id);
            if (z == null) return Results.NotFound(new { success = false, errors = new[] { "Zone not found" } });

            var deviceCount = await db.Devices.CountAsync(d => d.NetworkZoneId == id);
            if (deviceCount > 0)
                return Results.BadRequest(new { success = false, errors = new[] { $"Zone has {deviceCount} devices. Unassign devices first." } });

            db.NetworkZones.Remove(z);
            await db.SaveChangesAsync();

            var userId = ctx.User.FindFirst("sub")?.Value;
            if (userId != null)
                await audit.LogAsync("System", "NETWORK_ZONE_DELETED", Guid.TryParse(userId, out var uid3) ? uid3 : null, null, ctx.Connection.RemoteIpAddress?.ToString(),
                    "NetworkZone", id.ToString(), $"Zone '{z.Name}' deleted");

            return Results.Ok(new { success = true });
        });

        // Store jump host fingerprint (TOFU: called by SSH proxy on first successful connection)
        zones.MapPost("/{id:guid}/jump-fingerprint", async (Guid id, JumpFingerprintRequest req, OrkunPamDbContext db, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Fingerprint))
                return Results.BadRequest(new { success = false, errors = new[] { "Fingerprint is required" } });

            var z = await db.NetworkZones.FindAsync(id);
            if (z == null) return Results.NotFound(new { success = false, errors = new[] { "Zone not found" } });

            z.JumpHostFingerprint = req.Fingerprint.Trim();
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Test zone reachability (jump host ping)
        zones.MapPost("/{id:guid}/test", async (Guid id, OrkunPamDbContext db) =>
        {
            var z = await db.NetworkZones.FindAsync(id);
            if (z == null) return Results.NotFound(new { success = false, errors = new[] { "Zone not found" } });

            if (string.IsNullOrWhiteSpace(z.JumpHostAddress))
                return Results.Ok(new { success = true, data = new { reachable = true, latencyMs = 0, message = "No jump host configured (direct access zone)" } });

            // Parse host:port
            var parts = z.JumpHostAddress.Split(':');
            var host = parts[0];
            int port = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 22;

            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                using var tcp = new System.Net.Sockets.TcpClient();
                using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                await tcp.ConnectAsync(host, port, cts.Token);
                sw.Stop();
                return Results.Ok(new
                {
                    success = true,
                    data = new { reachable = true, latencyMs = (int)sw.ElapsedMilliseconds, message = $"Jump host {host}:{port} is reachable" }
                });
            }
            catch (Exception ex)
            {
                sw.Stop();
                return Results.Ok(new
                {
                    success = true,
                    data = new { reachable = false, latencyMs = (int)sw.ElapsedMilliseconds, message = $"Jump host {host}:{port} unreachable: {ex.Message}" }
                });
            }
        });
    }
}

record CreateNetworkZoneRequest(
    string Name,
    string? Description,
    string? IpRangesJson,
    string? JumpHostAddress,
    Guid? JumpHostCredentialId,
    string? JumpHostFingerprint,
    string? ProxyBindAddress,
    bool IsDefault,
    string? Notes);

record UpdateNetworkZoneRequest(
    string? Name,
    string? Description,
    string? IpRangesJson,
    string? JumpHostAddress,
    Guid? JumpHostCredentialId,
    string? JumpHostFingerprint,
    string? ProxyBindAddress,
    bool? IsDefault,
    string? Notes);

record JumpFingerprintRequest(string Fingerprint);
