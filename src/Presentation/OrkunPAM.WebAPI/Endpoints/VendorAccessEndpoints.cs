using System.Net;
using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Security;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.WebAPI.Endpoints;

public static class VendorAccessEndpoints
{
    public static void MapVendorAccessEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/api/v1/vendor-access").WithTags("VendorAccess").RequireAuthorization();

        // POST /api/v1/vendor-access — create vendor access profile
        grp.MapPost("/", async (CreateVendorAccessRequest req, OrkunPamDbContext db,
            HttpContext ctx, IAuditService audit, IEmailService? email,
            IConfiguration config) =>
        {
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");
            if (!isAdmin) return Results.Forbid();

            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (userId == null || !Guid.TryParse(userId, out var adminId))
                return Results.Unauthorized();

            var adminUsername = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            if (string.IsNullOrWhiteSpace(req.VendorName) || string.IsNullOrWhiteSpace(req.Email))
                return Results.BadRequest(new { success = false, error = "Vendor name and email are required." });

            if (req.EndAtUtc <= req.StartAtUtc)
                return Results.BadRequest(new { success = false, error = "End time must be after start time." });

            var token = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");

            var vendor = new VendorAccess
            {
                VendorName = req.VendorName.Trim(),
                Company = (req.Company ?? string.Empty).Trim(),
                Email = req.Email.Trim().ToLowerInvariant(),
                Phone = req.Phone?.Trim(),
                StartAtUtc = req.StartAtUtc.ToUniversalTime(),
                EndAtUtc = req.EndAtUtc.ToUniversalTime(),
                AllowedHoursStart = req.AllowedHoursStart,
                AllowedHoursEnd = req.AllowedHoursEnd,
                MaxSessionMinutesPerDay = req.MaxSessionMinutesPerDay > 0 ? req.MaxSessionMinutesPerDay : 120,
                AuthorizedDeviceIdsJson = JsonSerializer.Serialize(req.AuthorizedDeviceIds ?? []),
                IpWhitelist = string.IsNullOrWhiteSpace(req.IpWhitelist) ? null : req.IpWhitelist.Trim(),
                InviteToken = token,
                InviteExpiresAtUtc = DateTime.UtcNow.AddDays(7),
                SingleUseInvite = req.SingleUseInvite,
                Status = VendorAccessStatus.Active,
                CreatedByUserId = adminId,
                CreatedByUsername = adminUsername
            };

            db.VendorAccesses.Add(vendor);
            await db.SaveChangesAsync();

            var baseUrl = config["App:BaseUrl"] ?? $"https://{ctx.Request.Host}";
            var portalUrl = $"{baseUrl}/vendor-portal?token={token}";

            if (email != null)
            {
                var html = $"""
                    <h3>OrkunPAM — Vendor Access Invitation</h3>
                    <p>Hello {System.Net.WebUtility.HtmlEncode(req.VendorName)},</p>
                    <p>You have been granted temporary privileged access by <strong>{System.Net.WebUtility.HtmlEncode(adminUsername)}</strong>.</p>
                    <ul>
                        <li><strong>Access Period:</strong> {vendor.StartAtUtc:yyyy-MM-dd HH:mm} UTC — {vendor.EndAtUtc:yyyy-MM-dd HH:mm} UTC</li>
                        <li><strong>Max Session:</strong> {vendor.MaxSessionMinutesPerDay} minutes/day</li>
                    </ul>
                    <p>Use the link below to view your authorized devices:</p>
                    <p><a href="{System.Net.WebUtility.HtmlEncode(portalUrl)}">{System.Net.WebUtility.HtmlEncode(portalUrl)}</a></p>
                    <p>This link expires in 7 days. Do not share it.</p>
                    """;

                _ = email.SendAsync(vendor.Email, "OrkunPAM — Vendor Access Invitation", html);
            }

            _ = audit.LogAsync("VendorAccess", "VendorAccess.Created", adminId, adminUsername, ip,
                "VendorAccess", vendor.Id.ToString(),
                new { vendorName = vendor.VendorName, company = vendor.Company, email = vendor.Email });

            return Results.Ok(new { success = true, data = MapDto(vendor), portalUrl });
        });

        // GET /api/v1/vendor-access — list all vendor accesses
        grp.MapGet("/", async (OrkunPamDbContext db, HttpContext ctx, string? status = null,
            int page = 1, int pageSize = 50) =>
        {
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");
            if (!isAdmin) return Results.Forbid();

            // Auto-expire past-end vendors
            var now = DateTime.UtcNow;
            var expired = await db.VendorAccesses
                .Where(v => v.Status == VendorAccessStatus.Active && v.EndAtUtc < now)
                .ToListAsync();
            foreach (var v in expired) v.Status = VendorAccessStatus.Expired;
            if (expired.Count > 0) await db.SaveChangesAsync();

            var query = db.VendorAccesses.AsQueryable();
            if (!string.IsNullOrEmpty(status) && Enum.TryParse<VendorAccessStatus>(status, out var parsedStatus))
                query = query.Where(v => v.Status == parsedStatus);

            var total = await query.CountAsync();
            var items = await query
                .OrderByDescending(v => v.CreatedAtUtc)
                .Skip((page - 1) * pageSize)
                .Take(pageSize)
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = items.Select(MapDto),
                meta = new { page, pageSize, totalCount = total }
            });
        });

        // GET /api/v1/vendor-access/{id}
        grp.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");
            if (!isAdmin) return Results.Forbid();

            var vendor = await db.VendorAccesses.FindAsync(id);
            if (vendor == null) return Results.NotFound(new { success = false });
            return Results.Ok(new { success = true, data = MapDto(vendor) });
        });

        // POST /api/v1/vendor-access/{id}/revoke
        grp.MapPost("/{id:guid}/revoke", async (Guid id, RevokeVendorRequest req,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");
            if (!isAdmin) return Results.Forbid();

            var vendor = await db.VendorAccesses.FindAsync(id);
            if (vendor == null) return Results.NotFound(new { success = false });
            if (vendor.Status == VendorAccessStatus.Revoked)
                return Results.BadRequest(new { success = false, error = "Already revoked." });

            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var username = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            vendor.Status = VendorAccessStatus.Revoked;
            vendor.RevokeReason = req.Reason?.Trim();
            vendor.RevokedByUserId = Guid.TryParse(userId, out var uid) ? uid : null;
            vendor.RevokedByUsername = username;
            vendor.RevokedAtUtc = DateTime.UtcNow;

            await db.SaveChangesAsync();

            _ = audit.LogAsync("VendorAccess", "VendorAccess.Revoked",
                Guid.TryParse(userId, out var auid) ? auid : Guid.Empty,
                username, ip, "VendorAccess", id.ToString(),
                new { vendorName = vendor.VendorName, reason = req.Reason });

            return Results.Ok(new { success = true });
        });

        // POST /api/v1/vendor-access/{id}/resend — resend invite email
        grp.MapPost("/{id:guid}/resend", async (Guid id, OrkunPamDbContext db,
            HttpContext ctx, IEmailService? email, IConfiguration config) =>
        {
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");
            if (!isAdmin) return Results.Forbid();

            var vendor = await db.VendorAccesses.FindAsync(id);
            if (vendor == null) return Results.NotFound(new { success = false });
            if (vendor.Status == VendorAccessStatus.Revoked)
                return Results.BadRequest(new { success = false, error = "Cannot resend invite for a revoked vendor." });

            // Regenerate token + extend expiry
            vendor.InviteToken = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");
            vendor.InviteExpiresAtUtc = DateTime.UtcNow.AddDays(7);
            vendor.InviteUsedAtUtc = null;
            await db.SaveChangesAsync();

            var adminUsername = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var baseUrl = config["App:BaseUrl"] ?? $"https://{ctx.Request.Host}";
            var portalUrl = $"{baseUrl}/vendor-portal?token={vendor.InviteToken}";

            if (email != null)
            {
                var html = $"""
                    <h3>OrkunPAM — Vendor Access Invitation (Resent)</h3>
                    <p>Hello {System.Net.WebUtility.HtmlEncode(vendor.VendorName)},</p>
                    <p>Your vendor access invitation has been refreshed by <strong>{System.Net.WebUtility.HtmlEncode(adminUsername)}</strong>.</p>
                    <ul>
                        <li><strong>Access Period:</strong> {vendor.StartAtUtc:yyyy-MM-dd HH:mm} UTC — {vendor.EndAtUtc:yyyy-MM-dd HH:mm} UTC</li>
                    </ul>
                    <p><a href="{System.Net.WebUtility.HtmlEncode(portalUrl)}">{System.Net.WebUtility.HtmlEncode(portalUrl)}</a></p>
                    <p>This link expires in 7 days.</p>
                    """;

                _ = email.SendAsync(vendor.Email, "OrkunPAM — Vendor Access Invitation (Resent)", html);
            }

            return Results.Ok(new { success = true, portalUrl });
        });

        // GET /api/v1/vendor-access/portal?token=xxx — anonymous vendor portal entry
        app.MapGet("/api/v1/vendor-access/portal", async (string token, OrkunPamDbContext db,
            HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(token))
                return Results.BadRequest(new { success = false, error = "Token required." });

            var vendor = await db.VendorAccesses.FirstOrDefaultAsync(v => v.InviteToken == token);
            if (vendor == null)
                return Results.NotFound(new { success = false, error = "Invalid or expired invitation link." });

            if (vendor.Status == VendorAccessStatus.Revoked)
                return Results.Forbid();

            var now = DateTime.UtcNow;
            if (now < vendor.StartAtUtc || now > vendor.EndAtUtc)
                return Results.Forbid();

            if (vendor.AllowedHoursStart.HasValue && vendor.AllowedHoursEnd.HasValue)
            {
                var hour = now.Hour;
                if (hour < vendor.AllowedHoursStart.Value || hour >= vendor.AllowedHoursEnd.Value)
                    return Results.Forbid();
            }

            if (vendor.InviteExpiresAtUtc < now)
                return Results.Forbid();

            if (vendor.SingleUseInvite && vendor.InviteUsedAtUtc.HasValue)
                return Results.Forbid();

            // Optional IP check — exact IP or CIDR notation (e.g. "10.0.0.0/24")
            if (!string.IsNullOrEmpty(vendor.IpWhitelist))
            {
                var clientIp = ctx.Connection.RemoteIpAddress?.ToString() ?? "";
                if (!IsIpAllowed(clientIp, vendor.IpWhitelist))
                    return Results.Forbid();
            }

            // Mark first use
            if (vendor.SingleUseInvite && !vendor.InviteUsedAtUtc.HasValue)
            {
                vendor.InviteUsedAtUtc = now;
                await db.SaveChangesAsync();
            }

            // Resolve device list
            List<Guid> deviceIds;
            try { deviceIds = JsonSerializer.Deserialize<List<Guid>>(vendor.AuthorizedDeviceIdsJson) ?? []; }
            catch { deviceIds = []; }

            var devices = await db.Devices
                .Where(d => deviceIds.Contains(d.Id))
                .Select(d => new { d.Id, d.Hostname, d.Fqdn, d.IpAddress, Protocol = d.ConnectionProtocol, d.ConnectionPort })
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    vendorName = vendor.VendorName,
                    company = vendor.Company,
                    accessUntil = vendor.EndAtUtc,
                    maxSessionMinutesPerDay = vendor.MaxSessionMinutesPerDay,
                    devices
                }
            });
        }).WithTags("VendorAccess").AllowAnonymous();
    }

    private static bool IsIpAllowed(string clientIp, string whitelist)
    {
        if (!IPAddress.TryParse(clientIp, out var clientAddr)) return false;

        foreach (var entry in whitelist.Split(',', StringSplitOptions.RemoveEmptyEntries)
                                       .Select(s => s.Trim()))
        {
            int slash = entry.IndexOf('/');
            if (slash >= 0)
            {
                if (IPAddress.TryParse(entry[..slash], out var network) &&
                    int.TryParse(entry[(slash + 1)..], out var prefix) &&
                    IsInCidr(clientAddr, network, prefix))
                    return true;
            }
            else if (IPAddress.TryParse(entry, out var allowed) && clientAddr.Equals(allowed))
            {
                return true;
            }
        }
        return false;
    }

    private static bool IsInCidr(IPAddress addr, IPAddress network, int prefix)
    {
        var a = addr.GetAddressBytes();
        var n = network.GetAddressBytes();
        if (a.Length != n.Length) return false;
        int full = prefix / 8, rem = prefix % 8;
        for (int i = 0; i < full && i < a.Length; i++)
            if (a[i] != n[i]) return false;
        if (rem > 0 && full < a.Length)
        {
            byte mask = (byte)(0xFF << (8 - rem));
            if ((a[full] & mask) != (n[full] & mask)) return false;
        }
        return true;
    }

    private static object MapDto(VendorAccess v) => new
    {
        id = v.Id,
        vendorName = v.VendorName,
        company = v.Company,
        email = v.Email,
        phone = v.Phone,
        startAtUtc = v.StartAtUtc,
        endAtUtc = v.EndAtUtc,
        allowedHoursStart = v.AllowedHoursStart,
        allowedHoursEnd = v.AllowedHoursEnd,
        maxSessionMinutesPerDay = v.MaxSessionMinutesPerDay,
        authorizedDeviceIdsJson = v.AuthorizedDeviceIdsJson,
        ipWhitelist = v.IpWhitelist,
        inviteExpiresAtUtc = v.InviteExpiresAtUtc,
        inviteUsedAtUtc = v.InviteUsedAtUtc,
        singleUseInvite = v.SingleUseInvite,
        status = v.Status.ToString(),
        createdByUsername = v.CreatedByUsername,
        createdAtUtc = v.CreatedAtUtc,
        revokeReason = v.RevokeReason,
        revokedByUsername = v.RevokedByUsername,
        revokedAtUtc = v.RevokedAtUtc
    };
}

public record CreateVendorAccessRequest(
    string VendorName, string? Company, string Email, string? Phone,
    DateTime StartAtUtc, DateTime EndAtUtc,
    int? AllowedHoursStart, int? AllowedHoursEnd,
    int MaxSessionMinutesPerDay,
    List<Guid>? AuthorizedDeviceIds,
    string? IpWhitelist,
    bool SingleUseInvite = false);

public record RevokeVendorRequest(string? Reason);
