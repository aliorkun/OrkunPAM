using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.WebAPI.Endpoints;

public static class VendorEndpoints
{
    public static void MapVendorEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/api/v1/vendor").WithTags("Vendor").RequireAuthorization();

        // POST /api/v1/vendor/onboard — sponsor creates a vendor user account
        grp.MapPost("/onboard", async (OnboardVendorRequest req, OrkunPamDbContext db,
            HttpContext ctx, IAuditService audit, IEmailService? email, IConfiguration config) =>
        {
            var isSponsor = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin")
                         || ctx.User.IsInRole("Sponsor");
            if (!isSponsor) return Results.Forbid();

            var sponsorIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (!Guid.TryParse(sponsorIdStr, out var sponsorId)) return Results.Unauthorized();
            var sponsorUsername = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            if (string.IsNullOrWhiteSpace(req.DisplayName) || string.IsNullOrWhiteSpace(req.Email))
                return Results.BadRequest(new { success = false, error = "Display name and email are required." });

            if (req.AccessExpiresUtc <= DateTime.UtcNow)
                return Results.BadRequest(new { success = false, error = "Access expiry must be in the future." });

            var maxExpiry = DateTime.UtcNow.AddDays(30);
            if (req.AccessExpiresUtc > maxExpiry)
                return Results.BadRequest(new { success = false, error = "Vendor access cannot exceed 30 days." });

            // Generate a unique username from email
            var baseUsername = "vendor." + req.Email.Split('@')[0].ToLowerInvariant()
                .Replace(" ", "").Replace(".", "_");
            var username = baseUsername;
            var suffix = 1;
            while (await db.Users.AnyAsync(u => u.NormalizedUsername == username.ToUpperInvariant()))
            {
                username = baseUsername + suffix++;
                if (suffix > 99) return Results.Conflict(new { success = false, error = "Could not generate unique username." });
            }

            var inviteToken = Guid.NewGuid().ToString("N") + Guid.NewGuid().ToString("N");

            var vendor = new User
            {
                Username = username,
                NormalizedUsername = username.ToUpperInvariant(),
                DisplayName = req.DisplayName.Trim(),
                Email = req.Email.Trim().ToLowerInvariant(),
                Phone = req.Phone?.Trim(),
                AuthSource = AuthSource.Local,
                Status = UserStatus.Active,
                UserType = UserType.Vendor,
                VendorSponsorUserId = sponsorId,
                VendorDeviceIdsJson = JsonSerializer.Serialize(req.AuthorizedDeviceIds ?? []),
                IsTemporary = true,
                TemporaryExpiresUtc = req.AccessExpiresUtc.ToUniversalTime(),
                MustChangePassword = true,
                PasswordResetToken = inviteToken,
                PasswordResetExpiry = DateTime.UtcNow.AddHours(48),
                Language = "en-US"
            };

            db.Users.Add(vendor);
            await db.SaveChangesAsync();

            var baseUrl = config["App:BaseUrl"] ?? $"https://{ctx.Request.Host}";
            var inviteUrl = $"{baseUrl}/reset-password?token={inviteToken}";

            if (email != null)
            {
                var company = string.IsNullOrWhiteSpace(req.Company) ? "" : $" ({req.Company})";
                var html = $"""
                    <h3>OrkunPAM — Vendor Account Invitation</h3>
                    <p>Hello {System.Net.WebUtility.HtmlEncode(req.DisplayName)}{System.Net.WebUtility.HtmlEncode(company)},</p>
                    <p>You have been granted temporary privileged access by <strong>{System.Net.WebUtility.HtmlEncode(sponsorUsername)}</strong>.</p>
                    <ul>
                        <li><strong>Username:</strong> {System.Net.WebUtility.HtmlEncode(username)}</li>
                        <li><strong>Access Expires:</strong> {req.AccessExpiresUtc:yyyy-MM-dd HH:mm} UTC</li>
                        <li><strong>Authorized Devices:</strong> {req.AuthorizedDeviceIds?.Count ?? 0} device(s)</li>
                    </ul>
                    <p>Click the link below to set your password and activate your account (link valid 48 hours):</p>
                    <p><a href="{System.Net.WebUtility.HtmlEncode(inviteUrl)}">{System.Net.WebUtility.HtmlEncode(inviteUrl)}</a></p>
                    <p>After setting your password, you will be prompted to enroll MFA. Do not share this link.</p>
                    """;
                _ = email.SendAsync(vendor.Email, "OrkunPAM — Vendor Account Invitation", html);
            }

            _ = audit.LogAsync("Vendor", "Vendor.Onboarded", sponsorId, sponsorUsername, ip,
                "User", vendor.Id.ToString(),
                new { vendorUsername = vendor.Username, displayName = vendor.DisplayName, email = vendor.Email,
                      expiresUtc = vendor.TemporaryExpiresUtc, deviceCount = req.AuthorizedDeviceIds?.Count ?? 0 });

            return Results.Created($"/api/v1/vendor/{vendor.Id}", new
            {
                success = true,
                data = MapDto(vendor, null),
                inviteUrl
            });
        });

        // GET /api/v1/vendor — list vendor users
        grp.MapGet("/", async (OrkunPamDbContext db, HttpContext ctx,
            string? status = null, int page = 1, int pageSize = 50) =>
        {
            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");
            var isSponsor = isAdmin || ctx.User.IsInRole("Sponsor");
            if (!isSponsor) return Results.Forbid();

            // Auto-expire vendor accounts whose TemporaryExpiresUtc has passed
            var now = DateTime.UtcNow;
            var expiredVendors = await db.Users
                .Where(u => u.UserType == UserType.Vendor
                    && u.Status == UserStatus.Active
                    && u.TemporaryExpiresUtc.HasValue
                    && u.TemporaryExpiresUtc < now)
                .ToListAsync();
            foreach (var v in expiredVendors)
            {
                v.Status = UserStatus.Locked;
                v.LockoutEndUtc = DateTime.UtcNow.AddYears(100);
            }
            if (expiredVendors.Count > 0) await db.SaveChangesAsync();

            var query = db.Users
                .Where(u => u.UserType == UserType.Vendor);

            // Non-admin sponsors see only their own vendors
            if (!isAdmin && Guid.TryParse(userId, out var sponsorGuid))
                query = query.Where(u => u.VendorSponsorUserId == sponsorGuid);

            if (!string.IsNullOrEmpty(status) && Enum.TryParse<UserStatus>(status, true, out var parsedStatus))
                query = query.Where(u => u.Status == parsedStatus);

            var total = await query.CountAsync();
            var items = await query
                .OrderByDescending(u => u.CreatedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .ToListAsync();

            // Resolve sponsor usernames
            var sponsorIds = items.Where(v => v.VendorSponsorUserId.HasValue)
                .Select(v => v.VendorSponsorUserId!.Value).Distinct().ToList();
            var sponsors = await db.Users
                .Where(u => sponsorIds.Contains(u.Id))
                .ToDictionaryAsync(u => u.Id, u => u.Username);

            return Results.Ok(new
            {
                success = true,
                data = items.Select(v => MapDto(v, sponsors.GetValueOrDefault(v.VendorSponsorUserId ?? Guid.Empty))),
                meta = new { page, pageSize, totalCount = total }
            });
        });

        // GET /api/v1/vendor/{id}
        grp.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");

            var vendor = await db.Users.FirstOrDefaultAsync(u => u.Id == id && u.UserType == UserType.Vendor);
            if (vendor == null) return Results.NotFound(new { success = false });

            // Sponsor can only see own vendors
            if (!isAdmin && vendor.VendorSponsorUserId?.ToString() != userId)
                return Results.Forbid();

            string? sponsorUsername = null;
            if (vendor.VendorSponsorUserId.HasValue)
            {
                var sponsor = await db.Users.FindAsync(vendor.VendorSponsorUserId.Value);
                sponsorUsername = sponsor?.Username;
            }

            return Results.Ok(new { success = true, data = MapDto(vendor, sponsorUsername) });
        });

        // PUT /api/v1/vendor/{id}/extend — sponsor extends access (max +30 days from today)
        grp.MapPut("/{id:guid}/extend", async (Guid id, ExtendVendorRequest req,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var sponsorIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var sponsorUsername = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var vendor = await db.Users.FirstOrDefaultAsync(u => u.Id == id && u.UserType == UserType.Vendor);
            if (vendor == null) return Results.NotFound(new { success = false });

            // Sponsor can only extend own vendors
            if (!isAdmin && vendor.VendorSponsorUserId?.ToString() != sponsorIdStr)
                return Results.Forbid();

            var newExpiry = req.NewExpiresUtc.ToUniversalTime();
            var maxAllowed = DateTime.UtcNow.AddDays(30);
            if (newExpiry > maxAllowed)
                return Results.BadRequest(new { success = false, error = "Cannot extend beyond 30 days from today." });
            if (newExpiry <= DateTime.UtcNow)
                return Results.BadRequest(new { success = false, error = "New expiry must be in the future." });

            var oldExpiry = vendor.TemporaryExpiresUtc;
            vendor.TemporaryExpiresUtc = newExpiry;
            // Unlock if it was auto-expired
            if (vendor.Status == UserStatus.Locked
                && vendor.LockoutEndUtc.HasValue
                && vendor.LockoutEndUtc > DateTime.UtcNow.AddYears(50))
            {
                vendor.Status = UserStatus.Active;
                vendor.LockoutEndUtc = null;
            }
            await db.SaveChangesAsync();

            var actorId = Guid.TryParse(sponsorIdStr, out var sg) ? sg : Guid.Empty;
            _ = audit.LogAsync("Vendor", "Vendor.Extended", actorId, sponsorUsername, ip,
                "User", id.ToString(),
                new { vendorUsername = vendor.Username, oldExpiry, newExpiry });

            return Results.Ok(new { success = true, data = MapDto(vendor, sponsorUsername) });
        });

        // PUT /api/v1/vendor/{id}/revoke — sponsor revokes vendor access
        grp.MapPut("/{id:guid}/revoke", async (Guid id, RevokeVendorUserRequest req,
            OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var sponsorIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var sponsorUsername = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var vendor = await db.Users.FirstOrDefaultAsync(u => u.Id == id && u.UserType == UserType.Vendor);
            if (vendor == null) return Results.NotFound(new { success = false });

            if (!isAdmin && vendor.VendorSponsorUserId?.ToString() != sponsorIdStr)
                return Results.Forbid();

            if (vendor.Status == UserStatus.Locked && vendor.LockoutEndUtc > DateTime.UtcNow.AddYears(50))
                return Results.BadRequest(new { success = false, error = "Vendor account already revoked." });

            vendor.Status = UserStatus.Locked;
            vendor.LockoutEndUtc = DateTime.UtcNow.AddYears(100);
            await db.SaveChangesAsync();

            var actorId = Guid.TryParse(sponsorIdStr, out var sg) ? sg : Guid.Empty;
            _ = audit.LogAsync("Vendor", "Vendor.Revoked", actorId, sponsorUsername, ip,
                "User", id.ToString(),
                new { vendorUsername = vendor.Username, reason = req.Reason });

            return Results.Ok(new { success = true });
        });

        // GET /api/v1/vendor/{id}/sessions — vendor's session history
        grp.MapGet("/{id:guid}/sessions", async (Guid id, OrkunPamDbContext db, HttpContext ctx,
            int page = 1, int pageSize = 20) =>
        {
            var userId = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var isAdmin = ctx.User.IsInRole("GlobalAdmin") || ctx.User.IsInRole("VendorAdmin");

            var vendor = await db.Users.FirstOrDefaultAsync(u => u.Id == id && u.UserType == UserType.Vendor);
            if (vendor == null) return Results.NotFound(new { success = false });

            if (!isAdmin && vendor.VendorSponsorUserId?.ToString() != userId)
                return Results.Forbid();

            var total = await db.ProxySessions.CountAsync(s => s.UserId == id);
            var sessions = await db.ProxySessions
                .Where(s => s.UserId == id)
                .OrderByDescending(s => s.StartedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(s => new
                {
                    s.Id,
                    SessionType = s.SessionType.ToString(),
                    Status = s.Status.ToString(),
                    s.StartedAtUtc, s.EndedAtUtc, s.DurationSeconds,
                    s.ClientIpAddress, s.TargetIpAddress, s.TargetPort,
                    s.RecordingPath, s.RiskScore
                })
                .ToListAsync();

            return Results.Ok(new
            {
                success = true,
                data = sessions,
                meta = new { page, pageSize, totalCount = total }
            });
        });
    }

    private static object MapDto(User v, string? sponsorUsername) => new
    {
        id = v.Id,
        username = v.Username,
        displayName = v.DisplayName,
        email = v.Email,
        phone = v.Phone,
        status = v.Status.ToString(),
        userType = v.UserType.ToString(),
        vendorSponsorUserId = v.VendorSponsorUserId,
        vendorSponsorUsername = sponsorUsername,
        vendorDeviceIdsJson = v.VendorDeviceIdsJson,
        isTemporary = v.IsTemporary,
        temporaryExpiresUtc = v.TemporaryExpiresUtc,
        mfaEnabled = v.MfaEnabled,
        lastLoginAtUtc = v.LastLoginAtUtc,
        createdAtUtc = v.CreatedAtUtc,
        mustChangePassword = v.MustChangePassword
    };
}

public record OnboardVendorRequest(
    string DisplayName,
    string Email,
    string? Phone,
    string? Company,
    DateTime AccessExpiresUtc,
    List<Guid>? AuthorizedDeviceIds);

public record ExtendVendorRequest(DateTime NewExpiresUtc);

public record RevokeVendorUserRequest(string? Reason);
