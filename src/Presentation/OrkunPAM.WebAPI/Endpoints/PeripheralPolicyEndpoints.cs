using System.Security.Cryptography;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class PeripheralPolicyEndpoints
{
    public static void MapPeripheralPolicyEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/policies/peripheral")
            .WithTags("PeripheralPolicy")
            .RequireAuthorization("AdminPolicy");

        // GET — list all peripheral policies
        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var policies = await db.PeripheralRedirectionPolicies
                .OrderBy(p => p.Name)
                .Select(p => new
                {
                    p.Id, p.Name, p.Description, p.IsEnabled,
                    p.AllowClipboard, p.AllowDriveRedirection, p.AllowPrinterRedirection,
                    p.AllowUsbRedirection, p.AllowAudioRedirection, p.AllowSmartCardRedirection,
                    p.DeviceGroupId, p.CreatedAtUtc, p.UpdatedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = policies });
        });

        // POST — create policy
        group.MapPost("/", async (CreatePeripheralPolicyRequest req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            var policy = new PeripheralRedirectionPolicy
            {
                Id                        = Guid.NewGuid(),
                Name                      = req.Name.Trim(),
                Description               = req.Description?.Trim(),
                IsEnabled                 = req.IsEnabled ?? true,
                AllowClipboard            = req.AllowClipboard ?? false,
                AllowDriveRedirection     = req.AllowDriveRedirection ?? false,
                AllowPrinterRedirection   = req.AllowPrinterRedirection ?? true,
                AllowUsbRedirection       = req.AllowUsbRedirection ?? false,
                AllowAudioRedirection     = req.AllowAudioRedirection ?? false,
                AllowSmartCardRedirection = req.AllowSmartCardRedirection ?? true,
                DeviceGroupId             = req.DeviceGroupId
            };

            db.PeripheralRedirectionPolicies.Add(policy);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "PERIPHERAL_POLICY_CREATED", null, null, ip,
                "PeripheralRedirectionPolicy", policy.Id.ToString(), new { policy.Name });

            return Results.Created($"/api/v1/policies/peripheral/{policy.Id}",
                new { success = true, data = new { policy.Id, policy.Name } });
        });

        // GET {id}
        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var policy = await db.PeripheralRedirectionPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            return Results.Ok(new { success = true, data = policy });
        });

        // PUT {id}
        group.MapPut("/{id:guid}", async (Guid id, UpdatePeripheralPolicyRequest req,
            OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var policy = await db.PeripheralRedirectionPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            if (req.Name != null) policy.Name = req.Name.Trim();
            if (req.Description != null) policy.Description = req.Description.Trim();
            if (req.IsEnabled.HasValue) policy.IsEnabled = req.IsEnabled.Value;
            if (req.AllowClipboard.HasValue) policy.AllowClipboard = req.AllowClipboard.Value;
            if (req.AllowDriveRedirection.HasValue) policy.AllowDriveRedirection = req.AllowDriveRedirection.Value;
            if (req.AllowPrinterRedirection.HasValue) policy.AllowPrinterRedirection = req.AllowPrinterRedirection.Value;
            if (req.AllowUsbRedirection.HasValue) policy.AllowUsbRedirection = req.AllowUsbRedirection.Value;
            if (req.AllowAudioRedirection.HasValue) policy.AllowAudioRedirection = req.AllowAudioRedirection.Value;
            if (req.AllowSmartCardRedirection.HasValue) policy.AllowSmartCardRedirection = req.AllowSmartCardRedirection.Value;
            if (req.DeviceGroupId.HasValue) policy.DeviceGroupId = req.DeviceGroupId;

            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "PERIPHERAL_POLICY_UPDATED", null, null, ip,
                "PeripheralRedirectionPolicy", policy.Id.ToString(), new { policy.Name, policy.IsEnabled });

            return Results.Ok(new { success = true, data = new { policy.Id, policy.Name } });
        });

        // DELETE {id}
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var policy = await db.PeripheralRedirectionPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            db.PeripheralRedirectionPolicies.Remove(policy);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "PERIPHERAL_POLICY_DELETED", null, null, ip,
                "PeripheralRedirectionPolicy", id.ToString(), null);

            return Results.Ok(new { success = true });
        });

        // GET /effective?deviceGroupId=... — RDP proxy calls this at session start (X-Proxy-Secret)
        app.MapGet("/api/v1/policies/peripheral/effective",
            async (Guid? deviceGroupId, OrkunPamDbContext db, IConfiguration config, HttpContext ctx) =>
        {
            if (!ValidateProxySecret(ctx, config))
                return Results.Unauthorized();

            PeripheralRedirectionPolicy? policy = null;

            if (deviceGroupId.HasValue)
                policy = await db.PeripheralRedirectionPolicies
                    .Where(p => p.IsEnabled && p.DeviceGroupId == deviceGroupId)
                    .FirstOrDefaultAsync();

            policy ??= await db.PeripheralRedirectionPolicies
                .Where(p => p.IsEnabled && p.DeviceGroupId == null)
                .FirstOrDefaultAsync();

            // Secure defaults when no policy configured
            bool allowClipboard = policy?.AllowClipboard ?? false;
            bool allowDrive     = policy?.AllowDriveRedirection ?? false;
            bool allowPrinter   = policy?.AllowPrinterRedirection ?? true;
            bool allowUsb       = policy?.AllowUsbRedirection ?? false;
            bool allowAudio     = policy?.AllowAudioRedirection ?? false;
            bool allowSmartCard = policy?.AllowSmartCardRedirection ?? true;

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    allowClipboard,
                    allowDriveRedirection   = allowDrive,
                    allowPrinterRedirection = allowPrinter,
                    allowUsbRedirection     = allowUsb,
                    allowAudioRedirection   = allowAudio,
                    allowSmartCardRedirection = allowSmartCard
                }
            });
        }).WithTags("PeripheralPolicy").AllowAnonymous();
    }

    private static bool ValidateProxySecret(HttpContext context, IConfiguration config)
    {
        var expected = config["ProxyService:Secret"] ?? config["PamApi:ProxySecret"] ?? "";
        if (expected.Length < 32) return false;
        var provided = context.Request.Headers["X-Proxy-Secret"].FirstOrDefault() ?? "";
        var expectedBytes = System.Text.Encoding.UTF8.GetBytes(expected);
        var providedBytes = System.Text.Encoding.UTF8.GetBytes(provided);
        return CryptographicOperations.FixedTimeEquals(expectedBytes, providedBytes);
    }
}

public record CreatePeripheralPolicyRequest(
    string  Name,
    string? Description,
    bool?   IsEnabled,
    bool?   AllowClipboard,
    bool?   AllowDriveRedirection,
    bool?   AllowPrinterRedirection,
    bool?   AllowUsbRedirection,
    bool?   AllowAudioRedirection,
    bool?   AllowSmartCardRedirection,
    Guid?   DeviceGroupId);

public record UpdatePeripheralPolicyRequest(
    string? Name,
    string? Description,
    bool?   IsEnabled,
    bool?   AllowClipboard,
    bool?   AllowDriveRedirection,
    bool?   AllowPrinterRedirection,
    bool?   AllowUsbRedirection,
    bool?   AllowAudioRedirection,
    bool?   AllowSmartCardRedirection,
    Guid?   DeviceGroupId);
