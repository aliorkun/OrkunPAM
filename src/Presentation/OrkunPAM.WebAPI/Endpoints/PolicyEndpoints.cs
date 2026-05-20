using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Caching.Memory;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class PolicyEndpoints
{
    private static readonly JsonSerializerOptions JsonOpts = new() { PropertyNameCaseInsensitive = true };

    private static T ReadPolicy<T>(string json) where T : new()
    {
        try { return JsonSerializer.Deserialize<T>(json, JsonOpts) ?? new T(); }
        catch { return new T(); }
    }

    private static async Task UpsertGlobalPolicyAsync(
        OrkunPamDbContext db, string policyType, string name, object settings)
    {
        var json = JsonSerializer.Serialize(settings);
        var existing = await db.Policies.FirstOrDefaultAsync(
            p => p.PolicyType == policyType && p.Scope == PolicyScope.Global);
        if (existing == null)
            db.Policies.Add(new Policy { Name = name, PolicyType = policyType, Scope = PolicyScope.Global, PolicyJson = json, Priority = 100, IsEnabled = true });
        else
            existing.PolicyJson = json;
        await db.SaveChangesAsync();
    }

    public static void MapPolicyEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/policies").WithTags("Policies").RequireAuthorization("AdminPolicy");

        group.MapGet("/", async (OrkunPamDbContext db, string? type) =>
        {
            var query = db.Policies.AsQueryable();
            if (!string.IsNullOrEmpty(type))
                query = query.Where(p => p.PolicyType == type);

            var list = await query
                .OrderBy(p => p.Scope).ThenBy(p => p.Priority)
                .Select(p => new
                {
                    p.Id, p.Name, p.PolicyType,
                    Scope = p.Scope.ToString(),
                    p.ScopeId, p.Priority, p.IsEnabled
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list });
        });

        group.MapPost("/", async (CreatePolicyRequest req, OrkunPamDbContext db) =>
        {
            var policy = new Policy
            {
                Name = req.Name,
                PolicyType = req.PolicyType,
                Scope = req.Scope,
                ScopeId = req.ScopeId,
                PolicyJson = req.PolicyJson,
                Priority = req.Priority,
                IsEnabled = true
            };

            db.Policies.Add(policy);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/policies/{policy.Id}", new { success = true, data = new { policy.Id, policy.Name } });
        });

        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FindAsync(id);
            if (p == null) return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    p.Id, p.Name, p.PolicyType,
                    Scope = p.Scope.ToString(),
                    p.ScopeId, p.PolicyJson, p.Priority, p.IsEnabled,
                    p.CreatedAtUtc, p.UpdatedAtUtc
                }
            });
        });

        group.MapPut("/{id:guid}", async (Guid id, UpdatePolicyRequest req, OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FindAsync(id);
            if (p == null) return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            if (req.Name != null) p.Name = req.Name;
            if (req.PolicyJson != null) p.PolicyJson = req.PolicyJson;
            if (req.Priority.HasValue) p.Priority = req.Priority.Value;
            if (req.IsEnabled.HasValue) p.IsEnabled = req.IsEnabled.Value;

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { p.Id, p.Name } });
        });

        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FindAsync(id);
            if (p == null) return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            db.Policies.Remove(p);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        group.MapGet("/effective/{userId:guid}", async (Guid userId, string policyType, OrkunPamDbContext db) =>
        {
            var groupIds = await db.UserGroups
                .Where(ug => ug.UserId == userId)
                .Select(ug => ug.GroupId)
                .ToListAsync();

            var policies = await db.Policies
                .Where(p => p.PolicyType == policyType && p.IsEnabled &&
                    (p.Scope == PolicyScope.Global ||
                     (p.Scope == PolicyScope.User && p.ScopeId == userId) ||
                     (p.Scope == PolicyScope.Group && groupIds.Contains(p.ScopeId!.Value))))
                .OrderByDescending(p => p.Scope)
                .ThenByDescending(p => p.Priority)
                .Select(p => new { p.Id, p.Name, Scope = p.Scope.ToString(), p.PolicyJson, p.Priority })
                .ToListAsync();

            return Results.Ok(new { success = true, data = policies });
        });

        var pwdGroup = app.MapGroup("/api/v1/policy").WithTags("Policy Settings").RequireAuthorization("AdminPolicy");

        pwdGroup.MapGet("/password", async (OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FirstOrDefaultAsync(
                x => x.PolicyType == "Password" && x.Scope == PolicyScope.Global);
            var settings = ReadPolicy<PasswordPolicySettings>(p?.PolicyJson ?? "{}");
            return Results.Ok(new { success = true, data = settings });
        });

        pwdGroup.MapPost("/password", async (
            PasswordPolicySettings req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (req.MinLength < 1 || req.MinLength > 128)
                return Results.BadRequest(new { success = false, errors = new[] { "minLength must be 1-128" } });
            if (req.MaxLength < req.MinLength)
                return Results.BadRequest(new { success = false, errors = new[] { "maxLength must be >= minLength" } });
            if (req.PreventReuseCount < 0 || req.PreventReuseCount > 24)
                return Results.BadRequest(new { success = false, errors = new[] { "preventReuseCount must be 0-24" } });

            await UpsertGlobalPolicyAsync(db, "Password", "Global Password Policy", req);

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "PASSWORD_POLICY_UPDATED", null, null, ip,
                "Policy", "Password", new { settings = req });

            return Results.Ok(new { success = true });
        });

        pwdGroup.MapGet("/lockout", async (OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FirstOrDefaultAsync(
                x => x.PolicyType == "Lockout" && x.Scope == PolicyScope.Global);
            var settings = ReadPolicy<LockoutPolicySettings>(p?.PolicyJson ?? "{}");
            return Results.Ok(new { success = true, data = settings });
        });

        pwdGroup.MapPost("/lockout", async (
            LockoutPolicySettings req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (req.MaxFailedAttempts < 1 || req.MaxFailedAttempts > 20)
                return Results.BadRequest(new { success = false, errors = new[] { "maxFailedAttempts must be 1-20" } });

            await UpsertGlobalPolicyAsync(db, "Lockout", "Global Account Lockout Policy", req);

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "LOCKOUT_POLICY_UPDATED", null, null, ip,
                "Policy", "Lockout", new { settings = req });

            return Results.Ok(new { success = true });
        });

        pwdGroup.MapGet("/session", async (OrkunPamDbContext db, IMemoryCache cache) =>
        {
            const string CacheKey = "policy:session:effective";
            if (cache.TryGetValue<SessionPolicySettings>(CacheKey, out var cachedSettings) && cachedSettings != null)
                return Results.Ok(new { success = true, data = cachedSettings });

            var p = await db.Policies.FirstOrDefaultAsync(
                x => x.PolicyType == "Session" && x.Scope == PolicyScope.Global);
            var settings = ReadPolicy<SessionPolicySettings>(p?.PolicyJson ?? "{}");

            // Overlay with DB-backed CommandFilterPolicy (enabled global policy overrides JSON blob)
            var cfPolicy = await db.CommandFilterPolicies
                .Include(cfp => cfp.Rules.OrderBy(r => r.SortOrder))
                .Where(cfp => cfp.IsEnabled && cfp.DeviceGroupId == null)
                .FirstOrDefaultAsync();

            if (cfPolicy != null)
            {
                var rulesJson = JsonSerializer.Serialize(
                    cfPolicy.Rules.Select(r => new
                    {
                        pattern   = r.Pattern,
                        isRegex   = r.IsRegex,
                        riskScore = (decimal)r.RiskScore / 10m,
                        action    = r.Action ?? "Deny"
                    }));
                settings = settings with
                {
                    CommandFilterMode      = (byte)cfPolicy.Mode,
                    CommandFilterRulesJson = rulesJson
                };
            }

            cache.Set(CacheKey, settings, TimeSpan.FromMinutes(5));
            return Results.Ok(new { success = true, data = settings });
        });

        pwdGroup.MapGet("/mfa", async (OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FirstOrDefaultAsync(
                x => x.PolicyType == "MFA" && x.Scope == PolicyScope.Global);
            var settings = ReadPolicy<MfaPolicySettings>(p?.PolicyJson ?? "{}");
            return Results.Ok(new { success = true, data = settings });
        });

        pwdGroup.MapPost("/mfa", async (
            MfaPolicySettings req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            await UpsertGlobalPolicyAsync(db, "MFA", "Global MFA Policy", req);

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "MFA_POLICY_UPDATED", null, null, ip,
                "Policy", "MFA", new { settings = req });

            return Results.Ok(new { success = true });
        });

        pwdGroup.MapPost("/session", async (
            SessionPolicySettings req, OrkunPamDbContext db,
            IAuditService audit, IMemoryCache cache, HttpContext ctx) =>
        {
            if (req.IdleTimeoutMinutes < 1)
                return Results.BadRequest(new { success = false, errors = new[] { "idleTimeoutMinutes must be >= 1" } });

            await UpsertGlobalPolicyAsync(db, "Session", "Global Session Policy", req);

            cache.Remove("policy:session:global:concurrent");
            cache.Remove("policy:session:effective");

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "SESSION_POLICY_UPDATED", null, null, ip,
                "Policy", "Session", new { settings = req });

            return Results.Ok(new { success = true });
        });

        pwdGroup.MapGet("/watermark", async (OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FirstOrDefaultAsync(
                x => x.PolicyType == "Watermark" && x.Scope == PolicyScope.Global);
            var settings = ReadPolicy<WatermarkPolicySettings>(p?.PolicyJson ?? "{}");
            return Results.Ok(new { success = true, data = settings });
        });

        pwdGroup.MapPut("/watermark", async (
            WatermarkPolicySettings req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (req.MarkerIntervalMin < 1 || req.MarkerIntervalMin > 120)
                return Results.BadRequest(new { success = false, errors = new[] { "markerIntervalMin must be 1-120" } });
            if (string.IsNullOrWhiteSpace(req.Template))
                return Results.BadRequest(new { success = false, errors = new[] { "template is required" } });

            await UpsertGlobalPolicyAsync(db, "Watermark", "Global Watermark Policy", req);

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "WATERMARK_POLICY_UPDATED", null, null, ip,
                "Policy", "Watermark", new { settings = req });

            return Results.Ok(new { success = true });
        });

        pwdGroup.MapGet("/device-trust", async (OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FirstOrDefaultAsync(
                x => x.PolicyType == "DeviceTrust" && x.Scope == PolicyScope.Global);
            var settings = ReadPolicy<DeviceTrustPolicySettings>(p?.PolicyJson ?? "{}");
            return Results.Ok(new { success = true, data = settings });
        });

        pwdGroup.MapPut("/device-trust", async (
            DeviceTrustPolicySettings req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (!new[] { "Allow", "StepUpAuth", "Block" }.Contains(req.UnknownDeviceAction))
                return Results.BadRequest(new { success = false, errors = new[] { "unknownDeviceAction must be Allow, StepUpAuth, or Block" } });

            await UpsertGlobalPolicyAsync(db, "DeviceTrust", "Global Device Trust Policy", req);

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "DEVICE_TRUST_POLICY_UPDATED", null, null, ip,
                "Policy", "DeviceTrust", new { settings = req });

            return Results.Ok(new { success = true });
        });

        pwdGroup.MapGet("/geo-access", async (OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FirstOrDefaultAsync(
                x => x.PolicyType == "GeoAccess" && x.Scope == PolicyScope.Global);
            var settings = ReadPolicy<GeolocationPolicySettings>(p?.PolicyJson ?? "{}");
            return Results.Ok(new { success = true, data = settings });
        });

        pwdGroup.MapPut("/geo-access", async (
            GeolocationPolicySettings req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var validActions = new[] { "Allow", "StepUpAuth", "Block" };
            if (!validActions.Contains(req.ViolationAction))
                return Results.BadRequest(new { success = false, errors = new[] { "violationAction must be Allow, StepUpAuth, or Block" } });
            if (!validActions.Contains(req.UnknownLocationAction))
                return Results.BadRequest(new { success = false, errors = new[] { "unknownLocationAction must be Allow, StepUpAuth, or Block" } });

            await UpsertGlobalPolicyAsync(db, "GeoAccess", "Global Geolocation Access Policy", req);

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "GEO_ACCESS_POLICY_UPDATED", null, null, ip,
                "Policy", "GeoAccess", new { settings = req });

            return Results.Ok(new { success = true });
        });

        pwdGroup.MapGet("/adaptive-mfa", async (OrkunPamDbContext db) =>
        {
            var p = await db.Policies.FirstOrDefaultAsync(
                x => x.PolicyType == "AdaptiveMFA" && x.Scope == PolicyScope.Global);
            var settings = ReadPolicy<AdaptiveMfaPolicySettings>(p?.PolicyJson ?? "{}");
            return Results.Ok(new { success = true, data = settings });
        });

        pwdGroup.MapPut("/adaptive-mfa", async (
            AdaptiveMfaPolicySettings req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (req.LowRiskThreshold < 0 || req.LowRiskThreshold >= req.MediumRiskThreshold ||
                req.MediumRiskThreshold >= req.HighRiskThreshold ||
                req.HighRiskThreshold >= req.BlockThreshold)
                return Results.BadRequest(new { success = false, errors = new[] { "Thresholds must be strictly increasing: Low < Medium < High < Block" } });

            await UpsertGlobalPolicyAsync(db, "AdaptiveMFA", "Global Adaptive MFA Policy", req);

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "ADAPTIVE_MFA_POLICY_UPDATED", null, null, ip,
                "Policy", "AdaptiveMFA", new { settings = req });

            return Results.Ok(new { success = true });
        });
    }
}

public record CreatePolicyRequest(string Name, string PolicyType, PolicyScope Scope, Guid? ScopeId, string PolicyJson, int Priority);
public record UpdatePolicyRequest(string? Name, string? PolicyJson, int? Priority, bool? IsEnabled);

public record PasswordPolicySettings
{
    public int  MinLength             { get; init; } = 12;
    public int  MaxLength             { get; init; } = 128;
    public bool RequireUppercase      { get; init; } = true;
    public bool RequireLowercase      { get; init; } = true;
    public bool RequireDigit          { get; init; } = true;
    public bool RequireSpecial        { get; init; } = true;
    public int  ExpiryDays            { get; init; } = 90;
    public int  PreventReuseCount     { get; init; } = 12;
    public bool ForceChangeOnFirstLogin { get; init; } = true;
}

public record LockoutPolicySettings
{
    public int MaxFailedAttempts          { get; init; } = 5;
    public int LockoutMinutes             { get; init; } = 30;
    public int FailedAttemptWindowMinutes { get; init; } = 15;
}

public record SessionPolicySettings
{
    public int     IdleTimeoutMinutes         { get; init; } = 30;
    public int     MaxConcurrentSessions      { get; init; } = 3;
    public byte    CommandFilterMode          { get; init; } = 0;
    public string? CommandFilterRulesJson     { get; init; }
    public decimal DoubleConfirmRiskThreshold { get; init; } = 0;
    public string? DoubleConfirmCommandsJson  { get; init; }
}

public record MfaPolicySettings
{
    public bool MfaRequired     { get; init; }
    public bool EmailOtpEnabled { get; init; }
    public bool SmsOtpEnabled   { get; init; }
}

public record WatermarkPolicySettings
{
    public bool   Enabled           { get; init; } = false;
    public string Template          { get; init; } = "{username} | {ip} | {device} | {utc}";
    public int    MarkerIntervalMin { get; init; } = 15;
    public bool   EnableSsh         { get; init; } = true;
    public bool   EnableRdp         { get; init; } = true;
    public bool   EnableVnc         { get; init; } = true;
}

public record DeviceTrustPolicySettings
{
    public bool   Enabled               { get; init; } = false;
    public bool   RequireTrustedDevice  { get; init; } = false;
    public string UnknownDeviceAction   { get; init; } = "Allow";
    public int    MaxTrustAgeDays       { get; init; } = 90;
    public bool   AutoRegisterOnLogin   { get; init; } = true;
}

public record GeolocationPolicySettings
{
    public bool     Enabled               { get; init; } = false;
    public string[] AllowedCountryCodes   { get; init; } = [];  // empty = all allowed
    public string[] BlockedCountryCodes   { get; init; } = [];  // explicit deny list
    public string   ViolationAction       { get; init; } = "Block";
    public string   UnknownLocationAction { get; init; } = "Allow";
    public bool     AllowPrivateIps       { get; init; } = true;
}

public record AdaptiveMfaPolicySettings
{
    public bool Enabled              { get; init; } = false;
    public int  LowRiskThreshold    { get; init; } = 25;
    public int  MediumRiskThreshold { get; init; } = 50;
    public int  HighRiskThreshold   { get; init; } = 75;
    public int  BlockThreshold      { get; init; } = 90;
}
