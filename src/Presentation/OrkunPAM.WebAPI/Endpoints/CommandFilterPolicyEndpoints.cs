using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class CommandFilterPolicyEndpoints
{
    public static void MapCommandFilterPolicyEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/policies/command-filter")
            .WithTags("CommandFilter")
            .RequireAuthorization("AdminPolicy");

        // GET — list all command filter policies
        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var policies = await db.CommandFilterPolicies
                .Include(p => p.Rules)
                .OrderBy(p => p.Name)
                .Select(p => new
                {
                    p.Id, p.Name, p.Description, p.IsEnabled,
                    Mode = p.Mode.ToString(),
                    p.DeviceGroupId,
                    RuleCount = p.Rules.Count,
                    p.CreatedAtUtc, p.UpdatedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = policies });
        });

        // POST — create policy
        group.MapPost("/", async (CreateCommandFilterPolicyRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            if (!Enum.TryParse<CommandFilterMode>(req.Mode, true, out var mode))
                return Results.BadRequest(new { success = false, errors = new[] { "Mode must be None, Whitelist, or Blacklist" } });

            var policy = new CommandFilterPolicy
            {
                Id          = Guid.NewGuid(),
                Name        = req.Name.Trim(),
                Description = req.Description?.Trim(),
                IsEnabled   = req.IsEnabled ?? true,
                Mode        = mode,
                DeviceGroupId = req.DeviceGroupId
            };

            db.CommandFilterPolicies.Add(policy);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "COMMAND_FILTER_POLICY_CREATED", null, null, ip,
                "CommandFilterPolicy", policy.Id.ToString(), new { policy.Name, policy.Mode });

            return Results.Created($"/api/v1/policies/command-filter/{policy.Id}",
                new { success = true, data = new { policy.Id, policy.Name } });
        });

        // GET {id} — get policy with rules
        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var policy = await db.CommandFilterPolicies
                .Include(p => p.Rules.OrderBy(r => r.SortOrder))
                .FirstOrDefaultAsync(p => p.Id == id);

            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    policy.Id, policy.Name, policy.Description, policy.IsEnabled,
                    Mode = policy.Mode.ToString(),
                    policy.DeviceGroupId,
                    policy.CreatedAtUtc, policy.UpdatedAtUtc,
                    Rules = policy.Rules.Select(r => new
                    {
                        r.Id, r.Pattern, r.IsRegex, r.Action,
                        r.RiskScore, r.Justification, r.SortOrder
                    })
                }
            });
        });

        // PUT {id} — update policy metadata
        group.MapPut("/{id:guid}", async (Guid id, UpdateCommandFilterPolicyRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var policy = await db.CommandFilterPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            if (req.Name != null) policy.Name = req.Name.Trim();
            if (req.Description != null) policy.Description = req.Description.Trim();
            if (req.IsEnabled.HasValue) policy.IsEnabled = req.IsEnabled.Value;
            if (req.DeviceGroupId.HasValue) policy.DeviceGroupId = req.DeviceGroupId;

            if (req.Mode != null && Enum.TryParse<CommandFilterMode>(req.Mode, true, out var mode))
                policy.Mode = mode;

            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "COMMAND_FILTER_POLICY_UPDATED", null, null, ip,
                "CommandFilterPolicy", policy.Id.ToString(), new { policy.Name, policy.IsEnabled });

            return Results.Ok(new { success = true, data = new { policy.Id, policy.Name } });
        });

        // DELETE {id}
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var policy = await db.CommandFilterPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            db.CommandFilterPolicies.Remove(policy);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "COMMAND_FILTER_POLICY_DELETED", null, null, ip,
                "CommandFilterPolicy", id.ToString(), null);

            return Results.Ok(new { success = true });
        });

        // PUT {id}/toggle — enable / disable
        group.MapPut("/{id:guid}/toggle", async (Guid id, ToggleCommandFilterPolicyRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var policy = await db.CommandFilterPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            policy.IsEnabled = req.IsEnabled;
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            var action = req.IsEnabled ? "COMMAND_FILTER_POLICY_ENABLED" : "COMMAND_FILTER_POLICY_DISABLED";
            await audit.LogAsync("Policy", action, null, null, ip,
                "CommandFilterPolicy", id.ToString(), new { policy.Name });

            return Results.Ok(new { success = true });
        });

        // GET {id}/rules
        group.MapGet("/{id:guid}/rules", async (Guid id, OrkunPamDbContext db) =>
        {
            var exists = await db.CommandFilterPolicies.AnyAsync(p => p.Id == id);
            if (!exists)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            var rules = await db.CommandFilterPolicyRules
                .Where(r => r.PolicyId == id)
                .OrderBy(r => r.SortOrder)
                .Select(r => new { r.Id, r.Pattern, r.IsRegex, r.Action, r.RiskScore, r.Justification, r.SortOrder })
                .ToListAsync();

            return Results.Ok(new { success = true, data = rules });
        });

        // POST {id}/rules — add rule
        group.MapPost("/{id:guid}/rules", async (Guid id, AddCommandFilterRuleRequest req, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var policy = await db.CommandFilterPolicies.FindAsync(id);
            if (policy == null)
                return Results.NotFound(new { success = false, errors = new[] { "Policy not found" } });

            if (string.IsNullOrWhiteSpace(req.Pattern))
                return Results.BadRequest(new { success = false, errors = new[] { "Pattern is required" } });

            var validActions = new[] { "Allow", "Deny", "Alert" };
            var action = validActions.Contains(req.Action) ? req.Action : "Deny";

            var riskScore = Math.Clamp(req.RiskScore ?? 50, 0, 100);

            var maxOrder = await db.CommandFilterPolicyRules
                .Where(r => r.PolicyId == id)
                .Select(r => (int?)r.SortOrder)
                .MaxAsync() ?? -1;

            var rule = new CommandFilterPolicyRule
            {
                Id          = Guid.NewGuid(),
                PolicyId    = id,
                Pattern     = req.Pattern.Trim(),
                IsRegex     = req.IsRegex ?? false,
                Action      = action,
                RiskScore   = riskScore,
                Justification = req.Justification?.Trim(),
                SortOrder   = maxOrder + 1
            };

            db.CommandFilterPolicyRules.Add(rule);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "COMMAND_FILTER_RULE_ADDED", null, null, ip,
                "CommandFilterPolicyRule", rule.Id.ToString(),
                new { PolicyId = id, rule.Pattern, rule.Action });

            return Results.Created($"/api/v1/policies/command-filter/{id}/rules/{rule.Id}",
                new { success = true, data = new { rule.Id, rule.Pattern, rule.Action } });
        });

        // DELETE {id}/rules/{ruleId}
        group.MapDelete("/{id:guid}/rules/{ruleId:guid}", async (Guid id, Guid ruleId, OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var rule = await db.CommandFilterPolicyRules
                .FirstOrDefaultAsync(r => r.Id == ruleId && r.PolicyId == id);

            if (rule == null)
                return Results.NotFound(new { success = false, errors = new[] { "Rule not found" } });

            db.CommandFilterPolicyRules.Remove(rule);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Policy", "COMMAND_FILTER_RULE_REMOVED", null, null, ip,
                "CommandFilterPolicyRule", ruleId.ToString(), new { PolicyId = id });

            return Results.Ok(new { success = true });
        });

        // GET /effective — effective policy for device group (merged rules as JSON for proxy)
        group.MapGet("/effective", async (Guid? deviceGroupId, OrkunPamDbContext db) =>
        {
            CommandFilterPolicy? policy = null;
            if (deviceGroupId.HasValue)
                policy = await db.CommandFilterPolicies
                    .Include(p => p.Rules.OrderBy(r => r.SortOrder))
                    .Where(p => p.IsEnabled && p.DeviceGroupId == deviceGroupId)
                    .FirstOrDefaultAsync();

            policy ??= await db.CommandFilterPolicies
                .Include(p => p.Rules.OrderBy(r => r.SortOrder))
                .Where(p => p.IsEnabled && p.DeviceGroupId == null)
                .FirstOrDefaultAsync();

            if (policy == null)
                return Results.Ok(new { success = true, data = new { mode = 0, rulesJson = (string?)null } });

            var rulesJson = JsonSerializer.Serialize(
                policy.Rules.Select(r => new { pattern = r.Pattern, isRegex = r.IsRegex, riskScore = (decimal)r.RiskScore / 10m }));

            return Results.Ok(new
            {
                success = true,
                data = new { mode = (byte)policy.Mode, rulesJson }
            });
        });
    }
}

public record CreateCommandFilterPolicyRequest(
    string Name,
    string? Description,
    bool? IsEnabled,
    string Mode,
    Guid? DeviceGroupId);

public record UpdateCommandFilterPolicyRequest(
    string? Name,
    string? Description,
    bool? IsEnabled,
    string? Mode,
    Guid? DeviceGroupId);

public record ToggleCommandFilterPolicyRequest(bool IsEnabled);

public record AddCommandFilterRuleRequest(
    string Pattern,
    bool? IsRegex,
    string Action,
    int? RiskScore,
    string? Justification);
