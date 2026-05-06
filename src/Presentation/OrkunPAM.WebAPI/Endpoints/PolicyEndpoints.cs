using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class PolicyEndpoints
{
    public static void MapPolicyEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/v1/policies").WithTags("Policies");

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

        // Evaluate effective policies for a user
        group.MapGet("/effective/{userId:guid}", async (Guid userId, string policyType, OrkunPamDbContext db) =>
        {
            // Get user's groups
            var groupIds = await db.UserGroups
                .Where(ug => ug.UserId == userId)
                .Select(ug => ug.GroupId)
                .ToListAsync();

            // Collect policies: Global + user's groups + direct user, ordered by priority
            var policies = await db.Policies
                .Where(p => p.PolicyType == policyType && p.IsEnabled &&
                    (p.Scope == PolicyScope.Global ||
                     (p.Scope == PolicyScope.User && p.ScopeId == userId) ||
                     (p.Scope == PolicyScope.Group && groupIds.Contains(p.ScopeId!.Value))))
                .OrderByDescending(p => p.Scope) // User > Group > Global (higher scope wins)
                .ThenByDescending(p => p.Priority)
                .Select(p => new { p.Id, p.Name, Scope = p.Scope.ToString(), p.PolicyJson, p.Priority })
                .ToListAsync();

            return Results.Ok(new { success = true, data = policies });
        });
    }
}

public record CreatePolicyRequest(string Name, string PolicyType, PolicyScope Scope, Guid? ScopeId, string PolicyJson, int Priority);
public record UpdatePolicyRequest(string? Name, string? PolicyJson, int? Priority, bool? IsEnabled);
