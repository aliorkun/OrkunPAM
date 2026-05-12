using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Compliance;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ComplianceEndpoints
{
    public static void MapComplianceEndpoints(this IEndpointRouteBuilder app)
    {
        var frameworks = app.MapGroup("/api/v1/compliance/frameworks").WithTags("Compliance");

        frameworks.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.ComplianceFrameworks
                .Select(f => new { f.Id, f.Name, f.Version, f.IsBuiltIn, f.CreatedAtUtc })
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        frameworks.MapPost("/", async (CreateFrameworkRequest req, OrkunPamDbContext db) =>
        {
            var fw = new ComplianceFramework
            {
                Name = req.Name,
                Version = req.Version,
                ControlsJson = req.ControlsJson ?? "[]"
            };
            db.ComplianceFrameworks.Add(fw);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/compliance/frameworks/{fw.Id}", new { success = true, data = new { fw.Id, fw.Name } });
        });

        frameworks.MapGet("/{id:guid}/assessment", async (Guid id, OrkunPamDbContext db) =>
        {
            var fw = await db.ComplianceFrameworks.FindAsync(id);
            if (fw == null) return Results.NotFound(new { success = false, errors = new[] { "Framework not found" } });

            var assessments = await db.ControlAssessments
                .Where(ca => ca.FrameworkId == id)
                .Select(ca => new { ca.ControlCode, ca.Status, ca.EvidenceJson, ca.AssessedAtUtc })
                .ToListAsync();

            var total = assessments.Count;
            var compliant = assessments.Count(a => a.Status == 1);

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    framework = new { fw.Id, fw.Name, fw.Version },
                    score = total > 0 ? Math.Round((double)compliant / total * 100, 1) : 0,
                    totalControls = total,
                    compliant,
                    nonCompliant = assessments.Count(a => a.Status == 0),
                    partial = assessments.Count(a => a.Status == 2),
                    na = assessments.Count(a => a.Status == 3),
                    assessments
                }
            });
        });

        var sod = app.MapGroup("/api/v1/compliance/sod").WithTags("Compliance");

        sod.MapGet("/rules", async (OrkunPamDbContext db) =>
        {
            var rules = await db.SodRules.ToListAsync();
            return Results.Ok(new { success = true, data = rules });
        });

        sod.MapPost("/rules", async (CreateSodRuleRequest req, OrkunPamDbContext db) =>
        {
            var rule = new SodRule { Name = req.Name, RoleA = req.RoleA, RoleB = req.RoleB };
            db.SodRules.Add(rule);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/compliance/sod/rules/{rule.Id}", new { success = true, data = new { rule.Id } });
        });

        sod.MapGet("/violations", async (OrkunPamDbContext db) =>
        {
            var rules = await db.SodRules.Where(r => r.IsEnabled).ToListAsync();
            var violations = new List<object>();

            foreach (var rule in rules)
            {
                var usersWithBoth = await db.UserRoles
                    .Where(ur => ur.RoleId == rule.RoleA)
                    .Select(ur => ur.UserId)
                    .Intersect(db.UserRoles.Where(ur => ur.RoleId == rule.RoleB).Select(ur => ur.UserId))
                    .ToListAsync();

                foreach (var userId in usersWithBoth)
                {
                    violations.Add(new { rule.Id, RuleName = rule.Name, UserId = userId, rule.RoleA, rule.RoleB });
                }
            }

            return Results.Ok(new { success = true, data = violations, meta = new { violationCount = violations.Count } });
        });

        var attestations = app.MapGroup("/api/v1/compliance/attestations").WithTags("Compliance");

        attestations.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.AttestationCampaigns
                .Select(c => new { c.Id, c.Name, c.StartsAtUtc, c.DeadlineUtc, c.Status, c.AutoRevokeOnMiss })
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        attestations.MapPost("/", async (CreateAttestationRequest req, OrkunPamDbContext db) =>
        {
            var campaign = new AttestationCampaign
            {
                Name = req.Name,
                ScopeJson = req.ScopeJson,
                ReviewerRuleJson = req.ReviewerRuleJson,
                StartsAtUtc = req.StartsAtUtc ?? DateTime.UtcNow,
                DeadlineUtc = req.DeadlineUtc,
                AutoRevokeOnMiss = req.AutoRevokeOnMiss
            };
            db.AttestationCampaigns.Add(campaign);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/compliance/attestations/{campaign.Id}",
                new { success = true, data = new { campaign.Id, campaign.Name } });
        });

        app.MapPost("/api/v1/compliance/evidence/export", async (EvidenceExportRequest req, OrkunPamDbContext db) =>
        {
            var auditLogs = await db.AuditLogs
                .Where(a => a.Timestamp >= req.From && a.Timestamp <= req.To)
                .CountAsync();

            var sessions = await db.ProxySessions
                .Where(s => s.StartedAtUtc >= req.From && s.StartedAtUtc <= req.To)
                .CountAsync();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    period = new { req.From, req.To },
                    auditLogEntries = auditLogs,
                    sessionRecords = sessions,
                    message = "Evidence bundle ready for download (full implementation: ZIP export with index)",
                    exportFormat = "ZIP",
                    generatedAt = DateTime.UtcNow
                }
            });
        }).WithTags("Compliance");
    }
}

public record CreateFrameworkRequest(string Name, string? Version, string? ControlsJson);
public record CreateSodRuleRequest(string Name, Guid RoleA, Guid RoleB);
public record CreateAttestationRequest(string Name, string? ScopeJson, string? ReviewerRuleJson,
    DateTime? StartsAtUtc, DateTime DeadlineUtc, bool AutoRevokeOnMiss);
public record EvidenceExportRequest(DateTime From, DateTime To, string? FrameworkId);
