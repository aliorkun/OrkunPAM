using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Compliance;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ComplianceEndpoints
{
    public static void MapComplianceEndpoints(this IEndpointRouteBuilder app)
    {
        var frameworks = app.MapGroup("/api/v1/compliance/frameworks").WithTags("Compliance").RequireAuthorization();

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

        var sod = app.MapGroup("/api/v1/compliance/sod").WithTags("Compliance").RequireAuthorization();

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

        var attestations = app.MapGroup("/api/v1/compliance/attestations").WithTags("Compliance").RequireAuthorization();

        attestations.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.AttestationCampaigns
                .Select(c => new { c.Id, c.Name, c.StartsAtUtc, c.DeadlineUtc, c.Status, c.AutoRevokeOnMiss, c.ReviewerUserId, c.CompletedAtUtc })
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
                ReviewerUserId = req.ReviewerUserId,
                StartsAtUtc = req.StartsAtUtc ?? DateTime.UtcNow,
                DeadlineUtc = req.DeadlineUtc,
                AutoRevokeOnMiss = req.AutoRevokeOnMiss
            };
            db.AttestationCampaigns.Add(campaign);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/compliance/attestations/{campaign.Id}",
                new { success = true, data = new { campaign.Id, campaign.Name } });
        });

        attestations.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var campaign = await db.AttestationCampaigns.FindAsync(id);
            if (campaign == null) return Results.NotFound(new { success = false, errors = new[] { "Campaign not found" } });

            var decisions = await db.AttestationDecisions
                .Where(d => d.CampaignId == id)
                .Select(d => new
                {
                    d.Id, d.SubjectUserId, d.SubjectUsername,
                    d.ResourceType, d.ResourceId, d.ResourceName,
                    d.Decision, d.DecisionAtUtc, d.Comments, d.ReviewerUserId
                })
                .ToListAsync();

            var total = decisions.Count;
            var decided = decisions.Count(d => d.Decision != null && d.Decision != 0);
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    campaign.Id, campaign.Name, campaign.Status, campaign.StartsAtUtc,
                    campaign.DeadlineUtc, campaign.AutoRevokeOnMiss, campaign.ReviewerUserId,
                    campaign.CompletedAtUtc,
                    totalItems = total,
                    decidedItems = decided,
                    pendingItems = total - decided,
                    decisions
                }
            });
        });

        attestations.MapPost("/{id:guid}/start", async (Guid id, OrkunPamDbContext db) =>
        {
            var campaign = await db.AttestationCampaigns.FindAsync(id);
            if (campaign == null) return Results.NotFound(new { success = false, errors = new[] { "Campaign not found" } });
            if (campaign.Status != 0) return Results.BadRequest(new { success = false, errors = new[] { "Campaign is not in Draft status" } });

            var reviewerId = campaign.ReviewerUserId ?? Guid.Empty;

            List<(Guid UserId, string Username)> subjects = new();
            var scopeType = "AllUsers";
            Guid scopeId = Guid.Empty;

            if (!string.IsNullOrEmpty(campaign.ScopeJson))
            {
                try
                {
                    var scopeDoc = System.Text.Json.JsonDocument.Parse(campaign.ScopeJson);
                    if (scopeDoc.RootElement.TryGetProperty("type", out var t)) scopeType = t.GetString() ?? "AllUsers";
                    if (scopeDoc.RootElement.TryGetProperty("groupId", out var g) && g.GetString() is string gs) scopeId = Guid.Parse(gs);
                    if (scopeDoc.RootElement.TryGetProperty("roleId", out var r) && r.GetString() is string rs) scopeId = Guid.Parse(rs);
                }
                catch { }
            }

            if (scopeType == "Group" && scopeId != Guid.Empty)
            {
                var rawList = await db.UserGroups
                    .Where(ug => ug.GroupId == scopeId)
                    .Join(db.Users, ug => ug.UserId, u => u.Id, (ug, u) => new { u.Id, u.Username })
                    .AsNoTracking()
                    .ToListAsync();
                subjects = rawList.Select(x => (x.Id, x.Username)).ToList();
            }
            else if (scopeType == "Role" && scopeId != Guid.Empty)
            {
                var rawList = await db.UserRoles
                    .Where(ur => ur.RoleId == scopeId)
                    .Join(db.Users, ur => ur.UserId, u => u.Id, (ur, u) => new { u.Id, u.Username })
                    .AsNoTracking()
                    .ToListAsync();
                subjects = rawList.Select(x => (x.Id, x.Username)).ToList();
            }
            else
            {
                var rawList = await db.Users
                    .Select(u => new { u.Id, u.Username })
                    .AsNoTracking()
                    .ToListAsync();
                subjects = rawList.Select(x => (x.Id, x.Username)).ToList();
            }

            var existingIds = (await db.AttestationDecisions
                .Where(d => d.CampaignId == id)
                .Select(d => d.SubjectUserId)
                .ToListAsync()).ToHashSet();

            int generated = 0;
            foreach (var (userId, username) in subjects)
            {
                if (existingIds.Contains(userId)) continue;
                db.AttestationDecisions.Add(new AttestationDecision
                {
                    CampaignId = id,
                    ReviewerUserId = reviewerId,
                    SubjectUserId = userId,
                    SubjectUsername = username,
                    ResourceType = "UserAccess",
                    Decision = 0
                });
                generated++;
            }

            campaign.Status = 1;
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, data = new { campaign.Id, campaign.Status, itemsGenerated = generated } });
        });

        attestations.MapPost("/{campaignId:guid}/decisions/{decisionId:long}/decide",
            async (Guid campaignId, long decisionId, AttestationDecideRequest req, OrkunPamDbContext db,
                   HttpContext ctx, IAuditService audit) =>
        {
            var decision = await db.AttestationDecisions
                .FirstOrDefaultAsync(d => d.Id == decisionId && d.CampaignId == campaignId);
            if (decision == null) return Results.NotFound(new { success = false, errors = new[] { "Decision item not found" } });

            decision.Decision = req.Decision;
            decision.DecisionAtUtc = DateTime.UtcNow;
            decision.Comments = req.Comments;

            if (req.Decision == 2)
            {
                var user = await db.Users.FindAsync(decision.SubjectUserId);
                if (user != null)
                    user.Status = OrkunPAM.Domain.Enums.UserStatus.Locked;
            }

            await db.SaveChangesAsync();

            var actorId  = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown";
            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _ = audit.LogAsync("Compliance", "AttestationDecisionMade", Guid.TryParse(actorId, out var aid) ? aid : Guid.Empty,
                actorName, ip, "AttestationDecision", decisionId.ToString(),
                new { campaignId, decision = req.Decision, subjectUserId = decision.SubjectUserId,
                      subjectUsername = decision.SubjectUsername, accountLocked = req.Decision == 2 });

            return Results.Ok(new { success = true, data = new { decisionId, decision.Decision, decision.DecisionAtUtc } });
        });

        attestations.MapPost("/{id:guid}/complete", async (Guid id, OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var campaign = await db.AttestationCampaigns.FindAsync(id);
            if (campaign == null) return Results.NotFound(new { success = false, errors = new[] { "Campaign not found" } });
            if (campaign.Status != 1) return Results.BadRequest(new { success = false, errors = new[] { "Campaign is not Active" } });

            var autoRevokedCount = 0;
            if (campaign.AutoRevokeOnMiss)
            {
                var pendingDecisions = await db.AttestationDecisions
                    .Where(d => d.CampaignId == id && (d.Decision == null || d.Decision == 0))
                    .ToListAsync();

                foreach (var d in pendingDecisions)
                {
                    d.Decision = 2;
                    d.DecisionAtUtc = DateTime.UtcNow;
                    d.Comments = "Auto-revoked on campaign completion (no decision made)";
                    var user = await db.Users.FindAsync(d.SubjectUserId);
                    if (user != null)
                        user.Status = OrkunPAM.Domain.Enums.UserStatus.Locked;
                    autoRevokedCount++;
                }
            }

            campaign.Status = 2;
            campaign.CompletedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            var actorId  = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier) ?? "unknown";
            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            _ = audit.LogAsync("Compliance", "AttestationCampaignCompleted", Guid.TryParse(actorId, out var aid) ? aid : Guid.Empty,
                actorName, ip, "AttestationCampaign", id.ToString(),
                new { campaignName = campaign.Name, autoRevokedCount, autoRevokeOnMiss = campaign.AutoRevokeOnMiss });

            return Results.Ok(new { success = true, data = new { campaign.Id, campaign.Status, campaign.CompletedAtUtc } });
        });

        // === Account Reconciliation (#195) ===
        var recon = app.MapGroup("/api/v1/compliance/reconciliation")
            .WithTags("Compliance").RequireAuthorization("AdminPolicy");

        recon.MapGet("/report", async (OrkunPamDbContext db) =>
        {
            var now = DateTime.UtcNow;

            var staleUsers = await db.Users
                .Where(u => u.Status != UserStatus.Active || u.IsOrphaned ||
                            (u.IsTemporary && u.TemporaryExpiresUtc.HasValue && u.TemporaryExpiresUtc < now))
                .Select(u => new { u.Id, u.Username, u.Status, u.IsOrphaned, u.IsTemporary, u.TemporaryExpiresUtc })
                .ToListAsync();

            var staleUserIds = staleUsers.Select(u => u.Id).ToList();

            var perms = await db.CredentialPermissions
                .Where(p => p.PrincipalType == PrincipalType.User && staleUserIds.Contains(p.PrincipalId) && p.FolderId != null)
                .Select(p => new
                {
                    PermId = p.Id,
                    p.PrincipalId,
                    p.PermissionLevel,
                    p.CanShare,
                    FolderId = p.FolderId,
                    FolderName = p.Folder != null ? p.Folder.Name : "(no folder)"
                })
                .ToListAsync();

            var drifts = perms.Select(x =>
            {
                var u = staleUsers.First(u => u.Id == x.PrincipalId);
                var driftType = u.IsOrphaned ? "OrphanedAssignment" :
                    (u.IsTemporary && u.TemporaryExpiresUtc.HasValue && u.TemporaryExpiresUtc < now) ? "TemporaryExpired" : "StaleAccess";
                return new
                {
                    PermissionId = x.PermId.ToString(),
                    UserId = u.Id.ToString(),
                    u.Username,
                    UserStatus = u.Status.ToString(),
                    u.IsOrphaned,
                    FolderId = x.FolderId.ToString(),
                    x.FolderName,
                    PermissionLevel = x.PermissionLevel.ToString(),
                    x.CanShare,
                    DriftType = driftType,
                    DetectedAt = now
                };
            }).ToList();

            return Results.Ok(new { success = true, data = drifts });
        });

        recon.MapPost("/auto-remediate", async (OrkunPamDbContext db, HttpContext ctx, IAuditService audit) =>
        {
            var now = DateTime.UtcNow;
            var actorIdStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            var actorName = ctx.User.FindFirstValue(ClaimTypes.Name) ?? "unknown";
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            Guid.TryParse(actorIdStr, out var actorId);

            var staleUserIds = await db.Users
                .Where(u => u.Status != UserStatus.Active || u.IsOrphaned ||
                            (u.IsTemporary && u.TemporaryExpiresUtc.HasValue && u.TemporaryExpiresUtc < now))
                .Select(u => u.Id)
                .ToListAsync();

            var stalePerms = await db.CredentialPermissions
                .Where(p => p.PrincipalType == PrincipalType.User && staleUserIds.Contains(p.PrincipalId))
                .ToListAsync();

            db.CredentialPermissions.RemoveRange(stalePerms);
            await db.SaveChangesAsync();

            _ = audit.LogAsync("Compliance", "ReconciliationAutoRemediate", actorId, actorName, ip,
                "CredentialPermission", "bulk",
                new { revokedCount = stalePerms.Count, staleUserCount = staleUserIds.Count });

            return Results.Ok(new { success = true, data = new { revokedPermissions = stalePerms.Count, remediatedAt = now } });
        });

        recon.MapGet("/history", async (OrkunPamDbContext db) =>
        {
            var history = await db.AuditLogs
                .Where(a => a.EventCategory == "Compliance" && a.EventType == "ReconciliationAutoRemediate")
                .OrderByDescending(a => a.Timestamp)
                .Take(20)
                .Select(a => new { a.Id, a.ActorUsername, a.Timestamp, a.Details })
                .ToListAsync();
            return Results.Ok(new { success = true, data = history });
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
        }).WithTags("Compliance").RequireAuthorization();
    }
}

public record CreateFrameworkRequest(string Name, string? Version, string? ControlsJson);
public record CreateSodRuleRequest(string Name, Guid RoleA, Guid RoleB);
public record CreateAttestationRequest(string Name, string? ScopeJson, string? ReviewerRuleJson,
    Guid? ReviewerUserId, DateTime? StartsAtUtc, DateTime DeadlineUtc, bool AutoRevokeOnMiss);
public record AttestationDecideRequest(byte Decision, string? Comments);
public record EvidenceExportRequest(DateTime From, DateTime To, string? FrameworkId);
