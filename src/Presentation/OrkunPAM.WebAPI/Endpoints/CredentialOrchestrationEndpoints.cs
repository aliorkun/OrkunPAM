using System.Security.Claims;
using System.Text;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class CredentialOrchestrationEndpoints
{
    public static void MapCredentialOrchestrationEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/v1/vault/orchestration")
            .WithTags("CredentialOrchestration")
            .RequireAuthorization("AdminPolicy");

        // GET / — list all sets
        group.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var sets = await db.CredentialOrchestrationSets
                .OrderByDescending(s => s.CreatedAtUtc)
                .Select(s => new
                {
                    id               = s.Id,
                    name             = s.Name,
                    description      = s.Description,
                    executionMode    = s.ExecutionMode.ToString(),
                    rollbackOnFailure = s.RollbackOnFailure,
                    notifyOnComplete  = s.NotifyOnComplete,
                    scheduleCron     = s.ScheduleCron,
                    memberCount      = s.Members.Count,
                    lastRunStatus    = s.Runs.OrderByDescending(r => r.StartedAtUtc).Select(r => r.Status.ToString()).FirstOrDefault(),
                    lastRunAt        = (DateTime?)s.Runs.OrderByDescending(r => r.StartedAtUtc).Select(r => r.StartedAtUtc).FirstOrDefault(),
                    createdAtUtc     = s.CreatedAtUtc
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = sets });
        });

        // POST / — create set
        group.MapPost("/", async (CreateOrchestrationSetRequest req, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(actorStr, out var actorId);

            var set = new CredentialOrchestrationSet
            {
                Id               = Guid.NewGuid(),
                Name             = req.Name.Trim(),
                Description      = req.Description?.Trim(),
                ExecutionMode    = Enum.TryParse<OrchestrationExecutionMode>(req.ExecutionMode, true, out var em) ? em : OrchestrationExecutionMode.Sequential,
                RollbackOnFailure = req.RollbackOnFailure,
                NotifyOnComplete  = req.NotifyOnComplete,
                ScheduleCron     = req.ScheduleCron?.Trim(),
                CreatedAtUtc     = DateTime.UtcNow,
                UpdatedAtUtc     = DateTime.UtcNow
            };

            // Add initial members if provided
            int order = 0;
            foreach (var credId in req.CredentialIds ?? [])
            {
                if (await db.Credentials.AnyAsync(c => c.Id == credId))
                    set.Members.Add(new CredentialOrchestrationMember
                    {
                        Id             = Guid.NewGuid(),
                        CredentialId   = credId,
                        ExecutionOrder = order++
                    });
            }

            db.CredentialOrchestrationSets.Add(set);
            await db.SaveChangesAsync();

            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Orchestration", "ORCHESTRATION_SET_CREATED", actorId, null, ip,
                "CredentialOrchestrationSet", set.Id.ToString(), new { set.Name, set.ExecutionMode });

            return Results.Created($"/api/v1/vault/orchestration/{set.Id}", new { success = true, data = new { set.Id } });
        });

        // GET /{id} — set detail with members
        group.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var set = await db.CredentialOrchestrationSets
                .Include(s => s.Members).ThenInclude(m => m.Credential)
                .FirstOrDefaultAsync(s => s.Id == id);

            if (set == null) return Results.NotFound();

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    id               = set.Id,
                    name             = set.Name,
                    description      = set.Description,
                    executionMode    = set.ExecutionMode.ToString(),
                    rollbackOnFailure = set.RollbackOnFailure,
                    notifyOnComplete  = set.NotifyOnComplete,
                    scheduleCron     = set.ScheduleCron,
                    members          = set.Members
                        .OrderBy(m => m.ExecutionOrder)
                        .Select(m => new
                        {
                            id             = m.Id,
                            credentialId   = m.CredentialId,
                            credentialName = m.Credential.Name,
                            credentialUser = m.Credential.Username,
                            executionOrder = m.ExecutionOrder
                        }),
                    createdAtUtc = set.CreatedAtUtc
                }
            });
        });

        // PUT /{id} — update set (metadata + full member list)
        group.MapPut("/{id:guid}", async (Guid id, UpdateOrchestrationSetRequest req,
            OrkunPamDbContext db, IAuditService audit, HttpContext ctx) =>
        {
            var set = await db.CredentialOrchestrationSets
                .Include(s => s.Members)
                .FirstOrDefaultAsync(s => s.Id == id);

            if (set == null) return Results.NotFound();

            if (!string.IsNullOrWhiteSpace(req.Name))        set.Name             = req.Name.Trim();
            if (req.Description != null)                      set.Description      = req.Description.Trim();
            if (!string.IsNullOrWhiteSpace(req.ExecutionMode))
                set.ExecutionMode = Enum.TryParse<OrchestrationExecutionMode>(req.ExecutionMode, true, out var em2) ? em2 : set.ExecutionMode;
            if (req.RollbackOnFailure.HasValue) set.RollbackOnFailure = req.RollbackOnFailure.Value;
            if (req.NotifyOnComplete.HasValue)  set.NotifyOnComplete  = req.NotifyOnComplete.Value;
            if (req.ScheduleCron != null)       set.ScheduleCron      = req.ScheduleCron.Trim();

            // Replace member list if provided
            if (req.CredentialIds != null)
            {
                db.CredentialOrchestrationMembers.RemoveRange(set.Members);
                set.Members.Clear();
                int order = 0;
                foreach (var credId in req.CredentialIds)
                {
                    if (await db.Credentials.AnyAsync(c => c.Id == credId))
                        set.Members.Add(new CredentialOrchestrationMember
                        {
                            Id             = Guid.NewGuid(),
                            SetId          = id,
                            CredentialId   = credId,
                            ExecutionOrder = order++
                        });
                }
            }

            set.UpdatedAtUtc = DateTime.UtcNow;
            await db.SaveChangesAsync();

            var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(actorStr, out var actorId);
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Orchestration", "ORCHESTRATION_SET_UPDATED", actorId, null, ip,
                "CredentialOrchestrationSet", id.ToString(), new { set.Name });

            return Results.Ok(new { success = true });
        });

        // DELETE /{id} — delete set
        group.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db,
            IAuditService audit, HttpContext ctx) =>
        {
            var set = await db.CredentialOrchestrationSets.FindAsync(id);
            if (set == null) return Results.NotFound();

            db.CredentialOrchestrationSets.Remove(set);
            await db.SaveChangesAsync();

            var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(actorStr, out var actorId);
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
            await audit.LogAsync("Orchestration", "ORCHESTRATION_SET_DELETED", actorId, null, ip,
                "CredentialOrchestrationSet", id.ToString(), new { set.Name });

            return Results.Ok(new { success = true });
        });

        // POST /{id}/run — trigger manual orchestration run
        group.MapPost("/{id:guid}/run", async (Guid id, OrkunPamDbContext db,
            IPasswordRotationOrchestrator rotator, IAuditService audit,
            IEmailService? email, HttpContext ctx) =>
        {
            var set = await db.CredentialOrchestrationSets
                .Include(s => s.Members.OrderBy(m => m.ExecutionOrder))
                .FirstOrDefaultAsync(s => s.Id == id);

            if (set == null) return Results.NotFound();
            if (!set.Members.Any())
                return Results.BadRequest(new { success = false, errors = new[] { "Set has no members" } });

            var actorStr = ctx.User.FindFirstValue(ClaimTypes.NameIdentifier);
            Guid.TryParse(actorStr, out var actorId);
            var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";

            var run = new CredentialOrchestrationRun
            {
                Id                = Guid.NewGuid(),
                SetId             = id,
                StartedAtUtc      = DateTime.UtcNow,
                Status            = OrchestrationRunStatus.Running,
                TriggeredByUserId = actorId == Guid.Empty ? null : actorId
            };
            db.CredentialOrchestrationRuns.Add(run);
            await db.SaveChangesAsync();

            await audit.LogAsync("Orchestration", "ORCHESTRATION_SET_STARTED", actorId, null, ip,
                "CredentialOrchestrationSet", id.ToString(), new { set.Name, RunId = run.Id });

            var logBuilder   = new StringBuilder();
            var rollbackList = new List<(Guid credId, byte[]? oldPasswordEnc)>();
            var credIds      = set.Members.Select(m => m.CredentialId).ToList();

            // Snapshot old passwords for potential rollback
            var credentials = await db.Credentials
                .Where(c => credIds.Contains(c.Id))
                .ToListAsync();
            foreach (var cred in credentials)
                rollbackList.Add((cred.Id, cred.PasswordEnc != null ? (byte[])cred.PasswordEnc.Clone() : null));

            async Task<bool> RotateOne(Guid credId)
            {
                try
                {
                    var result = await rotator.RotateAsync(credId);
                    if (result.IsSuccess)
                    {
                        logBuilder.AppendLine($"[OK] Credential {credId} rotated successfully.");
                        return true;
                    }
                    logBuilder.AppendLine($"[FAIL] Credential {credId}: {result.Error?.Message}");
                    return false;
                }
                catch (Exception ex)
                {
                    logBuilder.AppendLine($"[FAIL] Credential {credId}: {ex.Message}");
                    return false;
                }
            }

            var failedIds = new List<Guid>();

            if (set.ExecutionMode == OrchestrationExecutionMode.Sequential)
            {
                foreach (var member in set.Members)
                {
                    var ok = await RotateOne(member.CredentialId);
                    if (!ok)
                    {
                        failedIds.Add(member.CredentialId);
                        if (set.RollbackOnFailure) break;
                    }
                    else run.SuccessCount++;
                }
            }
            else // Parallel
            {
                var tasks = set.Members.Select(m => RotateOne(m.CredentialId)).ToList();
                var results = await Task.WhenAll(tasks);
                for (int i = 0; i < results.Length; i++)
                {
                    if (results[i]) run.SuccessCount++;
                    else failedIds.Add(set.Members.ElementAt(i).CredentialId);
                }
            }

            run.FailureCount = failedIds.Count;

            // Rollback: restore old passwords for already-rotated credentials
            if (failedIds.Count > 0 && set.RollbackOnFailure)
            {
                var rotatedIds = set.Members.Select(m => m.CredentialId)
                    .Where(cid => !failedIds.Contains(cid)).ToList();

                if (rotatedIds.Count > 0)
                {
                    var toRollback = await db.Credentials.Where(c => rotatedIds.Contains(c.Id)).ToListAsync();
                    foreach (var cred in toRollback)
                    {
                        var snap = rollbackList.FirstOrDefault(r => r.credId == cred.Id);
                        if (snap.oldPasswordEnc != null)
                        {
                            cred.PasswordEnc = snap.oldPasswordEnc;
                            logBuilder.AppendLine($"[ROLLBACK] Credential {cred.Id} reverted to previous password.");
                        }
                    }
                    await db.SaveChangesAsync();

                    run.Status = OrchestrationRunStatus.RolledBack;
                    await audit.LogAsync("Orchestration", "ORCHESTRATION_SET_ROLLEDBACK", actorId, null, ip,
                        "CredentialOrchestrationSet", id.ToString(), new { set.Name, run.FailureCount });
                }
            }
            else if (failedIds.Count == 0)
            {
                run.Status = OrchestrationRunStatus.Success;
            }
            else if (run.SuccessCount > 0)
            {
                run.Status = OrchestrationRunStatus.PartialFailure;
            }
            else
            {
                run.Status = OrchestrationRunStatus.Failed;
            }

            run.CompletedAtUtc = DateTime.UtcNow;
            run.Log            = logBuilder.ToString()[..Math.Min(logBuilder.Length, 8000)];
            await db.SaveChangesAsync();

            var finalStatus = run.Status.ToString();
            await audit.LogAsync("Orchestration", run.Status == OrchestrationRunStatus.Success
                ? "ORCHESTRATION_SET_COMPLETED" : "ORCHESTRATION_SET_FAILED",
                actorId, null, ip,
                "CredentialOrchestrationSet", id.ToString(),
                new { set.Name, RunId = run.Id, run.SuccessCount, run.FailureCount, Status = finalStatus });

            // Email notification
            if (set.NotifyOnComplete && email != null)
            {
                try
                {
                    var admins = await db.Users
                        .Where(u => u.UserRoles.Any(ur => ur.Role.Name == "GlobalAdmin" || ur.Role.Name == "VaultAdmin") && u.Email != null)
                        .Select(u => u.Email!).ToListAsync();

                    foreach (var addr in admins.Distinct())
                        await email.SendAsync(addr,
                            $"OrkunPAM — Orchestration Run {finalStatus}: {set.Name}",
                            $"<p>Orchestration set <strong>{set.Name}</strong> run completed.</p>" +
                            $"<p>Status: <strong>{finalStatus}</strong> — Success: {run.SuccessCount}, Failures: {run.FailureCount}</p>" +
                            $"<pre style='font-size:0.8em'>{System.Net.WebUtility.HtmlEncode(run.Log ?? "")}</pre>");
                }
                catch { /* non-critical */ }
            }

            return Results.Ok(new
            {
                success = true,
                data    = new
                {
                    runId        = run.Id,
                    status       = finalStatus,
                    successCount = run.SuccessCount,
                    failureCount = run.FailureCount,
                    log          = run.Log
                }
            });
        });

        // GET /{id}/runs — run history
        group.MapGet("/{id:guid}/runs", async (Guid id, OrkunPamDbContext db) =>
        {
            if (!await db.CredentialOrchestrationSets.AnyAsync(s => s.Id == id))
                return Results.NotFound();

            var runs = await db.CredentialOrchestrationRuns
                .Where(r => r.SetId == id)
                .OrderByDescending(r => r.StartedAtUtc)
                .Take(50)
                .Select(r => new
                {
                    id             = r.Id,
                    startedAtUtc   = r.StartedAtUtc,
                    completedAtUtc = r.CompletedAtUtc,
                    status         = r.Status.ToString(),
                    successCount   = r.SuccessCount,
                    failureCount   = r.FailureCount,
                    log            = r.Log,
                    triggeredBy    = r.TriggeredByUser != null ? r.TriggeredByUser.Username : "system"
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = runs });
        });
    }
}

public record CreateOrchestrationSetRequest(
    string Name,
    string? Description,
    string ExecutionMode,
    bool RollbackOnFailure,
    bool NotifyOnComplete,
    string? ScheduleCron,
    List<Guid>? CredentialIds);

public record UpdateOrchestrationSetRequest(
    string? Name,
    string? Description,
    string? ExecutionMode,
    bool? RollbackOnFailure,
    bool? NotifyOnComplete,
    string? ScheduleCron,
    List<Guid>? CredentialIds);
