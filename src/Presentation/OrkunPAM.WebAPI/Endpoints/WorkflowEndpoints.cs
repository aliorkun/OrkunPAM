using System.Security.Claims;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Workflow;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class WorkflowEndpoints
{
    public static void MapWorkflowEndpoints(this WebApplication app)
    {
        // === Workflow Definitions ===
        var wf = app.MapGroup("/api/v1/workflows").WithTags("Workflows");

        wf.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var list = await db.WorkflowDefinitions
                .Select(w => new { w.Id, w.Name, w.Description, w.TriggerType, w.IsEnabled })
                .ToListAsync();
            return Results.Ok(new { success = true, data = list });
        });

        wf.MapPost("/", async (CreateWorkflowRequest req, OrkunPamDbContext db) =>
        {
            var workflow = new WorkflowDefinition
            {
                Name = req.Name,
                Description = req.Description,
                TriggerType = req.TriggerType,
                StepsJson = req.StepsJson ?? "[]"
            };
            db.WorkflowDefinitions.Add(workflow);
            await db.SaveChangesAsync();
            return Results.Created($"/api/v1/workflows/{workflow.Id}", new { success = true, data = new { workflow.Id, workflow.Name } });
        });

        wf.MapGet("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var w = await db.WorkflowDefinitions.FindAsync(id);
            if (w == null) return Results.NotFound(new { success = false, errors = new[] { "Workflow not found" } });

            return Results.Ok(new
            {
                success = true,
                data = new { w.Id, w.Name, w.Description, w.TriggerType, w.StepsJson, w.IsEnabled, w.CreatedAtUtc }
            });
        });

        wf.MapPut("/{id:guid}", async (Guid id, UpdateWorkflowRequest req, OrkunPamDbContext db) =>
        {
            var w = await db.WorkflowDefinitions.FindAsync(id);
            if (w == null) return Results.NotFound(new { success = false, errors = new[] { "Workflow not found" } });

            if (req.Name != null) w.Name = req.Name;
            if (req.Description != null) w.Description = req.Description;
            if (req.StepsJson != null) w.StepsJson = req.StepsJson;
            if (req.IsEnabled.HasValue) w.IsEnabled = req.IsEnabled.Value;

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // === Approval Requests ===
        var approvals = app.MapGroup("/api/v1/approval-requests").WithTags("Workflows");

        approvals.MapGet("/", async (OrkunPamDbContext db, string? status, Guid? requesterId, int page = 1, int pageSize = 50) =>
        {
            var query = db.ApprovalRequests.AsQueryable();

            if (!string.IsNullOrEmpty(status) && Enum.TryParse<ApprovalStatus>(status, true, out var s))
                query = query.Where(ar => ar.Status == s);
            if (requesterId.HasValue)
                query = query.Where(ar => ar.RequesterId == requesterId.Value);

            var total = await query.CountAsync();
            var list = await query
                .OrderByDescending(ar => ar.CreatedAtUtc)
                .Skip((page - 1) * pageSize).Take(pageSize)
                .Select(ar => new
                {
                    ar.Id, ar.WorkflowId, ar.RequesterId, ar.ResourceType, ar.ResourceId,
                    ar.CurrentStep, Status = ar.Status.ToString(),
                    ar.Reason, ar.TicketNumber, ar.ExpiresAtUtc, ar.CreatedAtUtc, ar.CompletedAtUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = list, meta = new { page, pageSize, totalCount = total } });
        });

        approvals.MapGet("/pending", async (Guid approverId, OrkunPamDbContext db) =>
        {
            var pending = await db.ApprovalSteps
                .Where(s => (s.ApproverId == approverId || s.ApproverGroupId != null) &&
                            s.Decision == ApprovalStatus.Pending)
                .Include(s => s.Request)
                .Select(s => new
                {
                    StepId = s.Id,
                    s.RequestId,
                    s.Request.ResourceType,
                    s.Request.ResourceId,
                    s.Request.Reason,
                    s.Request.RequesterId,
                    s.StepOrder,
                    s.Request.CreatedAtUtc,
                    s.Request.ExpiresAtUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = pending });
        });

        approvals.MapPost("/", async (CreateApprovalRequest req, OrkunPamDbContext db, ILogger<Program> logger) =>
        {
            var request = new ApprovalRequest
            {
                WorkflowId = req.WorkflowId,
                RequesterId = req.RequesterId,
                ResourceType = req.ResourceType,
                ResourceId = req.ResourceId,
                Reason = req.Reason,
                TicketNumber = req.TicketNumber,
                ExpiresAtUtc = req.ExpiresInMinutes.HasValue
                    ? DateTime.UtcNow.AddMinutes(req.ExpiresInMinutes.Value)
                    : DateTime.UtcNow.AddHours(24)
            };

            // Create steps from approver list
            if (req.ApproverIds != null)
            {
                for (int i = 0; i < req.ApproverIds.Length; i++)
                {
                    request.Steps.Add(new ApprovalStep
                    {
                        RequestId = request.Id,
                        StepOrder = i,
                        ApproverId = req.ApproverIds[i]
                    });
                }
            }

            db.ApprovalRequests.Add(request);
            await db.SaveChangesAsync();

            logger.LogInformation("Approval request {Id} created for {ResourceType}/{ResourceId} by user {Requester}",
                request.Id, req.ResourceType, req.ResourceId, req.RequesterId);

            return Results.Created($"/api/v1/approval-requests/{request.Id}",
                new { success = true, data = new { request.Id, request.Status } });
        });

        approvals.MapPost("/{id:guid}/approve", async (Guid id, ApprovalDecisionRequest req, OrkunPamDbContext db, ILogger<Program> logger, HttpContext context) =>
        {
            var approverIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (approverIdStr == null || !Guid.TryParse(approverIdStr, out var approverId))
                return Results.Unauthorized();

            var request = await db.ApprovalRequests
                .Include(r => r.Steps.OrderBy(s => s.StepOrder))
                .FirstOrDefaultAsync(r => r.Id == id);

            if (request == null) return Results.NotFound(new { success = false, errors = new[] { "Request not found" } });
            if (request.Status != ApprovalStatus.Pending)
                return Results.Conflict(new { success = false, errors = new[] { $"Request already {request.Status}" } });

            var currentStep = request.Steps.FirstOrDefault(s => s.Decision == ApprovalStatus.Pending);
            if (currentStep == null)
                return Results.Conflict(new { success = false, errors = new[] { "No pending step" } });

            if (currentStep.ApproverId.HasValue && currentStep.ApproverId != approverId)
                return Results.Forbid();

            currentStep.Decision = ApprovalStatus.Approved;
            currentStep.ActualApproverId = approverId;
            currentStep.DecisionAtUtc = DateTime.UtcNow;
            currentStep.Comments = req.Comments;
            request.CurrentStep++;

            // If all steps approved, mark request as approved
            if (request.Steps.All(s => s.Decision == ApprovalStatus.Approved))
            {
                request.Status = ApprovalStatus.Approved;
                request.CompletedAtUtc = DateTime.UtcNow;
            }

            await db.SaveChangesAsync();
            logger.LogInformation("Approval step {StepOrder} approved for request {RequestId} by {Approver}",
                currentStep.StepOrder, id, approverId);

            return Results.Ok(new { success = true, data = new { request.Id, Status = request.Status.ToString(), request.CurrentStep } });
        }).RequireAuthorization();

        approvals.MapPost("/{id:guid}/deny", async (Guid id, ApprovalDecisionRequest req, OrkunPamDbContext db, ILogger<Program> logger, HttpContext context) =>
        {
            var approverIdStr = context.User.FindFirstValue(ClaimTypes.NameIdentifier);
            if (approverIdStr == null || !Guid.TryParse(approverIdStr, out var approverId))
                return Results.Unauthorized();

            var request = await db.ApprovalRequests
                .Include(r => r.Steps.OrderBy(s => s.StepOrder))
                .FirstOrDefaultAsync(r => r.Id == id);

            if (request == null) return Results.NotFound(new { success = false, errors = new[] { "Request not found" } });

            var currentStep = request.Steps.FirstOrDefault(s => s.Decision == ApprovalStatus.Pending);
            if (currentStep == null)
                return Results.Conflict(new { success = false, errors = new[] { "No pending step" } });

            if (currentStep.ApproverId.HasValue && currentStep.ApproverId != approverId)
                return Results.Forbid();

            currentStep.Decision = ApprovalStatus.Denied;
            currentStep.ActualApproverId = approverId;
            currentStep.DecisionAtUtc = DateTime.UtcNow;
            currentStep.Comments = req.Comments;

            request.Status = ApprovalStatus.Denied;
            request.CompletedAtUtc = DateTime.UtcNow;

            await db.SaveChangesAsync();
            logger.LogInformation("Approval request {RequestId} denied by {Approver}: {Comments}",
                id, approverId, req.Comments);

            return Results.Ok(new { success = true, data = new { request.Id, Status = request.Status.ToString() } });
        }).RequireAuthorization();
    }
}

public record CreateWorkflowRequest(string Name, string? Description, string TriggerType, string? StepsJson);
public record UpdateWorkflowRequest(string? Name, string? Description, string? StepsJson, bool? IsEnabled);
public record CreateApprovalRequest(Guid WorkflowId, Guid RequesterId, string ResourceType,
    Guid? ResourceId, string? Reason, string? TicketNumber, Guid[]? ApproverIds, int? ExpiresInMinutes);
public record ApprovalDecisionRequest(string? Comments);
