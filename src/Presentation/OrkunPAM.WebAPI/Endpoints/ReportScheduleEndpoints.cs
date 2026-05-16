using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Compliance;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ReportScheduleEndpoints
{
    public static void MapReportScheduleEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/api/v1/reports/schedules")
            .WithTags("Reports")
            .RequireAuthorization();

        // List schedules
        grp.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var schedules = await db.ReportSchedules
                .OrderBy(s => s.Name)
                .Select(s => new
                {
                    s.Id, s.Name, s.ReportType, s.Frequency,
                    s.DayOfWeek, s.DayOfMonth, s.RunAtHourUtc,
                    s.OutputFormat, s.Recipients, s.IsActive,
                    s.LastRunAtUtc, s.NextRunAtUtc, s.LastRunStatus,
                    s.CreatedAtUtc
                }).ToListAsync();

            return Results.Ok(new { success = true, data = schedules });
        });

        // Create schedule
        grp.MapPost("/", async (CreateReportScheduleRequest req, OrkunPamDbContext db) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });
            if (string.IsNullOrWhiteSpace(req.ReportType))
                return Results.BadRequest(new { success = false, errors = new[] { "ReportType is required" } });
            if (string.IsNullOrWhiteSpace(req.Recipients))
                return Results.BadRequest(new { success = false, errors = new[] { "At least one recipient is required" } });

            var schedule = new ReportSchedule
            {
                Name         = req.Name.Trim(),
                ReportType   = req.ReportType.Trim(),
                Frequency    = req.Frequency ?? "daily",
                DayOfWeek    = req.DayOfWeek ?? 1,
                DayOfMonth   = req.DayOfMonth ?? 1,
                RunAtHourUtc = req.RunAtHourUtc ?? 8,
                OutputFormat = req.OutputFormat ?? "csv",
                Recipients   = req.Recipients.Trim(),
                IsActive     = true,
                CreatedAtUtc = DateTime.UtcNow
            };
            schedule.NextRunAtUtc = ReportSchedulerService.CalculateNextRun(schedule);

            db.ReportSchedules.Add(schedule);
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, data = new { schedule.Id, schedule.Name, schedule.NextRunAtUtc } });
        });

        // Update schedule
        grp.MapPut("/{id:guid}", async (Guid id, UpdateReportScheduleRequest req, OrkunPamDbContext db) =>
        {
            var schedule = await db.ReportSchedules.FindAsync(id);
            if (schedule == null)
                return Results.NotFound(new { success = false, errors = new[] { "Schedule not found" } });

            if (!string.IsNullOrWhiteSpace(req.Name))       schedule.Name        = req.Name.Trim();
            if (!string.IsNullOrWhiteSpace(req.Recipients)) schedule.Recipients  = req.Recipients.Trim();
            if (req.IsActive.HasValue)                       schedule.IsActive    = req.IsActive.Value;
            if (!string.IsNullOrWhiteSpace(req.Frequency))  schedule.Frequency   = req.Frequency;
            if (req.DayOfWeek.HasValue)                      schedule.DayOfWeek   = req.DayOfWeek.Value;
            if (req.DayOfMonth.HasValue)                     schedule.DayOfMonth  = req.DayOfMonth.Value;
            if (req.RunAtHourUtc.HasValue)                   schedule.RunAtHourUtc = req.RunAtHourUtc.Value;

            // Recalculate next run if schedule timing changed
            if (schedule.IsActive)
                schedule.NextRunAtUtc = ReportSchedulerService.CalculateNextRun(schedule);

            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { schedule.Id, schedule.Name, schedule.IsActive, schedule.NextRunAtUtc } });
        });

        // Delete schedule
        grp.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
        {
            var schedule = await db.ReportSchedules.FindAsync(id);
            if (schedule == null)
                return Results.NotFound(new { success = false, errors = new[] { "Schedule not found" } });

            db.ReportSchedules.Remove(schedule);
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Manual trigger
        grp.MapPost("/{id:guid}/run-now", async (Guid id, OrkunPamDbContext db) =>
        {
            var schedule = await db.ReportSchedules.FindAsync(id);
            if (schedule == null)
                return Results.NotFound(new { success = false, errors = new[] { "Schedule not found" } });

            // Force NextRunAtUtc to now so the background service picks it up on next tick
            schedule.NextRunAtUtc = DateTime.UtcNow.AddSeconds(-1);
            await db.SaveChangesAsync();

            return Results.Ok(new { success = true, message = "Report queued for immediate delivery (runs within 60 seconds)" });
        });
    }
}

public record CreateReportScheduleRequest(
    string Name,
    string ReportType,
    string? Frequency,
    int? DayOfWeek,
    int? DayOfMonth,
    int? RunAtHourUtc,
    string? OutputFormat,
    string Recipients);

public record UpdateReportScheduleRequest(
    string? Name,
    string? Recipients,
    bool? IsActive,
    string? Frequency,
    int? DayOfWeek,
    int? DayOfMonth,
    int? RunAtHourUtc);
