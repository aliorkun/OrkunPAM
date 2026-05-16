using System.Security.Claims;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Compliance;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class CustomReportEndpoints
{
    private static readonly JsonSerializerOptions _jsonOpts = new(JsonSerializerDefaults.Web);

    public static void MapCustomReportEndpoints(this IEndpointRouteBuilder app)
    {
        var grp = app.MapGroup("/api/v1/reports/custom")
            .WithTags("Reports")
            .RequireAuthorization("AdminPolicy");

        // List saved custom report definitions
        grp.MapGet("/", async (OrkunPamDbContext db) =>
        {
            var defs = await db.CustomReportDefinitions
                .OrderByDescending(r => r.CreatedAtUtc)
                .Select(r => new
                {
                    r.Id, r.Name, r.Description, r.DataSource,
                    r.FiltersJson, r.ColumnsJson, r.CreatedAtUtc, r.LastRunAtUtc
                })
                .ToListAsync();
            return Results.Ok(new { success = true, data = defs });
        });

        // Create / save a new custom report definition
        grp.MapPost("/", async (CreateCustomReportRequest req, OrkunPamDbContext db, HttpContext ctx) =>
        {
            if (string.IsNullOrWhiteSpace(req.Name))
                return Results.BadRequest(new { success = false, errors = new[] { "Name is required" } });

            var def = new CustomReportDefinition
            {
                Name            = req.Name.Trim(),
                Description     = req.Description?.Trim(),
                DataSource      = req.DataSource?.Trim() ?? "AuditLogs",
                FiltersJson     = req.FiltersJson ?? "{}",
                ColumnsJson     = req.ColumnsJson ?? "[]",
                CreatedByUserId = Guid.TryParse(ctx.User.FindFirstValue(ClaimTypes.NameIdentifier), out var uid) ? uid : null,
                CreatedAtUtc    = DateTime.UtcNow
            };
            db.CustomReportDefinitions.Add(def);
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory  = "Report",
                EventType      = "CustomReportCreated",
                ActorUsername  = ctx.User.FindFirstValue(ClaimTypes.Name),
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType     = "CustomReport",
                TargetId       = def.Id.ToString(),
                Details        = $"name='{def.Name}' source={def.DataSource}",
                Outcome        = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = new { def.Id, def.Name } });
        });

        // Delete a saved definition
        grp.MapDelete("/{id:guid}", async (Guid id, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var def = await db.CustomReportDefinitions.FindAsync(id);
            if (def == null) return Results.NotFound(new { success = false });

            db.CustomReportDefinitions.Remove(def);
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory  = "Report",
                EventType      = "CustomReportDeleted",
                ActorUsername  = ctx.User.FindFirstValue(ClaimTypes.Name),
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType     = "CustomReport",
                TargetId       = def.Id.ToString(),
                Details        = $"name='{def.Name}'",
                Outcome        = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true });
        });

        // Preview — ad-hoc run, up to 50 rows, no persistence
        grp.MapPost("/preview", async (CustomReportPreviewRequest req, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var result = await ExecuteReportAsync(db,
                req.DataSource ?? "AuditLogs",
                req.FiltersJson ?? "{}",
                req.ColumnsJson ?? "[]",
                req.MaxRows > 0 ? req.MaxRows : 50);

            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory  = "Report",
                EventType      = "CustomReportPreview",
                ActorUsername  = ctx.User.FindFirstValue(ClaimTypes.Name),
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType     = "CustomReport",
                Details        = $"source={req.DataSource} rows={result.TotalRows}",
                Outcome        = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = result });
        });

        // Run a saved definition (full, up to 5000 rows), updates LastRunAtUtc
        grp.MapPost("/{id:guid}/run", async (Guid id, OrkunPamDbContext db, HttpContext ctx) =>
        {
            var def = await db.CustomReportDefinitions.FindAsync(id);
            if (def == null) return Results.NotFound(new { success = false });

            var result = await ExecuteReportAsync(db, def.DataSource, def.FiltersJson, def.ColumnsJson, 5000);
            def.LastRunAtUtc = DateTime.UtcNow;
            db.AuditLogs.Add(new AuditLogEntry
            {
                EventCategory  = "Report",
                EventType      = "CustomReportRun",
                ActorUsername  = ctx.User.FindFirstValue(ClaimTypes.Name),
                ActorIpAddress = ctx.Connection.RemoteIpAddress?.ToString(),
                TargetType     = "CustomReport",
                TargetId       = def.Id.ToString(),
                Details        = $"name='{def.Name}' rows={result.TotalRows}",
                Outcome        = AuditOutcome.Success
            });
            await db.SaveChangesAsync();
            return Results.Ok(new { success = true, data = result });
        });
    }

    // -----------------------------------------------------------------------
    // Query engine
    // -----------------------------------------------------------------------

    private static async Task<CustomReportRunResult> ExecuteReportAsync(
        OrkunPamDbContext db, string dataSource, string filtersJson,
        string columnsJson, int maxRows)
    {
        CustomReportFilters filters;
        try { filters = JsonSerializer.Deserialize<CustomReportFilters>(filtersJson, _jsonOpts) ?? new(); }
        catch { filters = new(); }

        List<string> requestedCols;
        try { requestedCols = JsonSerializer.Deserialize<List<string>>(columnsJson, _jsonOpts) ?? []; }
        catch { requestedCols = []; }

        string[] allCols = dataSource switch
        {
            "Sessions"    => ["Id","UserId","SessionType","Status","TargetIpAddress","TargetPort","StartedAtUtc","EndedAtUtc","DurationSeconds","RiskScore","Reason","TicketNumber"],
            "Credentials" => ["Id","Name","Username","DeviceId","CredentialType","Status","LastRotatedAtUtc","NextRotationAtUtc","RequiresApproval","IsDiscovered"],
            "Users"       => ["Id","Username","DisplayName","Email","Status","MfaEnabled","LastLoginAtUtc","CreatedAtUtc","IsTemporary"],
            _             => ["Timestamp","EventCategory","EventType","ActorUsername","ActorIpAddress","TargetType","TargetId","Outcome","Details"]
        };

        var effectiveCols = requestedCols.Count > 0
            ? requestedCols.Where(c => allCols.Contains(c, StringComparer.OrdinalIgnoreCase)).ToList()
            : allCols.ToList();

        var from = filters.DateFrom ?? DateTime.UtcNow.AddDays(-30);
        var to   = filters.DateTo   ?? DateTime.UtcNow;

        List<Dictionary<string, string>> rows = dataSource switch
        {
            "Sessions"    => await QuerySessionsAsync(db, filters, from, to, maxRows, effectiveCols),
            "Credentials" => await QueryCredentialsAsync(db, filters, maxRows, effectiveCols),
            "Users"       => await QueryUsersAsync(db, filters, maxRows, effectiveCols),
            _             => await QueryAuditLogsAsync(db, filters, from, to, maxRows, effectiveCols)
        };

        return new CustomReportRunResult(effectiveCols, rows, rows.Count, BuildSummary(dataSource, filters));
    }

    private static async Task<List<Dictionary<string, string>>> QueryAuditLogsAsync(
        OrkunPamDbContext db, CustomReportFilters f, DateTime from, DateTime to,
        int maxRows, List<string> cols)
    {
        var q = db.AuditLogs.Where(a => a.Timestamp >= from && a.Timestamp <= to);

        if (!string.IsNullOrWhiteSpace(f.Username))
            q = q.Where(a => a.ActorUsername != null && a.ActorUsername.Contains(f.Username));
        if (!string.IsNullOrWhiteSpace(f.EventCategory))
            q = q.Where(a => a.EventCategory == f.EventCategory);
        if (!string.IsNullOrWhiteSpace(f.EventType))
            q = q.Where(a => a.EventType.Contains(f.EventType));
        if (!string.IsNullOrWhiteSpace(f.Outcome) && Enum.TryParse<AuditOutcome>(f.Outcome, true, out var ao))
            q = q.Where(a => a.Outcome == ao);

        var data = await q.OrderByDescending(a => a.Timestamp).Take(maxRows)
            .Select(a => new
            {
                a.Timestamp, a.EventCategory, a.EventType,
                a.ActorUsername, a.ActorIpAddress, a.TargetType, a.TargetId,
                a.Outcome, a.Details
            }).ToListAsync();

        return data.Select(r => PickCols(new Dictionary<string, string>
        {
            ["Timestamp"]      = r.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
            ["EventCategory"]  = r.EventCategory,
            ["EventType"]      = r.EventType,
            ["ActorUsername"]  = r.ActorUsername ?? "",
            ["ActorIpAddress"] = r.ActorIpAddress ?? "",
            ["TargetType"]     = r.TargetType ?? "",
            ["TargetId"]       = r.TargetId ?? "",
            ["Outcome"]        = r.Outcome.ToString(),
            ["Details"]        = r.Details ?? ""
        }, cols)).ToList();
    }

    private static async Task<List<Dictionary<string, string>>> QuerySessionsAsync(
        OrkunPamDbContext db, CustomReportFilters f, DateTime from, DateTime to,
        int maxRows, List<string> cols)
    {
        var q = db.ProxySessions.Where(s => s.StartedAtUtc >= from && s.StartedAtUtc <= to);

        if (!string.IsNullOrWhiteSpace(f.Protocol) && Enum.TryParse<SessionType>(f.Protocol, true, out var pt))
            q = q.Where(s => s.SessionType == pt);
        if (f.MinRiskScore.HasValue) q = q.Where(s => s.RiskScore >= f.MinRiskScore.Value);
        if (f.MaxRiskScore.HasValue) q = q.Where(s => s.RiskScore <= f.MaxRiskScore.Value);

        var data = await q.OrderByDescending(s => s.StartedAtUtc).Take(maxRows)
            .Select(s => new
            {
                Id              = s.Id,
                UserId          = s.UserId,
                s.SessionType,
                s.Status,
                s.TargetIpAddress, s.TargetPort,
                s.StartedAtUtc, s.EndedAtUtc, s.DurationSeconds,
                s.RiskScore, s.Reason, s.TicketNumber
            }).ToListAsync();

        return data.Select(r => PickCols(new Dictionary<string, string>
        {
            ["Id"]              = r.Id.ToString(),
            ["UserId"]          = r.UserId.ToString(),
            ["SessionType"]     = r.SessionType.ToString(),
            ["Status"]          = r.Status.ToString(),
            ["TargetIpAddress"] = r.TargetIpAddress ?? "",
            ["TargetPort"]      = r.TargetPort.ToString(),
            ["StartedAtUtc"]    = r.StartedAtUtc.ToString("yyyy-MM-dd HH:mm:ss"),
            ["EndedAtUtc"]      = r.EndedAtUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
            ["DurationSeconds"] = r.DurationSeconds?.ToString() ?? "",
            ["RiskScore"]       = r.RiskScore.ToString(),
            ["Reason"]          = r.Reason ?? "",
            ["TicketNumber"]    = r.TicketNumber ?? ""
        }, cols)).ToList();
    }

    private static async Task<List<Dictionary<string, string>>> QueryCredentialsAsync(
        OrkunPamDbContext db, CustomReportFilters f, int maxRows, List<string> cols)
    {
        var q = db.Credentials.AsQueryable();

        if (!string.IsNullOrWhiteSpace(f.CredentialType) && Enum.TryParse<CredentialType>(f.CredentialType, true, out var ct))
            q = q.Where(c => c.CredentialType == ct);
        if (!string.IsNullOrWhiteSpace(f.CredentialStatus) && Enum.TryParse<CredentialStatus>(f.CredentialStatus, true, out var cs))
            q = q.Where(c => c.Status == cs);

        var data = await q.OrderBy(c => c.Name).Take(maxRows)
            .Select(c => new
            {
                c.Id, c.Name, c.Username, c.DeviceId,
                c.CredentialType, c.Status,
                c.LastRotatedAtUtc, c.NextRotationAtUtc,
                c.RequiresApproval, c.IsDiscovered
            }).ToListAsync();

        return data.Select(r => PickCols(new Dictionary<string, string>
        {
            ["Id"]                = r.Id.ToString(),
            ["Name"]              = r.Name,
            ["Username"]          = r.Username ?? "",
            ["DeviceId"]          = r.DeviceId?.ToString() ?? "",
            ["CredentialType"]    = r.CredentialType.ToString(),
            ["Status"]            = r.Status.ToString(),
            ["LastRotatedAtUtc"]  = r.LastRotatedAtUtc?.ToString("yyyy-MM-dd") ?? "",
            ["NextRotationAtUtc"] = r.NextRotationAtUtc?.ToString("yyyy-MM-dd") ?? "",
            ["RequiresApproval"]  = r.RequiresApproval.ToString(),
            ["IsDiscovered"]      = r.IsDiscovered.ToString()
        }, cols)).ToList();
    }

    private static async Task<List<Dictionary<string, string>>> QueryUsersAsync(
        OrkunPamDbContext db, CustomReportFilters f, int maxRows, List<string> cols)
    {
        var q = db.Users.AsQueryable();

        if (!string.IsNullOrWhiteSpace(f.UserStatus) && Enum.TryParse<UserStatus>(f.UserStatus, true, out var us))
            q = q.Where(u => u.Status == us);
        if (f.MfaEnabled.HasValue) q = q.Where(u => u.MfaEnabled == f.MfaEnabled.Value);

        var data = await q.OrderBy(u => u.Username).Take(maxRows)
            .Select(u => new
            {
                u.Id, u.Username, u.DisplayName, u.Email,
                u.Status, u.MfaEnabled, u.LastLoginAtUtc,
                u.CreatedAtUtc, u.IsTemporary
            }).ToListAsync();

        return data.Select(r => PickCols(new Dictionary<string, string>
        {
            ["Id"]            = r.Id.ToString(),
            ["Username"]      = r.Username,
            ["DisplayName"]   = r.DisplayName ?? "",
            ["Email"]         = r.Email ?? "",
            ["Status"]        = r.Status.ToString(),
            ["MfaEnabled"]    = r.MfaEnabled.ToString(),
            ["LastLoginAtUtc"]= r.LastLoginAtUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
            ["CreatedAtUtc"]  = r.CreatedAtUtc.ToString("yyyy-MM-dd"),
            ["IsTemporary"]   = r.IsTemporary.ToString()
        }, cols)).ToList();
    }

    private static Dictionary<string, string> PickCols(Dictionary<string, string> all, List<string> cols) =>
        cols.Count == 0 ? all : cols.Where(all.ContainsKey).ToDictionary(c => c, c => all[c]);

    private static string BuildSummary(string dataSource, CustomReportFilters f)
    {
        var parts = new List<string> { "Source: " + dataSource };
        if (f.DateFrom.HasValue) parts.Add("From: " + f.DateFrom.Value.ToString("yyyy-MM-dd"));
        if (f.DateTo.HasValue)   parts.Add("To: " + f.DateTo.Value.ToString("yyyy-MM-dd"));
        if (!string.IsNullOrWhiteSpace(f.Username))        parts.Add("Username: " + f.Username);
        if (!string.IsNullOrWhiteSpace(f.EventCategory))   parts.Add("Category: " + f.EventCategory);
        if (!string.IsNullOrWhiteSpace(f.EventType))       parts.Add("EventType: " + f.EventType);
        if (!string.IsNullOrWhiteSpace(f.Outcome))         parts.Add("Outcome: " + f.Outcome);
        if (!string.IsNullOrWhiteSpace(f.Protocol))        parts.Add("Protocol: " + f.Protocol);
        if (f.MinRiskScore.HasValue)                       parts.Add("MinRisk: " + f.MinRiskScore);
        if (f.MaxRiskScore.HasValue)                       parts.Add("MaxRisk: " + f.MaxRiskScore);
        if (!string.IsNullOrWhiteSpace(f.CredentialType))  parts.Add("CredType: " + f.CredentialType);
        if (!string.IsNullOrWhiteSpace(f.CredentialStatus))parts.Add("CredStatus: " + f.CredentialStatus);
        if (!string.IsNullOrWhiteSpace(f.UserStatus))      parts.Add("UserStatus: " + f.UserStatus);
        if (f.MfaEnabled.HasValue)                         parts.Add("MfaEnabled: " + f.MfaEnabled);
        return string.Join(", ", parts);
    }
}

public record CreateCustomReportRequest(
    string  Name,
    string? Description,
    string? DataSource,
    string? FiltersJson,
    string? ColumnsJson);

public record CustomReportPreviewRequest(
    string? DataSource,
    string? FiltersJson,
    string? ColumnsJson,
    int     MaxRows = 50);

public class CustomReportFilters
{
    public DateTime? DateFrom        { get; init; }
    public DateTime? DateTo          { get; init; }
    public string?   Username        { get; init; }
    public string?   EventCategory   { get; init; }
    public string?   EventType       { get; init; }
    public string?   Outcome         { get; init; }
    public string?   Protocol        { get; init; }
    public int?      MinRiskScore    { get; init; }
    public int?      MaxRiskScore    { get; init; }
    public string?   CredentialType  { get; init; }
    public string?   CredentialStatus { get; init; }
    public string?   UserStatus      { get; init; }
    public bool?     MfaEnabled      { get; init; }
}

public record CustomReportRunResult(
    List<string>                    Columns,
    List<Dictionary<string, string>> Rows,
    int                             TotalRows,
    string                          FilterSummary);
