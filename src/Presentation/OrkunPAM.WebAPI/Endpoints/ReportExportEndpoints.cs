using ClosedXML.Excel;
using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using QuestPDF.Fluent;
using QuestPDF.Helpers;
using QuestPDF.Infrastructure;

namespace OrkunPAM.WebAPI.Endpoints;

public static class ReportExportEndpoints
{
    public static void MapReportExportEndpoints(this IEndpointRouteBuilder app)
    {
        var exports = app.MapGroup("/api/v1/reports/export").WithTags("Reports");

        exports.MapGet("/pdf", async (OrkunPamDbContext db,
            string reportType, DateTime? from, DateTime? to) =>
        {
            var fromDate = from ?? DateTime.UtcNow.AddDays(-30);
            var toDate   = to   ?? DateTime.UtcNow;
            var data = await BuildReportDataAsync(reportType, fromDate, toDate, db);
            if (data == null)
                return Results.NotFound(new
                {
                    success = false,
                    errors  = new[] { $"Report type '{reportType}' not found or not exportable" }
                });

            var pdf      = GeneratePdf(data, fromDate, toDate);
            var filename = $"pam-{reportType}-{DateTime.UtcNow:yyyyMMdd}.pdf";
            return Results.File(pdf, "application/pdf", filename);
        });

        exports.MapGet("/excel", async (OrkunPamDbContext db,
            string reportType, DateTime? from, DateTime? to) =>
        {
            var fromDate = from ?? DateTime.UtcNow.AddDays(-30);
            var toDate   = to   ?? DateTime.UtcNow;
            var data = await BuildReportDataAsync(reportType, fromDate, toDate, db);
            if (data == null)
                return Results.NotFound(new
                {
                    success = false,
                    errors  = new[] { $"Report type '{reportType}' not found or not exportable" }
                });

            var excel    = GenerateExcel(data, fromDate, toDate);
            var filename = $"pam-{reportType}-{DateTime.UtcNow:yyyyMMdd}.xlsx";
            return Results.File(excel,
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                filename);
        });
    }

    private sealed record ExportData(string ReportName, string[] Headers, List<string[]> Rows);

    private static async Task<ExportData?> BuildReportDataAsync(
        string reportType, DateTime from, DateTime to, OrkunPamDbContext db)
    {
        return reportType switch
        {
            "audit-log"           => await BuildAuditLogData(db, from, to),
            "session-activity"    => await BuildSessionActivityData(db, from, to),
            "failed-logins"       => await BuildFailedLoginsData(db, from, to),
            "credential-expiry"   => await BuildCredentialExpiryData(db),
            "password-age"        => await BuildPasswordAgeData(db),
            "privileged-access"   => await BuildPrivilegedAccessData(db, from, to),
            "mfa-adoption"        => await BuildMfaAdoptionData(db),
            "device-inventory"    => await BuildDeviceInventoryData(db),
            "rotation-compliance" => await BuildRotationComplianceData(db),
            _                     => null
        };
    }

    private static async Task<ExportData> BuildAuditLogData(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var rows = await db.AuditLogs
            .Where(a => a.Timestamp >= from && a.Timestamp <= to)
            .OrderByDescending(a => a.Timestamp)
            .Take(2000)
            .Select(a => new
            {
                a.Timestamp, a.EventCategory, a.EventType,
                a.ActorUsername, a.ActorIpAddress,
                Outcome = a.Outcome.ToString(), a.Details
            })
            .ToListAsync();

        return new ExportData(
            "Audit Log",
            ["Timestamp (UTC)", "Category", "Event", "Actor", "IP Address", "Outcome", "Details"],
            rows.Select(r => new[]
            {
                r.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                r.EventCategory ?? "", r.EventType ?? "",
                r.ActorUsername ?? "", r.ActorIpAddress ?? "",
                r.Outcome, r.Details ?? ""
            }).ToList()
        );
    }

    private static async Task<ExportData> BuildSessionActivityData(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var rows = await db.ProxySessions
            .Where(s => s.StartedAtUtc >= from && s.StartedAtUtc <= to)
            .OrderByDescending(s => s.StartedAtUtc)
            .Take(2000)
            .Select(s => new
            {
                s.Id, s.UserId,
                Type   = s.SessionType.ToString(),
                Status = s.Status.ToString(),
                s.TargetIpAddress, s.TargetPort,
                s.StartedAtUtc, s.EndedAtUtc,
                s.DurationSeconds, s.ClientIpAddress, s.RiskScore
            })
            .ToListAsync();

        return new ExportData(
            "Session Activity",
            ["Session ID", "User ID", "Type", "Status", "Target IP", "Port",
             "Started At", "Ended At", "Duration (s)", "Client IP", "Risk Score"],
            rows.Select(r => new[]
            {
                r.Id.ToString(), r.UserId.ToString(), r.Type, r.Status,
                r.TargetIpAddress ?? "", r.TargetPort.ToString(),
                r.StartedAtUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                r.EndedAtUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "",
                r.DurationSeconds?.ToString() ?? "", r.ClientIpAddress ?? "", r.RiskScore.ToString()
            }).ToList()
        );
    }

    private static async Task<ExportData> BuildFailedLoginsData(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var rows = await db.AuditLogs
            .Where(a => a.Outcome == AuditOutcome.Failure &&
                        a.Timestamp >= from && a.Timestamp <= to &&
                        (a.EventCategory == "Auth" ||
                         a.EventType.Contains("Login") || a.EventType.Contains("Auth")))
            .OrderByDescending(a => a.Timestamp)
            .Take(2000)
            .Select(a => new { a.Timestamp, a.ActorUsername, a.ActorIpAddress, a.EventType, a.Details })
            .ToListAsync();

        return new ExportData(
            "Failed Logins",
            ["Timestamp (UTC)", "Username", "IP Address", "Event Type", "Details"],
            rows.Select(r => new[]
            {
                r.Timestamp.ToString("yyyy-MM-dd HH:mm:ss"),
                r.ActorUsername ?? "", r.ActorIpAddress ?? "",
                r.EventType ?? "", r.Details ?? ""
            }).ToList()
        );
    }

    private static async Task<ExportData> BuildCredentialExpiryData(OrkunPamDbContext db)
    {
        var now  = DateTime.UtcNow;
        var rows = await db.Credentials
            .Where(c => c.Status == CredentialStatus.Active && c.NextRotationAtUtc.HasValue)
            .OrderBy(c => c.NextRotationAtUtc)
            .Take(2000)
            .Select(c => new { c.Id, c.Name, c.Username, c.LastRotatedAtUtc, c.NextRotationAtUtc, c.RiskLevel })
            .ToListAsync();

        return new ExportData(
            "Credential Expiry",
            ["Credential ID", "Name", "Username", "Last Rotated", "Next Rotation", "Risk Level", "Status"],
            rows.Select(r => new[]
            {
                r.Id.ToString(), r.Name ?? "", r.Username ?? "",
                r.LastRotatedAtUtc?.ToString("yyyy-MM-dd") ?? "Never",
                r.NextRotationAtUtc?.ToString("yyyy-MM-dd") ?? "",
                r.RiskLevel,
                r.NextRotationAtUtc < now ? "Overdue" : "OK"
            }).ToList()
        );
    }

    private static async Task<ExportData> BuildPasswordAgeData(OrkunPamDbContext db)
    {
        var now  = DateTime.UtcNow;
        var rows = await db.Credentials
            .Where(c => c.Status == CredentialStatus.Active)
            .OrderByDescending(c => c.CreatedAtUtc)
            .Take(2000)
            .Select(c => new { c.Id, c.Name, c.Username, c.LastRotatedAtUtc, c.CreatedAtUtc, c.NextRotationAtUtc })
            .ToListAsync();

        return new ExportData(
            "Password Age",
            ["Credential ID", "Name", "Username", "Age (Days)", "Last Rotated", "Next Rotation", "Status"],
            rows.Select(r => new[]
            {
                r.Id.ToString(), r.Name ?? "", r.Username ?? "",
                r.LastRotatedAtUtc.HasValue
                    ? ((int)(now - r.LastRotatedAtUtc.Value).TotalDays).ToString()
                    : ((int)(now - r.CreatedAtUtc).TotalDays).ToString(),
                r.LastRotatedAtUtc?.ToString("yyyy-MM-dd") ?? "Never",
                r.NextRotationAtUtc?.ToString("yyyy-MM-dd") ?? "Not Set",
                r.NextRotationAtUtc.HasValue && r.NextRotationAtUtc < now ? "Overdue" : "OK"
            }).ToList()
        );
    }

    private static async Task<ExportData> BuildPrivilegedAccessData(OrkunPamDbContext db, DateTime from, DateTime to)
    {
        var rows = await db.CheckOutHistories
            .Where(h => h.CheckedOutAtUtc >= from && h.CheckedOutAtUtc <= to)
            .OrderByDescending(h => h.CheckedOutAtUtc)
            .Take(2000)
            .Select(h => new { h.CredentialId, h.UserId, h.CheckedOutAtUtc, h.CheckedInAtUtc, h.Reason })
            .ToListAsync();

        return new ExportData(
            "Privileged Access",
            ["Credential ID", "User ID", "Checked Out At", "Checked In At", "Duration (min)", "Reason"],
            rows.Select(r => new[]
            {
                r.CredentialId.ToString(), r.UserId.ToString(),
                r.CheckedOutAtUtc.ToString("yyyy-MM-dd HH:mm:ss"),
                r.CheckedInAtUtc?.ToString("yyyy-MM-dd HH:mm:ss") ?? "Active",
                r.CheckedInAtUtc.HasValue
                    ? ((int)(r.CheckedInAtUtc.Value - r.CheckedOutAtUtc).TotalMinutes).ToString()
                    : "",
                r.Reason ?? ""
            }).ToList()
        );
    }

    private static async Task<ExportData> BuildMfaAdoptionData(OrkunPamDbContext db)
    {
        var users = await db.Users
            .OrderBy(u => u.Username)
            .Select(u => new
            {
                u.Id, u.Username, u.Email,
                u.MfaEnabled, Status = u.Status.ToString(),
                u.CreatedAtUtc, u.LastLoginAtUtc
            })
            .ToListAsync();

        return new ExportData(
            "MFA Adoption",
            ["User ID", "Username", "Email", "MFA Enabled", "Status", "Created At", "Last Login"],
            users.Select(u => new[]
            {
                u.Id.ToString(), u.Username ?? "", u.Email ?? "",
                u.MfaEnabled ? "Yes" : "No", u.Status,
                u.CreatedAtUtc.ToString("yyyy-MM-dd"),
                u.LastLoginAtUtc?.ToString("yyyy-MM-dd HH:mm") ?? "Never"
            }).ToList()
        );
    }

    private static async Task<ExportData> BuildDeviceInventoryData(OrkunPamDbContext db)
    {
        var devices = await db.Devices
            .OrderBy(d => d.Hostname)
            .Select(d => new
            {
                d.Id, d.Hostname, d.IpAddress,
                Type   = d.DeviceType.ToString(),
                d.OperatingSystem,
                Status = d.Status.ToString()
            })
            .ToListAsync();

        return new ExportData(
            "Device Inventory",
            ["Device ID", "Hostname", "IP Address", "Type", "OS", "Status"],
            devices.Select(d => new[]
            {
                d.Id.ToString(), d.Hostname ?? "", d.IpAddress ?? "",
                d.Type, d.OperatingSystem ?? "", d.Status
            }).ToList()
        );
    }

    private static async Task<ExportData> BuildRotationComplianceData(OrkunPamDbContext db)
    {
        var now   = DateTime.UtcNow;
        var creds = await db.Credentials
            .Where(c => c.Status == CredentialStatus.Active)
            .OrderBy(c => c.Name)
            .Select(c => new
            {
                c.Id, c.Name, c.Username,
                c.LastRotatedAtUtc, c.NextRotationAtUtc, c.RotationFailureCount
            })
            .ToListAsync();

        return new ExportData(
            "Rotation Compliance",
            ["Credential ID", "Name", "Username", "Last Rotated", "Next Rotation", "Compliance", "Failures"],
            creds.Select(c => new[]
            {
                c.Id.ToString(), c.Name ?? "", c.Username ?? "",
                c.LastRotatedAtUtc?.ToString("yyyy-MM-dd") ?? "Never",
                c.NextRotationAtUtc?.ToString("yyyy-MM-dd") ?? "Not Set",
                c.NextRotationAtUtc.HasValue && c.NextRotationAtUtc < now
                    ? "Non-Compliant" : "Compliant",
                c.RotationFailureCount.ToString()
            }).ToList()
        );
    }

    private static byte[] GeneratePdf(ExportData data, DateTime from, DateTime to)
    {
        QuestPDF.Settings.License = LicenseType.Community;

        return Document.Create(container =>
        {
            container.Page(page =>
            {
                page.Size(PageSizes.A4.Landscape());
                page.Margin(1.5f, Unit.Centimetre);

                page.Header().Column(col =>
                {
                    col.Item()
                        .Text("Orkun PAM — " + data.ReportName)
                        .Bold().FontSize(16);
                    col.Item()
                        .Text($"Generated: {DateTime.UtcNow:yyyy-MM-dd HH:mm} UTC  |  " +
                              $"Period: {from:yyyy-MM-dd} — {to:yyyy-MM-dd}  |  Rows: {data.Rows.Count}")
                        .FontSize(9).FontColor(Colors.Grey.Medium);
                    col.Item()
                        .BorderBottom(1).BorderColor(Colors.Blue.Darken1)
                        .PaddingBottom(4);
                });

                page.Content().PaddingTop(8).Table(table =>
                {
                    table.ColumnsDefinition(cols =>
                    {
                        for (int i = 0; i < data.Headers.Length; i++)
                            cols.RelativeColumn();
                    });

                    table.Header(header =>
                    {
                        foreach (var h in data.Headers)
                        {
                            header.Cell()
                                .Background(Colors.Blue.Darken2)
                                .Padding(4)
                                .Text(h)
                                .Bold().FontSize(8).FontColor(Colors.White);
                        }
                    });

                    bool alt = false;
                    foreach (var row in data.Rows)
                    {
                        var bg = alt ? Colors.Grey.Lighten4 : Colors.White;
                        foreach (var val in row)
                        {
                            table.Cell()
                                .Background(bg)
                                .BorderBottom(0.5f).BorderColor(Colors.Grey.Lighten3)
                                .Padding(3)
                                .Text(val ?? "—")
                                .FontSize(7);
                        }
                        alt = !alt;
                    }
                });

                page.Footer().AlignCenter().Text(x =>
                {
                    x.Span("Orkun PAM  |  Page ").FontSize(8).FontColor(Colors.Grey.Medium);
                    x.CurrentPageNumber().FontSize(8);
                    x.Span(" of ").FontSize(8).FontColor(Colors.Grey.Medium);
                    x.TotalPages().FontSize(8);
                });
            });
        }).GeneratePdf();
    }

    private static byte[] GenerateExcel(ExportData data, DateTime from, DateTime to)
    {
        using var workbook = new XLWorkbook();

        var wsName = data.ReportName.Length > 31 ? data.ReportName[..31] : data.ReportName;
        var ws = workbook.Worksheets.Add(wsName);

        for (int i = 0; i < data.Headers.Length; i++)
        {
            var cell = ws.Cell(1, i + 1);
            cell.Value = data.Headers[i];
            cell.Style.Font.Bold = true;
            cell.Style.Fill.BackgroundColor = XLColor.FromHtml("#1D4ED8");
            cell.Style.Font.FontColor = XLColor.White;
            cell.Style.Alignment.Horizontal = XLAlignmentHorizontalValues.Center;
        }

        for (int r = 0; r < data.Rows.Count; r++)
        {
            for (int c = 0; c < data.Rows[r].Length && c < data.Headers.Length; c++)
            {
                var cell = ws.Cell(r + 2, c + 1);
                cell.Value = data.Rows[r][c] ?? "";
                if (r % 2 == 1)
                    cell.Style.Fill.BackgroundColor = XLColor.FromHtml("#F9FAFB");
            }
        }

        ws.Columns().AdjustToContents();
        ws.SheetView.FreezeRows(1);

        var metaWs = workbook.Worksheets.Add("Report Info");
        metaWs.Cell(1, 1).Value = "Property";
        metaWs.Cell(1, 2).Value = "Value";
        metaWs.Cell(1, 1).Style.Font.Bold = true;
        metaWs.Cell(1, 2).Style.Font.Bold = true;
        metaWs.Cell(2, 1).Value = "Report Name";   metaWs.Cell(2, 2).Value = data.ReportName;
        metaWs.Cell(3, 1).Value = "Generated At";  metaWs.Cell(3, 2).Value = DateTime.UtcNow.ToString("yyyy-MM-dd HH:mm:ss") + " UTC";
        metaWs.Cell(4, 1).Value = "Period From";   metaWs.Cell(4, 2).Value = from.ToString("yyyy-MM-dd");
        metaWs.Cell(5, 1).Value = "Period To";     metaWs.Cell(5, 2).Value = to.ToString("yyyy-MM-dd");
        metaWs.Cell(6, 1).Value = "Total Rows";    metaWs.Cell(6, 2).Value = data.Rows.Count;
        metaWs.Cell(7, 1).Value = "System";        metaWs.Cell(7, 2).Value = "Orkun PAM";
        metaWs.Columns().AdjustToContents();

        using var ms = new MemoryStream();
        workbook.SaveAs(ms);
        return ms.ToArray();
    }
}
