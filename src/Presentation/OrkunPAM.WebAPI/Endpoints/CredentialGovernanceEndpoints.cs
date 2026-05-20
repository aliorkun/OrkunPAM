using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class CredentialGovernanceEndpoints
{
    public static void MapCredentialGovernanceEndpoints(this IEndpointRouteBuilder app)
    {
        // GET /api/v1/vault/governance/summary
        app.MapGet("/api/v1/vault/governance/summary", async (OrkunPamDbContext db) =>
        {
            var now = DateTime.UtcNow;
            var totalCredentials  = await db.Credentials.CountAsync();
            var totalAssignments  = await db.AssignedCredentials.CountAsync(a => a.IsEnabled);
            var expiredCredentials = await db.Credentials.CountAsync(c => c.ExpiresAtUtc != null && c.ExpiresAtUtc < now);
            var expiringIn7Days   = await db.Credentials.CountAsync(c =>
                c.ExpiresAtUtc != null && c.ExpiresAtUtc >= now && c.ExpiresAtUtc <= now.AddDays(7));
            var neverRotated      = await db.Credentials.CountAsync(c =>
                c.LastRotatedAtUtc == null && c.RotationPolicyId != null);
            var criticalRisk      = await db.Credentials.CountAsync(c => c.RiskLevel == "Critical");
            var rotationFailures  = await db.Credentials.CountAsync(c => c.RotationFailureCount > 0);

            var activeUserIds = await db.Users
                .Where(u => u.Status == UserStatus.Active)
                .Select(u => u.Id)
                .ToListAsync();
            var activeSet = activeUserIds.ToHashSet();

            var userAssignedPrincipalIds = await db.AssignedCredentials
                .Where(a => a.IsEnabled && a.PrincipalType == PrincipalType.User)
                .Select(a => a.PrincipalId)
                .ToListAsync();
            var orphanedAssignments = userAssignedPrincipalIds.Count(id => !activeSet.Contains(id));

            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    totalCredentials,
                    totalAssignments,
                    expiredCredentials,
                    expiringIn7Days,
                    neverRotated,
                    criticalRisk,
                    rotationFailures,
                    orphanedAssignments
                }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("Vault");

        // GET /api/v1/vault/governance/access-matrix?page=1&pageSize=50
        app.MapGet("/api/v1/vault/governance/access-matrix", async (
            OrkunPamDbContext db, int page = 1, int pageSize = 50) =>
        {
            var query = db.AssignedCredentials
                .Include(a => a.Credential).ThenInclude(c => c.Folder)
                .Include(a => a.DeviceGroup)
                .OrderBy(a => a.Credential.Name);

            var total = await query.CountAsync();
            var items = await query.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync();

            var userIds  = items.Where(a => a.PrincipalType == PrincipalType.User).Select(a => a.PrincipalId).Distinct().ToList();
            var groupIds = items.Where(a => a.PrincipalType == PrincipalType.Group).Select(a => a.PrincipalId).Distinct().ToList();

            var userMap  = (await db.Users.Where(u => userIds.Contains(u.Id))
                .Select(u => new { u.Id, u.Username }).ToListAsync())
                .ToDictionary(u => u.Id, u => u.Username);
            var groupMap = (await db.Groups.Where(g => groupIds.Contains(g.Id))
                .Select(g => new { g.Id, g.Name }).ToListAsync())
                .ToDictionary(g => g.Id, g => g.Name);

            var userCredPairs = items
                .Where(a => a.PrincipalType == PrincipalType.User)
                .Select(a => new { a.CredentialId, UserId = a.PrincipalId })
                .Distinct().ToList();

            Dictionary<(Guid, Guid), DateTime> lastCheckouts = new();
            if (userCredPairs.Count > 0)
            {
                var credIds = userCredPairs.Select(p => p.CredentialId).Distinct().ToList();
                var uids    = userCredPairs.Select(p => p.UserId).Distinct().ToList();
                var rows = await db.CheckOutHistories
                    .Where(h => credIds.Contains(h.CredentialId) && uids.Contains(h.UserId))
                    .GroupBy(h => new { h.CredentialId, h.UserId })
                    .Select(g => new { g.Key.CredentialId, g.Key.UserId, Last = g.Max(h => h.CheckedOutAtUtc) })
                    .ToListAsync();
                foreach (var r in rows)
                    lastCheckouts[(r.CredentialId, r.UserId)] = r.Last;
            }

            var result = items.Select(a => new
            {
                a.Id,
                CredentialId       = a.CredentialId,
                CredentialName     = a.Credential.Name,
                FolderName         = a.Credential.Folder.Name,
                CredentialUsername = a.Credential.Username,
                CredentialRiskLevel = a.Credential.RiskLevel,
                PrincipalType      = a.PrincipalType.ToString(),
                PrincipalId        = a.PrincipalId,
                PrincipalName      = a.PrincipalType == PrincipalType.User
                    ? userMap.GetValueOrDefault(a.PrincipalId, a.PrincipalId.ToString()[..8])
                    : groupMap.GetValueOrDefault(a.PrincipalId, a.PrincipalId.ToString()[..8]),
                DeviceGroup    = a.DeviceGroup?.Name,
                a.IsEnabled,
                a.Notes,
                LastUsed = a.PrincipalType == PrincipalType.User
                    ? lastCheckouts.GetValueOrDefault((a.CredentialId, a.PrincipalId))
                    : (DateTime?)null,
                AssignedAt = a.CreatedAtUtc
            }).ToList();

            return Results.Ok(new { success = true, data = result, meta = new { page, pageSize, total } });
        }).RequireAuthorization("AdminPolicy").WithTags("Vault");

        // GET /api/v1/vault/governance/stale-access?inactiveDays=90
        app.MapGet("/api/v1/vault/governance/stale-access", async (
            OrkunPamDbContext db, int inactiveDays = 90) =>
        {
            var cutoff = DateTime.UtcNow.AddDays(-inactiveDays);

            var assignments = await db.AssignedCredentials
                .Include(a => a.Credential)
                .Where(a => a.IsEnabled && a.PrincipalType == PrincipalType.User)
                .ToListAsync();

            if (assignments.Count == 0)
                return Results.Ok(new { success = true, data = Array.Empty<object>(), total = 0 });

            var credIds = assignments.Select(a => a.CredentialId).Distinct().ToList();
            var uids    = assignments.Select(a => a.PrincipalId).Distinct().ToList();

            var checkoutMap = (await db.CheckOutHistories
                .Where(h => credIds.Contains(h.CredentialId) && uids.Contains(h.UserId))
                .GroupBy(h => new { h.CredentialId, h.UserId })
                .Select(g => new { g.Key.CredentialId, g.Key.UserId, Last = g.Max(h => h.CheckedOutAtUtc) })
                .ToListAsync())
                .ToDictionary(r => (r.CredentialId, r.UserId), r => (DateTime?)r.Last);

            var userMap = (await db.Users.Where(u => uids.Contains(u.Id))
                .Select(u => new { u.Id, u.Username }).ToListAsync())
                .ToDictionary(u => u.Id, u => u.Username);

            var stale = assignments
                .Select(a =>
                {
                    var lastUsed    = checkoutMap.GetValueOrDefault((a.CredentialId, a.PrincipalId));
                    var isNeverUsed = lastUsed == null;
                    var daysInactive = lastUsed.HasValue ? (int)(DateTime.UtcNow - lastUsed.Value).TotalDays : (int?)null;
                    return new
                    {
                        AssignmentId       = a.Id,
                        CredentialId       = a.CredentialId,
                        CredentialName     = a.Credential.Name,
                        CredentialUsername = a.Credential.Username,
                        UserId             = a.PrincipalId,
                        Username           = userMap.GetValueOrDefault(a.PrincipalId, a.PrincipalId.ToString()[..8]),
                        LastUsed           = lastUsed,
                        DaysInactive       = daysInactive,
                        IsNeverUsed        = isNeverUsed,
                        AssignedAt         = a.CreatedAtUtc
                    };
                })
                .Where(x => x.IsNeverUsed || (x.LastUsed.HasValue && x.LastUsed < cutoff))
                .OrderByDescending(x => x.IsNeverUsed)
                .ThenByDescending(x => x.DaysInactive ?? int.MaxValue)
                .ToList();

            return Results.Ok(new { success = true, data = stale, total = stale.Count });
        }).RequireAuthorization("AdminPolicy").WithTags("Vault");

        // GET /api/v1/vault/credentials/export — CSV metadata export (no passwords)
        app.MapGet("/api/v1/vault/credentials/export", async (OrkunPamDbContext db) =>
        {
            var credentials = await db.Credentials
                .Include(c => c.Folder)
                .OrderBy(c => c.Folder.Name).ThenBy(c => c.Name)
                .Select(c => new
                {
                    c.Id, c.Name, c.Username, c.CredentialType, FolderName = c.Folder.Name,
                    c.Status, c.RiskScore, c.RiskLevel,
                    c.LastRotatedAtUtc, c.NextRotationAtUtc, c.ExpiresAtUtc,
                    c.IsDiscovered, c.RotationFailureCount, c.CreatedAtUtc
                })
                .ToListAsync();

            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Id,Name,Username,Type,Folder,Status,RiskScore,RiskLevel,LastRotated,NextRotation,ExpiresAt,IsDiscovered,RotationFailures,CreatedAt");

            foreach (var c in credentials)
            {
                sb.Append(c.Id).Append(',')
                  .Append(CsvEscape(c.Name)).Append(',')
                  .Append(CsvEscape(c.Username ?? "")).Append(',')
                  .Append(c.CredentialType).Append(',')
                  .Append(CsvEscape(c.FolderName)).Append(',')
                  .Append(c.Status).Append(',')
                  .Append(c.RiskScore).Append(',')
                  .Append(c.RiskLevel).Append(',')
                  .Append(c.LastRotatedAtUtc?.ToString("yyyy-MM-dd HH:mm") ?? "").Append(',')
                  .Append(c.NextRotationAtUtc?.ToString("yyyy-MM-dd HH:mm") ?? "").Append(',')
                  .Append(c.ExpiresAtUtc?.ToString("yyyy-MM-dd") ?? "").Append(',')
                  .Append(c.IsDiscovered).Append(',')
                  .Append(c.RotationFailureCount).Append(',')
                  .AppendLine(c.CreatedAtUtc.ToString("yyyy-MM-dd HH:mm"));
            }

            return Results.Content(sb.ToString(), "text/csv", System.Text.Encoding.UTF8);
        }).RequireAuthorization("AdminPolicy").WithTags("Vault");
    }

    private static string CsvEscape(string value)
    {
        if (value.Contains(',') || value.Contains('"') || value.Contains('\n'))
            return "\"" + value.Replace("\"", "\"\"") + "\"";
        return value;
    }
}
