using Microsoft.EntityFrameworkCore;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Persistence;

namespace OrkunPAM.WebAPI.Endpoints;

public static class CredentialRiskEndpoints
{
    public static void MapCredentialRiskEndpoints(this IEndpointRouteBuilder app)
    {
        // GET /api/v1/vault/credentials/risk-summary — risk level distribution
        app.MapGet("/api/v1/vault/credentials/risk-summary", async (OrkunPamDbContext db) =>
        {
            var summary = await db.Credentials
                .GroupBy(c => c.RiskLevel)
                .Select(g => new { Level = g.Key, Count = g.Count() })
                .ToListAsync();

            var dict = summary.ToDictionary(x => x.Level, x => x.Count);
            return Results.Ok(new
            {
                success = true,
                data = new
                {
                    critical = dict.GetValueOrDefault("Critical", 0),
                    high     = dict.GetValueOrDefault("High", 0),
                    medium   = dict.GetValueOrDefault("Medium", 0),
                    low      = dict.GetValueOrDefault("Low", 0),
                    total    = dict.Values.Sum()
                }
            });
        }).RequireAuthorization().WithTags("Vault");

        // GET /api/v1/vault/credentials/high-risk — credentials with score > 50
        app.MapGet("/api/v1/vault/credentials/high-risk", async (OrkunPamDbContext db) =>
        {
            var items = await db.Credentials
                .Where(c => c.RiskScore > 50)
                .OrderByDescending(c => c.RiskScore)
                .Take(50)
                .Select(c => new
                {
                    c.Id,
                    c.Name,
                    c.Username,
                    c.RiskScore,
                    c.RiskLevel,
                    c.RiskScoredAtUtc,
                    c.LastRotatedAtUtc,
                    c.ExpiresAtUtc,
                    FolderName = c.Folder.Name
                })
                .ToListAsync();

            return Results.Ok(new { success = true, data = items });
        }).RequireAuthorization("AdminPolicy").WithTags("Vault");

        // POST /api/v1/vault/credentials/{id}/risk/rescore — manually rescore a single credential
        app.MapPost("/api/v1/vault/credentials/{id:guid}/risk/rescore", async (
            Guid id, OrkunPamDbContext db, IAuditService audit,
            System.Security.Claims.ClaimsPrincipal user) =>
        {
            var cred = await db.Credentials
                .Include(c => c.Permissions)
                .FirstOrDefaultAsync(c => c.Id == id);
            if (cred == null)
                return Results.NotFound(new { success = false, errors = new[] { "Credential not found" } });

            var now = DateTime.UtcNow;
            var sevenDaysAgo = now.AddDays(-7);

            var terminatedCount = await db.ProxySessions
                .CountAsync(s => s.CredentialId == id &&
                                 s.StartedAtUtc > sevenDaysAgo &&
                                 (s.Status == Domain.Enums.SessionStatus.Failed ||
                                  s.Status == Domain.Enums.SessionStatus.Terminated));

            var shareCount = await db.AssignedCredentials
                .CountAsync(a => a.CredentialId == id && a.IsEnabled);

            var hasCheckout = await db.CheckOutHistories.AnyAsync(h => h.CredentialId == id);

            int score = 0;
            if (cred.LastRotatedAtUtc == null && cred.RotationPolicyId != null) score += 30;
            else if (cred.LastRotatedAtUtc != null && (now - cred.LastRotatedAtUtc.Value).TotalDays > 90) score += 20;
            if (shareCount > 1) score += 15;
            if (!hasCheckout) score += 10;
            if (cred.ExpiresAtUtc.HasValue && cred.ExpiresAtUtc < now) score += 25;
            if (terminatedCount > 0) score += 15;
            var username = (cred.Username ?? "").ToLowerInvariant();
            if (username is "root" or "administrator" or "admin" or "sa" ||
                username.StartsWith("svc") || username.StartsWith("service")) score += 10;

            score = Math.Min(100, score);
            cred.RiskScore = score;
            cred.RiskLevel = score switch { > 75 => "Critical", > 50 => "High", > 25 => "Medium", _ => "Low" };
            cred.RiskScoredAtUtc = now;
            await db.SaveChangesAsync();

            var userId = user.FindFirst(System.Security.Claims.ClaimTypes.NameIdentifier)?.Value;
            _ = audit.LogAsync("Vault", "CREDENTIAL_RISK_SCORED", Guid.TryParse(userId, out var uid) ? uid : Guid.Empty,
                user.Identity?.Name ?? "unknown", "manual", "Credential", id.ToString(), new { id, score = cred.RiskScore });

            return Results.Ok(new
            {
                success = true,
                data = new { cred.RiskScore, cred.RiskLevel, cred.RiskScoredAtUtc }
            });
        }).RequireAuthorization("AdminPolicy").WithTags("Vault");
    }
}
