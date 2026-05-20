using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Runs daily and scores every credential's risk level based on rotation age,
/// sharing, expiry, failed sessions, and account type. (#232)
/// </summary>
public sealed class CredentialRiskScoringService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<CredentialRiskScoringService> _logger;

    public CredentialRiskScoringService(IServiceScopeFactory scopeFactory, ILogger<CredentialRiskScoringService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Initial delay — let the app warm up
        await Task.Delay(TimeSpan.FromMinutes(3), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await ScoreAllCredentialsAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogError(ex, "Credential risk scoring cycle error"); }

            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }

    internal async Task ScoreAllCredentialsAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();

        var credentials = await db.Credentials
            .Include(c => c.Permissions)
            .ToListAsync(ct);

        var sevenDaysAgo = DateTime.UtcNow.AddDays(-7);

        // Get credentials that had failed or force-terminated sessions in the last 7 days
        var failedSessionCredentialIds = await db.ProxySessions
            .Where(s => s.StartedAtUtc > sevenDaysAgo &&
                        (s.Status == Domain.Enums.SessionStatus.Failed ||
                         s.Status == Domain.Enums.SessionStatus.Terminated) &&
                        s.CredentialId != Guid.Empty)
            .Select(s => s.CredentialId)
            .Distinct()
            .ToListAsync(ct);

        var failedSet = failedSessionCredentialIds.ToHashSet();

        // Get assigned credential counts (shared to multiple)
        var sharedCounts = await db.AssignedCredentials
            .Where(a => a.IsEnabled)
            .GroupBy(a => a.CredentialId)
            .Select(g => new { CredentialId = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.CredentialId, x => x.Count, ct);

        // Get credentials with checkout history
        var hasCheckoutHistory = await db.CheckOutHistories
            .Select(h => h.CredentialId)
            .Distinct()
            .ToListAsync(ct);
        var checkoutSet = hasCheckoutHistory.ToHashSet();

        var now = DateTime.UtcNow;
        int scored = 0;

        foreach (var cred in credentials)
        {
            var score = CalculateRiskScore(cred, failedSet, sharedCounts, checkoutSet, now);
            var level = score switch
            {
                > 75 => "Critical",
                > 50 => "High",
                > 25 => "Medium",
                _    => "Low"
            };

            if (cred.RiskScore != score || cred.RiskLevel != level)
            {
                cred.RiskScore = score;
                cred.RiskLevel = level;
                cred.RiskScoredAtUtc = now;
                scored++;
            }
        }

        if (scored > 0)
        {
            await db.SaveChangesAsync(ct);
            _logger.LogInformation("Credential risk scoring: updated {Count}/{Total} credentials", scored, credentials.Count);
        }
    }

    private static int CalculateRiskScore(
        Domain.Entities.Vault.Credential cred,
        HashSet<Guid> failedSessionCreds,
        Dictionary<Guid, int> sharedCounts,
        HashSet<Guid> checkoutSet,
        DateTime now)
    {
        int score = 0;

        // +30 — never rotated
        if (cred.LastRotatedAtUtc == null && cred.RotationPolicyId != null)
            score += 30;
        // +20 — rotation overdue (>90 days)
        else if (cred.LastRotatedAtUtc != null && (now - cred.LastRotatedAtUtc.Value).TotalDays > 90)
            score += 20;

        // +15 — shared to multiple principals
        if (sharedCounts.TryGetValue(cred.Id, out var shareCount) && shareCount > 1)
            score += 15;

        // +10 — orphaned (no checkout history)
        if (!checkoutSet.Contains(cred.Id))
            score += 10;

        // +25 — password expired
        if (cred.ExpiresAtUtc.HasValue && cred.ExpiresAtUtc < now)
            score += 25;

        // +15 — failed sessions in the last 7 days
        if (failedSessionCreds.Contains(cred.Id))
            score += 15;

        // +10 — admin/root/service account by username pattern
        var username = (cred.Username ?? "").ToLowerInvariant();
        if (username is "root" or "administrator" or "admin" or "sa" ||
            username.StartsWith("svc") || username.StartsWith("service"))
            score += 10;

        return Math.Min(100, score);
    }
}
