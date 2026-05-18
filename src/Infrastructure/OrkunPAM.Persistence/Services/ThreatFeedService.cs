using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Analytics;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Refreshes threat intelligence IOC feeds hourly.
/// Supports EmergingThreats IP blocklist (public) and AbuseIPDB (API key required).
/// </summary>
public sealed class ThreatFeedService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<ThreatFeedService> _logger;
    private readonly IHttpClientFactory _httpFactory;

    public ThreatFeedService(
        IServiceScopeFactory scopeFactory,
        ILogger<ThreatFeedService> logger,
        IHttpClientFactory httpFactory)
    {
        _scopeFactory = scopeFactory;
        _logger       = logger;
        _httpFactory  = httpFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromMinutes(3), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RefreshAllFeedsAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogError(ex, "Threat feed refresh error"); }

            await Task.Delay(TimeSpan.FromHours(1), stoppingToken);
        }
    }

    private async Task RefreshAllFeedsAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db    = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var vault = scope.ServiceProvider.GetService<IVaultEncryptionService>();

        var now  = DateTime.UtcNow;
        var configs = await db.ThreatFeedConfigs
            .Where(c => c.IsEnabled)
            .ToListAsync(ct);

        foreach (var cfg in configs)
        {
            if (cfg.LastRefreshedAtUtc.HasValue &&
                (now - cfg.LastRefreshedAtUtc.Value).TotalMinutes < cfg.RefreshIntervalMinutes)
                continue;

            try
            {
                var apiKey = DecryptApiKey(vault, cfg.ApiKeyEnc);
                var count  = cfg.FeedType switch
                {
                    "EmergingThreats" => await RefreshEmergingThreatsAsync(db, cfg, ct),
                    "AbuseIPDB"       => await RefreshAbuseIpDbAsync(db, cfg, apiKey, ct),
                    _                 => await RefreshCustomFeedAsync(db, cfg, apiKey, ct),
                };

                await PurgeExpiredAsync(db, ct);

                cfg.LastRefreshedAtUtc  = now;
                cfg.LastIndicatorCount  = count;
                cfg.LastError           = null;
                await db.SaveChangesAsync(ct);

                _logger.LogInformation("Threat feed {Name} refreshed: {Count} indicators", cfg.Name, count);
            }
            catch (Exception ex)
            {
                cfg.LastError = ex.Message[..Math.Min(ex.Message.Length, 500)];
                await db.SaveChangesAsync(ct);
                _logger.LogWarning(ex, "Threat feed {Name} refresh failed", cfg.Name);
            }
        }
    }

    private async Task<int> RefreshEmergingThreatsAsync(
        OrkunPamDbContext db, ThreatFeedConfig cfg, CancellationToken ct)
    {
        var http = _httpFactory.CreateClient();
        http.Timeout = TimeSpan.FromSeconds(30);

        var text = await http.GetStringAsync(cfg.FeedUrl, ct);
        var ips  = text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => !l.StartsWith('#') && !string.IsNullOrWhiteSpace(l))
            .Select(l => l.Split(' ', StringSplitOptions.RemoveEmptyEntries)[0])
            .Where(ip => IsValidIp(ip))
            .Distinct()
            .ToList();

        return await UpsertIndicatorsAsync(db, ips, "IP", cfg.Name, 2,
            DateTime.UtcNow.AddDays(7), ct);
    }

    private async Task<int> RefreshAbuseIpDbAsync(
        OrkunPamDbContext db, ThreatFeedConfig cfg, string? apiKey, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(apiKey))
        {
            _logger.LogWarning("AbuseIPDB feed {Name} has no API key", cfg.Name);
            return 0;
        }

        var http = _httpFactory.CreateClient();
        http.Timeout = TimeSpan.FromSeconds(30);
        http.DefaultRequestHeaders.Add("Key", apiKey);
        http.DefaultRequestHeaders.Add("Accept", "application/json");

        var resp = await http.GetAsync(cfg.FeedUrl, ct);
        resp.EnsureSuccessStatusCode();

        using var doc = await JsonDocument.ParseAsync(await resp.Content.ReadAsStreamAsync(ct), cancellationToken: ct);
        var ips = doc.RootElement
            .GetProperty("data")
            .EnumerateArray()
            .Select(e => e.TryGetProperty("ipAddress", out var ip) ? ip.GetString() : null)
            .Where(ip => !string.IsNullOrEmpty(ip) && IsValidIp(ip!))
            .Select(ip => ip!)
            .Distinct()
            .ToList();

        return await UpsertIndicatorsAsync(db, ips, "IP", cfg.Name, 3,
            DateTime.UtcNow.AddDays(1), ct);
    }

    private async Task<int> RefreshCustomFeedAsync(
        OrkunPamDbContext db, ThreatFeedConfig cfg, string? apiKey, CancellationToken ct)
    {
        var http = _httpFactory.CreateClient();
        http.Timeout = TimeSpan.FromSeconds(30);
        if (!string.IsNullOrEmpty(apiKey))
            http.DefaultRequestHeaders.Add("Authorization", "Bearer " + apiKey);

        var text = await http.GetStringAsync(cfg.FeedUrl, ct);
        var ips  = text.Split('\n', StringSplitOptions.RemoveEmptyEntries)
            .Select(l => l.Trim())
            .Where(l => !l.StartsWith('#') && IsValidIp(l))
            .Distinct()
            .ToList();

        return await UpsertIndicatorsAsync(db, ips, "IP", cfg.Name, 2,
            DateTime.UtcNow.AddDays(7), ct);
    }

    private static async Task<int> UpsertIndicatorsAsync(
        OrkunPamDbContext db, List<string> values, string type, string source,
        byte severity, DateTime expiresAt, CancellationToken ct)
    {
        var now = DateTime.UtcNow;
        var count = 0;

        foreach (var batch in values.Chunk(200))
        {
            var existing = await db.ThreatIndicators
                .Where(t => t.IndicatorType == type && batch.Contains(t.Value))
                .ToDictionaryAsync(t => t.Value, ct);

            foreach (var v in batch)
            {
                if (existing.TryGetValue(v, out var indicator))
                {
                    indicator.Severity     = severity;
                    indicator.Source       = source;
                    indicator.ExpiresAtUtc = expiresAt;
                    indicator.UpdatedAtUtc = now;
                }
                else
                {
                    db.ThreatIndicators.Add(new ThreatIndicator
                    {
                        IndicatorType = type,
                        Value         = v,
                        Severity      = severity,
                        Source        = source,
                        ExpiresAtUtc  = expiresAt,
                        CreatedAtUtc  = now,
                        UpdatedAtUtc  = now
                    });
                    count++;
                }
            }

            await db.SaveChangesAsync(ct);
        }

        return values.Count;
    }

    private static async Task PurgeExpiredAsync(OrkunPamDbContext db, CancellationToken ct)
    {
        var cutoff = DateTime.UtcNow;
        var expired = await db.ThreatIndicators
            .Where(t => t.ExpiresAtUtc.HasValue && t.ExpiresAtUtc < cutoff)
            .ToListAsync(ct);

        if (expired.Count > 0)
        {
            db.ThreatIndicators.RemoveRange(expired);
            await db.SaveChangesAsync(ct);
        }
    }

    private static string? DecryptApiKey(IVaultEncryptionService? vault, string? stored)
    {
        if (string.IsNullOrEmpty(stored) || vault == null) return stored;
        try
        {
            var bytes  = Convert.FromBase64String(stored);
            var result = vault.DecryptString(bytes);
            return result.IsSuccess ? result.Value : stored;
        }
        catch { return stored; }
    }

    private static bool IsValidIp(string s)
    {
        if (string.IsNullOrWhiteSpace(s) || s.Length > 45) return false;
        return System.Net.IPAddress.TryParse(s, out _);
    }
}
