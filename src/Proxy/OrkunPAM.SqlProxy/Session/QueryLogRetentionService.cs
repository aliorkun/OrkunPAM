using Microsoft.Extensions.Options;

namespace OrkunPAM.SqlProxy.Session;

/// <summary>
/// Deletes SQL query log files (.sql.jsonl) older than the configured retention period.
/// Runs once per day after a 5-minute startup delay.
/// </summary>
internal sealed class QueryLogRetentionService : BackgroundService
{
    private readonly ILogger<QueryLogRetentionService> _log;
    private readonly SqlProxyOptions _opts;

    public QueryLogRetentionService(
        ILogger<QueryLogRetentionService> log,
        IOptions<SqlProxyOptions> opts)
    {
        _log  = log;
        _opts = opts.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try { await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken); }
        catch (OperationCanceledException) { return; }

        while (!stoppingToken.IsCancellationRequested)
        {
            try { PurgeExpired(); }
            catch (Exception ex) { _log.LogError(ex, "SQL log retention purge failed"); }

            try { await Task.Delay(TimeSpan.FromHours(24), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void PurgeExpired()
    {
        var dir = _opts.QueryLogDirectory;
        if (!Directory.Exists(dir)) return;

        var cutoff = DateTime.UtcNow.AddDays(-_opts.RetentionDays);
        int deleted = 0;

        foreach (var file in Directory.EnumerateFiles(dir, "*.sql.jsonl"))
        {
            try
            {
                if (File.GetCreationTimeUtc(file) < cutoff)
                {
                    File.Delete(file);
                    deleted++;
                }
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Failed to delete SQL log {File}", file);
            }
        }

        if (deleted > 0)
            _log.LogInformation("Purged {Count} expired SQL query logs (retention={Days}d)",
                deleted, _opts.RetentionDays);
    }
}
