using Microsoft.Extensions.Options;

namespace OrkunPAM.RdpProxy.Session;

/// <summary>
/// Background service that deletes RDP recordings older than the configured retention period.
/// Runs once per day.
/// </summary>
internal sealed class RecordingRetentionService : BackgroundService
{
    private readonly ILogger<RecordingRetentionService> _log;
    private readonly RdpProxyOptions _opts;

    public RecordingRetentionService(ILogger<RecordingRetentionService> log, IOptions<RdpProxyOptions> opts)
    {
        _log = log;
        _opts = opts.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            PurgeExpired();
            try { await Task.Delay(TimeSpan.FromHours(24), stoppingToken); }
            catch (OperationCanceledException) { break; }
        }
    }

    private void PurgeExpired()
    {
        var dir = _opts.RecordingDirectory;
        if (!Directory.Exists(dir)) return;

        var cutoff = DateTime.UtcNow.AddDays(-_opts.RetentionDays);
        int deleted = 0;

        foreach (var file in Directory.EnumerateFiles(dir, "*.rdp.rec"))
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
                _log.LogWarning(ex, "Failed to delete recording {File}", file);
            }
        }

        if (deleted > 0)
            _log.LogInformation("Purged {Count} expired RDP recordings (retention={Days}d)", deleted, _opts.RetentionDays);
    }
}
