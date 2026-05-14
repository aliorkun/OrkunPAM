using Microsoft.Extensions.Options;

namespace OrkunPAM.HttpProxy.Session;

/// <summary>
/// Background service that periodically deletes HTTP session recordings older than
/// the configured retention period (default 183 days / ~6 months per RFP §66).
/// </summary>
internal sealed class RecordingRetentionService : BackgroundService
{
    private readonly ILogger<RecordingRetentionService> _log;
    private readonly HttpProxyOptions _opts;

    public RecordingRetentionService(ILogger<RecordingRetentionService> log,
        IOptions<HttpProxyOptions> opts)
    {
        _log  = log;
        _opts = opts.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Run daily
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                PurgeOldRecordings();
            }
            catch (Exception ex)
            {
                _log.LogError(ex, "Recording retention purge failed");
            }

            await Task.Delay(TimeSpan.FromHours(24), stoppingToken);
        }
    }

    private void PurgeOldRecordings()
    {
        var dir = _opts.RecordingDirectory;
        if (!Directory.Exists(dir)) return;

        var cutoff = DateTime.UtcNow.AddDays(-_opts.RetentionDays);
        var deleted = 0;

        foreach (var file in Directory.EnumerateFiles(dir, "*.httprec"))
        {
            if (File.GetCreationTimeUtc(file) < cutoff)
            {
                try
                {
                    File.Delete(file);
                    // Also delete the corresponding DEK file
                    var dekFile = Path.ChangeExtension(file, ".dek");
                    if (File.Exists(dekFile)) File.Delete(dekFile);
                    deleted++;
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex, "Failed to delete old recording: {File}", file);
                }
            }
        }

        if (deleted > 0)
            _log.LogInformation("Retention: deleted {Count} recordings older than {Days} days",
                deleted, _opts.RetentionDays);
    }
}
