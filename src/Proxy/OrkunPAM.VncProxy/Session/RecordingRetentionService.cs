using Microsoft.Extensions.Options;

namespace OrkunPAM.VncProxy.Session;

/// <summary>Background service that deletes VNC recordings older than RetentionDays.</summary>
internal sealed class RecordingRetentionService : BackgroundService
{
    private readonly ILogger<RecordingRetentionService> _log;
    private readonly VncProxyOptions _opts;

    public RecordingRetentionService(
        ILogger<RecordingRetentionService> log, IOptions<VncProxyOptions> opts)
    {
        _log  = log;
        _opts = opts.Value;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                if (Directory.Exists(_opts.RecordingDirectory))
                {
                    var cutoff = DateTime.UtcNow.AddDays(-_opts.RetentionDays);
                    foreach (var file in Directory.EnumerateFiles(_opts.RecordingDirectory, "*.rfb"))
                    {
                        if (File.GetCreationTimeUtc(file) < cutoff)
                        {
                            File.Delete(file);
                            _log.LogInformation("Deleted expired VNC recording: {File}",
                                Path.GetFileName(file));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "VNC recording retention check failed");
            }

            await Task.Delay(TimeSpan.FromHours(6), stoppingToken);
        }
    }
}
