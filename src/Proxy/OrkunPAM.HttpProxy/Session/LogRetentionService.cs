using Microsoft.Extensions.Options;

namespace OrkunPAM.HttpProxy.Session;

/// <summary>Background service that deletes HTTP session logs older than RetentionDays.</summary>
internal sealed class LogRetentionService : BackgroundService
{
    private readonly ILogger<LogRetentionService> _log;
    private readonly HttpProxyOptions _opts;

    public LogRetentionService(
        ILogger<LogRetentionService> log, IOptions<HttpProxyOptions> opts)
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
                if (Directory.Exists(_opts.LogDirectory))
                {
                    var cutoff = DateTime.UtcNow.AddDays(-_opts.RetentionDays);
                    foreach (var file in Directory.EnumerateFiles(_opts.LogDirectory, "http-*.log"))
                    {
                        if (File.GetCreationTimeUtc(file) < cutoff)
                        {
                            File.Delete(file);
                            _log.LogInformation("Deleted expired HTTP session log: {File}",
                                Path.GetFileName(file));
                        }
                    }
                }
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "HTTP session log retention check failed");
            }

            await Task.Delay(TimeSpan.FromHours(6), stoppingToken);
        }
    }
}
