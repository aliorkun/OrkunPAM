using Microsoft.Extensions.Options;

namespace OrkunPAM.SshProxy.Session;

/// <summary>
/// Deletes session recording files older than the configured retention period.
/// RFP §66: recordings must be retained for at least 6 months (default: 183 days).
/// Runs once per hour; only .ascrec and their paired .dek files are removed.
/// chain.jsonl entries are intentionally preserved: the chain proves the recording
/// existed and was legitimately purged after its retention period.
/// </summary>
internal sealed class RecordingRetentionService(
    IOptions<SshProxyOptions> opts,
    ILogger<RecordingRetentionService> log) : BackgroundService
{
    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        // Stagger first run by 5 minutes so service startup isn't impacted
        await Task.Delay(TimeSpan.FromMinutes(5), ct);

        while (!ct.IsCancellationRequested)
        {
            try { PurgeExpired(); }
            catch (Exception ex) { log.LogError(ex, "Retention purge failed"); }

            await Task.Delay(TimeSpan.FromHours(1), ct);
        }
    }

    private void PurgeExpired()
    {
        var recDir = opts.Value.RecordingDirectory;
        if (!Directory.Exists(recDir)) return;

        var cutoff = DateTime.UtcNow.AddDays(-opts.Value.RetentionDays);
        int deleted = 0;

        foreach (var recFile in Directory.GetFiles(recDir, "*.ascrec"))
        {
            var info = new FileInfo(recFile);
            if (info.LastWriteTimeUtc > cutoff) continue;

            var dekFile = Path.ChangeExtension(recFile, ".dek");
            try
            {
                File.Delete(recFile);
                if (File.Exists(dekFile)) File.Delete(dekFile);
                deleted++;
                log.LogDebug("Retention: deleted {File}", Path.GetFileName(recFile));
            }
            catch (Exception ex)
            {
                log.LogWarning(ex, "Retention: failed to delete {File}", recFile);
            }
        }

        if (deleted > 0)
            log.LogInformation("Retention: purged {Count} recording(s) older than {Days} days",
                deleted, opts.Value.RetentionDays);
    }
}
