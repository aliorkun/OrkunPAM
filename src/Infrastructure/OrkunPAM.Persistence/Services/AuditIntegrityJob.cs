using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;

namespace OrkunPAM.Persistence.Services;

public sealed class AuditIntegrityJob : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<AuditIntegrityJob> _logger;

    public AuditIntegrityJob(IServiceScopeFactory scopeFactory, ILogger<AuditIntegrityJob> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        // Initial delay on startup
        await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken).ConfigureAwait(false);
        while (!stoppingToken.IsCancellationRequested)
        {
            try
            {
                await RunVerificationAsync(stoppingToken);
            }
            catch (Exception ex) when (ex is not OperationCanceledException)
            {
                _logger.LogError(ex, "Audit integrity verification error");
            }
            await Task.Delay(TimeSpan.FromHours(24), stoppingToken).ConfigureAwait(false);
        }
    }

    private async Task RunVerificationAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();

        var logs = await db.AuditLogs.OrderBy(a => a.Id).ToListAsync(ct);

        byte[]? previousHash = null;
        int tamperedCount = 0;

        foreach (var log in logs)
        {
            if (previousHash != null && log.PreviousHash != null)
            {
                var broken = !previousHash.SequenceEqual(log.PreviousHash);
                if (broken && !log.IsTampered) { log.IsTampered = true; tamperedCount++; }
                else if (!broken && log.IsTampered) { log.IsTampered = false; }
            }
            previousHash = log.EntryHash;
        }

        if (tamperedCount > 0)
        {
            await db.SaveChangesAsync(ct);
            _logger.LogWarning("Audit integrity: {Count} tampered entries detected", tamperedCount);
        }

        await audit.LogAsync("System", "AUDIT_INTEGRITY_CHECK", null, "System", null,
            null, null,
            new { totalChecked = logs.Count, tamperedCount, integrityValid = tamperedCount == 0 },
            ct: ct);

        _logger.LogInformation("Audit integrity check complete. Entries: {Total}, Tampered: {Tampered}",
            logs.Count, tamperedCount);
    }
}
