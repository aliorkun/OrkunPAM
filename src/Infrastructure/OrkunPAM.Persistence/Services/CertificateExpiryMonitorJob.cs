using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

public sealed class CertificateExpiryMonitorJob : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<CertificateExpiryMonitorJob> _logger;
    private static readonly TimeSpan RunInterval = TimeSpan.FromHours(24);

    private static readonly int[] WarnThresholdsDays = [90, 30, 7];

    public CertificateExpiryMonitorJob(IServiceScopeFactory scopeFactory, ILogger<CertificateExpiryMonitorJob> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("CertificateExpiryMonitorJob started");
        await Task.Delay(TimeSpan.FromMinutes(3), stoppingToken).ConfigureAwait(false);

        using var timer = new PeriodicTimer(RunInterval);
        do
        {
            try { await RunAsync(stoppingToken); }
            catch (Exception ex) when (ex is not OperationCanceledException)
            { _logger.LogError(ex, "CertificateExpiryMonitorJob sweep failed"); }
        }
        while (await timer.WaitForNextTickAsync(stoppingToken));
    }

    private async Task RunAsync(CancellationToken ct)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db    = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var email = scope.ServiceProvider.GetRequiredService<IEmailService>();
        var audit = scope.ServiceProvider.GetRequiredService<IAuditService>();

        var now = DateTime.UtcNow;
        var maxThreshold = now.AddDays(WarnThresholdsDays.Max());

        var expiring = await db.ManagedCertificates
            .Where(c => c.NotAfter <= maxThreshold)
            .OrderBy(c => c.NotAfter)
            .ToListAsync(ct);

        if (expiring.Count == 0)
        {
            _logger.LogDebug("CertificateExpiryMonitorJob: no expiring certificates found");
            return;
        }

        var adminEmails = await db.Users
            .Where(u => u.Status == OrkunPAM.Domain.Enums.UserStatus.Active && u.Email != null && u.UserRoles.Any(r => r.Role.Name == "GlobalAdmin"))
            .Select(u => u.Email!)
            .ToListAsync(ct);

        int notified = 0;
        foreach (var cert in expiring)
        {
            var daysLeft = (int)(cert.NotAfter - now).TotalDays;
            var isExpired = daysLeft < 0;

            var subject = isExpired
                ? $"[PAM ALERT] Certificate EXPIRED: {cert.SubjectCN}"
                : $"[PAM ALERT] Certificate expiring in {daysLeft} days: {cert.SubjectCN}";

            var body = isExpired
                ? $"Certificate '{cert.SubjectCN}' (Thumbprint: {cert.Thumbprint}) EXPIRED on {cert.NotAfter:yyyy-MM-dd}.\n\nPlease renew immediately."
                : $"Certificate '{cert.SubjectCN}' (Thumbprint: {cert.Thumbprint}) expires on {cert.NotAfter:yyyy-MM-dd} ({daysLeft} days remaining).\n\nSource: {cert.Source}";

            foreach (var adminEmail in adminEmails)
            {
                await SendEmailAsync(email, adminEmail, subject, body);
            }

            await audit.LogAsync("Certificate", isExpired ? "CERT_EXPIRED" : "CERT_EXPIRY_WARNING",
                null, null, "system", "ManagedCertificate", cert.Id.ToString(),
                new { cert.SubjectCN, cert.Thumbprint, cert.NotAfter, DaysLeft = daysLeft });

            notified++;
        }

        _logger.LogInformation("CertificateExpiryMonitorJob: {Count} expiring/expired certificates, {Notified} notifications sent",
            expiring.Count, notified);
    }

    private async Task SendEmailAsync(IEmailService email, string to, string subject, string body)
    {
        try { await email.SendAsync(to, subject, body); }
        catch (Exception ex) { _logger.LogWarning(ex, "Failed to send certificate expiry email to {To}", to); }
    }
}
