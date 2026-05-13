using System.Net;
using System.Net.Mail;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OrkunPAM.Cryptography;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

public sealed class SmtpEmailService : IEmailService
{
    private readonly OrkunPamDbContext _db;
    private readonly IVaultEncryptionService _vault;
    private readonly ILogger<SmtpEmailService> _logger;

    public SmtpEmailService(OrkunPamDbContext db, IVaultEncryptionService vault, ILogger<SmtpEmailService> logger)
    {
        _db = db;
        _vault = vault;
        _logger = logger;
    }

    public async Task<bool> SendAsync(string to, string subject, string htmlBody, CancellationToken ct = default)
    {
        try
        {
            var (client, from, fromName) = await BuildClientAsync(ct);
            if (client == null)
            {
                _logger.LogWarning("SMTP not configured — skipping email to {To}", to);
                return false;
            }

            using (client)
            using var msg = new MailMessage();
            msg.From = new MailAddress(from, fromName ?? "OrkunPAM");
            msg.To.Add(to);
            msg.Subject = subject;
            msg.Body = htmlBody;
            msg.IsBodyHtml = true;

            await client.SendMailAsync(msg, ct);
            _logger.LogInformation("Email sent to {To}: {Subject}", to, subject);
            return true;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMTP send failed to {To}: {Subject}", to, subject);
            return false;
        }
    }

    public async Task<bool> TestConnectionAsync(CancellationToken ct = default)
    {
        var (client, _, _) = await BuildClientAsync(ct);
        client?.Dispose();
        return client != null;
    }

    private async Task<(SmtpClient? Client, string From, string? FromName)> BuildClientAsync(CancellationToken ct)
    {
        var configs = await _db.SystemConfigs
            .Where(c => c.Category == "smtp")
            .ToDictionaryAsync(c => c.Key, c => c, ct);

        if (!configs.TryGetValue("smtp.host", out var hostCfg) || string.IsNullOrEmpty(hostCfg.Value))
            return (null, string.Empty, null);

        var host = hostCfg.Value;
        var port = int.TryParse(configs.GetValueOrDefault("smtp.port")?.Value, out var p) ? p : 587;
        var useTls = configs.GetValueOrDefault("smtp.tls")?.Value == "true";
        var from = configs.GetValueOrDefault("smtp.from")?.Value ?? "noreply@orkunpam.local";
        var fromName = configs.GetValueOrDefault("smtp.fromname")?.Value;

        var client = new SmtpClient(host, port)
        {
            EnableSsl = useTls,
            Timeout = 10_000,
            DeliveryMethod = SmtpDeliveryMethod.Network
        };

        if (configs.TryGetValue("smtp.username", out var userCfg) && !string.IsNullOrEmpty(userCfg.Value))
        {
            var password = string.Empty;
            if (configs.TryGetValue("smtp.password", out var passCfg) && !string.IsNullOrEmpty(passCfg.Value))
            {
                if (passCfg.IsEncrypted)
                {
                    var dec = _vault.DecryptString(Convert.FromBase64String(passCfg.Value), "SystemConfig");
                    password = dec.IsSuccess ? dec.Value : string.Empty;
                }
                else
                {
                    password = passCfg.Value;
                }
            }
            client.Credentials = new NetworkCredential(userCfg.Value, password);
        }

        return (client, from, fromName);
    }
}
