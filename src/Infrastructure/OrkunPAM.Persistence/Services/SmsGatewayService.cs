using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OrkunPAM.Cryptography;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

public sealed class SmsGatewayService : ISmsGatewayService
{
    private readonly OrkunPamDbContext _db;
    private readonly IVaultEncryptionService _vault;
    private readonly IHttpClientFactory _http;
    private readonly ILogger<SmsGatewayService> _logger;

    public SmsGatewayService(OrkunPamDbContext db, IVaultEncryptionService vault,
        IHttpClientFactory http, ILogger<SmsGatewayService> logger)
    {
        _db = db;
        _vault = vault;
        _http = http;
        _logger = logger;
    }

    public async Task<bool> SendAsync(string toPhoneNumber, string message, CancellationToken ct = default)
    {
        try
        {
            var cfg = await LoadConfigAsync(ct);
            if (cfg == null)
            {
                _logger.LogWarning("SMS gateway not configured — skipping SMS to {To}", toPhoneNumber);
                return false;
            }

            return cfg.Provider switch
            {
                "twilio"  => await SendTwilioAsync(cfg, toPhoneNumber, message, ct),
                "netgsm"  => await SendNetGsmAsync(cfg, toPhoneNumber, message, ct),
                "webhook" => await SendWebhookAsync(cfg, toPhoneNumber, message, ct),
                _ => false
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "SMS send failed to {To}", toPhoneNumber);
            return false;
        }
    }

    public async Task<bool> TestConnectionAsync(CancellationToken ct = default)
    {
        var cfg = await LoadConfigAsync(ct);
        return cfg != null;
    }

    private async Task<SmsConfig?> LoadConfigAsync(CancellationToken ct)
    {
        var rows = await _db.SystemConfigs
            .Where(c => c.Category == "sms")
            .ToListAsync(ct);

        if (rows.Count == 0) return null;

        var dict = rows.ToDictionary(r => r.Key, r => r.Value ?? "");

        string Decrypt(string key)
        {
            if (!dict.TryGetValue(key, out var v) || string.IsNullOrEmpty(v)) return "";
            if (v.StartsWith("enc:", StringComparison.Ordinal))
                return _vault.Decrypt(v[4..]);
            return v;
        }

        string Get(string key) => dict.TryGetValue(key, out var v) ? v ?? "" : "";

        var provider = Get("sms.provider");
        if (string.IsNullOrEmpty(provider)) return null;

        return new SmsConfig
        {
            Provider       = provider,
            AccountSid     = Get("sms.account_sid"),
            AuthToken      = Decrypt("sms.auth_token"),
            FromNumber     = Get("sms.from_number"),
            WebhookUrl     = Get("sms.webhook_url"),
            WebhookSecret  = Decrypt("sms.webhook_secret"),
            NetGsmUser     = Get("sms.netgsm_user"),
            NetGsmPassword = Decrypt("sms.netgsm_password"),
            NetGsmOriginator = Get("sms.netgsm_originator")
        };
    }

    private async Task<bool> SendTwilioAsync(SmsConfig cfg, string to, string body, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(cfg.AccountSid) || string.IsNullOrEmpty(cfg.AuthToken))
        {
            _logger.LogWarning("Twilio not fully configured (missing AccountSid/AuthToken)");
            return false;
        }

        var client = _http.CreateClient();
        var credential = Convert.ToBase64String(Encoding.ASCII.GetBytes(cfg.AccountSid + ":" + cfg.AuthToken));
        client.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Basic", credential);

        var form = new FormUrlEncodedContent([
            new KeyValuePair<string,string>("To", to),
            new KeyValuePair<string,string>("From", cfg.FromNumber),
            new KeyValuePair<string,string>("Body", body)
        ]);

        var url = "https://api.twilio.com/2010-04-01/Accounts/" + cfg.AccountSid + "/Messages.json";
        var resp = await client.PostAsync(url, form, ct);
        if (!resp.IsSuccessStatusCode)
        {
            var err = await resp.Content.ReadAsStringAsync(ct);
            _logger.LogError("Twilio send failed: {Status} {Error}", (int)resp.StatusCode, err);
            return false;
        }

        _logger.LogInformation("SMS sent via Twilio to {To}", to);
        return true;
    }

    private async Task<bool> SendNetGsmAsync(SmsConfig cfg, string to, string body, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(cfg.NetGsmUser) || string.IsNullOrEmpty(cfg.NetGsmPassword))
        {
            _logger.LogWarning("NetGSM not fully configured");
            return false;
        }

        var client = _http.CreateClient();
        var normalized = to.Replace("+", "").Replace(" ", "");
        var url = "https://api.netgsm.com.tr/sms/send/get/"
            + "?usercode=" + Uri.EscapeDataString(cfg.NetGsmUser)
            + "&password=" + Uri.EscapeDataString(cfg.NetGsmPassword)
            + "&gsmno=" + Uri.EscapeDataString(normalized)
            + "&message=" + Uri.EscapeDataString(body)
            + "&msgheader=" + Uri.EscapeDataString(cfg.NetGsmOriginator ?? "OrkunPAM");

        var resp = await client.GetAsync(url, ct);
        var content = await resp.Content.ReadAsStringAsync(ct);

        if (resp.IsSuccessStatusCode && (content.StartsWith("0") || content.StartsWith("1")))
        {
            _logger.LogInformation("SMS sent via NetGSM to {To}", to);
            return true;
        }

        _logger.LogError("NetGSM send failed: {Response}", content);
        return false;
    }

    private async Task<bool> SendWebhookAsync(SmsConfig cfg, string to, string body, CancellationToken ct)
    {
        if (string.IsNullOrEmpty(cfg.WebhookUrl))
        {
            _logger.LogWarning("Webhook URL not configured");
            return false;
        }

        var client = _http.CreateClient();
        var payload = JsonSerializer.Serialize(new { to, message = body });
        var content = new StringContent(payload, Encoding.UTF8, "application/json");

        if (!string.IsNullOrEmpty(cfg.WebhookSecret))
            client.DefaultRequestHeaders.Add("X-OrkunPAM-Secret", cfg.WebhookSecret);

        var resp = await client.PostAsync(cfg.WebhookUrl, content, ct);
        if (!resp.IsSuccessStatusCode)
        {
            _logger.LogError("Webhook SMS send failed: {Status}", (int)resp.StatusCode);
            return false;
        }

        _logger.LogInformation("SMS sent via webhook to {To}", to);
        return true;
    }

    private sealed class SmsConfig
    {
        public string Provider { get; set; } = "";
        public string AccountSid { get; set; } = "";
        public string AuthToken { get; set; } = "";
        public string FromNumber { get; set; } = "";
        public string WebhookUrl { get; set; } = "";
        public string WebhookSecret { get; set; } = "";
        public string NetGsmUser { get; set; } = "";
        public string NetGsmPassword { get; set; } = "";
        public string NetGsmOriginator { get; set; } = "";
    }
}
