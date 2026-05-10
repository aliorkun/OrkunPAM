using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.Extensions.Logging;

namespace OrkunPAM.Persistence.Services;

public interface IWebhookDeliveryService
{
    Task<WebhookDeliveryResult> SendAsync(string url, object payload, string? secret, int timeoutSeconds = 10);
    Task<WebhookDeliveryResult> SendTestAsync(string url, string? secret, int timeoutSeconds = 10);
}

public record WebhookDeliveryResult(bool Success, int StatusCode, string? ResponseBody, int ResponseTimeMs, string? Error);

public sealed class WebhookDeliveryService : IWebhookDeliveryService, IDisposable
{
    private readonly HttpClient _httpClient;
    private readonly ILogger<WebhookDeliveryService> _logger;

    public WebhookDeliveryService(ILogger<WebhookDeliveryService> logger)
    {
        _logger = logger;
        _httpClient = new HttpClient();
        _httpClient.DefaultRequestHeaders.UserAgent.Add(new ProductInfoHeaderValue("OrkunPAM-Webhook", "1.0"));
        _httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    }

    public async Task<WebhookDeliveryResult> SendAsync(string url, object payload, string? secret, int timeoutSeconds = 10)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var json = JsonSerializer.Serialize(payload, new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });
            var content = new StringContent(json, Encoding.UTF8, "application/json");

            using var request = new HttpRequestMessage(HttpMethod.Post, url) { Content = content };

            // HMAC-SHA256 signature
            if (!string.IsNullOrEmpty(secret))
            {
                var signatureBytes = HMACSHA256.HashData(Encoding.UTF8.GetBytes(secret), Encoding.UTF8.GetBytes(json));
                var signature = $"sha256={Convert.ToHexString(signatureBytes).ToLowerInvariant()}";
                request.Headers.Add("X-OrkunPAM-Signature", signature);
            }

            request.Headers.Add("X-OrkunPAM-Event", payload.GetType().Name);
            request.Headers.Add("X-OrkunPAM-Delivery", Guid.NewGuid().ToString());
            request.Headers.Add("X-OrkunPAM-Timestamp", DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString());

            _httpClient.Timeout = TimeSpan.FromSeconds(timeoutSeconds);
            var response = await _httpClient.SendAsync(request);
            sw.Stop();

            var body = await response.Content.ReadAsStringAsync();

            _logger.LogInformation("Webhook delivered to {Url}. Status: {StatusCode}, Time: {Ms}ms",
                url, (int)response.StatusCode, sw.ElapsedMilliseconds);

            return new WebhookDeliveryResult(response.IsSuccessStatusCode, (int)response.StatusCode, body, (int)sw.ElapsedMilliseconds, null);
        }
        catch (TaskCanceledException)
        {
            sw.Stop();
            _logger.LogWarning("Webhook delivery timed out for {Url} after {Timeout}s", url, timeoutSeconds);
            return new WebhookDeliveryResult(false, 0, null, (int)sw.ElapsedMilliseconds, $"Request timed out after {timeoutSeconds}s");
        }
        catch (HttpRequestException ex)
        {
            sw.Stop();
            _logger.LogWarning(ex, "Webhook delivery failed for {Url}", url);
            return new WebhookDeliveryResult(false, 0, null, (int)sw.ElapsedMilliseconds, $"Connection failed: {ex.Message}");
        }
    }

    public async Task<WebhookDeliveryResult> SendTestAsync(string url, string? secret, int timeoutSeconds = 10)
    {
        var testPayload = new
        {
            eventType = "webhook.test",
            timestamp = DateTime.UtcNow,
            source = "OrkunPAM",
            message = "This is a test webhook delivery from Orkun PAM",
            data = new { testId = Guid.NewGuid() }
        };

        return await SendAsync(url, testPayload, secret, timeoutSeconds);
    }

    public void Dispose() => _httpClient.Dispose();
}
