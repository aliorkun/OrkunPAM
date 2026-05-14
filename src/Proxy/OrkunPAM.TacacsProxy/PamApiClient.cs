using System.Net.Http.Json;
using System.Text.Json;

namespace OrkunPAM.TacacsProxy;

/// <summary>HTTP client for calling the OrkunPAM Core API from the TACACS+ proxy.</summary>
internal sealed class PamApiClient
{
    private readonly IHttpClientFactory _factory;
    private readonly ILogger<PamApiClient> _log;

    public PamApiClient(IHttpClientFactory factory, ILogger<PamApiClient> log)
    {
        _factory = factory;
        _log = log;
    }

    /// <summary>Validates NAS device credentials against the PAM vault.</summary>
    public async Task<bool> ValidateCredentialAsync(
        string username, string password, string deviceIp, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var payload = new { Username = username, Password = password, DeviceIp = deviceIp };
            var resp = await client.PostAsJsonAsync("/api/v1/tacacs/authenticate", payload, ct);
            if (!resp.IsSuccessStatusCode) return false;

            var json = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
            return json.TryGetProperty("success", out var s) && s.GetBoolean();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "PAM API call failed during TACACS+ authentication");
            return false;
        }
    }

    /// <summary>Checks command authorization policy for a user on a device.</summary>
    public async Task<bool> AuthorizeCommandAsync(
        string username, string command, string deviceIp, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var payload = new { Username = username, Command = command, DeviceIp = deviceIp };
            var resp = await client.PostAsJsonAsync("/api/v1/tacacs/authorize", payload, ct);
            if (!resp.IsSuccessStatusCode) return false;

            var json = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
            return json.TryGetProperty("success", out var s) && s.GetBoolean();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "PAM API call failed during TACACS+ authorization");
            return false;
        }
    }

    /// <summary>Verifies a TOTP code for the given username.</summary>
    public async Task<bool> VerifyTotpAsync(string username, string code, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var payload = new { Username = username, Code = code };
            var resp = await client.PostAsJsonAsync("/api/v1/auth/verify-totp", payload, ct);
            if (!resp.IsSuccessStatusCode) return false;
            var json = await resp.Content.ReadFromJsonAsync<JsonElement>(cancellationToken: ct);
            return json.TryGetProperty("success", out var s) && s.GetBoolean();
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogError(ex, "PAM API call failed during TACACS+ TOTP verification");
            return false;
        }
    }

    /// <summary>Posts an accounting event to the PAM audit log.</summary>
    public async Task SendAccountingAsync(
        string username, string deviceIp, string command,
        string eventType, string port, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var payload = new
            {
                Username  = username,
                DeviceIp  = deviceIp,
                Command   = command,
                EventType = eventType,
                Port      = port,
                Timestamp = DateTimeOffset.UtcNow
            };
            await client.PostAsJsonAsync("/api/v1/tacacs/accounting", payload, ct);
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _log.LogWarning(ex, "PAM API call failed during TACACS+ accounting (non-fatal)");
        }
    }
}
