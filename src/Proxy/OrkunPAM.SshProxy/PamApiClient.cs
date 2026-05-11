using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace OrkunPAM.SshProxy;

/// <summary>
/// Calls the OrkunPAM WebAPI to validate users and retrieve target credentials.
/// </summary>
internal sealed class PamApiClient
{
    private readonly IHttpClientFactory _factory;
    private readonly ILogger<PamApiClient> _log;
    private readonly string _proxySecret;

    public PamApiClient(IHttpClientFactory factory, ILogger<PamApiClient> log, IConfiguration config)
    {
        _factory = factory;
        _log = log;
        _proxySecret = config["PamApi:ProxySecret"] ?? "changeme";
    }

    internal async Task<bool> ValidateUserAsync(string username, string password, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { username, password, mfaCode = (string?)null }, ct);
            return resp.IsSuccessStatusCode;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to validate user '{User}'", username);
            return false;
        }
    }

    internal async Task<(string ip, int port, string user, string password)>
        GetTargetCredentialAsync(string pamUser, string targetHost, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");

            // Login as proxy service account
            var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { username = "proxy-service", password = _proxySecret, mfaCode = (string?)null }, ct);

            if (!loginResp.IsSuccessStatusCode)
                return (targetHost, 22, "root", "");

            var loginData = await loginResp.Content.ReadFromJsonAsync<LoginResponse>(ct);
            var jwt = loginData?.Data?.Token;
            if (jwt == null) return (targetHost, 22, "root", "");

            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

            // Find device by hostname/IP
            var devResp = await client.GetAsync(
                $"/api/v1/devices?search={Uri.EscapeDataString(targetHost)}&pageSize=1", ct);

            if (!devResp.IsSuccessStatusCode) return (targetHost, 22, "root", "");

            var devData = await devResp.Content.ReadFromJsonAsync<DeviceListResponse>(ct);
            var device = devData?.Data?.FirstOrDefault();
            if (device == null) return (targetHost, 22, "root", "");

            // Get first SSH credential for this device
            var credResp = await client.GetAsync(
                $"/api/v1/vault/credentials?deviceId={device.Id}&pageSize=1", ct);

            if (!credResp.IsSuccessStatusCode)
                return (device.IpAddress ?? targetHost, device.ConnectionPort ?? 22, "root", "");

            var credData = await credResp.Content.ReadFromJsonAsync<CredentialListResponse>(ct);
            var cred = credData?.Data?.FirstOrDefault();
            if (cred == null)
                return (device.IpAddress ?? targetHost, device.ConnectionPort ?? 22, "root", "");

            // Decrypt credential via proxy endpoint
            var decryptResp = await client.PostAsJsonAsync("/api/v1/vault/credentials/proxy-decrypt",
                new { credentialId = cred.Id }, ct);

            if (!decryptResp.IsSuccessStatusCode)
                return (device.IpAddress ?? targetHost, device.ConnectionPort ?? 22, cred.Username ?? "root", "");

            var decryptData = await decryptResp.Content.ReadFromJsonAsync<DecryptResponse>(ct);

            return (
                device.IpAddress ?? targetHost,
                device.ConnectionPort ?? 22,
                cred.Username ?? "root",
                decryptData?.Data?.Password ?? "");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to get target credential for {Host}", targetHost);
            return (targetHost, 22, "root", "");
        }
    }

    private record LoginResponse(LoginData? Data);
    private record LoginData(string Token);
    private record DeviceListResponse(IEnumerable<DeviceDto>? Data);
    private record DeviceDto(string Id, string? IpAddress, string? Hostname, int? ConnectionPort);
    private record CredentialListResponse(IEnumerable<CredentialDto>? Data);
    private record CredentialDto(string Id, string? Username);
    private record DecryptResponse(DecryptData? Data);
    private record DecryptData(string Password);
}
