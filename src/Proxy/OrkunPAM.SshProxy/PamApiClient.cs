using System.Net.Http.Json;
using Microsoft.Extensions.Options;

namespace OrkunPAM.SshProxy;

/// <summary>
/// Calls the OrkunPAM WebAPI to validate users and retrieve target credentials.
/// Used by the SSH proxy to authenticate PAM users and perform credential injection.
/// </summary>
internal sealed class PamApiClient
{
    private readonly IHttpClientFactory _factory;
    private readonly ILogger<PamApiClient> _log;
    private readonly string _proxySecret;

    public PamApiClient(IHttpClientFactory factory, ILogger<PamApiClient> log,
        IConfiguration config)
    {
        _factory = factory;
        _log = log;
        _proxySecret = config["PamApi:ProxySecret"] ?? "changeme-in-production";
    }

    /// <summary>Validate PAM username + password. Returns true if valid.</summary>
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
            _log.LogError(ex, "Failed to validate user '{User}' against PAM API", username);
            return false;
        }
    }

    /// <summary>
    /// Look up a device by hostname/IP and return the SSH credential for it.
    /// Throws InvalidOperationException on any failure — caller must close session (fail-closed).
    /// </summary>
    internal async Task<(string ip, int port, string user, string password)>
        GetTargetCredentialAsync(string pamUser, string targetHost, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");

            // Get JWT for the proxy service account
            var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { username = "proxy-service", password = _proxySecret, mfaCode = (string?)null }, ct);

            string? jwt = null;
            if (loginResp.IsSuccessStatusCode)
            {
                var loginData = await loginResp.Content.ReadFromJsonAsync<LoginResponse>(ct);
                jwt = loginData?.Data?.Token;
            }

            if (jwt == null)
            {
                _log.LogError("Proxy service account login failed — aborting session for {Host}", targetHost);
                throw new InvalidOperationException("Proxy service account authentication failed");
            }

            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

            // Look up device by hostname/IP
            var devResp = await client.GetAsync(
                $"/api/v1/devices?search={Uri.EscapeDataString(targetHost)}&pageSize=1", ct);

            if (!devResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Device lookup failed for '{targetHost}' (HTTP {(int)devResp.StatusCode})");

            var devData = await devResp.Content.ReadFromJsonAsync<DeviceListResponse>(ct);
            var device = devData?.Data?.FirstOrDefault();

            if (device == null)
                throw new InvalidOperationException($"No device found for host '{targetHost}'");

            // Get the first SSH credential for this device
            var credResp = await client.GetAsync(
                $"/api/v1/vault/credentials?deviceId={device.Id}&credentialType=Ssh&pageSize=1", ct);

            if (!credResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Credential lookup failed for device '{device.Id}' (HTTP {(int)credResp.StatusCode})");

            var credData = await credResp.Content.ReadFromJsonAsync<CredentialListResponse>(ct);
            var cred = credData?.Data?.FirstOrDefault();

            if (cred == null)
                throw new InvalidOperationException($"No SSH credential found for device '{device.Id}'");

            // Decrypt via dedicated proxy endpoint — also sends X-Proxy-Secret for defense-in-depth
            using var decryptReq = new HttpRequestMessage(HttpMethod.Post,
                "/api/v1/vault/credentials/proxy-decrypt");
            decryptReq.Content = JsonContent.Create(new { credentialId = cred.Id, purpose = "SshProxy" });
            decryptReq.Headers.Add("X-Proxy-Secret", _proxySecret);
            var decryptResp = await client.SendAsync(decryptReq, ct);

            if (!decryptResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Credential decryption failed for '{cred.Id}' (HTTP {(int)decryptResp.StatusCode})");

            var decryptData = await decryptResp.Content.ReadFromJsonAsync<DecryptResponse>(ct);
            var password = decryptData?.Data?.Password;

            if (string.IsNullOrEmpty(password))
                throw new InvalidOperationException($"Decrypted credential is empty for '{cred.Id}'");

            return (
                device.IpAddress ?? targetHost,
                device.ConnectionPort ?? 22,
                cred.Username ?? throw new InvalidOperationException("Credential has no username"),
                password);
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Unexpected error retrieving credential for {Host}", targetHost);
            throw new InvalidOperationException($"Failed to retrieve credential for '{targetHost}'", ex);
        }
    }

    // Response DTOs
    private record LoginResponse(LoginData? Data);
    private record LoginData(string Token);
    private record DeviceListResponse(IEnumerable<DeviceDto>? Data);
    private record DeviceDto(string Id, string? IpAddress, string? Hostname, int? ConnectionPort);
    private record CredentialListResponse(IEnumerable<CredentialDto>? Data);
    private record CredentialDto(string Id, string? Username);
    private record DecryptResponse(DecryptData? Data);
    private record DecryptData(string Password);
}
