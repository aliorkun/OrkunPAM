using System.Net.Http.Json;

namespace OrkunPAM.VncProxy;

/// <summary>
/// Calls the OrkunPAM WebAPI to authenticate PAM users and retrieve vault VNC credentials.
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
        _proxySecret = config["PamApi:ProxySecret"]
            ?? throw new InvalidOperationException(
                "PamApi:ProxySecret is not configured. Set via environment variable PAM_PROXY_SECRET or appsettings.");

        if (string.IsNullOrWhiteSpace(_proxySecret) ||
            _proxySecret.Equals("changeme-generate-with-openssl-rand-base64-32", StringComparison.Ordinal))
            throw new InvalidOperationException(
                "PamApi:ProxySecret is not configured or uses a known default. " +
                "Generate with: openssl rand -base64 32");

        if (_proxySecret.Length < 32)
            throw new InvalidOperationException(
                "PamApi:ProxySecret must be at least 32 characters. Generate with: openssl rand -base64 32");
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
            _log.LogError(ex, "Failed to validate user '{User}' against PAM API", username);
            return false;
        }
    }

    internal async Task<(string ip, int port, string vncPassword)>
        GetTargetCredentialAsync(string pamUser, string targetHost, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");

            var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { username = "proxy-service", password = _proxySecret, mfaCode = (string?)null }, ct);

            string? jwt = null;
            if (loginResp.IsSuccessStatusCode)
            {
                var data = await loginResp.Content.ReadFromJsonAsync<LoginResponse>(ct);
                jwt = data?.Data?.Token;
            }

            if (jwt == null)
            {
                _log.LogError("Proxy service account login failed — aborting VNC session for {Host}", targetHost);
                throw new InvalidOperationException("Proxy service account authentication failed");
            }

            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

            var devResp = await client.GetAsync(
                $"/api/v1/devices?search={Uri.EscapeDataString(targetHost)}&pageSize=1", ct);

            if (!devResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Device lookup failed for '{targetHost}' (HTTP {(int)devResp.StatusCode})");

            var devData = await devResp.Content.ReadFromJsonAsync<DeviceListResponse>(ct);
            var device = devData?.Data?.FirstOrDefault();

            if (device == null)
                throw new InvalidOperationException($"No device found for VNC host '{targetHost}'");

            var credResp = await client.GetAsync(
                $"/api/v1/vault/credentials?deviceId={device.Id}&credentialType=Vnc&pageSize=1", ct);

            if (!credResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"VNC credential lookup failed for device '{device.Id}' (HTTP {(int)credResp.StatusCode})");

            var credData = await credResp.Content.ReadFromJsonAsync<CredentialListResponse>(ct);
            var cred = credData?.Data?.FirstOrDefault();

            if (cred == null)
                throw new InvalidOperationException($"No VNC credential found for device '{device.Id}'");

            using var decryptReq = new HttpRequestMessage(HttpMethod.Post,
                "/api/v1/vault/credentials/proxy-decrypt");
            decryptReq.Content = JsonContent.Create(new { credentialId = cred.Id, purpose = "VncProxy" });
            decryptReq.Headers.Add("X-Proxy-Secret", _proxySecret);
            var decryptResp = await client.SendAsync(decryptReq, ct);

            if (!decryptResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Credential decryption failed for '{cred.Id}' (HTTP {(int)decryptResp.StatusCode})");

            var decryptData = await decryptResp.Content.ReadFromJsonAsync<DecryptResponse>(ct);
            var vncPassword = decryptData?.Data?.Password
                ?? throw new InvalidOperationException($"Decrypted VNC credential has no password for '{cred.Id}'");

            return (
                device.IpAddress ?? targetHost,
                device.ConnectionPort ?? 5900,
                vncPassword);
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Unexpected error retrieving VNC credential for {Host}", targetHost);
            throw new InvalidOperationException($"Failed to retrieve VNC credential for '{targetHost}'", ex);
        }
    }

    internal async Task ReportSessionEndedAsync(string sessionId, int durationSeconds, string recordingPath, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { username = "proxy-service", password = _proxySecret, mfaCode = (string?)null }, ct);

            string? jwt = null;
            if (loginResp.IsSuccessStatusCode)
            {
                var data = await loginResp.Content.ReadFromJsonAsync<LoginResponse>(ct);
                jwt = data?.Data?.Token;
            }

            if (jwt == null) return;

            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

            using var req = new HttpRequestMessage(HttpMethod.Post, $"/api/v1/sessions/{sessionId}/end");
            req.Content = JsonContent.Create(new { durationSeconds, recordingPath });
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            await client.SendAsync(req, ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to report VNC session end for {SessionId}", sessionId);
        }
    }

    internal async Task ReportScreenCaptureAsync(
        string sessionId, int frameIndex, int? width, int? height, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/sessions/screen-captures");
            req.Content = JsonContent.Create(new
            {
                sessionId,
                frameIndex,
                capturedAtUtc = DateTime.UtcNow,
                width,
                height,
                dataBase64 = (string?)null,
                sessionType = "VNC"
            });
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            await client.SendAsync(req, ct);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Failed to report VNC screen capture for session {SessionId} frame {FrameIndex}",
                sessionId, frameIndex);
        }
    }

    internal async Task<(int IdleTimeoutMinutes, int MaxConcurrentSessions)> GetSessionPolicyAsync(CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var resp = await client.GetAsync("/api/v1/policy/session", ct);
            if (resp.IsSuccessStatusCode)
            {
                var data = await resp.Content.ReadFromJsonAsync<SessionPolicyResponse>(ct);
                var p = data?.Data;
                if (p != null)
                    return (p.IdleTimeoutMinutes > 0 ? p.IdleTimeoutMinutes : 60,
                            p.MaxConcurrentSessions > 0 ? p.MaxConcurrentSessions : 3);
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to fetch session policy — using defaults (60 min idle)");
        }
        return (60, 3);
    }

    private record LoginResponse(LoginData? Data);
    private record LoginData(string Token);
    private record DeviceListResponse(IEnumerable<DeviceDto>? Data);
    private record DeviceDto(string Id, string? IpAddress, string? Hostname, int? ConnectionPort);
    private record CredentialListResponse(IEnumerable<CredentialDto>? Data);
    private record CredentialDto(string Id, string? Username);
    private record DecryptResponse(DecryptData? Data);
    private record DecryptData(string? Password);
    private record SessionPolicyResponse(bool Success, SessionPolicyData? Data);
    private record SessionPolicyData(int IdleTimeoutMinutes, int MaxConcurrentSessions);
}
