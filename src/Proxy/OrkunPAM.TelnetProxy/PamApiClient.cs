using System.Net.Http.Json;
using System.Text.Json;

namespace OrkunPAM.TelnetProxy;

/// <summary>HTTP client for calling the OrkunPAM Core API from the Telnet proxy.</summary>
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
        _proxySecret = config["PamApi:ProxySecret"]
            ?? throw new InvalidOperationException(
                "PamApi:ProxySecret is not configured. Set via environment variable or appsettings.");

        if (string.IsNullOrWhiteSpace(_proxySecret) ||
            _proxySecret.Equals("changeme-generate-with-openssl-rand-base64-32", StringComparison.Ordinal))
            throw new InvalidOperationException(
                "PamApi:ProxySecret is not configured or uses a known default. " +
                "Generate with: openssl rand -base64 32");

        if (_proxySecret.Length < 32)
            throw new InvalidOperationException(
                "PamApi:ProxySecret must be at least 32 characters.");
    }

    /// <summary>Validate PAM username + password. Returns (isValid, userId) tuple.</summary>
    internal async Task<(bool Valid, string? UserId)> ValidateUserAsync(
        string username, string password, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { username, password, mfaCode = (string?)null }, ct);

            if (!resp.IsSuccessStatusCode) return (false, null);

            var json = await resp.Content.ReadFromJsonAsync<LoginResponse>(ct);
            var userId = json?.Data?.UserId;
            return (!string.IsNullOrEmpty(userId), userId);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to validate user '{User}' against PAM API", username);
            return (false, null);
        }
    }

    /// <summary>
    /// Retrieve target device credential for Telnet session.
    /// Returns (targetIp, targetPort, credUser, passwordBytes, deviceId, credentialId).
    /// Throws InvalidOperationException on any failure (fail-closed policy).
    /// </summary>
    internal async Task<(string Ip, int Port, string CredUser, byte[] Password, string DeviceId, string CredentialId)>
        GetTargetCredentialAsync(string targetHost, CancellationToken ct)
    {
        var client = _factory.CreateClient("PamApi");

        // Authenticate proxy service account
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new { username = "proxy-service", password = _proxySecret, mfaCode = (string?)null }, ct);

        if (!loginResp.IsSuccessStatusCode)
            throw new InvalidOperationException("Proxy service account authentication failed");

        var loginData = await loginResp.Content.ReadFromJsonAsync<LoginResponse>(ct);
        var jwt = loginData?.Data?.Token
            ?? throw new InvalidOperationException("Proxy service account returned no JWT");

        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        // Device lookup
        var devResp = await client.GetAsync(
            $"/api/v1/devices?search={Uri.EscapeDataString(targetHost)}&pageSize=1", ct);

        if (!devResp.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Device lookup failed for '{targetHost}' (HTTP {(int)devResp.StatusCode})");

        var devData = await devResp.Content.ReadFromJsonAsync<DeviceListResponse>(ct);
        var device = devData?.Data?.FirstOrDefault()
            ?? throw new InvalidOperationException($"No device found for host '{targetHost}'");

        // Credential lookup — prefer Telnet type, fall back to UserPassword
        var credResp = await client.GetAsync(
            $"/api/v1/vault/credentials?deviceId={device.Id}&credentialType=Telnet&pageSize=1", ct);

        CredentialDto? cred = null;
        if (credResp.IsSuccessStatusCode)
        {
            var credData = await credResp.Content.ReadFromJsonAsync<CredentialListResponse>(ct);
            cred = credData?.Data?.FirstOrDefault();
        }

        if (cred == null)
        {
            credResp = await client.GetAsync(
                $"/api/v1/vault/credentials?deviceId={device.Id}&credentialType=UserPassword&pageSize=1", ct);

            if (!credResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Credential lookup failed for device '{device.Id}' (HTTP {(int)credResp.StatusCode})");

            var credData = await credResp.Content.ReadFromJsonAsync<CredentialListResponse>(ct);
            cred = credData?.Data?.FirstOrDefault()
                ?? throw new InvalidOperationException($"No credential found for device '{device.Id}'");
        }

        // Decrypt credential
        using var decryptReq = new HttpRequestMessage(HttpMethod.Post,
            "/api/v1/vault/credentials/proxy-decrypt");
        decryptReq.Content = JsonContent.Create(new { credentialId = cred.Id, purpose = "TelnetProxy" });
        decryptReq.Headers.Add("X-Proxy-Secret", _proxySecret);
        var decryptResp = await client.SendAsync(decryptReq, ct);

        if (!decryptResp.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Credential decryption failed for '{cred.Id}' (HTTP {(int)decryptResp.StatusCode})");

        var decryptData = await decryptResp.Content.ReadFromJsonAsync<DecryptResponse>(ct);
        var password = decryptData?.Data?.Password
            ?? throw new InvalidOperationException($"Decrypted credential has no password for '{cred.Id}'");

        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        return (
            device.IpAddress ?? targetHost,
            device.ConnectionPort ?? 23,
            cred.Username ?? "admin",
            passwordBytes,
            device.Id,
            cred.Id);
    }

    /// <summary>Register session start. Returns assigned session ID or null on failure.</summary>
    internal async Task<string?> StartSessionAsync(
        string userId, string deviceId, string credentialId,
        string clientIp, string targetIp, int targetPort, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/telnet/proxy/session-start");
            req.Content = JsonContent.Create(new
            {
                userId, deviceId, credentialId, clientIp, targetIp, targetPort,
                sessionType = "Telnet"
            });
            req.Headers.Add("X-Proxy-Secret", _proxySecret);

            var resp = await client.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode) return null;

            var json = await resp.Content.ReadFromJsonAsync<SessionStartResponse>(ct);
            return json?.Data?.SessionId;
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "StartSession API call failed (non-fatal)");
            return null;
        }
    }

    /// <summary>Record session end and upload compressed recording. Best-effort.</summary>
    internal async Task EndSessionAsync(
        string sessionId, int durationSeconds, byte[] recordingData, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/telnet/proxy/session-end");
            req.Content = JsonContent.Create(new
            {
                sessionId,
                durationSeconds,
                recordingBase64 = Convert.ToBase64String(recordingData)
            });
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            await client.SendAsync(req, ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "EndSession API call failed for session {SessionId} (non-fatal)", sessionId);
        }
    }

    /// <summary>Check if an admin has terminated this session via the UI.</summary>
    internal async Task<bool> IsTerminatedAsync(string sessionId, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            using var req = new HttpRequestMessage(HttpMethod.Get,
                $"/api/v1/telnet/proxy/sessions/{sessionId}/status");
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            var resp = await client.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode) return false;
            var json = await resp.Content.ReadFromJsonAsync<JsonElement>(ct);
            return json.TryGetProperty("data", out var d) &&
                   d.TryGetProperty("terminated", out var t) && t.GetBoolean();
        }
        catch
        {
            return false;
        }
    }

    // Response DTOs
    private record LoginResponse(LoginData? Data);
    private record LoginData(string? Token, string? UserId);
    private record DeviceListResponse(IEnumerable<DeviceDto>? Data);
    private record DeviceDto(string Id, string? IpAddress, string? Hostname, int? ConnectionPort);
    private record CredentialListResponse(IEnumerable<CredentialDto>? Data);
    private record CredentialDto(string Id, string? Username);
    private record DecryptResponse(DecryptData? Data);
    private record DecryptData(string? Password);
    private record SessionStartResponse(SessionStartData? Data);
    private record SessionStartData(string SessionId);
}
