using System.Net.Http.Json;

namespace OrkunPAM.SqlProxy;

/// <summary>
/// Calls the OrkunPAM WebAPI to authenticate PAM users and retrieve vault credentials
/// for target SQL Server instances.
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

        // Reject empty or known placeholder values — deployment with default fails fast at startup
        if (string.IsNullOrWhiteSpace(_proxySecret) ||
            _proxySecret.Equals("changeme-generate-with-openssl-rand-base64-32", StringComparison.Ordinal))
            throw new InvalidOperationException(
                "PamApi:ProxySecret is not configured or uses a known default. " +
                "Generate with: openssl rand -base64 32");

        if (_proxySecret.Length < 32)
            throw new InvalidOperationException(
                "PamApi:ProxySecret must be at least 32 characters. Generate with: openssl rand -base64 32");
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
    /// Look up a SQL Server device by hostname/IP and return vault SQL credentials.
    /// Returns (targetIp, targetPort, sqlUsername, sqlPassword).
    /// Throws <see cref="InvalidOperationException"/> on failure — caller must close session.
    /// </summary>
    internal async Task<(string ip, int port, string sqlUser, string sqlPassword)>
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
                var loginData = await loginResp.Content.ReadFromJsonAsync<LoginResponse>(ct);
                jwt = loginData?.Data?.Token;
            }

            if (jwt == null)
            {
                _log.LogError("Proxy service account login failed — aborting SQL session for {Host}", targetHost);
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
                throw new InvalidOperationException($"No device found for SQL host '{targetHost}'");

            var credResp = await client.GetAsync(
                $"/api/v1/vault/credentials?deviceId={device.Id}&credentialType=SqlServer&pageSize=1", ct);

            if (!credResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"SQL credential lookup failed for device '{device.Id}' (HTTP {(int)credResp.StatusCode})");

            var credData = await credResp.Content.ReadFromJsonAsync<CredentialListResponse>(ct);
            var cred = credData?.Data?.FirstOrDefault();

            if (cred == null)
                throw new InvalidOperationException($"No SQL credential found for device '{device.Id}'");

            using var decryptReq = new HttpRequestMessage(HttpMethod.Post,
                "/api/v1/vault/credentials/proxy-decrypt");
            decryptReq.Content = JsonContent.Create(new { credentialId = cred.Id, purpose = "SqlProxy" });
            decryptReq.Headers.Add("X-Proxy-Secret", _proxySecret);
            var decryptResp = await client.SendAsync(decryptReq, ct);

            if (!decryptResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Credential decryption failed for '{cred.Id}' (HTTP {(int)decryptResp.StatusCode})");

            var decryptData = await decryptResp.Content.ReadFromJsonAsync<DecryptResponse>(ct);
            var sqlPassword = decryptData?.Data?.Password;

            if (string.IsNullOrEmpty(sqlPassword))
                throw new InvalidOperationException($"Decrypted SQL credential has no password for '{cred.Id}'");

            var sqlUser = cred.Username
                ?? throw new InvalidOperationException("SQL credential has no username");

            return (
                device.IpAddress ?? targetHost,
                device.ConnectionPort ?? 1433,
                sqlUser,
                sqlPassword);
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Unexpected error retrieving SQL credential for {Host}", targetHost);
            throw new InvalidOperationException($"Failed to retrieve SQL credential for '{targetHost}'", ex);
        }
    }

    /// <summary>Reports that a SQL session has ended.</summary>
    internal async Task ReportSessionEndedAsync(string sessionId, int durationSeconds, string logPath, CancellationToken ct)
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
            req.Content = JsonContent.Create(new { durationSeconds, recordingPath = logPath });
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            await client.SendAsync(req, ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to report SQL session end for {SessionId}", sessionId);
        }
    }

    /// <summary>Returns (IdleTimeoutMinutes, MaxConcurrentSessions) from global session policy. Falls back to safe defaults.</summary>
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

    // Response DTOs
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
