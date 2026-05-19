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

    /// <summary>Validate PAM username + password bytes. Returns (isValid, userId).</summary>
    internal async Task<(bool Valid, string? UserId)> ValidateUserAsync(string username, byte[] passwordBytes, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            // String is unavoidably on managed heap during JSON serialization; byte[] is zeroed by caller.
            var password = System.Text.Encoding.UTF8.GetString(passwordBytes);
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { username, password, mfaCode = (string?)null }, ct);

            if (!resp.IsSuccessStatusCode) return (false, null);

            var json = await resp.Content.ReadFromJsonAsync<LoginResponse>(ct);
            var userId = json?.Data?.UserId;
            return (true, userId);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to validate user '{User}' against PAM API", username);
            return (false, null);
        }
    }

    /// <summary>
    /// Look up a device by hostname/IP and return the SSH credential for it.
    /// Also returns the stored SSH host key fingerprint (null = first connection, TOFU applies) and deviceId.
    /// Throws InvalidOperationException on any failure -- caller must close session (fail-closed).
    /// </summary>
    internal async Task<(string ip, int port, string user, byte[] password, string? privateKey, string? expectedFingerprint, string deviceId, string credentialId)>
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
                _log.LogError("Proxy service account login failed -- aborting session for {Host}", targetHost);
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

            // Decrypt via dedicated proxy endpoint -- also sends X-Proxy-Secret for defense-in-depth
            using var decryptReq = new HttpRequestMessage(HttpMethod.Post,
                "/api/v1/vault/credentials/proxy-decrypt");
            decryptReq.Content = JsonContent.Create(new { credentialId = cred.Id, purpose = "SshProxy" });
            decryptReq.Headers.Add("X-Proxy-Secret", _proxySecret);
            var decryptResp = await client.SendAsync(decryptReq, ct);

            if (!decryptResp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Credential decryption failed for '{cred.Id}' (HTTP {(int)decryptResp.StatusCode})");

            var decryptData = await decryptResp.Content.ReadFromJsonAsync<DecryptResponse>(ct);
            var password   = decryptData?.Data?.Password;
            var privateKey = decryptData?.Data?.PrivateKey;

            if (string.IsNullOrEmpty(password) && string.IsNullOrEmpty(privateKey))
                throw new InvalidOperationException($"Decrypted credential has neither password nor private key for '{cred.Id}'");

            // Convert password to byte[] immediately so callers can zero the buffer after use
            var passwordBytes = string.IsNullOrEmpty(password)
                ? []
                : System.Text.Encoding.UTF8.GetBytes(password);

            return (
                device.IpAddress ?? targetHost,
                device.ConnectionPort ?? 22,
                cred.Username ?? throw new InvalidOperationException("Credential has no username"),
                passwordBytes,
                string.IsNullOrEmpty(privateKey) ? null : privateKey,
                device.SshHostKeyFingerprint,
                device.Id,
                cred.Id);
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

    /// <summary>Returns (IdleTimeoutMinutes, MaxConcurrentSessions) from the global session policy. Falls back to safe defaults on any error.</summary>
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
                    return (p.IdleTimeoutMinutes > 0 ? p.IdleTimeoutMinutes : 30,
                            p.MaxConcurrentSessions > 0 ? p.MaxConcurrentSessions : 3);
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to fetch session policy -- using defaults (30 min idle)");
        }
        return (30, 3);
    }

    /// <summary>
    /// Returns the full session policy including command filter settings.
    /// Falls back to null (no filtering) on error.
    /// </summary>
    internal async Task<SessionPolicyInfo?> GetFullSessionPolicyAsync(CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var resp = await client.GetAsync("/api/v1/policy/session", ct);
            if (resp.IsSuccessStatusCode)
            {
                var data = await resp.Content.ReadFromJsonAsync<FullSessionPolicyResponse>(ct);
                var p = data?.Data;
                if (p != null)
                    return new SessionPolicyInfo(
                        p.IdleTimeoutMinutes,
                        p.MaxConcurrentSessions,
                        p.CommandFilterMode,
                        p.CommandFilterRulesJson,
                        p.DoubleConfirmRiskThreshold,
                        p.DoubleConfirmCommandsJson);
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to fetch full session policy -- command filtering disabled");
        }
        return null;
    }

    /// <summary>
    /// Store SSH host key fingerprint for a device (TOFU: first successful connection).
    /// Best-effort -- never throws, logs on failure.
    /// </summary>
    internal async Task StoreSshFingerprintAsync(string deviceId, string fingerprint, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            using var req = new HttpRequestMessage(HttpMethod.Post,
                $"/api/v1/devices/{deviceId}/ssh-fingerprint");
            req.Content = JsonContent.Create(new { fingerprint });
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            var resp = await client.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode)
                _log.LogWarning("StoreSshFingerprint: failed for device {DeviceId} (HTTP {Status})",
                    deviceId, (int)resp.StatusCode);
            else
                _log.LogInformation("TOFU: SSH host key fingerprint stored for device {DeviceId}: {Fp}",
                    deviceId, fingerprint);
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "StoreSshFingerprint: unexpected error for device {DeviceId}", deviceId);
        }
    }

    /// <summary>
    /// Fire-and-forget: send a live terminal chunk to the WebAPI for admin live monitoring.
    /// Never throws -- any failure is silently swallowed to not impact session performance.
    /// </summary>
    internal void SendLiveChunk(string sessionId, string text)
    {
        if (string.IsNullOrEmpty(text)) return;
        _ = Task.Run(async () =>
        {
            try
            {
                var client = _factory.CreateClient("PamApi");
                using var req = new HttpRequestMessage(HttpMethod.Post,
                    $"/api/v1/sessions/{sessionId}/live/chunk");
                req.Content = JsonContent.Create(new { text });
                req.Headers.Add("X-Proxy-Secret", _proxySecret);
                await client.SendAsync(req, CancellationToken.None).ConfigureAwait(false);
            }
            catch { /* best-effort: silently ignore */ }
        });
    }

    /// <summary>Register session start with the PAM WebAPI. Returns assigned session ID or null on failure.</summary>
    internal async Task<string?> StartSessionAsync(
        string? userId, string deviceId, string credentialId,
        string clientIp, string targetIp, int targetPort, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/ssh/proxy/session-start");
            req.Content = JsonContent.Create(new { userId, deviceId, credentialId, clientIp, targetIp, targetPort });
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

    /// <summary>Record session end. Best-effort — never throws.</summary>
    internal async Task EndSessionAsync(string sessionId, int durationSeconds, string? recordingPath)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/ssh/proxy/session-end");
            req.Content = JsonContent.Create(new { sessionId, durationSeconds, recordingPath });
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            await client.SendAsync(req, CancellationToken.None).ConfigureAwait(false);
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
                $"/api/v1/ssh/proxy/sessions/{sessionId}/status");
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            var resp = await client.SendAsync(req, ct);
            if (!resp.IsSuccessStatusCode) return false;
            var json = await resp.Content.ReadFromJsonAsync<System.Text.Json.JsonElement>(ct);
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
    private record DeviceDto(string Id, string? IpAddress, string? Hostname, int? ConnectionPort, string? SshHostKeyFingerprint);
    private record CredentialListResponse(IEnumerable<CredentialDto>? Data);
    private record CredentialDto(string Id, string? Username);
    private record DecryptResponse(DecryptData? Data);
    private record DecryptData(string? Password, string? PrivateKey);
    private record SessionStartResponse(SessionStartData? Data);
    private record SessionStartData(string SessionId);
    private record SessionPolicyResponse(bool Success, SessionPolicyData? Data);
    private record SessionPolicyData(int IdleTimeoutMinutes, int MaxConcurrentSessions);
    private record FullSessionPolicyResponse(bool Success, FullSessionPolicyData? Data);
    private record FullSessionPolicyData(
        int IdleTimeoutMinutes, int MaxConcurrentSessions,
        byte CommandFilterMode, string? CommandFilterRulesJson,
        decimal DoubleConfirmRiskThreshold, string? DoubleConfirmCommandsJson);
}

/// <summary>
/// Session policy info including command filter and double-confirmation configuration.
/// </summary>
internal sealed record SessionPolicyInfo(
    int IdleTimeoutMinutes,
    int MaxConcurrentSessions,
    byte CommandFilterMode,
    string? CommandFilterRulesJson,
    decimal DoubleConfirmRiskThreshold = 0,
    string? DoubleConfirmCommandsJson = null);
