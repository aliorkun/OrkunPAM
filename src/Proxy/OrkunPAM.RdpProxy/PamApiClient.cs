using System.Net.Http.Json;

namespace OrkunPAM.RdpProxy;

/// <summary>
/// Calls the OrkunPAM WebAPI to validate session tokens and retrieve target credentials.
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

        if (_proxySecret.Length < 32)
            throw new InvalidOperationException(
                "PamApi:ProxySecret must be at least 32 characters.");
    }

    /// <summary>
    /// Validates an RDP session token and returns target connection info + credentials.
    /// Throws <see cref="InvalidOperationException"/> on failure — caller must close connection (fail-closed).
    /// </summary>
    internal async Task<RdpSessionInfo> ValidateSessionTokenAsync(string sessionToken, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");

            // Authenticate as proxy service account to get a JWT
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
                _log.LogError("Proxy service account login failed — cannot validate session token {Token}", sessionToken[..8]);
                throw new InvalidOperationException("Proxy service account authentication failed");
            }

            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

            // Validate the RDP session token
            using var req = new HttpRequestMessage(HttpMethod.Post, "/api/v1/sessions/rdp/validate-token");
            req.Content = JsonContent.Create(new { sessionToken });
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            var resp = await client.SendAsync(req, ct);

            if (!resp.IsSuccessStatusCode)
                throw new InvalidOperationException(
                    $"Session token validation failed (HTTP {(int)resp.StatusCode})");

            var result = await resp.Content.ReadFromJsonAsync<SessionTokenResponse>(ct);
            var info = result?.Data;

            if (info == null || string.IsNullOrEmpty(info.TargetIp))
                throw new InvalidOperationException("Invalid session token response");

            return info;
        }
        catch (InvalidOperationException)
        {
            throw;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Unexpected error validating session token");
            throw new InvalidOperationException("Session token validation failed", ex);
        }
    }

    /// <summary>Reports that a session has ended so the WebAPI can update session status.</summary>
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
            _log.LogWarning(ex, "Failed to report session end for {SessionId}", sessionId);
        }
    }

    /// <summary>Check if an admin has terminated this RDP session via the UI.</summary>
    internal async Task<bool> IsTerminatedAsync(string sessionId, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            using var req = new HttpRequestMessage(HttpMethod.Get,
                $"/api/v1/rdp/proxy/sessions/{sessionId}/status");
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
            _log.LogWarning(ex, "Failed to fetch session policy — using defaults (30 min idle)");
        }
        return (30, 3);
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
                sessionType = "RDP"
            });
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            await client.SendAsync(req, ct);
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Failed to report RDP screen capture for session {SessionId} frame {FrameIndex}",
                sessionId, frameIndex);
        }
    }

    /// <summary>Returns peripheral channel permissions. Falls back to secure defaults (block clipboard/drive/USB/audio) on any error.</summary>
    internal async Task<PeripheralPolicy> GetPeripheralPolicyAsync(Guid? deviceGroupId, CancellationToken ct)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var url = deviceGroupId.HasValue
                ? $"/api/v1/policies/peripheral/effective?deviceGroupId={deviceGroupId}"
                : "/api/v1/policies/peripheral/effective";
            using var req = new HttpRequestMessage(HttpMethod.Get, url);
            req.Headers.Add("X-Proxy-Secret", _proxySecret);
            var resp = await client.SendAsync(req, ct);
            if (resp.IsSuccessStatusCode)
            {
                var data = await resp.Content.ReadFromJsonAsync<PeripheralPolicyResponse>(ct);
                var p = data?.Data;
                if (p != null)
                    return new PeripheralPolicy(
                        p.AllowClipboard, p.AllowDriveRedirection,
                        p.AllowPrinterRedirection, p.AllowUsbRedirection,
                        p.AllowAudioRedirection, p.AllowSmartCardRedirection);
            }
        }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "Failed to fetch peripheral policy — using secure defaults");
        }
        // Secure defaults: block clipboard/drive/USB/audio, allow printer+smartcard
        return new PeripheralPolicy(false, false, true, false, false, true);
    }

    // ---- Response DTOs ----
    private record LoginResponse(LoginData? Data);
    private record LoginData(string Token);
    private record SessionTokenResponse(RdpSessionInfo? Data);
    private record SessionPolicyResponse(bool Success, SessionPolicyData? Data);
    private record SessionPolicyData(int IdleTimeoutMinutes, int MaxConcurrentSessions);
    private record PeripheralPolicyResponse(bool Success, PeripheralPolicyData? Data);
    private record PeripheralPolicyData(
        bool AllowClipboard, bool AllowDriveRedirection, bool AllowPrinterRedirection,
        bool AllowUsbRedirection, bool AllowAudioRedirection, bool AllowSmartCardRedirection);
}

internal sealed record PeripheralPolicy(
    bool AllowClipboard,
    bool AllowDriveRedirection,
    bool AllowPrinterRedirection,
    bool AllowUsbRedirection,
    bool AllowAudioRedirection,
    bool AllowSmartCardRedirection);

internal sealed record RdpSessionInfo(
    string SessionId,
    string TargetIp,
    int TargetPort,
    string TargetUsername,
    byte[] TargetPasswordBytes,
    string? TargetDomain);
