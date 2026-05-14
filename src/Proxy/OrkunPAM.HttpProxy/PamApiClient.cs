using System.Net.Http.Json;

namespace OrkunPAM.HttpProxy;

/// <summary>
/// Calls the OrkunPAM WebAPI to validate session tokens and retrieve target credentials.
/// Used by the HTTP proxy to authenticate browser sessions and perform credential injection.
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

    /// <summary>
    /// Validates a session token issued by the PAM WebAPI when a user clicks "Connect".
    /// Returns session details on success, null on failure (fail-closed).
    /// </summary>
    internal async Task<HttpSessionInfo?> ValidateSessionTokenAsync(string sessionToken, CancellationToken ct)
    {
        try
        {
            var client = CreateAuthenticatedClient();

            // Get JWT for the proxy service account
            var jwt = await GetProxyJwtAsync(client, ct);
            if (jwt == null)
            {
                _log.LogError("Proxy service account login failed — cannot validate session token");
                return null;
            }

            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

            // Validate session token via dedicated proxy endpoint
            using var request = new HttpRequestMessage(HttpMethod.Post,
                "/api/v1/sessions/http/validate");
            request.Content = JsonContent.Create(new { sessionToken });
            request.Headers.Add("X-Proxy-Secret", _proxySecret);

            var resp = await client.SendAsync(request, ct);
            if (!resp.IsSuccessStatusCode)
            {
                _log.LogWarning("Session token validation failed (HTTP {Status})", (int)resp.StatusCode);
                return null;
            }

            var data = await resp.Content.ReadFromJsonAsync<ValidateSessionResponse>(ct);
            if (data?.Data == null)
            {
                _log.LogWarning("Session token validation returned empty data");
                return null;
            }

            var s = data.Data;
            return new HttpSessionInfo
            {
                SessionId = s.SessionId,
                TargetUrl = s.TargetUrl,
                Username = s.Username,
                CredentialId = s.CredentialId,
                AuthStrategy = Enum.TryParse<AuthStrategy>(s.AuthStrategy, true, out var strategy)
                    ? strategy : AuthStrategy.BasicAuth,
                CustomHeaders = s.CustomHeaders,
                FormLoginUrl = s.FormLoginUrl,
                FormUsernameField = s.FormUsernameField,
                FormPasswordField = s.FormPasswordField,
            };
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Unexpected error validating session token");
            return null;
        }
    }

    /// <summary>
    /// Decrypts credential from vault for the given credential ID.
    /// Returns password bytes (caller must zero after use). Throws on failure (fail-closed).
    /// </summary>
    internal async Task<(string username, byte[] password)> GetCredentialAsync(
        string credentialId, CancellationToken ct)
    {
        var client = CreateAuthenticatedClient();
        var jwt = await GetProxyJwtAsync(client, ct)
            ?? throw new InvalidOperationException("Proxy service account authentication failed");

        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);

        using var decryptReq = new HttpRequestMessage(HttpMethod.Post,
            "/api/v1/vault/credentials/proxy-decrypt");
        decryptReq.Content = JsonContent.Create(new { credentialId, purpose = "HttpProxy" });
        decryptReq.Headers.Add("X-Proxy-Secret", _proxySecret);

        var resp = await client.SendAsync(decryptReq, ct);
        if (!resp.IsSuccessStatusCode)
            throw new InvalidOperationException(
                $"Credential decryption failed for '{credentialId}' (HTTP {(int)resp.StatusCode})");

        var data = await resp.Content.ReadFromJsonAsync<DecryptResponse>(ct);
        var password = data?.Data?.Password;
        var username = data?.Data?.Username;

        if (string.IsNullOrEmpty(password))
            throw new InvalidOperationException($"Decrypted credential has no password for '{credentialId}'");

        var passwordBytes = System.Text.Encoding.UTF8.GetBytes(password);

        return (
            username ?? throw new InvalidOperationException("Credential has no username"),
            passwordBytes);
    }

    /// <summary>Returns (IdleTimeoutMinutes, MaxConcurrentSessions) from the global session policy.</summary>
    internal async Task<(int IdleTimeoutMinutes, int MaxConcurrentSessions)> GetSessionPolicyAsync(CancellationToken ct)
    {
        try
        {
            var client = CreateAuthenticatedClient();
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

    private HttpClient CreateAuthenticatedClient() => _factory.CreateClient("PamApi");

    private async Task<string?> GetProxyJwtAsync(HttpClient client, CancellationToken ct)
    {
        var loginResp = await client.PostAsJsonAsync("/api/v1/auth/login",
            new { username = "proxy-service", password = _proxySecret, mfaCode = (string?)null }, ct);

        if (!loginResp.IsSuccessStatusCode) return null;

        var loginData = await loginResp.Content.ReadFromJsonAsync<LoginResponse>(ct);
        return loginData?.Data?.Token;
    }

    // Response DTOs
    private record LoginResponse(LoginData? Data);
    private record LoginData(string Token);
    private record ValidateSessionResponse(bool Success, HttpSessionData? Data);
    private record HttpSessionData(
        string SessionId, string TargetUrl, string Username, string CredentialId,
        string AuthStrategy, Dictionary<string, string>? CustomHeaders,
        string? FormLoginUrl, string? FormUsernameField, string? FormPasswordField);
    private record DecryptResponse(DecryptData? Data);
    private record DecryptData(string? Username, string? Password);
    private record SessionPolicyResponse(bool Success, SessionPolicyData? Data);
    private record SessionPolicyData(int IdleTimeoutMinutes, int MaxConcurrentSessions);
}

/// <summary>Validated session information returned by the PAM API.</summary>
internal sealed class HttpSessionInfo
{
    public required string SessionId { get; init; }
    public required string TargetUrl { get; init; }
    public required string Username { get; init; }
    public required string CredentialId { get; init; }
    public AuthStrategy AuthStrategy { get; init; }
    public Dictionary<string, string>? CustomHeaders { get; init; }
    public string? FormLoginUrl { get; init; }
    public string? FormUsernameField { get; init; }
    public string? FormPasswordField { get; init; }
}

/// <summary>Authentication strategy for injecting credentials into proxied HTTP requests.</summary>
internal enum AuthStrategy
{
    BasicAuth,
    FormLogin,
    HeaderInjection,
    CookieReplay
}
