using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Text.RegularExpressions;
using OrkunPAM.HttpProxy.Session;

namespace OrkunPAM.HttpProxy;

/// <summary>
/// Per-session HTTP reverse proxy handler. Receives requests from the user's browser,
/// injects credentials, forwards to the target web console, rewrites URLs in responses,
/// and records all exchanges.
///
/// Lifecycle:
///   1. User clicks "Connect" in Blazor UI → PAM creates session token
///   2. Browser redirects to https://pam:8443/session/{token}
///   3. This handler validates the token, loads target + credentials
///   4. All subsequent requests under /proxy/{sessionId}/* are forwarded to the target
/// </summary>
internal sealed class HttpProxySession : IDisposable
{
    private readonly HttpSessionInfo _session;
    private readonly ICredentialInjector _injector;
    private readonly HttpClient _upstreamClient;
    private readonly HttpSessionRecorder _recorder;
    private readonly HttpProxyOptions _opts;
    private readonly ILogger _log;

    private string _username = "";
    private byte[] _password = [];
    private DateTime _lastActivityUtc = DateTime.UtcNow;
    private bool _disposed;

    // Per-session rate limiter
    private int _requestCount;
    private DateTimeOffset _rateLimitWindowStart = DateTimeOffset.UtcNow;

    /// <summary>Session ID for URL routing (e.g., /proxy/{SessionId}/*).</summary>
    internal string SessionId => _session.SessionId;

    /// <summary>UTC time of last request — used for idle timeout enforcement.</summary>
    internal DateTime LastActivityUtc => _lastActivityUtc;

    internal HttpProxySession(
        HttpSessionInfo session,
        ICredentialInjector injector,
        HttpProxyOptions opts,
        ILogger log,
        HashChainStore? hashChain)
    {
        _session  = session;
        _injector = injector;
        _opts     = opts;
        _log      = log;

        _recorder = new HttpSessionRecorder(opts.RecordingDirectory, log, hashChain);

        // Create a dedicated HttpClient for upstream calls to the target
        var handler = new HttpClientHandler
        {
            AllowAutoRedirect = false, // We handle redirects ourselves to rewrite URLs
            UseCookies = false,        // Cookie management is handled by the injector
            AutomaticDecompression = DecompressionMethods.None, // Preserve encoding for passthrough
        };

        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

        _upstreamClient = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(120),
        };
    }

    /// <summary>Initialize session: load credentials from vault.</summary>
    internal async Task InitializeAsync(PamApiClient api, CancellationToken ct)
    {
        var (username, password) = await api.GetCredentialAsync(_session.CredentialId, ct);
        _username = username;
        _password = password;
        _recorder.Start(_session.SessionId);
        _log.LogInformation("HTTP proxy session {SessionId} initialized for target {Target}",
            _session.SessionId, _session.TargetUrl);
    }

    /// <summary>
    /// Proxies a single HTTP request from the browser to the target and returns the response.
    /// This is the core proxy loop entry point, called for each request under /proxy/{sessionId}/*.
    /// </summary>
    internal async Task<ProxyResponse> HandleRequestAsync(
        string method, string relativePath, string queryString,
        Dictionary<string, string> requestHeaders,
        byte[]? requestBody,
        CancellationToken ct)
    {
        if (_disposed)
            return ProxyResponse.Error(502, "Session has been terminated");

        // Rate limiting
        if (IsRateLimited())
            return ProxyResponse.Error(429, "Too many requests — rate limit exceeded");

        _lastActivityUtc = DateTime.UtcNow;

        // Check blocked URL patterns
        var fullPath = $"{relativePath}{queryString}";
        if (IsBlocked(fullPath))
        {
            _log.LogWarning("Blocked URL pattern matched: {Path} in session {SessionId}",
                fullPath, _session.SessionId);
            return ProxyResponse.Error(403, "Access to this URL is blocked by policy");
        }

        try
        {
            // Build the upstream URL
            var targetBase = _session.TargetUrl.TrimEnd('/');
            var targetUrl = string.IsNullOrEmpty(relativePath) || relativePath == "/"
                ? targetBase + queryString
                : $"{targetBase}/{relativePath.TrimStart('/')}{queryString}";

            // Create the upstream request
            var upstreamReq = new HttpRequestMessage(new HttpMethod(method), targetUrl);

            // Copy safe headers from the browser request
            foreach (var (key, value) in requestHeaders)
            {
                if (IsHopByHopHeader(key)) continue;
                if (key.Equals("Host", StringComparison.OrdinalIgnoreCase)) continue;
                upstreamReq.Headers.TryAddWithoutValidation(key, value);
            }

            // Set the correct Host header for the target
            var targetUri = new Uri(targetUrl);
            upstreamReq.Headers.Host = targetUri.Authority;

            // Attach request body
            if (requestBody != null && requestBody.Length > 0)
            {
                upstreamReq.Content = new ByteArrayContent(requestBody);
                if (requestHeaders.TryGetValue("Content-Type", out var contentType))
                    upstreamReq.Content.Headers.TryAddWithoutValidation("Content-Type", contentType);
            }

            // Inject credentials via the configured strategy
            var injected = await _injector.InjectAsync(upstreamReq, _session, _username, _password, ct);
            if (!injected)
            {
                _log.LogWarning("Credential injection failed for session {SessionId}", _session.SessionId);
                return ProxyResponse.Error(502, "Authentication to target failed");
            }

            // Send to target
            var upstreamResp = await _upstreamClient.SendAsync(upstreamReq, ct);

            // Let the injector process the response (capture cookies, etc.)
            await _injector.ProcessResponseAsync(upstreamResp, _session, ct);

            // Read response body
            var responseBody = await upstreamResp.Content.ReadAsByteArrayAsync(ct);

            // Collect response headers
            var responseHeaders = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var h in upstreamResp.Headers)
                responseHeaders[h.Key] = string.Join(", ", h.Value);
            foreach (var h in upstreamResp.Content.Headers)
                responseHeaders[h.Key] = string.Join(", ", h.Value);

            // Clean up response headers
            CleanupResponseHeaders(responseHeaders);

            // Rewrite URLs in HTML/CSS/JS responses
            var contentTypeHeader = responseHeaders.GetValueOrDefault("Content-Type") ?? "";
            if (IsTextContent(contentTypeHeader))
            {
                var bodyText = Encoding.UTF8.GetString(responseBody);
                bodyText = RewriteUrls(bodyText, targetBase);
                responseBody = Encoding.UTF8.GetBytes(bodyText);
                responseHeaders["Content-Length"] = responseBody.Length.ToString();
            }

            // Rewrite Location header for redirects
            if (responseHeaders.TryGetValue("Location", out var location))
            {
                responseHeaders["Location"] = RewriteLocationHeader(location, targetBase);
            }

            // Record the exchange (metadata only — body is hashed, not stored)
            var reqBodyHash = requestBody is { Length: > 0 }
                ? HttpSessionRecorder.ComputeBodyHash(requestBody) : null;
            var respBodyHash = responseBody.Length > 0
                ? HttpSessionRecorder.ComputeBodyHash(responseBody) : null;

            // Sanitize headers for recording (remove auth headers)
            var sanitizedReqHeaders = SanitizeHeadersForRecording(requestHeaders);
            var sanitizedRespHeaders = SanitizeHeadersForRecording(responseHeaders);

            _recorder.RecordExchange(
                new HttpMethod(method), fullPath, (int)upstreamResp.StatusCode,
                sanitizedReqHeaders, sanitizedRespHeaders,
                requestBody?.Length ?? 0, reqBodyHash,
                responseBody.Length, respBodyHash);

            return new ProxyResponse
            {
                StatusCode = (int)upstreamResp.StatusCode,
                Headers = responseHeaders,
                Body = responseBody,
            };
        }
        catch (TaskCanceledException)
        {
            return ProxyResponse.Error(504, "Target server timed out");
        }
        catch (HttpRequestException ex)
        {
            _log.LogError(ex, "Upstream request failed for session {SessionId}", _session.SessionId);
            return ProxyResponse.Error(502, "Failed to connect to target server");
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Unexpected error in HTTP proxy session {SessionId}", _session.SessionId);
            return ProxyResponse.Error(500, "Internal proxy error");
        }
    }

    /// <summary>Terminates the session, flushes recordings, zeros credentials.</summary>
    internal async Task TerminateAsync()
    {
        _recorder.Stop();
        await _recorder.FlushAsync();

        // Zero credential material
        CryptographicOperations.ZeroMemory(_password);
        _password = [];
        _username = "";

        _log.LogInformation("HTTP proxy session {SessionId} terminated", _session.SessionId);
    }

    /// <summary>Rewrites absolute target URLs in response content to route through the proxy.</summary>
    private string RewriteUrls(string content, string targetBase)
    {
        // Replace absolute target URLs with proxy-relative paths
        // e.g., https://target.example.com/page → /proxy/{sessionId}/page
        var proxyPrefix = $"/proxy/{_session.SessionId}";
        var result = content.Replace(targetBase, proxyPrefix, StringComparison.OrdinalIgnoreCase);

        // Also handle protocol-relative URLs
        var targetUri = new Uri(targetBase);
        var protocolRelative = $"//{targetUri.Authority}";
        result = result.Replace(protocolRelative, proxyPrefix, StringComparison.OrdinalIgnoreCase);

        return result;
    }

    private string RewriteLocationHeader(string location, string targetBase)
    {
        if (location.StartsWith(targetBase, StringComparison.OrdinalIgnoreCase))
        {
            var relative = location[targetBase.Length..];
            return $"/proxy/{_session.SessionId}{relative}";
        }

        // If it's a relative path, prefix with session path
        if (location.StartsWith('/'))
            return $"/proxy/{_session.SessionId}{location}";

        return location;
    }

    private static void CleanupResponseHeaders(Dictionary<string, string> headers)
    {
        // Remove HSTS from target — PAM proxy has its own HSTS policy
        headers.Remove("Strict-Transport-Security");

        // Remove hop-by-hop headers
        headers.Remove("Transfer-Encoding");
        headers.Remove("Connection");
        headers.Remove("Keep-Alive");
        headers.Remove("Upgrade");

        // Remove CSP that might block proxy-served content
        headers.Remove("Content-Security-Policy");
        headers.Remove("X-Frame-Options");
    }

    private static bool IsHopByHopHeader(string name) =>
        name.Equals("Connection", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Keep-Alive", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Transfer-Encoding", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("TE", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Trailer", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Upgrade", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Proxy-Authorization", StringComparison.OrdinalIgnoreCase) ||
        name.Equals("Proxy-Authenticate", StringComparison.OrdinalIgnoreCase);

    private static bool IsTextContent(string contentType) =>
        contentType.Contains("text/", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("application/json", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("application/javascript", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("application/xml", StringComparison.OrdinalIgnoreCase) ||
        contentType.Contains("application/xhtml", StringComparison.OrdinalIgnoreCase);

    private bool IsBlocked(string path)
    {
        foreach (var pattern in _opts.BlockedUrlPatterns)
        {
            try
            {
                if (Regex.IsMatch(path, pattern, RegexOptions.IgnoreCase, TimeSpan.FromMilliseconds(100)))
                    return true;
            }
            catch { /* Ignore invalid regex patterns */ }
        }
        return false;
    }

    private bool IsRateLimited()
    {
        var now = DateTimeOffset.UtcNow;
        if (now - _rateLimitWindowStart > TimeSpan.FromSeconds(_opts.RateLimitWindowSeconds))
        {
            _requestCount = 1;
            _rateLimitWindowStart = now;
            return false;
        }
        return Interlocked.Increment(ref _requestCount) > _opts.RateLimitMaxRequests;
    }

    /// <summary>Strips sensitive headers (Authorization, Cookie) from recording.</summary>
    private static Dictionary<string, string> SanitizeHeadersForRecording(Dictionary<string, string> headers)
    {
        var sanitized = new Dictionary<string, string>(headers, StringComparer.OrdinalIgnoreCase);
        sanitized.Remove("Authorization");
        sanitized.Remove("Cookie");
        sanitized.Remove("Set-Cookie");
        sanitized.Remove("X-Proxy-Secret");
        return sanitized;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _disposed = true;
        _upstreamClient.Dispose();
        CryptographicOperations.ZeroMemory(_password);
    }
}

/// <summary>Response from the proxy to send back to the user's browser.</summary>
internal sealed class ProxyResponse
{
    public int StatusCode { get; init; }
    public Dictionary<string, string> Headers { get; init; } = new();
    public byte[] Body { get; init; } = [];

    internal static ProxyResponse Error(int statusCode, string message) => new()
    {
        StatusCode = statusCode,
        Headers = new Dictionary<string, string>
        {
            ["Content-Type"] = "text/plain; charset=utf-8"
        },
        Body = Encoding.UTF8.GetBytes(message),
    };
}
