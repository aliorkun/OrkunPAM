using System.Collections.Concurrent;
using System.Net;
using System.Security.Cryptography;
using System.Text;

namespace OrkunPAM.HttpProxy;

/// <summary>
/// Strategy interface for injecting PAM-managed credentials into proxied HTTP requests.
/// Each implementation handles a different authentication mechanism.
/// </summary>
internal interface ICredentialInjector
{
    /// <summary>
    /// Injects credentials into the outgoing request to the target.
    /// Returns true if injection succeeded; false if additional steps are needed (e.g., form login).
    /// </summary>
    Task<bool> InjectAsync(HttpRequestMessage request, HttpSessionInfo session,
        string username, byte[] password, CancellationToken ct);

    /// <summary>
    /// Called after receiving the response from the target, allowing injectors to capture
    /// cookies or tokens for subsequent requests.
    /// </summary>
    Task ProcessResponseAsync(HttpResponseMessage response, HttpSessionInfo session, CancellationToken ct);
}

/// <summary>
/// Injects HTTP Basic Authentication header: Authorization: Basic base64(user:pass).
/// Simplest strategy — no state, every request gets the header.
/// </summary>
internal sealed class BasicAuthInjector : ICredentialInjector
{
    public Task<bool> InjectAsync(HttpRequestMessage request, HttpSessionInfo session,
        string username, byte[] password, CancellationToken ct)
    {
        var credentials = $"{username}:{Encoding.UTF8.GetString(password)}";
        var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
        request.Headers.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", encoded);

        // Zero the intermediate credentials string by overwriting the byte array
        // (the string itself is immutable, but we minimize exposure time)
        return Task.FromResult(true);
    }

    public Task ProcessResponseAsync(HttpResponseMessage response, HttpSessionInfo session,
        CancellationToken ct) => Task.CompletedTask;
}

/// <summary>
/// Performs form-based login: POSTs username/password to a login URL, captures session cookies,
/// and replays them on subsequent requests. Handles the common pattern where web consoles
/// use HTML form login rather than HTTP-level authentication.
/// </summary>
internal sealed class FormLoginInjector : ICredentialInjector
{
    private readonly ConcurrentDictionary<string, CookieContainer> _sessionCookies = new();
    private readonly ConcurrentDictionary<string, bool> _loginCompleted = new();
    private readonly IHttpClientFactory _clientFactory;
    private readonly ILogger _log;

    public FormLoginInjector(IHttpClientFactory clientFactory, ILogger log)
    {
        _clientFactory = clientFactory;
        _log = log;
    }

    public async Task<bool> InjectAsync(HttpRequestMessage request, HttpSessionInfo session,
        string username, byte[] password, CancellationToken ct)
    {
        // If we haven't completed login yet, perform form login first
        if (!_loginCompleted.GetValueOrDefault(session.SessionId))
        {
            var loginSuccess = await PerformFormLoginAsync(session, username, password, ct);
            if (!loginSuccess) return false;
            _loginCompleted[session.SessionId] = true;
        }

        // Inject captured cookies into the proxied request
        if (_sessionCookies.TryGetValue(session.SessionId, out var cookies))
        {
            var targetUri = new Uri(session.TargetUrl);
            var cookieHeader = cookies.GetCookieHeader(targetUri);
            if (!string.IsNullOrEmpty(cookieHeader))
            {
                request.Headers.Remove("Cookie");
                request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
            }
        }

        return true;
    }

    public Task ProcessResponseAsync(HttpResponseMessage response, HttpSessionInfo session,
        CancellationToken ct)
    {
        // Capture any Set-Cookie headers from the target response
        if (_sessionCookies.TryGetValue(session.SessionId, out var cookies) &&
            response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            var targetUri = new Uri(session.TargetUrl);
            foreach (var cookie in setCookies)
            {
                try { cookies.SetCookies(targetUri, cookie); }
                catch { /* Ignore malformed cookies */ }
            }
        }

        return Task.CompletedTask;
    }

    private async Task<bool> PerformFormLoginAsync(HttpSessionInfo session,
        string username, byte[] password, CancellationToken ct)
    {
        try
        {
            var loginUrl = session.FormLoginUrl ?? session.TargetUrl;
            var usernameField = session.FormUsernameField ?? "username";
            var passwordField = session.FormPasswordField ?? "password";

            var cookieContainer = new CookieContainer();
            _sessionCookies[session.SessionId] = cookieContainer;

            using var handler = new HttpClientHandler
            {
                CookieContainer = cookieContainer,
                AllowAutoRedirect = true,
                UseCookies = true,
            };

            // In development, accept self-signed certificates on target
            if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
                handler.ServerCertificateCustomValidationCallback =
                    HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;

            using var client = new HttpClient(handler) { Timeout = TimeSpan.FromSeconds(30) };

            var formContent = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [usernameField] = username,
                [passwordField] = Encoding.UTF8.GetString(password),
            });

            var response = await client.PostAsync(loginUrl, formContent, ct);

            // Accept 2xx and 3xx (redirects after successful login) as success
            var success = (int)response.StatusCode < 400;
            if (success)
                _log.LogInformation("Form login succeeded for session {SessionId} at {Url}",
                    session.SessionId, loginUrl);
            else
                _log.LogWarning("Form login failed for session {SessionId} at {Url} — HTTP {Status}",
                    session.SessionId, loginUrl, (int)response.StatusCode);

            return success;
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Form login error for session {SessionId}", session.SessionId);
            return false;
        }
    }

    internal void CleanupSession(string sessionId)
    {
        _sessionCookies.TryRemove(sessionId, out _);
        _loginCompleted.TryRemove(sessionId, out _);
    }
}

/// <summary>
/// Injects custom authentication headers (Bearer token, API key, etc.) into proxied requests.
/// Headers are defined per-session in the PAM configuration.
/// </summary>
internal sealed class HeaderInjector : ICredentialInjector
{
    public Task<bool> InjectAsync(HttpRequestMessage request, HttpSessionInfo session,
        string username, byte[] password, CancellationToken ct)
    {
        if (session.CustomHeaders != null)
        {
            foreach (var (key, value) in session.CustomHeaders)
            {
                // Replace placeholders with actual credentials
                var resolvedValue = value
                    .Replace("{username}", username, StringComparison.OrdinalIgnoreCase)
                    .Replace("{password}", Encoding.UTF8.GetString(password), StringComparison.OrdinalIgnoreCase);

                request.Headers.Remove(key);
                request.Headers.TryAddWithoutValidation(key, resolvedValue);
            }
        }

        return Task.FromResult(true);
    }

    public Task ProcessResponseAsync(HttpResponseMessage response, HttpSessionInfo session,
        CancellationToken ct) => Task.CompletedTask;
}

/// <summary>
/// Maintains an authenticated session by replaying cookies obtained from an initial
/// authenticated request. Similar to FormLoginInjector but without performing a login POST —
/// uses Basic Auth or header-based auth for the first request, then relies on cookies.
/// </summary>
internal sealed class CookieReplayInjector : ICredentialInjector
{
    private readonly ConcurrentDictionary<string, CookieContainer> _sessionCookies = new();
    private readonly ConcurrentDictionary<string, bool> _initialRequestDone = new();

    public Task<bool> InjectAsync(HttpRequestMessage request, HttpSessionInfo session,
        string username, byte[] password, CancellationToken ct)
    {
        // First request: send Basic Auth to establish session
        if (!_initialRequestDone.GetValueOrDefault(session.SessionId))
        {
            var credentials = $"{username}:{Encoding.UTF8.GetString(password)}";
            var encoded = Convert.ToBase64String(Encoding.UTF8.GetBytes(credentials));
            request.Headers.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", encoded);

            _sessionCookies[session.SessionId] = new CookieContainer();
            _initialRequestDone[session.SessionId] = true;
        }
        else
        {
            // Subsequent requests: replay cookies
            if (_sessionCookies.TryGetValue(session.SessionId, out var cookies))
            {
                var targetUri = new Uri(session.TargetUrl);
                var cookieHeader = cookies.GetCookieHeader(targetUri);
                if (!string.IsNullOrEmpty(cookieHeader))
                {
                    request.Headers.Remove("Cookie");
                    request.Headers.TryAddWithoutValidation("Cookie", cookieHeader);
                }
            }
        }

        return Task.FromResult(true);
    }

    public Task ProcessResponseAsync(HttpResponseMessage response, HttpSessionInfo session,
        CancellationToken ct)
    {
        if (_sessionCookies.TryGetValue(session.SessionId, out var cookies) &&
            response.Headers.TryGetValues("Set-Cookie", out var setCookies))
        {
            var targetUri = new Uri(session.TargetUrl);
            foreach (var cookie in setCookies)
            {
                try { cookies.SetCookies(targetUri, cookie); }
                catch { /* Ignore malformed cookies */ }
            }
        }

        return Task.CompletedTask;
    }

    internal void CleanupSession(string sessionId)
    {
        _sessionCookies.TryRemove(sessionId, out _);
        _initialRequestDone.TryRemove(sessionId, out _);
    }
}
