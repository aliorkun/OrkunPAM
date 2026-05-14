using System.Collections.Concurrent;
using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.Extensions.Options;
using OrkunPAM.HttpProxy.Session;

namespace OrkunPAM.HttpProxy;

/// <summary>
/// Windows Service / IHostedService that listens on HTTPS (default :8443) and dispatches
/// incoming HTTP requests to the appropriate HttpProxySession.
///
/// Request flow:
///   1. GET /session/{token}  → validate token, create session, redirect to /proxy/{sessionId}/
///   2. * /proxy/{sessionId}/* → forward to target via HttpProxySession
///   3. GET /health            → service health check
///
/// Uses raw TcpListener + SslStream for the HTTPS listener (native C#, no Kestrel dependency).
/// Parses HTTP/1.1 requests manually for full control over proxying behavior.
/// </summary>
internal sealed class HttpProxyService : BackgroundService
{
    private readonly ILogger<HttpProxyService> _log;
    private readonly HttpProxyOptions _opts;
    private readonly PamApiClient _api;
    private readonly HashChainStore _hashChain;
    private readonly IHttpClientFactory _clientFactory;

    // Active sessions keyed by session ID
    private readonly ConcurrentDictionary<string, HttpProxySession> _sessions = new();

    // Credential injectors (reused across sessions of the same type)
    private readonly BasicAuthInjector _basicAuth = new();
    private readonly HeaderInjector _headerInjector = new();
    private FormLoginInjector? _formLogin;
    private readonly CookieReplayInjector _cookieReplay = new();

    // Per-IP connection rate limiter: max 20 connections per 60-second window
    private readonly ConcurrentDictionary<string, (int count, DateTimeOffset windowStart)> _connTracker = new();
    private const int MaxConnectionsPerWindow = 20;
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromSeconds(60);

    // Idle session cleanup timer
    private Timer? _idleTimer;

    public HttpProxyService(
        ILogger<HttpProxyService> log,
        IOptions<HttpProxyOptions> opts,
        PamApiClient api,
        HashChainStore hashChain,
        IHttpClientFactory clientFactory)
    {
        _log           = log;
        _opts          = opts.Value;
        _api           = api;
        _hashChain     = hashChain;
        _clientFactory = clientFactory;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _formLogin = new FormLoginInjector(_clientFactory, _log);

        // Start idle session cleanup (runs every minute)
        _idleTimer = new Timer(_ => CleanupIdleSessions(), null,
            TimeSpan.FromMinutes(1), TimeSpan.FromMinutes(1));

        var address = string.IsNullOrEmpty(_opts.ListenAddress)
            ? IPAddress.Any
            : IPAddress.Parse(_opts.ListenAddress);

        X509Certificate2? tlsCert = null;
        if (!string.IsNullOrEmpty(_opts.TlsCertPath))
        {
            tlsCert = new X509Certificate2(_opts.TlsCertPath, _opts.TlsCertPassword);
            _log.LogInformation("TLS certificate loaded: {Subject} (expires {Expiry})",
                tlsCert.Subject, tlsCert.NotAfter);
        }

        var listener = new TcpListener(address, _opts.ListenPort);
        listener.Start();
        _log.LogInformation("HTTP proxy listening on {Address}:{Port} (TLS: {TlsEnabled})",
            address, _opts.ListenPort, tlsCert != null);

        using var semaphore = new SemaphoreSlim(_opts.MaxConcurrentSessions);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(stoppingToken); }
                catch (OperationCanceledException) { break; }

                var clientIp = ((IPEndPoint?)client.Client.RemoteEndPoint)?.Address.ToString() ?? "unknown";

                if (IsConnectionRateLimited(clientIp))
                {
                    _log.LogWarning("HTTP connection from {ClientIp} dropped — rate limit exceeded", clientIp);
                    client.Dispose();
                    continue;
                }

                await semaphore.WaitAsync(stoppingToken);
                client.NoDelay = true;

                _ = Task.Run(async () =>
                {
                    try
                    {
                        await HandleConnectionAsync(client, tlsCert, stoppingToken);
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "Connection error from {ClientIp}", clientIp);
                    }
                    finally
                    {
                        client.Dispose();
                        semaphore.Release();
                    }
                }, stoppingToken);
            }
        }
        finally
        {
            listener.Stop();
            _idleTimer?.Dispose();

            // Terminate all active sessions
            foreach (var session in _sessions.Values)
            {
                try { await session.TerminateAsync(); }
                catch (Exception ex) { _log.LogError(ex, "Error terminating session on shutdown"); }
                session.Dispose();
            }
            _sessions.Clear();

            tlsCert?.Dispose();
            _log.LogInformation("HTTP proxy stopped");
        }
    }

    private async Task HandleConnectionAsync(TcpClient client, X509Certificate2? tlsCert,
        CancellationToken ct)
    {
        Stream stream = client.GetStream();

        // TLS termination
        if (tlsCert != null)
        {
            var sslStream = new SslStream(stream, leaveInnerStreamOpen: false);
            try
            {
                await sslStream.AuthenticateAsServerAsync(new SslServerAuthenticationOptions
                {
                    ServerCertificate = tlsCert,
                    EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                    ClientCertificateRequired = false,
                }, ct);
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "TLS handshake failed");
                sslStream.Dispose();
                return;
            }
            stream = sslStream;
        }

        // Handle multiple HTTP/1.1 requests on the same connection (keep-alive)
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var request = await ParseHttpRequestAsync(stream, ct);
                if (request == null) break; // Connection closed

                var response = await RouteRequestAsync(request, ct);
                await WriteHttpResponseAsync(stream, response, ct);

                // Check Connection: close
                if (request.Headers.TryGetValue("Connection", out var conn) &&
                    conn.Equals("close", StringComparison.OrdinalIgnoreCase))
                    break;
            }
        }
        catch (IOException) { /* Client disconnected */ }
        catch (OperationCanceledException) { }
        finally
        {
            if (stream is SslStream ssl)
                ssl.Dispose();
        }
    }

    private async Task<ProxyResponse> RouteRequestAsync(HttpRequest request, CancellationToken ct)
    {
        var path = request.Path;

        // Health check
        if (path == "/health")
            return new ProxyResponse
            {
                StatusCode = 200,
                Headers = new() { ["Content-Type"] = "application/json" },
                Body = Encoding.UTF8.GetBytes(
                    $"{{\"status\":\"healthy\",\"activeSessions\":{_sessions.Count}}}"),
            };

        // Session initialization: GET /session/{token}
        if (path.StartsWith("/session/", StringComparison.OrdinalIgnoreCase) &&
            request.Method.Equals("GET", StringComparison.OrdinalIgnoreCase))
        {
            var token = path["/session/".Length..].TrimEnd('/');
            return await InitializeSessionAsync(token, ct);
        }

        // Proxy requests: * /proxy/{sessionId}/*
        if (path.StartsWith("/proxy/", StringComparison.OrdinalIgnoreCase))
        {
            var remaining = path["/proxy/".Length..];
            var slashIdx = remaining.IndexOf('/');
            var sessionId = slashIdx >= 0 ? remaining[..slashIdx] : remaining;
            var relativePath = slashIdx >= 0 ? remaining[(slashIdx + 1)..] : "";

            if (_sessions.TryGetValue(sessionId, out var session))
            {
                return await session.HandleRequestAsync(
                    request.Method, relativePath, request.QueryString,
                    request.Headers, request.Body, ct);
            }

            return ProxyResponse.Error(404, "Session not found or has expired");
        }

        return ProxyResponse.Error(404, "Not Found. Use /session/{token} to start a session.");
    }

    private async Task<ProxyResponse> InitializeSessionAsync(string token, CancellationToken ct)
    {
        // Validate session token with PAM API
        var sessionInfo = await _api.ValidateSessionTokenAsync(token, ct);
        if (sessionInfo == null)
            return ProxyResponse.Error(401, "Invalid or expired session token");

        // Check if session already exists
        if (_sessions.ContainsKey(sessionInfo.SessionId))
        {
            return new ProxyResponse
            {
                StatusCode = 302,
                Headers = new()
                {
                    ["Location"] = $"/proxy/{sessionInfo.SessionId}/",
                    ["Content-Type"] = "text/plain",
                },
                Body = Encoding.UTF8.GetBytes("Redirecting to existing session..."),
            };
        }

        // Select credential injector based on auth strategy
        ICredentialInjector injector = sessionInfo.AuthStrategy switch
        {
            AuthStrategy.BasicAuth => _basicAuth,
            AuthStrategy.FormLogin => _formLogin!,
            AuthStrategy.HeaderInjection => _headerInjector,
            AuthStrategy.CookieReplay => _cookieReplay,
            _ => _basicAuth,
        };

        // Create and initialize session
        var session = new HttpProxySession(sessionInfo, injector, _opts, _log, _hashChain);
        try
        {
            await session.InitializeAsync(_api, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to initialize HTTP session for token");
            session.Dispose();
            return ProxyResponse.Error(502, "Failed to retrieve credentials for target");
        }

        if (!_sessions.TryAdd(sessionInfo.SessionId, session))
        {
            session.Dispose();
            return ProxyResponse.Error(409, "Session already exists");
        }

        _log.LogInformation("HTTP proxy session {SessionId} created (strategy: {Strategy}, target: {Target})",
            sessionInfo.SessionId, sessionInfo.AuthStrategy, sessionInfo.TargetUrl);

        // Redirect browser to the proxy path
        return new ProxyResponse
        {
            StatusCode = 302,
            Headers = new()
            {
                ["Location"] = $"/proxy/{sessionInfo.SessionId}/",
                ["Content-Type"] = "text/plain",
            },
            Body = Encoding.UTF8.GetBytes("Session established. Redirecting..."),
        };
    }

    private void CleanupIdleSessions()
    {
        var timeout = TimeSpan.FromMinutes(_opts.IdleTimeoutMinutes);
        var now = DateTime.UtcNow;

        foreach (var (sessionId, session) in _sessions)
        {
            if (now - session.LastActivityUtc > timeout)
            {
                if (_sessions.TryRemove(sessionId, out var removed))
                {
                    _log.LogInformation("Session {SessionId} terminated due to idle timeout", sessionId);
                    Task.Run(async () =>
                    {
                        try { await removed.TerminateAsync(); }
                        catch (Exception ex) { _log.LogError(ex, "Error terminating idle session"); }
                        finally { removed.Dispose(); }
                    });
                }
            }
        }
    }

    private bool IsConnectionRateLimited(string ip)
    {
        var now = DateTimeOffset.UtcNow;
        var entry = _connTracker.AddOrUpdate(ip,
            _ => (1, now),
            (_, old) => now - old.windowStart > RateLimitWindow
                ? (1, now)
                : (old.count + 1, old.windowStart));
        return entry.count > MaxConnectionsPerWindow;
    }

    // ──────────────────────────────────────────────────────────────────
    //  HTTP/1.1 request/response parser (minimal, native C#)
    // ──────────────────────────────────────────────────────────────────

    private async Task<HttpRequest?> ParseHttpRequestAsync(Stream stream, CancellationToken ct)
    {
        var headerBytes = new List<byte>(4096);
        var prevByte = 0;
        var crlfCount = 0;

        // Read until we find \r\n\r\n (end of headers)
        var buf = new byte[1];
        while (crlfCount < 2)
        {
            int read;
            try { read = await stream.ReadAsync(buf, ct); }
            catch { return null; }

            if (read == 0) return null; // Connection closed

            headerBytes.Add(buf[0]);

            if (buf[0] == '\n' && prevByte == '\r')
                crlfCount++;
            else if (buf[0] != '\r')
                crlfCount = 0;

            prevByte = buf[0];
        }

        var headerText = Encoding.ASCII.GetString(headerBytes.ToArray());
        var lines = headerText.Split("\r\n", StringSplitOptions.None);

        if (lines.Length == 0) return null;

        // Parse request line: METHOD PATH HTTP/1.1
        var requestLine = lines[0].Split(' ', 3);
        if (requestLine.Length < 3) return null;

        var method = requestLine[0];
        var fullPath = requestLine[1];

        // Split path and query string
        var qIdx = fullPath.IndexOf('?');
        var path = qIdx >= 0 ? fullPath[..qIdx] : fullPath;
        var queryString = qIdx >= 0 ? fullPath[qIdx..] : "";

        // Parse headers
        var headers = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        for (int i = 1; i < lines.Length; i++)
        {
            if (string.IsNullOrWhiteSpace(lines[i])) break;
            var colonIdx = lines[i].IndexOf(':');
            if (colonIdx > 0)
            {
                var key = lines[i][..colonIdx].Trim();
                var value = lines[i][(colonIdx + 1)..].Trim();
                headers[key] = value;
            }
        }

        // Read body if Content-Length is present
        byte[]? body = null;
        if (headers.TryGetValue("Content-Length", out var clStr) &&
            int.TryParse(clStr, out var contentLength) && contentLength > 0)
        {
            if (contentLength > _opts.MaxRequestBodyBytes)
                return null; // Request too large

            body = new byte[contentLength];
            var totalRead = 0;
            while (totalRead < contentLength)
            {
                var n = await stream.ReadAsync(body.AsMemory(totalRead, contentLength - totalRead), ct);
                if (n == 0) break;
                totalRead += n;
            }
        }

        return new HttpRequest
        {
            Method = method,
            Path = path,
            QueryString = queryString,
            Headers = headers,
            Body = body,
        };
    }

    private static async Task WriteHttpResponseAsync(Stream stream, ProxyResponse response,
        CancellationToken ct)
    {
        var sb = new StringBuilder();
        sb.Append($"HTTP/1.1 {response.StatusCode} {GetReasonPhrase(response.StatusCode)}\r\n");

        foreach (var (key, value) in response.Headers)
            sb.Append($"{key}: {value}\r\n");

        if (!response.Headers.ContainsKey("Content-Length"))
            sb.Append($"Content-Length: {response.Body.Length}\r\n");

        sb.Append("\r\n");

        var headerData = Encoding.ASCII.GetBytes(sb.ToString());
        await stream.WriteAsync(headerData, ct);

        if (response.Body.Length > 0)
            await stream.WriteAsync(response.Body, ct);

        await stream.FlushAsync(ct);
    }

    private static string GetReasonPhrase(int statusCode) => statusCode switch
    {
        200 => "OK",
        201 => "Created",
        301 => "Moved Permanently",
        302 => "Found",
        304 => "Not Modified",
        400 => "Bad Request",
        401 => "Unauthorized",
        403 => "Forbidden",
        404 => "Not Found",
        405 => "Method Not Allowed",
        409 => "Conflict",
        429 => "Too Many Requests",
        500 => "Internal Server Error",
        502 => "Bad Gateway",
        503 => "Service Unavailable",
        504 => "Gateway Timeout",
        _ => "Unknown",
    };

    private sealed class HttpRequest
    {
        public required string Method { get; init; }
        public required string Path { get; init; }
        public required string QueryString { get; init; }
        public required Dictionary<string, string> Headers { get; init; }
        public byte[]? Body { get; init; }
    }
}
