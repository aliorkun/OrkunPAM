using System.Net.Sockets;
using System.Text;
using OrkunPAM.HttpProxy.Protocol;

namespace OrkunPAM.HttpProxy.Session;

/// <summary>
/// Handles a single privileged HTTP/HTTPS proxy session:
///
///   1. Reads the HTTP request headers from the client.
///   2. Authenticates the PAM user via Proxy-Authorization: Basic.
///   3. Enforces URL policy (whitelist / blacklist).
///   4. For CONNECT (HTTPS): relays a raw TCP tunnel to the target.
///   5. For HTTP:  looks up the vault web credential, optionally injects
///      an Authorization: Basic header, and relays request/response.
///   6. Logs every request to an audit file via HttpSessionLogger.
/// </summary>
internal sealed class HttpSession
{
    private readonly TcpClient _client;
    private readonly PamApiClient _api;
    private readonly HttpProxyOptions _opts;
    private readonly ILogger _log;
    private readonly CancellationToken _ct;
    private readonly string _clientIp;

    private static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(12);
    private static readonly TimeSpan ConnectTimeout  = TimeSpan.FromSeconds(30);
    private static readonly TimeSpan HttpTimeout     = TimeSpan.FromMinutes(5);

    // Hop-by-hop headers stripped from forwarded HTTP requests
    private static readonly HashSet<string> HopByHop = new(StringComparer.OrdinalIgnoreCase)
    {
        "Proxy-Authorization", "Proxy-Connection", "Transfer-Encoding",
        "Connection", "Keep-Alive", "Upgrade", "Authorization"
    };

    public HttpSession(
        TcpClient client, PamApiClient api,
        HttpProxyOptions opts, ILogger log, CancellationToken ct)
    {
        _client   = client;
        _api      = api;
        _opts     = opts;
        _log      = log;
        _ct       = ct;
        _clientIp = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
    }

    public async Task RunAsync()
    {
        _log.LogInformation("HTTP connection from {ClientIp}", _clientIp);

        await using var clientStream = _client.GetStream();
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(_ct);
        sessionCts.CancelAfter(SessionTimeout);
        var ct = sessionCts.Token;

        // 1. Parse request
        ParsedRequest? request;
        try
        {
            request = await HttpRequestParser.ReadAsync(clientStream, ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning("HTTP from {ClientIp}: request parse failed — {Msg}", _clientIp, ex.Message);
            return;
        }

        if (request == null) return;

        // 2. PAM authentication via Proxy-Authorization: Basic
        var (pamUser, pamPass) = HttpRequestParser.ParseBasicAuth(request.ProxyAuthorization);
        if (string.IsNullOrEmpty(pamUser) || string.IsNullOrEmpty(pamPass))
        {
            _log.LogDebug("HTTP from {ClientIp}: no Proxy-Authorization — returning 407", _clientIp);
            await WriteStatusAsync(clientStream, 407, "Proxy Authentication Required",
                [("Proxy-Authenticate", "Basic realm=\"OrkunPAM\"")], null, ct);
            return;
        }

        if (!await _api.ValidateUserAsync(pamUser, pamPass, ct))
        {
            _log.LogWarning("HTTP from {ClientIp}: PAM auth failed for '{User}'", _clientIp, pamUser);
            await WriteStatusAsync(clientStream, 407, "Proxy Authentication Required",
                [("Proxy-Authenticate", "Basic realm=\"OrkunPAM\"")], null, ct);
            return;
        }

        // 3. URL policy
        var targetUrl = request.IsConnect
            ? $"https://{request.TargetHost}:{request.TargetPort}"
            : request.RequestUri;

        if (!IsUrlAllowed(targetUrl))
        {
            _log.LogWarning("HTTP {User}: URL blocked by policy — {Url}", pamUser, targetUrl);
            await WriteStatusAsync(clientStream, 403, "Forbidden", [],
                "URL blocked by proxy policy.", ct);
            return;
        }

        // 4. Dispatch
        var sessionId = Guid.NewGuid().ToString("N");
        var logger    = HttpSessionLogger.Create(_opts.LogDirectory, sessionId, pamUser, _clientIp);

        if (request.IsConnect)
            await HandleConnectAsync(clientStream, request, pamUser, sessionId, logger, ct);
        else
            await HandleHttpAsync(clientStream, request, pamUser, pamPass, sessionId, logger, ct);
    }

    // ── CONNECT tunnel (HTTPS passthrough) ────────────────────────────────────────────

    private async Task HandleConnectAsync(
        NetworkStream clientStream, ParsedRequest req,
        string pamUser, string sessionId, HttpSessionLogger logger, CancellationToken ct)
    {
        using var target = new TcpClient { NoDelay = true };

        try
        {
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(ConnectTimeout);
            await target.ConnectAsync(req.TargetHost, req.TargetPort, connectCts.Token);
        }
        catch (Exception ex)
        {
            _log.LogWarning("HTTP CONNECT {User}: cannot reach {Host}:{Port} — {Msg}",
                pamUser, req.TargetHost, req.TargetPort, ex.Message);
            await WriteStatusAsync(clientStream, 502, "Bad Gateway", [], null, ct);
            logger.Write(sessionId, pamUser, _clientIp, "CONNECT",
                $"https://{req.TargetHost}:{req.TargetPort}", 502, 0, false);
            return;
        }

        // Tunnel established — inform client
        await WriteStatusAsync(clientStream, 200, "Connection Established", [], null, ct);

        await using var targetStream = target.GetStream();

        var (idleTimeoutMinutes, _) = await _api.GetSessionPolicyAsync(ct);
        var startTime    = DateTimeOffset.UtcNow;
        long[] lastTicks = [DateTime.UtcNow.Ticks];

        using var relayCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var clientToTarget = PumpAsync(clientStream, targetStream, relayCts.Token, lastTicks);
        var targetToClient = PumpAsync(targetStream, clientStream, relayCts.Token, lastTicks);
        var idleWatcher    = IdleWatchAsync(idleTimeoutMinutes, lastTicks, relayCts);

        await Task.WhenAny(clientToTarget, targetToClient, idleWatcher);
        await relayCts.CancelAsync();

        try { await Task.WhenAll(clientToTarget, targetToClient); }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or SocketException) { }

        var duration = (int)(DateTimeOffset.UtcNow - startTime).TotalSeconds;
        _log.LogInformation("HTTP CONNECT {SessionId} ended — {Sec}s user={User} target={Host}:{Port}",
            sessionId, duration, pamUser, req.TargetHost, req.TargetPort);

        logger.Write(sessionId, pamUser, _clientIp, "CONNECT",
            $"https://{req.TargetHost}:{req.TargetPort}", 200, duration * 1000, false);

        _ = _api.ReportSessionEndedAsync(sessionId, duration, "", CancellationToken.None);
    }

    // ── Plain HTTP forward ─────────────────────────────────────────────────────

    private async Task HandleHttpAsync(
        NetworkStream clientStream, ParsedRequest req,
        string pamUser, string? pamPass, string sessionId, HttpSessionLogger logger, CancellationToken ct)
    {
        // Look up vault credential for optional Basic Auth injection
        var (vaultUser, vaultPass) = await _api.GetWebCredentialAsync(pamUser, req.TargetHost, ct);
        bool vaultInjected = false;

        // Connect to target
        using var target = new TcpClient { NoDelay = true };
        try
        {
            using var connectCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            connectCts.CancelAfter(ConnectTimeout);
            await target.ConnectAsync(req.TargetHost, req.TargetPort, connectCts.Token);
        }
        catch (Exception ex)
        {
            _log.LogWarning("HTTP {User}: cannot reach {Host}:{Port} — {Msg}",
                pamUser, req.TargetHost, req.TargetPort, ex.Message);
            await WriteStatusAsync(clientStream, 502, "Bad Gateway", [], null, ct);
            logger.Write(sessionId, pamUser, _clientIp, req.Method, req.RequestUri, 502, 0, false);
            return;
        }

        await using var targetStream = target.GetStream();

        // Build forwarded request
        var fwdSb = new StringBuilder(512);

        string path = "/";
        if (Uri.TryCreate(req.RequestUri, UriKind.Absolute, out var parsedUri))
            path = string.IsNullOrEmpty(parsedUri.PathAndQuery) ? "/" : parsedUri.PathAndQuery;
        else if (req.RequestUri.StartsWith('/'))
            path = req.RequestUri;

        fwdSb.Append(req.Method).Append(' ').Append(path).Append(" HTTP/1.1\r\n");

        foreach (var (name, value) in req.Headers)
        {
            if (!HopByHop.Contains(name))
                fwdSb.Append(name).Append(": ").Append(value).Append("\r\n");
        }

        // Inject vault credential (replaces any existing Authorization header)
        if (!string.IsNullOrEmpty(vaultUser) && !string.IsNullOrEmpty(vaultPass))
        {
            var raw   = $"{vaultUser}:{vaultPass}";
            var basic = Convert.ToBase64String(Encoding.UTF8.GetBytes(raw));
            fwdSb.Append("Authorization: Basic ").Append(basic).Append("\r\n");
            // Zero-fill sensitive strings
            raw      = null!;
            vaultPass = null;
            vaultInjected = true;
        }

        fwdSb.Append("Connection: close\r\n\r\n");
        await targetStream.WriteAsync(Encoding.ASCII.GetBytes(fwdSb.ToString()), ct);

        var startTime = DateTimeOffset.UtcNow;

        using var httpCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        httpCts.CancelAfter(HttpTimeout);

        // Relay client body (POST/PUT) to target concurrently with target response
        var bodyRelay    = PumpAsync(clientStream, targetStream, httpCts.Token, null);
        int statusCode   = 0;
        var responseTask = RelayResponseWithStatusAsync(
            targetStream, clientStream, httpCts.Token, code => statusCode = code);

        // Response completes when target closes its side
        await Task.WhenAny(responseTask, bodyRelay);
        await httpCts.CancelAsync();

        try { await Task.WhenAll(responseTask, bodyRelay); }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or SocketException) { }

        var duration = (int)(DateTimeOffset.UtcNow - startTime).TotalMilliseconds;
        _log.LogInformation("HTTP {SessionId}: {Method} {Url} → {Status} ({Duration}ms) user={User}",
            sessionId, req.Method, req.RequestUri, statusCode, duration, pamUser);

        logger.Write(sessionId, pamUser, _clientIp, req.Method, req.RequestUri,
            statusCode, duration, vaultInjected);

        _ = _api.ReportSessionEndedAsync(sessionId, (int)(duration / 1000), "", CancellationToken.None);
    }

    // ── Relay helpers ──────────────────────────────────────────────────────

    private static async Task PumpAsync(
        Stream src, Stream dst, CancellationToken ct, long[]? lastActivityTicks)
    {
        var buf = new byte[65536];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await src.ReadAsync(buf, ct);
                if (read == 0) break;
                if (lastActivityTicks != null)
                    Interlocked.Exchange(ref lastActivityTicks[0], DateTime.UtcNow.Ticks);
                await dst.WriteAsync(buf.AsMemory(0, read), ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or SocketException) { }
    }

    /// <summary>
    /// Relays the HTTP response from source to dest, capturing the status code
    /// from the first response line for audit logging.
    /// </summary>
    private static async Task RelayResponseWithStatusAsync(
        NetworkStream source, NetworkStream dest,
        CancellationToken ct, Action<int> onStatus)
    {
        var buf           = new byte[65536];
        bool statusParsed = false;

        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await source.ReadAsync(buf, ct);
                if (read == 0) break;

                if (!statusParsed)
                {
                    // Scan for the first CRLF in this chunk to extract the status line
                    var span = buf.AsSpan(0, read);
                    for (int i = 0; i < span.Length - 1; i++)
                    {
                        if (span[i] == '\r' && span[i + 1] == '\n')
                        {
                            var line  = Encoding.ASCII.GetString(span[..i]);
                            var parts = line.Split(' ', 3);
                            if (parts.Length >= 2 && int.TryParse(parts[1], out var code))
                                onStatus(code);
                            statusParsed = true;
                            break;
                        }
                    }
                }

                await dest.WriteAsync(buf.AsMemory(0, read), ct);
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or SocketException) { }
    }

    private static async Task IdleWatchAsync(
        int timeoutMinutes, long[] lastTicks, CancellationTokenSource cts)
    {
        var timeout = TimeSpan.FromMinutes(timeoutMinutes);
        try
        {
            while (!cts.IsCancellationRequested)
            {
                await Task.Delay(30_000, cts.Token);
                var idleFor = TimeSpan.FromTicks(
                    DateTime.UtcNow.Ticks - Interlocked.Read(ref lastTicks[0]));
                if (idleFor >= timeout)
                {
                    await cts.CancelAsync();
                    return;
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    // ── HTTP response writer ─────────────────────────────────────────────────────

    private static async Task WriteStatusAsync(
        NetworkStream stream, int statusCode, string statusText,
        IEnumerable<(string Name, string Value)> extraHeaders,
        string? body, CancellationToken ct)
    {
        try
        {
            var sb = new StringBuilder();
            sb.Append($"HTTP/1.1 {statusCode} {statusText}\r\n");
            foreach (var (name, value) in extraHeaders)
                sb.Append($"{name}: {value}\r\n");

            if (!string.IsNullOrEmpty(body))
            {
                var bodyBytes = Encoding.UTF8.GetBytes(body);
                sb.Append($"Content-Length: {bodyBytes.Length}\r\n");
                sb.Append("Content-Type: text/plain\r\n\r\n");
                await stream.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct);
                await stream.WriteAsync(bodyBytes, ct);
            }
            else
            {
                sb.Append("Content-Length: 0\r\n\r\n");
                await stream.WriteAsync(Encoding.ASCII.GetBytes(sb.ToString()), ct);
            }
        }
        catch { /* best-effort — client may have disconnected */ }
    }

    // ── URL policy ──────────────────────────────────────────────────────────────────

    private bool IsUrlAllowed(string url)
    {
        // Whitelist: if configured, URL must match at least one entry
        if (_opts.UrlWhitelist.Count > 0)
            return _opts.UrlWhitelist.Any(pattern => MatchesPattern(url, pattern));

        // Blacklist: URL must not match any blocked pattern
        if (_opts.UrlBlacklist.Count > 0)
            return !_opts.UrlBlacklist.Any(pattern => MatchesPattern(url, pattern));

        return true;
    }

    // Simple glob matching: * matches any substring, ? matches one character.
    private static bool MatchesPattern(string input, string pattern)
    {
        int pi = 0, si = 0, starPi = -1, starSi = 0;
        var p = pattern.AsSpan();
        var s = input.AsSpan();

        while (si < s.Length)
        {
            if (pi < p.Length && (p[pi] == '?' || char.ToLowerInvariant(p[pi]) == char.ToLowerInvariant(s[si])))
            {
                pi++; si++;
            }
            else if (pi < p.Length && p[pi] == '*')
            {
                starPi = pi++;
                starSi = si;
            }
            else if (starPi >= 0)
            {
                pi = starPi + 1;
                si = ++starSi;
            }
            else
            {
                return false;
            }
        }

        while (pi < p.Length && p[pi] == '*') pi++;
        return pi == p.Length;
    }
}
