using System.Net.Sockets;
using System.Text;

namespace OrkunPAM.TelnetProxy;

/// <summary>
/// Manages one PAM-brokered Telnet session:
/// authenticate PAM user → inject target credential → bidirectional relay + recording.
/// </summary>
internal sealed class TelnetSession
{
    private readonly TcpClient _client;
    private readonly PamApiClient _api;
    private readonly TelnetProxyOptions _opts;
    private readonly ILogger _log;
    private readonly string _clientIp;

    private static readonly byte[] CRLF = "\r\n"u8.ToArray();

    public TelnetSession(TcpClient client, PamApiClient api, TelnetProxyOptions opts,
        ILogger log, string clientIp)
    {
        _client   = client;
        _api      = api;
        _opts     = opts;
        _log      = log;
        _clientIp = clientIp;
    }

    public async Task RunAsync(CancellationToken ct)
    {
        using (_client)
        {
            _client.ReceiveTimeout = _opts.IdleTimeoutSeconds * 1000;
            _client.SendTimeout    = 30_000;
            var stream = _client.GetStream();

            try
            {
                await DoSessionAsync(stream, ct);
            }
            catch (OperationCanceledException) { }
            catch (IOException ex)
            {
                _log.LogDebug("Telnet client {Ip} disconnected: {Msg}", _clientIp, ex.Message);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Telnet session error for {Ip}", _clientIp);
            }
        }
    }

    private async Task DoSessionAsync(NetworkStream stream, CancellationToken ct)
    {
        // ── 1. Initial RFC 854 option negotiation ───────────────────────────────────────
        await stream.WriteAsync(TelnetNegotiator.InitialNegotiation(), ct);

        if (_opts.SessionBannerEnabled)
        {
            await SendLineAsync(stream, "", ct);
            await SendLineAsync(stream, "Orkun PAM Telnet Gateway", ct);
            await SendLineAsync(stream, "Connect: [pam-username]@[target-host[:port]]", ct);
            await SendLineAsync(stream, "", ct);
        }

        // ── 2. Read username: pamuser@target-host[:port] ─────────────────────────────
        await stream.WriteAsync(Encoding.ASCII.GetBytes("Login: "), ct);
        var loginLine = await ReadLineAsync(stream, ct, echoChars: true);
        if (loginLine == null) return;

        loginLine = loginLine.Trim();
        if (!ParseLogin(loginLine, out var pamUser, out var targetHost, out var targetPort))
        {
            await SendLineAsync(stream, "\r\nInvalid login format. Use: user@host[:port]", ct);
            return;
        }

        // ── 3. Read PAM password (suppress echo) ──────────────────────────────────
        await stream.WriteAsync(Encoding.ASCII.GetBytes("PAM Password: "), ct);
        var pamPassword = await ReadLineAsync(stream, ct, echoChars: false);
        if (pamPassword == null) return;
        await SendLineAsync(stream, "", ct); // newline after hidden input

        // ── 4. Validate against PAM ──────────────────────────────────────────────
        var (valid, userId) = await _api.ValidateUserAsync(pamUser, pamPassword, ct);
        // Zero-out password immediately
        if (pamPassword.Length > 0)
            pamPassword = new string('\0', pamPassword.Length);

        if (!valid)
        {
            await SendLineAsync(stream, "Authentication failed.", ct);
            _log.LogWarning("Telnet login failed for user '{User}' from {Ip}", pamUser, _clientIp);
            return;
        }

        _log.LogInformation("Telnet PAM auth OK: {User} from {Ip} → {Host}:{Port}",
            pamUser, _clientIp, targetHost, targetPort);

        // ── 5. Retrieve target credential ─────────────────────────────────────────
        string credTargetIp, credUser, deviceId, credentialId;
        int credTargetPort;
        byte[] credPassword;
        try
        {
            var cred = await _api.GetTargetCredentialAsync(targetHost, ct);
            credTargetIp   = cred.Ip;
            credTargetPort = targetPort != 23 ? targetPort : cred.Port;
            credUser       = cred.CredUser;
            credPassword   = cred.Password;
            deviceId       = cred.DeviceId;
            credentialId   = cred.CredentialId;
        }
        catch (InvalidOperationException ex)
        {
            await SendLineAsync(stream, $"Access denied: {ex.Message}", ct);
            _log.LogWarning("Telnet credential lookup failed for {User} → {Host}: {Err}",
                pamUser, targetHost, ex.Message);
            return;
        }

        // ── 6. Register session ───────────────────────────────────────────────────
        var sessionId = await _api.StartSessionAsync(
            userId ?? Guid.Empty.ToString(), deviceId, credentialId,
            _clientIp, credTargetIp, credTargetPort, ct);

        // ── 7. Connect to target ──────────────────────────────────────────────────
        using var targetClient = new TcpClient();
        targetClient.ReceiveTimeout = _opts.IdleTimeoutSeconds * 1000;
        targetClient.SendTimeout    = 30_000;

        try
        {
            await targetClient.ConnectAsync(credTargetIp, credTargetPort, ct);
        }
        catch (Exception ex)
        {
            await SendLineAsync(stream, $"\r\nCannot connect to {credTargetIp}:{credTargetPort}: {ex.Message}", ct);
            Array.Clear(credPassword, 0, credPassword.Length);
            return;
        }

        await SendLineAsync(stream, $"\r\nConnected to {credTargetIp}:{credTargetPort} via PAM.", ct);

        var targetStream = targetClient.GetStream();

        // ── 8. Auto-inject credential via Telnet login sequence ────────────────────────────
        await AutoLoginAsync(targetStream, credUser, credPassword, ct);
        Array.Clear(credPassword, 0, credPassword.Length);

        // Restore client echo for interactive session
        await stream.WriteAsync(TelnetNegotiator.ResumeClientEcho(), ct);

        // ── 9. Bidirectional relay with session recording ─────────────────────────────────
        var startTime = DateTime.UtcNow;
        var recording = new MemoryStream();

        using var idleTimer = new CancellationTokenSource(
            TimeSpan.FromSeconds(_opts.IdleTimeoutSeconds));
        using var linked = CancellationTokenSource.CreateLinkedTokenSource(ct, idleTimer.Token);

        // Live chunk broadcast: target→client output → WebAPI (#214)
        Action<string>? liveChunk = sessionId != null
            ? text => _api.SendLiveChunk(sessionId, text)
            : null;

        var clientToTarget = RelayAsync(stream, targetStream, recording, linked.Token,
            "client→target", refreshIdle: () => idleTimer.CancelAfter(
                TimeSpan.FromSeconds(_opts.IdleTimeoutSeconds)));

        var targetToClient = RelayAsync(targetStream, stream, recording, linked.Token,
            "target→client", refreshIdle: () => idleTimer.CancelAfter(
                TimeSpan.FromSeconds(_opts.IdleTimeoutSeconds)),
            liveChunk: liveChunk);

        // Also check for admin-initiated termination every 30 seconds
        var terminationChecker = sessionId != null
            ? CheckTerminationAsync(sessionId, linked, ct)
            : Task.CompletedTask;

        await Task.WhenAny(clientToTarget, targetToClient, terminationChecker);
        linked.Cancel();
        await Task.WhenAll(clientToTarget, targetToClient);

        // ── 10. Session cleanup ─────────────────────────────────────────────────────
        var duration = (int)(DateTime.UtcNow - startTime).TotalSeconds;
        _log.LogInformation("Telnet session {Id} ended: {User} → {Host} ({Dur}s, {Bytes} bytes recorded)",
            sessionId ?? "?", pamUser, targetHost, duration, recording.Length);

        if (sessionId != null)
            await _api.EndSessionAsync(sessionId, duration, recording.ToArray(), CancellationToken.None);
    }

    private static async Task RelayAsync(
        NetworkStream from, NetworkStream to, MemoryStream recording,
        CancellationToken ct, string label, Action refreshIdle,
        Action<string>? liveChunk = null)
    {
        var buf = new byte[4096];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await from.ReadAsync(buf, ct);
                if (read == 0) break;

                refreshIdle();

                // Process Telnet negotiation from remote and send responses back
                var response = TelnetNegotiator.BuildResponse(buf.AsSpan(0, read));
                if (response.Length > 0)
                    await from.WriteAsync(response, ct);

                await to.WriteAsync(buf.AsMemory(0, read), ct);

                // Strip IAC for clean recording
                var stripped = TelnetNegotiator.StripIac(buf.AsSpan(0, read));
                if (stripped.Length > 0)
                {
                    await recording.WriteAsync(stripped, ct);
                    // Broadcast to live monitor (#214)
                    liveChunk?.Invoke(Encoding.UTF8.GetString(stripped));
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (IOException) { }
        catch (Exception ex)
        {
            _ = ex; // relay teardown is expected on session close
        }
    }

    private static async Task AutoLoginAsync(
        NetworkStream targetStream, string credUser, byte[] password, CancellationToken ct)
    {
        // Wait briefly for target to send its login prompt, then inject credentials
        await Task.Delay(800, ct);

        var buf = new byte[1024];
        if (targetStream.DataAvailable)
        {
            int n = await targetStream.ReadAsync(buf, ct);
            // Discard target banner/prompt — client will see it after we authenticate
            _ = n;
        }

        // Send username
        await targetStream.WriteAsync(Encoding.ASCII.GetBytes(credUser + "\r\n"), ct);
        await Task.Delay(300, ct);

        if (targetStream.DataAvailable)
        {
            int n = await targetStream.ReadAsync(buf, ct); // consume password prompt
            _ = n;
        }

        // Send password
        await targetStream.WriteAsync(password, ct);
        await targetStream.WriteAsync("\r\n"u8.ToArray(), ct);
    }

    private static async Task CheckTerminationAsync(
        string sessionId, CancellationTokenSource linked, CancellationToken ct)
    {
        // Stub — real implementation would call PAM API every 30s
        // For now this task just runs until cancelled
        try { await Task.Delay(Timeout.Infinite, ct); }
        catch (OperationCanceledException) { }
    }

    /// <summary>Read one line from Telnet stream. Returns null on disconnect.</summary>
    private static async Task<string?> ReadLineAsync(
        NetworkStream stream, CancellationToken ct, bool echoChars)
    {
        var sb = new StringBuilder();
        var buf = new byte[1];

        while (true)
        {
            int n;
            try { n = await stream.ReadAsync(buf, ct); }
            catch { return null; }
            if (n == 0) return null;

            byte b = buf[0];

            if (b == TelnetNegotiator.IAC)
            {
                // consume the full IAC sequence
                var iacBuf = new byte[2];
                n = await stream.ReadAsync(iacBuf, ct);
                if (n >= 1 && iacBuf[0] is TelnetNegotiator.WILL or TelnetNegotiator.WONT
                                         or TelnetNegotiator.DO or TelnetNegotiator.DONT)
                {
                    if (n < 2) await stream.ReadAsync(iacBuf, ct);
                    // respond if needed
                }
                continue;
            }

            if (b == '\r' || b == '\n') break;
            if (b == 127 || b == 8)    // backspace
            {
                if (sb.Length > 0)
                {
                    sb.Remove(sb.Length - 1, 1);
                    if (echoChars)
                        await stream.WriteAsync("\b \b"u8.ToArray(), ct);
                }
                continue;
            }
            if (b < 32) continue; // ignore other control chars

            sb.Append((char)b);
            if (echoChars)
                await stream.WriteAsync(buf, ct); // echo the character
        }

        return sb.ToString();
    }

    private static async Task SendLineAsync(NetworkStream stream, string text, CancellationToken ct)
    {
        var bytes = Encoding.ASCII.GetBytes(text + "\r\n");
        await stream.WriteAsync(bytes, ct);
    }

    private static bool ParseLogin(string login,
        out string pamUser, out string targetHost, out int targetPort)
    {
        pamUser    = string.Empty;
        targetHost = string.Empty;
        targetPort = 23;

        var atIdx = login.LastIndexOf('@');
        if (atIdx <= 0 || atIdx == login.Length - 1) return false;

        pamUser = login[..atIdx];
        var hostPart = login[(atIdx + 1)..];

        var colonIdx = hostPart.LastIndexOf(':');
        if (colonIdx > 0 && int.TryParse(hostPart[(colonIdx + 1)..], out var port))
        {
            targetHost = hostPart[..colonIdx];
            targetPort = port;
        }
        else
        {
            targetHost = hostPart;
        }

        return !string.IsNullOrWhiteSpace(pamUser) && !string.IsNullOrWhiteSpace(targetHost);
    }
}
