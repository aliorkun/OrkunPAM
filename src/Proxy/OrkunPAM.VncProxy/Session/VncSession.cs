using System.Net.Sockets;
using OrkunPAM.VncProxy.Protocol;

namespace OrkunPAM.VncProxy.Session;

/// <summary>
/// Handles a single privileged VNC session:
///
///   1. VeNCrypt Plain handshake with client — extracts pamUser, pamPassword, targetHost.
///   2. Authenticates PAM user against PAM API.
///   3. Retrieves vault VNC credential for the target device.
///   4. Connects to real VNC server and authenticates with vault password.
///   5. Sends SecurityResult=OK to client, relays ClientInit → target.
///   6. Forwards ServerInit from target to client.
///   7. Relays all subsequent RFB messages bidirectionally.
///   8. Records target→client RFB stream to a .rfb binary file.
/// </summary>
internal sealed class VncSession
{
    private readonly TcpClient _client;
    private readonly PamApiClient _api;
    private readonly VncProxyOptions _opts;
    private readonly ILogger _log;
    private readonly CancellationToken _ct;

    private static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(12);

    public VncSession(
        TcpClient client, PamApiClient api,
        VncProxyOptions opts, ILogger log, CancellationToken ct)
    {
        _client = client;
        _api    = api;
        _opts   = opts;
        _log    = log;
        _ct     = ct;
    }

    public async Task RunAsync()
    {
        var clientIp = _client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        _log.LogInformation("VNC connection from {ClientIp}", clientIp);

        await using var clientStream = _client.GetStream();
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(_ct);
        sessionCts.CancelAfter(SessionTimeout);
        var ct = sessionCts.Token;

        // ── 1. VeNCrypt Plain handshake ─────────────────────────────────────────────
        string pamUser, pamPassword, targetHost;
        int targetPort;
        try
        {
            (pamUser, pamPassword, targetHost, targetPort) =
                await RfbHandshake.HandshakeClientAsync(clientStream, ct);
        }
        catch (Exception ex)
        {
            _log.LogWarning("VNC from {ClientIp}: handshake failed — {Msg}", clientIp, ex.Message);
            return;
        }

        _log.LogInformation("VNC from {ClientIp}: user={User} target={Target}:{Port}",
            clientIp, pamUser, targetHost, targetPort);

        // ── 2. PAM authentication ───────────────────────────────────────────────────
        if (string.IsNullOrEmpty(pamPassword) ||
            !await _api.ValidateUserAsync(pamUser, pamPassword, ct))
        {
            _log.LogWarning("VNC from {ClientIp}: PAM auth failed for '{User}'", clientIp, pamUser);
            try { await RfbHandshake.SendSecurityResultAsync(clientStream, false, $"Authentication failed for '{pamUser}'.", ct); }
            catch { /* best-effort */ }
            return;
        }

        // ── 3. Vault credential lookup ──────────────────────────────────────────────
        string targetIp, vaultVncPassword;
        int resolvedPort;
        try
        {
            (targetIp, resolvedPort, vaultVncPassword) =
                await _api.GetTargetCredentialAsync(pamUser, targetHost, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "VNC {User}→{Target}: vault credential retrieval failed", pamUser, targetHost);
            try { await RfbHandshake.SendSecurityResultAsync(clientStream, false, $"No VNC credential found for '{targetHost}'.", ct); }
            catch { /* best-effort */ }
            return;
        }

        // ── 4. Connect to target VNC ────────────────────────────────────────────────
        TcpClient? targetClient = null;
        byte[] serverInitPayload;
        try
        {
            (targetClient, serverInitPayload) =
                await RfbHandshake.ConnectTargetAsync(targetIp, resolvedPort, vaultVncPassword, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "VNC {User}: cannot connect to {TargetIp}:{TargetPort}", pamUser, targetIp, resolvedPort);
            targetClient?.Dispose();
            try { await RfbHandshake.SendSecurityResultAsync(clientStream, false, $"Cannot connect to VNC server at '{targetHost}'.", ct); }
            catch { /* best-effort */ }
            return;
        }

        // ── 5. Send SecurityResult=OK and relay ──────────────────────────────────────
        try
        {
            await RfbHandshake.SendSecurityResultAsync(clientStream, true, null, ct);
        }
        catch (Exception ex)
        {
            _log.LogDebug("VNC {User}: failed to send SecurityResult OK — {Msg}", pamUser, ex.Message);
            targetClient.Dispose();
            return;
        }

        var sessionId = Guid.NewGuid().ToString("N");
        _log.LogInformation("VNC session {SessionId} established: {PamUser}→{TargetIp}:{TargetPort}",
            sessionId, pamUser, targetIp, resolvedPort);

        using (targetClient)
        await using (var targetStream = targetClient.GetStream())
        await using (var recorder = VncSessionRecorder.Create(_opts.RecordingDirectory, sessionId, pamUser, targetHost))
        {
            try
            {
                // ── 5a. ClientInit: read from client, forward to target ──────────────
                var clientInitBuf = new byte[1];
                await RfbHandshake.ReadExactlyAsync(clientStream, clientInitBuf, ct);
                await targetStream.WriteAsync(clientInitBuf, ct);

                // ── 5b. ServerInit: forward from target to client, record ───────────
                await clientStream.WriteAsync(serverInitPayload, ct);
                recorder.Write(serverInitPayload);

                var (idleTimeoutMinutes, _) = await _api.GetSessionPolicyAsync(ct);
                var startTime = DateTimeOffset.UtcNow;

                // ── 6. Bidirectional relay with recording ───────────────────────────
                await RelayAsync(clientStream, targetStream, recorder, ct, idleTimeoutMinutes);

                var duration = (int)(DateTimeOffset.UtcNow - startTime).TotalSeconds;
                _log.LogInformation("VNC session {SessionId} ended — {Sec}s user={PamUser}",
                    sessionId, duration, pamUser);

                _ = _api.ReportSessionEndedAsync(sessionId, duration,
                    recorder.FilePath ?? "", CancellationToken.None);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) when (ex is IOException or SocketException)
            {
                _log.LogDebug("VNC session {SessionId}: connection closed", sessionId);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "VNC session {SessionId}: relay error", sessionId);
            }
        }
    }

    // ── Relay loop ──────────────────────────────────────────────────────────────────

    private static async Task RelayAsync(
        NetworkStream clientStream,
        NetworkStream targetStream,
        VncSessionRecorder recorder,
        CancellationToken ct,
        int idleTimeoutMinutes)
    {
        long[] lastActivityTicks = [DateTime.UtcNow.Ticks];
        using var idleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        // client→target: raw relay (no recording — we don’t log keystrokes by default)
        var clientToTarget = PumpAsync(clientStream, targetStream, recorder: null, idleCts.Token, lastActivityTicks);
        // target→client: raw relay + record framebuffer updates
        var targetToClient = PumpAsync(targetStream, clientStream, recorder, idleCts.Token, lastActivityTicks);
        var idleWatcher    = IdleWatchAsync(idleTimeoutMinutes, lastActivityTicks, idleCts);

        await Task.WhenAny(clientToTarget, targetToClient, idleWatcher);
        await idleCts.CancelAsync();

        try { await Task.WhenAll(clientToTarget, targetToClient); }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or SocketException) { }
    }

    private static async Task PumpAsync(
        Stream src, Stream dst,
        VncSessionRecorder? recorder,
        CancellationToken ct,
        long[] lastActivityTicks)
    {
        var buf = new byte[65536];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await src.ReadAsync(buf, ct);
                if (read == 0) break;

                Interlocked.Exchange(ref lastActivityTicks[0], DateTime.UtcNow.Ticks);
                await dst.WriteAsync(buf.AsMemory(0, read), ct);
                recorder?.Write(buf.AsSpan(0, read));
            }
        }
        catch (OperationCanceledException) { }
    }

    private static async Task IdleWatchAsync(
        int timeoutMinutes, long[] lastActivityTicks, CancellationTokenSource cts)
    {
        var timeout = TimeSpan.FromMinutes(timeoutMinutes);
        try
        {
            while (!cts.IsCancellationRequested)
            {
                await Task.Delay(30_000, cts.Token);
                var idleFor = TimeSpan.FromTicks(DateTime.UtcNow.Ticks - Interlocked.Read(ref lastActivityTicks[0]));
                if (idleFor >= timeout)
                {
                    await cts.CancelAsync();
                    return;
                }
            }
        }
        catch (OperationCanceledException) { }
    }
}
