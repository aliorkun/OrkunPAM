using System.Net.Sockets;
using OrkunPAM.RdpProxy.Protocol;
using OrkunPAM.RdpProxy.Session;

namespace OrkunPAM.RdpProxy.Server;

/// <summary>
/// Handles a single RDP proxied session:
///   1. Parse X.224 CR — extract PAM session token from RDP cookie.
///   2. Validate token via PAM API → get target IP + credentials.
///   3. Connect to target server TCP.
///   4. Relay traffic bidirectionally while recording both streams.
///
/// Protocol note: The proxy operates at the TCP relay level (below TLS).
/// It reads the plaintext X.224 CR (sent before TLS negotiation) to extract
/// the session token, then forwards the negotiation CC and relays everything
/// thereafter.  Credential injection at the CLIENT_INFO_PDU level (replacing
/// vault credentials inline) is planned for v2 once TLS termination is added.
/// </summary>
internal sealed class RdpServerSession
{
    private readonly TcpClient _client;
    private readonly PamApiClient _api;
    private readonly RdpProxyOptions _opts;
    private readonly ILogger _log;
    private readonly CancellationToken _ct;

    private static readonly TimeSpan RelayTimeout = TimeSpan.FromHours(8);

    public RdpServerSession(
        TcpClient client,
        PamApiClient api,
        RdpProxyOptions opts,
        ILogger log,
        CancellationToken ct)
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
        _log.LogInformation("RDP connection from {ClientIp}", clientIp);

        await using var clientStream = _client.GetStream();
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(_ct);
        sessionCts.CancelAfter(RelayTimeout);
        var ct = sessionCts.Token;

        // 1. Read the initial X.224 CR (plain TCP — sent before TLS)
        byte[]? crPacket;
        try { crPacket = await TpktPacket.ReadAsync(clientStream, ct); }
        catch { return; }

        if (crPacket == null)
        {
            _log.LogWarning("RDP from {ClientIp}: no initial TPKT packet", clientIp);
            return;
        }

        var (sessionToken, requestedProtocols) = X224Packet.ParseConnectionRequest(crPacket);

        if (string.IsNullOrEmpty(sessionToken))
        {
            _log.LogWarning("RDP from {ClientIp}: no session token in cookie", clientIp);
            await clientStream.WriteAsync(X224Packet.BuildConnectionFailure(2), ct);
            return;
        }

        _log.LogInformation("RDP from {ClientIp}: session token={Token}", clientIp, sessionToken[..Math.Min(8, sessionToken.Length)]);

        // 2. Validate the session token against PAM API
        RdpSessionInfo sessionInfo;
        try { sessionInfo = await _api.ValidateSessionTokenAsync(sessionToken, ct); }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "RDP from {ClientIp}: session token validation failed", clientIp);
            await clientStream.WriteAsync(X224Packet.BuildConnectionFailure(5), ct);
            return;
        }

        _log.LogInformation("RDP session {SessionId}: {ClientIp} → {TargetIp}:{TargetPort}",
            sessionInfo.SessionId, clientIp, sessionInfo.TargetIp, sessionInfo.TargetPort);

        // 3. Send X.224 CC to client accepting TLS
        var ccPacket = X224Packet.BuildConnectionConfirm(X224Packet.ProtocolSsl);
        await clientStream.WriteAsync(ccPacket, ct);

        // 4. Connect to target server
        TcpClient? targetClient = null;
        try
        {
            targetClient = new TcpClient();
            targetClient.NoDelay = true;
            await targetClient.ConnectAsync(sessionInfo.TargetIp, sessionInfo.TargetPort, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "RDP session {SessionId}: cannot connect to target {TargetIp}:{TargetPort}",
                sessionInfo.SessionId, sessionInfo.TargetIp, sessionInfo.TargetPort);
            targetClient?.Dispose();
            return;
        }

        _log.LogInformation("RDP session {SessionId}: target connection established", sessionInfo.SessionId);

        var masterKey = string.IsNullOrEmpty(_opts.RecordingEncryptionKeyBase64)
            ? null : Convert.FromBase64String(_opts.RecordingEncryptionKeyBase64);
        await using var recorder = await RdpSessionRecorder.CreateAsync(
            _opts.RecordingDirectory, sessionInfo.SessionId, masterKey);

        using (targetClient)
        await using (var targetStream = targetClient.GetStream())
        {
            // 5. Forward the client's X.224 CR to the target then consume target's CC
            await targetStream.WriteAsync(crPacket, ct);
            await TpktPacket.ReadAsync(targetStream, ct);

            var startTime = DateTimeOffset.UtcNow;
            try
            {
                await RelayAsync(clientStream, targetStream, recorder, ct);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) when (IsExpectedDisconnect(ex))
            {
                _log.LogDebug("RDP session {SessionId}: client disconnected", sessionInfo.SessionId);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "RDP session {SessionId}: relay error", sessionInfo.SessionId);
            }

            var duration = (int)(DateTimeOffset.UtcNow - startTime).TotalSeconds;
            _log.LogInformation("RDP session {SessionId} ended — duration {Sec}s, recording={Path}",
                sessionInfo.SessionId, duration, recorder.FilePath);

            Array.Clear(sessionInfo.TargetPasswordBytes, 0, sessionInfo.TargetPasswordBytes.Length);

            _ = _api.ReportSessionEndedAsync(sessionInfo.SessionId, duration, recorder.FilePath, CancellationToken.None);
        }
    }

    private static async Task RelayAsync(
        NetworkStream client,
        NetworkStream target,
        RdpSessionRecorder recorder,
        CancellationToken ct)
    {
        const int BufSize = 65536;
        var buf1 = new byte[BufSize];
        var buf2 = new byte[BufSize];

        var clientToTarget = PumpAsync(client, target, buf1, fromTarget: false, recorder, ct);
        var targetToClient = PumpAsync(target, client, buf2, fromTarget: true,  recorder, ct);

        await Task.WhenAny(clientToTarget, targetToClient);
        ct.ThrowIfCancellationRequested();
    }

    private static async Task PumpAsync(
        Stream from,
        Stream to,
        byte[] buf,
        bool fromTarget,
        RdpSessionRecorder recorder,
        CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            int read = await from.ReadAsync(buf, ct);
            if (read == 0) break;

            await recorder.WriteAsync(fromTarget, buf.AsMemory(0, read));
            await to.WriteAsync(buf.AsMemory(0, read), ct);
        }
    }

    private static bool IsExpectedDisconnect(Exception ex) =>
        ex is IOException or SocketException;
}
