using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using OrkunPAM.SshProxy.Client;
using OrkunPAM.SshProxy.Crypto;
using OrkunPAM.SshProxy.Protocol;
using OrkunPAM.SshProxy.Session;

namespace OrkunPAM.SshProxy.Server;

/// <summary>
/// Handles one SSH client connection acting as SSH server (PAM proxy server side).
/// Flow: version exchange → KEXINIT → DH key exchange → NEWKEYS → userauth →
///       channel open → pty-req → shell/exec → relay (with session recording).
/// </summary>
internal sealed class SshServerSession
{
    private const string ServerVersion = "SSH-2.0-OrkunPAM_1.0";

    private readonly SshConnection _conn;
    private readonly SshHostKey _hostKey;
    private readonly PamApiClient _api;
    private readonly SshProxyOptions _opts;
    private readonly ILogger _log;
    private readonly CancellationToken _ct;
    private readonly HashChainStore? _hashChain;

    private byte[] _serverKexInitPayload = [];
    private byte[] _clientKexInitPayload = [];
    private string _clientVersion = "";
    private byte[]? _sessionId;
    private readonly string _clientIp;

    internal SshServerSession(TcpClient client, SshHostKey hostKey, PamApiClient api,
        SshProxyOptions opts, ILogger log, CancellationToken ct, HashChainStore? hashChain = null)
    {
        _clientIp  = ((System.Net.IPEndPoint?)client.Client.RemoteEndPoint)?.Address.ToString() ?? "unknown";
        _conn      = new SshConnection(client.GetStream());
        _hostKey   = hostKey;
        _api       = api;
        _opts      = opts;
        _log       = log;
        _ct        = ct;
        _hashChain = hashChain;
    }

    internal async Task RunAsync()
    {
        try
        {
            _clientVersion = await _conn.ExchangeVersionsAsync(ServerVersion, _ct);
            _log.LogInformation("Client connected, version: {Version}", _clientVersion);

            await DoKeyExchangeAsync();

            var (pamUser, targetHost, _) = await DoUserAuthAsync();

            var (targetIp, targetPort, targetUser, targetPassword) =
                await _api.GetTargetCredentialAsync(pamUser, targetHost, _ct);

            _log.LogInformation("Connecting to target {User}@{Host}:{Port} for PAM user '{PamUser}'",
                targetUser, targetIp, targetPort, pamUser);

            using var target = new SshTargetClient(
                targetIp, targetPort, targetUser, targetPassword, _log);
            await target.ConnectAsync(_ct);

            await RelayAsync(target);
        }
        catch (OperationCanceledException) { }
        catch (SshException ex) { _log.LogWarning("SSH protocol error: {Msg}", ex.Message); }
        catch (Exception ex)    { _log.LogError(ex, "Session error"); }
        finally
        {
            await _conn.DisposeAsync();
        }
    }

    // -------------------------------------------------------------------------
    // Key Exchange (server side)
    // -------------------------------------------------------------------------

    private async Task DoKeyExchangeAsync()
    {
        var serverKexInit = BuildKexInit();
        _serverKexInitPayload = serverKexInit;
        await _conn.SendPacketAsync(serverKexInit, _ct);

        var clientKexPkt = await _conn.ReadPacketAsync(_ct);
        if (clientKexPkt[0] != Msg.KexInit)
            throw new SshException($"Expected KEXINIT, got {clientKexPkt[0]}");
        _clientKexInitPayload = clientKexPkt;

        var dhInitPkt = await _conn.ReadPacketAsync(_ct);
        if (dhInitPkt[0] != Msg.KexDhInit)
            throw new SshException($"Expected KEXDH_INIT, got {dhInitPkt[0]}");

        int offset = 1;
        var e = SshEncoding.ReadMpInt(dhInitPkt, ref offset);

        var dh         = new DhGroup14();
        var K          = dh.ComputeSharedSecret(e);
        var hostKeyBlob = _hostKey.GetPublicKeyBlob();
        var H          = ComputeExchangeHash(hostKeyBlob, e, dh.PublicKey, K);
        _sessionId ??= H;

        var signature = _hostKey.Sign(H);

        using var reply = new MemoryStream();
        SshEncoding.WriteByte(reply, Msg.KexDhReply);
        SshEncoding.WriteByteString(reply, hostKeyBlob);
        SshEncoding.WriteMpInt(reply, dh.PublicKey);
        SshEncoding.WriteByteString(reply, signature);
        await _conn.SendAsync(reply, _ct);

        await _conn.SendPacketAsync([Msg.NewKeys], _ct);

        var newkeys = await _conn.ReadPacketAsync(_ct);
        if (newkeys[0] != Msg.NewKeys)
            throw new SshException("Expected NEWKEYS");

        var keys = DhGroup14.DeriveKeys(K, H, _sessionId);
        _conn.EnableEncryption(
            rxKey: keys.EkC2S, rxIv: keys.IvC2S, rxMacKey: keys.MkC2S,
            txKey: keys.EkS2C, txIv: keys.IvS2C, txMacKey: keys.MkS2C);

        _log.LogDebug("Key exchange complete, encryption enabled");
    }

    private byte[] BuildKexInit()
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.KexInit);
        var cookie = new byte[16];
        RandomNumberGenerator.Fill(cookie);
        SshEncoding.WriteBytes(ms, cookie);
        SshEncoding.WriteNameList(ms, Alg.Kex);
        SshEncoding.WriteNameList(ms, "rsa-sha2-256");
        SshEncoding.WriteNameList(ms, Alg.Cipher);
        SshEncoding.WriteNameList(ms, Alg.Cipher);
        SshEncoding.WriteNameList(ms, Alg.Mac);
        SshEncoding.WriteNameList(ms, Alg.Mac);
        SshEncoding.WriteNameList(ms, Alg.Compression);
        SshEncoding.WriteNameList(ms, Alg.Compression);
        SshEncoding.WriteString(ms, "");
        SshEncoding.WriteString(ms, "");
        SshEncoding.WriteBool(ms, false);
        SshEncoding.WriteUInt32(ms, 0);
        return ms.ToArray();
    }

    private byte[] ComputeExchangeHash(byte[] hostKeyBlob, BigInteger e, BigInteger f, BigInteger K)
    {
        using var sha = SHA256.Create();
        using var ms  = new MemoryStream();

        SshEncoding.WriteByteString(ms, Encoding.ASCII.GetBytes(_clientVersion));
        SshEncoding.WriteByteString(ms, Encoding.ASCII.GetBytes(ServerVersion));
        SshEncoding.WriteByteString(ms, _clientKexInitPayload);
        SshEncoding.WriteByteString(ms, _serverKexInitPayload);
        SshEncoding.WriteByteString(ms, hostKeyBlob);
        SshEncoding.WriteMpInt(ms, e);
        SshEncoding.WriteMpInt(ms, f);
        SshEncoding.WriteMpInt(ms, K);

        return sha.ComputeHash(ms.ToArray());
    }

    // -------------------------------------------------------------------------
    // User Auth (PAM credentials — username format: pamuser@target-host)
    // -------------------------------------------------------------------------

    private async Task<(string pamUser, string targetHost, string pamPassword)> DoUserAuthAsync()
    {
        var svcReq = await _conn.ReadPacketAsync(_ct);
        if (svcReq[0] != Msg.ServiceRequest)
            throw new SshException($"Expected SERVICE_REQUEST, got {svcReq[0]}");

        int o       = 1;
        var svcName = SshEncoding.ReadString(svcReq, ref o);
        if (svcName != "ssh-userauth")
            throw new SshException("Unexpected service: " + svcName);

        using var acceptMs = new MemoryStream();
        SshEncoding.WriteByte(acceptMs, Msg.ServiceAccept);
        SshEncoding.WriteString(acceptMs, "ssh-userauth");
        await _conn.SendAsync(acceptMs, _ct);

        using var bannerMs = new MemoryStream();
        SshEncoding.WriteByte(bannerMs, Msg.UserauthBanner);
        SshEncoding.WriteString(bannerMs,
            "OrkunPAM - Privileged Access Management\r\nUsername format: pamuser@target-host\r\n");
        SshEncoding.WriteString(bannerMs, "en");
        await _conn.SendAsync(bannerMs, _ct);

        for (int attempt = 0; attempt < 5; attempt++)
        {
            var authPkt = await _conn.ReadPacketAsync(_ct);
            if (authPkt[0] != Msg.UserauthRequest)
                throw new SshException("Expected USERAUTH_REQUEST");

            int pos      = 1;
            var username = SshEncoding.ReadString(authPkt, ref pos);
            var _service = SshEncoding.ReadString(authPkt, ref pos);
            var method   = SshEncoding.ReadString(authPkt, ref pos);

            if (method != "password")
            {
                await SendAuthFailureAsync("password");
                continue;
            }

            var _changeReq = SshEncoding.ReadBool(authPkt, ref pos);
            var password   = SshEncoding.ReadString(authPkt, ref pos);

            var atIdx     = username.IndexOf('@');
            var pamUser   = atIdx > 0 ? username[..atIdx]        : username;
            var targetHost = atIdx > 0 ? username[(atIdx + 1)..]  : "";

            if (string.IsNullOrEmpty(targetHost))
            {
                _log.LogWarning("Auth rejected: no target host in username '{User}'", username);
                await SendAuthFailureAsync("password");
                continue;
            }

            if (!await _api.ValidateUserAsync(pamUser, password, _ct, _clientIp))
            {
                _log.LogWarning("PAM auth failure for '{User}' from {ClientIp}", pamUser, _clientIp);
                await SendAuthFailureAsync("password");
                // Exponential backoff per attempt to slow brute-force: 200ms, 400ms, 800ms, 1600ms, 3200ms
                await Task.Delay(200 << attempt, _ct);
                continue;
            }

            await _conn.SendPacketAsync([Msg.UserauthSuccess], _ct);
            _log.LogInformation("Authenticated: {PamUser} → target '{TargetHost}'",
                pamUser, targetHost);
            return (pamUser, targetHost, password);
        }

        throw new SshException("Too many authentication failures");
    }

    private async Task SendAuthFailureAsync(string methods)
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.UserauthFailure);
        SshEncoding.WriteString(ms, methods);
        SshEncoding.WriteBool(ms, false);
        await _conn.SendAsync(ms, _ct);
    }

    // -------------------------------------------------------------------------
    // Channel handling: capture client requests, then relay
    // -------------------------------------------------------------------------

    private async Task RelayAsync(SshTargetClient target)
    {
        // Step 1: receive CHANNEL_OPEN from client
        var pkt = await _conn.ReadPacketAsync(_ct);
        if (pkt[0] != Msg.ChannelOpen)
            throw new SshException("Expected CHANNEL_OPEN");

        int pos         = 1;
        var _chanType   = SshEncoding.ReadString(pkt, ref pos);
        var clientChanId = SshEncoding.ReadUInt32(pkt, ref pos);
        var _clientWin  = SshEncoding.ReadUInt32(pkt, ref pos);
        var _clientMax  = SshEncoding.ReadUInt32(pkt, ref pos);

        const uint ServerChanId = 0;
        const uint ServerWindow = 1024 * 1024;
        const uint ServerMaxPkt = 32768;

        using var confMs = new MemoryStream();
        SshEncoding.WriteByte(confMs, Msg.ChannelOpenConf);
        SshEncoding.WriteUInt32(confMs, clientChanId);
        SshEncoding.WriteUInt32(confMs, ServerChanId);
        SshEncoding.WriteUInt32(confMs, ServerWindow);
        SshEncoding.WriteUInt32(confMs, ServerMaxPkt);
        await _conn.SendAsync(confMs, _ct);

        // Step 2: collect channel requests from client (pty-req, shell/exec, …)
        PtyParams? pty     = null;
        bool isExec        = false;
        string? execCmd    = null;
        bool sessionReady  = false;

        while (!sessionReady)
        {
            var reqPkt = await _conn.ReadPacketAsync(_ct);
            switch (reqPkt[0])
            {
                case Msg.ChannelRequest:
                {
                    pos = 1;
                    var _recipChan = SshEncoding.ReadUInt32(reqPkt, ref pos);
                    var reqType    = SshEncoding.ReadString(reqPkt, ref pos);
                    var wantReply  = SshEncoding.ReadBool(reqPkt, ref pos);

                    switch (reqType)
                    {
                        case "pty-req":
                        {
                            var termType     = SshEncoding.ReadString(reqPkt, ref pos);
                            var widthChars   = SshEncoding.ReadUInt32(reqPkt, ref pos);
                            var heightRows   = SshEncoding.ReadUInt32(reqPkt, ref pos);
                            var widthPixels  = SshEncoding.ReadUInt32(reqPkt, ref pos);
                            var heightPixels = SshEncoding.ReadUInt32(reqPkt, ref pos);
                            var modes        = SshEncoding.ReadByteString(reqPkt, ref pos);
                            pty = new PtyParams(termType, widthChars, heightRows,
                                widthPixels, heightPixels, modes);
                            if (wantReply) await SendChannelSuccessAsync(clientChanId);
                            break;
                        }
                        case "shell":
                            if (wantReply) await SendChannelSuccessAsync(clientChanId);
                            sessionReady = true;
                            break;
                        case "exec":
                            execCmd = SshEncoding.ReadString(reqPkt, ref pos);
                            isExec  = true;
                            if (wantReply) await SendChannelSuccessAsync(clientChanId);
                            sessionReady = true;
                            break;
                        case "window-change":
                            // Terminal resize before shell is open — just accept, no reply
                            break;
                        default:
                            if (wantReply) await SendChannelFailureAsync(clientChanId);
                            break;
                    }
                    break;
                }

                case Msg.ChannelWinAdj:
                    break; // client adjusting pre-shell window — ignore

                case Msg.GlobalRequest:
                {
                    pos = 1;
                    var _name     = SshEncoding.ReadString(reqPkt, ref pos);
                    var wantReply = SshEncoding.ReadBool(reqPkt, ref pos);
                    if (wantReply)
                        await _conn.SendPacketAsync([Msg.RequestFailure], _ct);
                    break;
                }

                default:
                    break; // silently skip unknown pre-channel messages
            }
        }

        // Step 3: open session on target with the parameters the client requested
        try
        {
            await target.OpenSessionAsync(pty, isExec, execCmd, _ct);
        }
        catch (SshException ex)
        {
            _log.LogError("Target session open failed: {Msg}", ex.Message);
            using var eofMs = new MemoryStream();
            SshEncoding.WriteByte(eofMs, Msg.ChannelEof);
            SshEncoding.WriteUInt32(eofMs, clientChanId);
            await _conn.SendAsync(eofMs, _ct);
            using var closeMs = new MemoryStream();
            SshEncoding.WriteByte(closeMs, Msg.ChannelClose);
            SshEncoding.WriteUInt32(closeMs, clientChanId);
            await _conn.SendAsync(closeMs, _ct);
            return;
        }

        _log.LogInformation("Relay started for channel {ChanId} (pty={HasPty}, exec={IsExec})",
            clientChanId, pty != null, isExec);

        // Step 4: record + relay
        var recorder = new SessionRecorder(_opts.RecordingDirectory, _log, pty, _hashChain);
        recorder.Start(_sessionId);

        try
        {
            await target.RelayToClientAsync(_conn, clientChanId, recorder, _ct);
        }
        finally
        {
            recorder.Stop();
            await recorder.FlushAsync();
        }
    }

    private async Task SendChannelSuccessAsync(uint recipientChan)
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.ChannelSuccess);
        SshEncoding.WriteUInt32(ms, recipientChan);
        await _conn.SendAsync(ms, _ct);
    }

    private async Task SendChannelFailureAsync(uint recipientChan)
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.ChannelFailure);
        SshEncoding.WriteUInt32(ms, recipientChan);
        await _conn.SendAsync(ms, _ct);
    }
}
