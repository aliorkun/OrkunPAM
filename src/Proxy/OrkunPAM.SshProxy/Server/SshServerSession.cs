using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using OrkunPAM.SshProxy.Client;
using OrkunPAM.SshProxy.Crypto;
using OrkunPAM.SshProxy.Protocol;

namespace OrkunPAM.SshProxy.Server;

/// <summary>
/// Handles one SSH client connection acting as SSH server (PAM proxy server side).
/// Flow: version exchange → KEXINIT → DH key exchange → NEWKEYS → userauth → channel → relay.
/// </summary>
internal sealed class SshServerSession
{
    private const string ServerVersion = "SSH-2.0-OrkunPAM_1.0";

    private readonly SshConnection _conn;
    private readonly SshHostKey _hostKey;
    private readonly PamApiClient _api;
    private readonly ILogger _log;
    private readonly CancellationToken _ct;

    // KexInit payloads saved for exchange hash computation
    private byte[] _serverKexInitPayload = [];
    private byte[] _clientKexInitPayload = [];
    private string _clientVersion = "";
    private byte[]? _sessionId;

    internal SshServerSession(TcpClient client, SshHostKey hostKey, PamApiClient api,
        ILogger log, CancellationToken ct)
    {
        _conn = new SshConnection(client.GetStream());
        _hostKey = hostKey;
        _api = api;
        _log = log;
        _ct = ct;
    }

    internal async Task RunAsync()
    {
        try
        {
            _clientVersion = await _conn.ExchangeVersionsAsync(ServerVersion, _ct);
            _log.LogInformation("Client connected, version: {Version}", _clientVersion);

            await DoKeyExchangeAsync();

            var (pamUser, targetHost, pamPassword) = await DoUserAuthAsync();

            var (targetIp, targetPort, targetUser, targetPassword) =
                await _api.GetTargetCredentialAsync(pamUser, targetHost, _ct);

            _log.LogInformation("Relay: {PamUser}@{Target}:{Port}", pamUser, targetIp, targetPort);

            // Connect to target and start relay
            using var target = new SshTargetClient(
                targetIp, targetPort, targetUser, targetPassword, _log);
            await target.ConnectAsync(_ct);

            await RelayAsync(target);
        }
        catch (OperationCanceledException) { }
        catch (SshException ex) { _log.LogWarning("SSH protocol error: {Msg}", ex.Message); }
        catch (Exception ex) { _log.LogError(ex, "Session error"); }
        finally
        {
            await _conn.DisposeAsync();
        }
    }

    // -------------------------------------------------------------------------
    // Key Exchange
    // -------------------------------------------------------------------------

    private async Task DoKeyExchangeAsync()
    {
        // Build and send server KEXINIT
        var serverKexInit = BuildKexInit();
        _serverKexInitPayload = serverKexInit;
        await _conn.SendPacketAsync(serverKexInit, _ct);

        // Receive client KEXINIT
        var clientKexPkt = await _conn.ReadPacketAsync(_ct);
        if (clientKexPkt[0] != Msg.KexInit)
            throw new SshException($"Expected KEXINIT, got {clientKexPkt[0]}");
        _clientKexInitPayload = clientKexPkt;

        // Receive SSH_MSG_KEXDH_INIT (client's DH public value e)
        var dhInitPkt = await _conn.ReadPacketAsync(_ct);
        if (dhInitPkt[0] != Msg.KexDhInit)
            throw new SshException($"Expected KEXDH_INIT, got {dhInitPkt[0]}");

        int offset = 1;
        var e = SshEncoding.ReadMpInt(dhInitPkt, ref offset);

        // Compute server DH
        var dh = new DhGroup14();
        var K = dh.ComputeSharedSecret(e);
        var hostKeyBlob = _hostKey.GetPublicKeyBlob();

        // Compute exchange hash H
        var H = ComputeExchangeHash(hostKeyBlob, e, dh.PublicKey, K);
        _sessionId ??= H;

        var signature = _hostKey.Sign(H);

        // Send KEXDH_REPLY
        using var reply = new MemoryStream();
        SshEncoding.WriteByte(reply, Msg.KexDhReply);
        SshEncoding.WriteByteString(reply, hostKeyBlob);
        SshEncoding.WriteMpInt(reply, dh.PublicKey);
        SshEncoding.WriteByteString(reply, signature);
        await _conn.SendAsync(reply, _ct);

        // Send NEWKEYS
        await _conn.SendPacketAsync([Msg.NewKeys], _ct);

        // Receive client NEWKEYS
        var newkeys = await _conn.ReadPacketAsync(_ct);
        if (newkeys[0] != Msg.NewKeys)
            throw new SshException("Expected NEWKEYS");

        // Derive and activate session keys
        var keys = DhGroup14.DeriveKeys(K, H, _sessionId);
        // Server reads from client (C→S) and writes to client (S→C)
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
        SshEncoding.WriteNameList(ms, "rsa-sha2-256", "ssh-rsa");
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
        using var ms = new MemoryStream();

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
    // User Auth (SSH_MSG_USERAUTH)
    // -------------------------------------------------------------------------

    private async Task<(string pamUser, string targetHost, string pamPassword)> DoUserAuthAsync()
    {
        var svcReq = await _conn.ReadPacketAsync(_ct);
        if (svcReq[0] != Msg.ServiceRequest)
            throw new SshException($"Expected SERVICE_REQUEST, got {svcReq[0]}");

        int o = 1;
        var svcName = SshEncoding.ReadString(svcReq, ref o);
        if (svcName != "ssh-userauth")
            throw new SshException("Unexpected service: " + svcName);

        using var acceptMs = new MemoryStream();
        SshEncoding.WriteByte(acceptMs, Msg.ServiceAccept);
        SshEncoding.WriteString(acceptMs, "ssh-userauth");
        await _conn.SendAsync(acceptMs, _ct);

        using var bannerMs = new MemoryStream();
        SshEncoding.WriteByte(bannerMs, Msg.UserauthBanner);
        SshEncoding.WriteString(bannerMs, "OrkunPAM - Privileged Access Management\r\nUsername: pamuser@target-host\r\n");
        SshEncoding.WriteString(bannerMs, "en");
        await _conn.SendAsync(bannerMs, _ct);

        for (int attempt = 0; attempt < 5; attempt++)
        {
            var authPkt = await _conn.ReadPacketAsync(_ct);
            if (authPkt[0] != Msg.UserauthRequest)
                throw new SshException("Expected USERAUTH_REQUEST");

            int pos = 1;
            var username  = SshEncoding.ReadString(authPkt, ref pos);
            var _service  = SshEncoding.ReadString(authPkt, ref pos);
            var method    = SshEncoding.ReadString(authPkt, ref pos);

            if (method is not "password")
            {
                await SendAuthFailureAsync("password");
                continue;
            }

            var _changeReq = SshEncoding.ReadBool(authPkt, ref pos);
            var password   = SshEncoding.ReadString(authPkt, ref pos);

            var atIdx = username.IndexOf('@');
            string pamUser    = atIdx > 0 ? username[..atIdx]     : username;
            string targetHost = atIdx > 0 ? username[(atIdx + 1)..] : "";

            if (string.IsNullOrEmpty(targetHost))
            {
                await SendAuthFailureAsync("password");
                continue;
            }

            if (!await _api.ValidateUserAsync(pamUser, password, _ct))
            {
                _log.LogWarning("Auth failure for {User}", pamUser);
                await SendAuthFailureAsync("password");
                continue;
            }

            await _conn.SendPacketAsync([Msg.UserauthSuccess], _ct);
            _log.LogInformation("Authenticated: {User} → {Target}", pamUser, targetHost);
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
    // Channel handling + relay
    // -------------------------------------------------------------------------

    private async Task RelayAsync(SshTargetClient target)
    {
        var pkt = await _conn.ReadPacketAsync(_ct);
        if (pkt[0] != Msg.ChannelOpen)
            throw new SshException("Expected CHANNEL_OPEN");

        int pos = 1;
        var _chanType    = SshEncoding.ReadString(pkt, ref pos);
        var clientChanId = SshEncoding.ReadUInt32(pkt, ref pos);
        var _clientWin   = SshEncoding.ReadUInt32(pkt, ref pos);
        var _clientMax   = SshEncoding.ReadUInt32(pkt, ref pos);

        using var confMs = new MemoryStream();
        SshEncoding.WriteByte(confMs, Msg.ChannelOpenConf);
        SshEncoding.WriteUInt32(confMs, clientChanId);
        SshEncoding.WriteUInt32(confMs, 0);           // server channel id
        SshEncoding.WriteUInt32(confMs, 1024 * 1024); // server window
        SshEncoding.WriteUInt32(confMs, 32768);        // max packet
        await _conn.SendAsync(confMs, _ct);

        bool shellStarted = false;
        while (!shellStarted)
        {
            var reqPkt = await _conn.ReadPacketAsync(_ct);
            if (reqPkt[0] == Msg.ChannelRequest)
            {
                pos = 1;
                var _recipChan = SshEncoding.ReadUInt32(reqPkt, ref pos);
                var reqType    = SshEncoding.ReadString(reqPkt, ref pos);
                var wantReply  = SshEncoding.ReadBool(reqPkt, ref pos);

                if (reqType == "pty-req")
                {
                    if (wantReply) await SendChannelSuccessAsync(clientChanId);
                }
                else if (reqType is "shell" or "exec")
                {
                    if (wantReply) await SendChannelSuccessAsync(clientChanId);
                    shellStarted = true;
                }
                else
                {
                    if (wantReply) await SendChannelFailureAsync(clientChanId);
                }
            }
            // ignore ChannelWinAdj and other pre-shell messages
        }

        await target.RelayToClientAsync(_conn, clientChanId, _ct);
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
