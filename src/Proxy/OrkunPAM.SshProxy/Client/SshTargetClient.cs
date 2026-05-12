using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using OrkunPAM.SshProxy.Crypto;
using OrkunPAM.SshProxy.Protocol;
using OrkunPAM.SshProxy.Session;

namespace OrkunPAM.SshProxy.Client;

/// <summary>
/// SSH client that connects PAM to the target server.
/// ConnectAsync handles TCP + key exchange + user auth only.
/// OpenSessionAsync opens the session channel with PTY/exec forwarding,
/// so it can be called after the PAM server has captured the client's
/// pty-req and shell/exec parameters.
/// </summary>
internal sealed class SshTargetClient : IDisposable
{
    private const string ClientVersion = "SSH-2.0-OrkunPAM_1.0";

    private readonly string _host;
    private readonly int _port;
    private readonly string _username;
    private byte[] _password;
    private readonly ILogger _log;
    private readonly string? _expectedFingerprint;

    internal string? ObservedFingerprint { get; private set; }

    private TcpClient? _tcp;
    private SshConnection? _conn;
    private uint _serverChanId;
    private readonly uint _clientChanId = 1;
    private string _targetSshVersion = "SSH-2.0-Unknown";

    internal SshTargetClient(string host, int port, string username, byte[] password, ILogger log,
        string? expectedFingerprint = null)
    {
        _host                = host;
        _port                = port;
        _username            = username;
        _password            = password;
        _log                 = log;
        _expectedFingerprint = expectedFingerprint;
    }

    // -------------------------------------------------------------------------
    // Phase 1: TCP + key exchange + user auth (no channel yet)
    // -------------------------------------------------------------------------

    internal async Task ConnectAsync(CancellationToken ct)
    {
        _tcp = new TcpClient();
        await _tcp.ConnectAsync(_host, _port, ct);
        _conn = new SshConnection(_tcp.GetStream());

        _targetSshVersion = await _conn.ExchangeVersionsAsync(ClientVersion, ct);
        _log.LogDebug("Target SSH version: {Ver}", _targetSshVersion);

        await DoKeyExchangeAsync(ct);
        await DoUserAuthAsync(ct);
        CryptographicOperations.ZeroMemory(_password);

        _log.LogInformation("Authenticated to target {Host}:{Port} as '{User}'",
            _host, _port, _username);
    }

    // -------------------------------------------------------------------------
    // Phase 2: Open session channel with PTY / exec / shell
    // -------------------------------------------------------------------------

    internal async Task OpenSessionAsync(
        PtyParams? pty, bool isExec, string? execCommand, CancellationToken ct)
    {
        await OpenSessionChannelAsync(ct);

        if (pty != null)
            await SendPtyReqAsync(pty, ct);

        if (isExec && execCommand != null)
            await RequestExecAsync(execCommand, ct);
        else
            await RequestShellAsync(ct);
    }

    // -------------------------------------------------------------------------
    // Key Exchange (client-side, connects to real SSH server on target)
    // -------------------------------------------------------------------------

    private async Task DoKeyExchangeAsync(CancellationToken ct)
    {
        var clientKexPayload = BuildKexInit();
        await _conn!.SendPacketAsync(clientKexPayload, ct);

        var serverKexPkt = await _conn.ReadPacketAsync(ct);
        if (serverKexPkt[0] != Msg.KexInit)
            throw new SshException("Expected KEXINIT from target");
        var serverKexPayload = serverKexPkt;

        var dh = new DhGroup14();

        using var dhInitMs = new MemoryStream();
        SshEncoding.WriteByte(dhInitMs, Msg.KexDhInit);
        SshEncoding.WriteMpInt(dhInitMs, dh.PublicKey);
        await _conn.SendAsync(dhInitMs, ct);

        var replyPkt = await _conn.ReadPacketAsync(ct);
        if (replyPkt[0] != Msg.KexDhReply)
            throw new SshException("Expected KEXDH_REPLY from target");

        int pos = 1;
        var hostKeyBlob = SshEncoding.ReadByteString(replyPkt, ref pos);
        var f           = SshEncoding.ReadMpInt(replyPkt, ref pos);
        var sigBlob     = SshEncoding.ReadByteString(replyPkt, ref pos);

        var K = dh.ComputeSharedSecret(f);
        var H = ComputeExchangeHash(clientKexPayload, serverKexPayload, hostKeyBlob,
            dh.PublicKey, f, K);

        VerifyHostKeySignature(hostKeyBlob, sigBlob, H);

        var fingerprint = ComputeHostKeyFingerprint(hostKeyBlob);
        if (_expectedFingerprint != null && _expectedFingerprint != fingerprint)
        {
            _log.LogCritical("Host key mismatch for {Host} — possible MITM. Expected {Expected}, got {Got}",
                _host, _expectedFingerprint, fingerprint);
            throw new SshException(
                $"Host key fingerprint mismatch for {_host} — connection refused (possible MITM)");
        }
        ObservedFingerprint = fingerprint;
        if (_expectedFingerprint == null)
            _log.LogWarning("TOFU: Host key fingerprint for {Host}: {Fp}", _host, fingerprint);

        _log.LogDebug("Target host key verified ({Bytes}B)", hostKeyBlob.Length);

        await _conn.SendPacketAsync([Msg.NewKeys], ct);

        var newkeys = await _conn.ReadPacketAsync(ct);
        if (newkeys[0] != Msg.NewKeys)
            throw new SshException("Expected NEWKEYS from target");

        var keys = DhGroup14.DeriveKeys(K, H, H);
        _conn.EnableEncryption(
            rxKey: keys.EkS2C, rxIv: keys.IvS2C, rxMacKey: keys.MkS2C,
            txKey: keys.EkC2S, txIv: keys.IvC2S, txMacKey: keys.MkC2S);
    }

    private static byte[] BuildKexInit()
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.KexInit);
        var cookie = new byte[16];
        RandomNumberGenerator.Fill(cookie);
        SshEncoding.WriteBytes(ms, cookie);
        SshEncoding.WriteNameList(ms, Alg.Kex);
        SshEncoding.WriteNameList(ms, "rsa-sha2-256", "ecdsa-sha2-nistp256");
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

    private static string ComputeHostKeyFingerprint(byte[] hostKeyBlob) =>
        Convert.ToHexString(SHA256.HashData(hostKeyBlob)).ToLowerInvariant();

    private static void VerifyHostKeySignature(byte[] hostKeyBlob, byte[] sigBlob, byte[] H)
    {
        int kpos    = 0;
        var keyType = SshEncoding.ReadString(hostKeyBlob, ref kpos);
        if (keyType is not ("ssh-rsa" or "rsa-sha2-256"))
            throw new SshException($"Unsupported host key type: {keyType}");
        var e = SshEncoding.ReadMpInt(hostKeyBlob, ref kpos);
        var n = SshEncoding.ReadMpInt(hostKeyBlob, ref kpos);

        int spos    = 0;
        var sigType = SshEncoding.ReadString(sigBlob, ref spos);
        var rawSig  = SshEncoding.ReadByteString(sigBlob, ref spos);

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Exponent = e.ToByteArray(isUnsigned: true, isBigEndian: true),
            Modulus  = n.ToByteArray(isUnsigned: true, isBigEndian: true),
        });

        if (rsa.KeySize < 2048)
            throw new SshException(
                $"Host key rejected: RSA {rsa.KeySize}-bit is below NIST SP 800-131A minimum of 2048 bits");

        if (sigType != "rsa-sha2-256")
            throw new SshException(
                $"Host key signature algorithm '{sigType}' rejected — only rsa-sha2-256 accepted (RFC 8332)");

        if (!rsa.VerifyData(H, rawSig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1))
            throw new SshException("Target host key signature verification failed — possible MITM");
    }

    private byte[] ComputeExchangeHash(
        byte[] clientKexInit, byte[] serverKexInit, byte[] hostKeyBlob,
        BigInteger e, BigInteger f, BigInteger K)
    {
        using var sha = SHA256.Create();
        using var ms  = new MemoryStream();

        SshEncoding.WriteByteString(ms, Encoding.ASCII.GetBytes(ClientVersion));
        SshEncoding.WriteByteString(ms, Encoding.ASCII.GetBytes(_targetSshVersion));
        SshEncoding.WriteByteString(ms, clientKexInit);
        SshEncoding.WriteByteString(ms, serverKexInit);
        SshEncoding.WriteByteString(ms, hostKeyBlob);
        SshEncoding.WriteMpInt(ms, e);
        SshEncoding.WriteMpInt(ms, f);
        SshEncoding.WriteMpInt(ms, K);

        return sha.ComputeHash(ms.ToArray());
    }

    // -------------------------------------------------------------------------
    // User Auth (password injection)
    // -------------------------------------------------------------------------

    private async Task DoUserAuthAsync(CancellationToken ct)
    {
        using var reqMs = new MemoryStream();
        SshEncoding.WriteByte(reqMs, Msg.ServiceRequest);
        SshEncoding.WriteString(reqMs, "ssh-userauth");
        await _conn!.SendAsync(reqMs, ct);

        var resp = await _conn.ReadPacketAsync(ct);
        if (resp[0] != Msg.ServiceAccept)
            throw new SshException("Service ssh-userauth not accepted by target");

        using var authMs = new MemoryStream();
        SshEncoding.WriteByte(authMs, Msg.UserauthRequest);
        SshEncoding.WriteString(authMs, _username);
        SshEncoding.WriteString(authMs, "ssh-connection");
        SshEncoding.WriteString(authMs, "password");
        SshEncoding.WriteBool(authMs, false);
        SshEncoding.WriteByteString(authMs, _password);
        await _conn.SendAsync(authMs, ct);

        for (int i = 0; i < 5; i++)
        {
            var authResp = await _conn.ReadPacketAsync(ct);
            if (authResp[0] == Msg.UserauthSuccess) return;
            if (authResp[0] == Msg.UserauthBanner)  continue;
            if (authResp[0] == Msg.UserauthFailure)
                throw new SshException($"Target rejected auth for '{_username}'");
        }
        throw new SshException("Target auth failed after retries");
    }

    // -------------------------------------------------------------------------
    // Session channel setup
    // -------------------------------------------------------------------------

    private async Task OpenSessionChannelAsync(CancellationToken ct)
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.ChannelOpen);
        SshEncoding.WriteString(ms, "session");
        SshEncoding.WriteUInt32(ms, _clientChanId);
        SshEncoding.WriteUInt32(ms, 1024 * 1024); // initial window
        SshEncoding.WriteUInt32(ms, 32768);        // max packet
        await _conn!.SendAsync(ms, ct);

        var resp = await _conn.ReadPacketAsync(ct);
        if (resp[0] != Msg.ChannelOpenConf)
            throw new SshException("Target did not confirm session channel open");

        int pos  = 1;
        var _our = SshEncoding.ReadUInt32(resp, ref pos);
        _serverChanId = SshEncoding.ReadUInt32(resp, ref pos);
    }

    private async Task SendPtyReqAsync(PtyParams pty, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.ChannelRequest);
        SshEncoding.WriteUInt32(ms, _serverChanId);
        SshEncoding.WriteString(ms, "pty-req");
        SshEncoding.WriteBool(ms, true); // want reply
        SshEncoding.WriteString(ms, pty.TermType);
        SshEncoding.WriteUInt32(ms, pty.WidthChars);
        SshEncoding.WriteUInt32(ms, pty.HeightRows);
        SshEncoding.WriteUInt32(ms, pty.WidthPixels);
        SshEncoding.WriteUInt32(ms, pty.HeightPixels);
        SshEncoding.WriteByteString(ms, pty.Modes);
        await _conn!.SendAsync(ms, ct);

        var resp = await _conn.ReadPacketAsync(ct);
        if (resp[0] == Msg.ChannelFailure)
            _log.LogWarning("Target rejected pty-req (proceeding without PTY)");
    }

    private async Task RequestShellAsync(CancellationToken ct)
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.ChannelRequest);
        SshEncoding.WriteUInt32(ms, _serverChanId);
        SshEncoding.WriteString(ms, "shell");
        SshEncoding.WriteBool(ms, true);
        await _conn!.SendAsync(ms, ct);

        var resp = await _conn.ReadPacketAsync(ct);
        if (resp[0] == Msg.ChannelFailure)
            throw new SshException("Target refused shell request");
    }

    private async Task RequestExecAsync(string command, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.ChannelRequest);
        SshEncoding.WriteUInt32(ms, _serverChanId);
        SshEncoding.WriteString(ms, "exec");
        SshEncoding.WriteBool(ms, true);
        SshEncoding.WriteString(ms, command);
        await _conn!.SendAsync(ms, ct);

        var resp = await _conn.ReadPacketAsync(ct);
        if (resp[0] == Msg.ChannelFailure)
            throw new SshException("Target refused exec command");
    }

    // -------------------------------------------------------------------------
    // Bidirectional relay (target ↔ PAM client)
    // -------------------------------------------------------------------------

    internal async Task RelayToClientAsync(
        SshConnection clientConn, uint clientSideChanId,
        SessionRecorder? recorder, CancellationToken ct)
    {
        var t2c = Task.Run(() => TargetToClientLoopAsync(clientConn, clientSideChanId, recorder, ct), ct);
        var c2t = Task.Run(() => ClientToTargetLoopAsync(clientConn, clientSideChanId, ct), ct);
        await Task.WhenAny(t2c, c2t);
    }

    // Receives data from target → forwards to client connection
    private async Task TargetToClientLoopAsync(
        SshConnection clientConn, uint clientSideChanId,
        SessionRecorder? recorder, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var pkt = await _conn!.ReadPacketAsync(ct);
            switch (pkt[0])
            {
                case Msg.ChannelData:
                {
                    int pos  = 1;
                    var _ch  = SshEncoding.ReadUInt32(pkt, ref pos);
                    var data = SshEncoding.ReadByteString(pkt, ref pos);

                    using var fwd = new MemoryStream();
                    SshEncoding.WriteByte(fwd, Msg.ChannelData);
                    SshEncoding.WriteUInt32(fwd, clientSideChanId);
                    SshEncoding.WriteByteString(fwd, data);
                    await clientConn.SendAsync(fwd, ct);

                    // Replenish target's view of our receive window so it never stalls
                    using var adj = new MemoryStream();
                    SshEncoding.WriteByte(adj, Msg.ChannelWinAdj);
                    SshEncoding.WriteUInt32(adj, _serverChanId);
                    SshEncoding.WriteUInt32(adj, (uint)data.Length);
                    await _conn.SendAsync(adj, ct);

                    recorder?.WriteOutput(data);
                    break;
                }
                case Msg.ChannelExtData:
                {
                    int pos  = 1;
                    var _ch  = SshEncoding.ReadUInt32(pkt, ref pos);
                    var dt   = SshEncoding.ReadUInt32(pkt, ref pos);
                    var data = SshEncoding.ReadByteString(pkt, ref pos);

                    using var fwd = new MemoryStream();
                    SshEncoding.WriteByte(fwd, Msg.ChannelExtData);
                    SshEncoding.WriteUInt32(fwd, clientSideChanId);
                    SshEncoding.WriteUInt32(fwd, dt);
                    SshEncoding.WriteByteString(fwd, data);
                    await clientConn.SendAsync(fwd, ct);

                    using var adj = new MemoryStream();
                    SshEncoding.WriteByte(adj, Msg.ChannelWinAdj);
                    SshEncoding.WriteUInt32(adj, _serverChanId);
                    SshEncoding.WriteUInt32(adj, (uint)data.Length);
                    await _conn.SendAsync(adj, ct);
                    break;
                }
                case Msg.ChannelWinAdj:
                    // Target is giving us more window to send TO it — relay to client so
                    // client knows PAM can forward more data toward the target.
                    break;
                case Msg.ChannelRequest:
                {
                    // Forward exit-status and exit-signal to client
                    int pos      = 1;
                    var _rch     = SshEncoding.ReadUInt32(pkt, ref pos);
                    var reqType  = SshEncoding.ReadString(pkt, ref pos);
                    var wantReply = SshEncoding.ReadBool(pkt, ref pos);

                    if (reqType is "exit-status" or "exit-signal")
                    {
                        using var fwd = new MemoryStream();
                        SshEncoding.WriteByte(fwd, Msg.ChannelRequest);
                        SshEncoding.WriteUInt32(fwd, clientSideChanId);
                        SshEncoding.WriteString(fwd, reqType);
                        SshEncoding.WriteBool(fwd, false);
                        fwd.Write(pkt.AsSpan(pos));
                        await clientConn.SendAsync(fwd, ct);
                    }
                    else if (wantReply)
                    {
                        using var fail = new MemoryStream();
                        SshEncoding.WriteByte(fail, Msg.ChannelFailure);
                        SshEncoding.WriteUInt32(fail, _serverChanId);
                        await _conn.SendAsync(fail, ct);
                    }
                    break;
                }
                case Msg.ChannelEof:
                {
                    using var eof = new MemoryStream();
                    SshEncoding.WriteByte(eof, Msg.ChannelEof);
                    SshEncoding.WriteUInt32(eof, clientSideChanId);
                    await clientConn.SendAsync(eof, ct);
                    break;
                }
                case Msg.ChannelClose:
                {
                    using var close = new MemoryStream();
                    SshEncoding.WriteByte(close, Msg.ChannelClose);
                    SshEncoding.WriteUInt32(close, clientSideChanId);
                    await clientConn.SendAsync(close, ct);
                    return;
                }
                default:
                    _log.LogDebug("Unhandled target msg type={Type}", pkt[0]);
                    break;
            }
        }
    }

    // Receives data from client connection → forwards to target
    private async Task ClientToTargetLoopAsync(
        SshConnection clientConn, uint clientSideChanId, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var pkt = await clientConn.ReadPacketAsync(ct);
            switch (pkt[0])
            {
                case Msg.ChannelData:
                {
                    int pos  = 1;
                    var _ch  = SshEncoding.ReadUInt32(pkt, ref pos);
                    var data = SshEncoding.ReadByteString(pkt, ref pos);

                    using var fwd = new MemoryStream();
                    SshEncoding.WriteByte(fwd, Msg.ChannelData);
                    SshEncoding.WriteUInt32(fwd, _serverChanId);
                    SshEncoding.WriteByteString(fwd, data);
                    await _conn!.SendAsync(fwd, ct);

                    // Replenish client's view of our receive window
                    using var adj = new MemoryStream();
                    SshEncoding.WriteByte(adj, Msg.ChannelWinAdj);
                    SshEncoding.WriteUInt32(adj, clientSideChanId);
                    SshEncoding.WriteUInt32(adj, (uint)data.Length);
                    await clientConn.SendAsync(adj, ct);
                    break;
                }
                case Msg.ChannelRequest:
                {
                    // Forward window-change (terminal resize) to target
                    int pos      = 1;
                    var _rch     = SshEncoding.ReadUInt32(pkt, ref pos);
                    var reqType  = SshEncoding.ReadString(pkt, ref pos);
                    var wantReply = SshEncoding.ReadBool(pkt, ref pos);

                    if (reqType == "window-change")
                    {
                        using var fwd = new MemoryStream();
                        SshEncoding.WriteByte(fwd, Msg.ChannelRequest);
                        SshEncoding.WriteUInt32(fwd, _serverChanId);
                        SshEncoding.WriteString(fwd, "window-change");
                        SshEncoding.WriteBool(fwd, false);
                        fwd.Write(pkt.AsSpan(pos)); // width, height, pixels
                        await _conn!.SendAsync(fwd, ct);
                    }
                    else if (wantReply)
                    {
                        using var fail = new MemoryStream();
                        SshEncoding.WriteByte(fail, Msg.ChannelFailure);
                        SshEncoding.WriteUInt32(fail, clientSideChanId);
                        await clientConn.SendAsync(fail, ct);
                    }
                    break;
                }
                case Msg.ChannelWinAdj:
                    // Client is increasing the window for data we send to it — no relay action needed.
                    break;
                case Msg.ChannelEof:
                {
                    using var eof = new MemoryStream();
                    SshEncoding.WriteByte(eof, Msg.ChannelEof);
                    SshEncoding.WriteUInt32(eof, _serverChanId);
                    await _conn!.SendAsync(eof, ct);
                    break;
                }
                case Msg.ChannelClose:
                {
                    using var close = new MemoryStream();
                    SshEncoding.WriteByte(close, Msg.ChannelClose);
                    SshEncoding.WriteUInt32(close, _serverChanId);
                    await _conn!.SendAsync(close, ct);
                    return;
                }
                case Msg.GlobalRequest:
                {
                    int pos      = 1;
                    var _name    = SshEncoding.ReadString(pkt, ref pos);
                    var wantReply = SshEncoding.ReadBool(pkt, ref pos);
                    if (wantReply)
                        await clientConn.SendPacketAsync([Msg.RequestFailure], ct);
                    break;
                }
                default:
                    break;
            }
        }
    }

    public void Dispose()
    {
        _conn?.DisposeAsync().AsTask().Wait(500);
        _tcp?.Dispose();
    }
}
