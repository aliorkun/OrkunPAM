using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using OrkunPAM.SshProxy.Crypto;
using OrkunPAM.SshProxy.Protocol;

namespace OrkunPAM.SshProxy.Client;

/// <summary>
/// SSH client that connects PAM to the target server.
/// Implements the SSH client side: version exchange, key exchange, password auth,
/// session channel open, then provides bidirectional relay to the PAM-client side.
/// </summary>
internal sealed class SshTargetClient : IDisposable
{
    private const string ClientVersion = "SSH-2.0-OrkunPAM_1.0";

    private readonly string _host;
    private readonly int _port;
    private readonly string _username;
    private readonly string _password;
    private readonly ILogger _log;

    private TcpClient? _tcp;
    private SshConnection? _conn;
    private uint _serverChanId;
    private uint _clientChanId = 1;
    private string _targetSshVersion = "SSH-2.0-Unknown";

    internal SshTargetClient(string host, int port, string username, string password, ILogger log)
    {
        _host = host;
        _port = port;
        _username = username;
        _password = password;
        _log = log;
    }

    internal async Task ConnectAsync(CancellationToken ct)
    {
        _tcp = new TcpClient();
        await _tcp.ConnectAsync(_host, _port, ct);
        _conn = new SshConnection(_tcp.GetStream());

        _targetSshVersion = await _conn.ExchangeVersionsAsync(ClientVersion, ct);
        _log.LogDebug("Target SSH version: {Ver}", _targetSshVersion);

        await DoKeyExchangeAsync(ct);
        await DoUserAuthAsync(ct);
        await OpenSessionChannelAsync(ct);
        await RequestShellAsync(ct);

        _log.LogInformation("Connected to target {Host}:{Port}", _host, _port);
    }

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
        var f = SshEncoding.ReadMpInt(replyPkt, ref pos);
        var sigBlob = SshEncoding.ReadByteString(replyPkt, ref pos);

        var K = dh.ComputeSharedSecret(f);
        var H = ComputeExchangeHash(clientKexPayload, serverKexPayload, hostKeyBlob,
            dh.PublicKey, f, K);

        VerifyHostKeySignature(hostKeyBlob, sigBlob, H);
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
        SshEncoding.WriteNameList(ms, "rsa-sha2-256", "ssh-rsa", "ecdsa-sha2-nistp256");
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

    private static void VerifyHostKeySignature(byte[] hostKeyBlob, byte[] sigBlob, byte[] H)
    {
        // Parse RSA public key: string(key-type) || mpint(e) || mpint(n)
        int kpos = 0;
        var keyType = SshEncoding.ReadString(hostKeyBlob, ref kpos);
        if (keyType is not ("ssh-rsa" or "rsa-sha2-256"))
            throw new SshException($"Unsupported host key type: {keyType}");
        var e = SshEncoding.ReadMpInt(hostKeyBlob, ref kpos);
        var n = SshEncoding.ReadMpInt(hostKeyBlob, ref kpos);

        // Parse signature blob: string(sig-type) || string(raw-sig-bytes)
        int spos = 0;
        var sigType = SshEncoding.ReadString(sigBlob, ref spos);
        var rawSig  = SshEncoding.ReadByteString(sigBlob, ref spos);

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Exponent = e.ToByteArray(isUnsigned: true, isBigEndian: true),
            Modulus  = n.ToByteArray(isUnsigned: true, isBigEndian: true),
        });

        var hashAlg = sigType == "rsa-sha2-256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
        if (!rsa.VerifyData(H, rawSig, hashAlg, RSASignaturePadding.Pkcs1))
            throw new SshException("Target host key signature verification failed — possible MITM attack");
    }

    private byte[] ComputeExchangeHash(
        byte[] clientKexInit, byte[] serverKexInit, byte[] hostKeyBlob,
        BigInteger e, BigInteger f, BigInteger K)
    {
        using var sha = SHA256.Create();
        using var ms = new MemoryStream();

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
        SshEncoding.WriteString(authMs, _password);
        await _conn.SendAsync(authMs, ct);

        for (int i = 0; i < 5; i++)
        {
            var authResp = await _conn.ReadPacketAsync(ct);
            if (authResp[0] == Msg.UserauthSuccess) return;
            if (authResp[0] == Msg.UserauthBanner) continue;
            if (authResp[0] == Msg.UserauthFailure)
                throw new SshException($"Target rejected auth for '{_username}'");
        }
        throw new SshException("Target auth failed");
    }

    private async Task OpenSessionChannelAsync(CancellationToken ct)
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.ChannelOpen);
        SshEncoding.WriteString(ms, "session");
        SshEncoding.WriteUInt32(ms, _clientChanId);
        SshEncoding.WriteUInt32(ms, 1024 * 1024);
        SshEncoding.WriteUInt32(ms, 32768);
        await _conn!.SendAsync(ms, ct);

        var resp = await _conn.ReadPacketAsync(ct);
        if (resp[0] != Msg.ChannelOpenConf)
            throw new SshException("Target did not confirm session channel");

        int pos = 1;
        var _ourChan = SshEncoding.ReadUInt32(resp, ref pos);
        _serverChanId = SshEncoding.ReadUInt32(resp, ref pos);
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

    internal async Task RelayToClientAsync(SshConnection clientConn, uint clientSideChanId, CancellationToken ct)
    {
        var t2c = Task.Run(() => TargetToClientLoopAsync(clientConn, clientSideChanId, ct), ct);
        var c2t = Task.Run(() => ClientToTargetLoopAsync(clientConn, ct), ct);
        await Task.WhenAny(t2c, c2t);
    }

    private async Task TargetToClientLoopAsync(SshConnection clientConn, uint clientSideChanId, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var pkt = await _conn!.ReadPacketAsync(ct);
            switch (pkt[0])
            {
                case Msg.ChannelData:
                {
                    int pos = 1;
                    var _ch = SshEncoding.ReadUInt32(pkt, ref pos);
                    var data = SshEncoding.ReadByteString(pkt, ref pos);
                    using var fwd = new MemoryStream();
                    SshEncoding.WriteByte(fwd, Msg.ChannelData);
                    SshEncoding.WriteUInt32(fwd, clientSideChanId);
                    SshEncoding.WriteByteString(fwd, data);
                    await clientConn.SendAsync(fwd, ct);
                    break;
                }
                case Msg.ChannelExtData:
                {
                    int pos = 1;
                    var _ch = SshEncoding.ReadUInt32(pkt, ref pos);
                    var dt = SshEncoding.ReadUInt32(pkt, ref pos);
                    var data = SshEncoding.ReadByteString(pkt, ref pos);
                    using var fwd = new MemoryStream();
                    SshEncoding.WriteByte(fwd, Msg.ChannelExtData);
                    SshEncoding.WriteUInt32(fwd, clientSideChanId);
                    SshEncoding.WriteUInt32(fwd, dt);
                    SshEncoding.WriteByteString(fwd, data);
                    await clientConn.SendAsync(fwd, ct);
                    break;
                }
                case Msg.ChannelWinAdj:
                    break;
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
                    _log.LogDebug("Unhandled target msg {T}", pkt[0]);
                    break;
            }
        }
    }

    private async Task ClientToTargetLoopAsync(SshConnection clientConn, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            var pkt = await clientConn.ReadPacketAsync(ct);
            switch (pkt[0])
            {
                case Msg.ChannelData:
                {
                    int pos = 1;
                    var _ch = SshEncoding.ReadUInt32(pkt, ref pos);
                    var data = SshEncoding.ReadByteString(pkt, ref pos);
                    using var fwd = new MemoryStream();
                    SshEncoding.WriteByte(fwd, Msg.ChannelData);
                    SshEncoding.WriteUInt32(fwd, _serverChanId);
                    SshEncoding.WriteByteString(fwd, data);
                    await _conn!.SendAsync(fwd, ct);
                    break;
                }
                case Msg.ChannelWinAdj:
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
