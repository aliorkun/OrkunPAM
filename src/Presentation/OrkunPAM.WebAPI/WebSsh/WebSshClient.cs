using System.Net.Sockets;
using System.Net.WebSockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OrkunPAM.WebAPI.WebSsh;

internal sealed class SshWebException(string msg) : IOException(msg);

/// <summary>
/// Native SSH client for the WebSocket terminal bridge.
/// RFC 4253 (transport) + RFC 4252 (userauth) + RFC 4254 (connection).
/// Suite: diffie-hellman-group14-sha256 / aes256-ctr / hmac-sha2-256.
/// No external SSH library — entirely native C#.
/// </summary>
internal sealed class WebSshClient : IAsyncDisposable
{
    private const string ClientVersion = "SSH-2.0-OrkunPAM_WebSSH_1.0";

    private readonly string _host;
    private readonly int _port;
    private readonly string _username;
    private readonly string _password;
    private readonly ILogger _log;

    private TcpClient? _tcp;
    private SshPackets? _pkt;
    private string _serverVersion = "";
    private byte[]? _sessionId;
    private uint _serverChanId;
    private const uint ClientChanId = 0;

    // RFC 3526 §3 — 2048-bit MODP Group 14
    private static readonly BigInteger DhPrime = new BigInteger(
        Convert.FromHexString(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF"),
        isUnsigned: true, isBigEndian: true);

    private static readonly BigInteger DhGenerator = 2;

    internal WebSshClient(string host, int port, string username, string password, ILogger log)
    {
        _host = host; _port = port;
        _username = username; _password = password; _log = log;
    }

    // Phase 1: TCP connect + key exchange + user auth
    internal async Task ConnectAsync(CancellationToken ct)
    {
        _tcp = new TcpClient();
        await _tcp.ConnectAsync(_host, _port, ct);
        _pkt = new SshPackets(_tcp.GetStream());
        _serverVersion = await _pkt.ExchangeVersionsAsync(ClientVersion, ct);
        await DoKeyExchangeAsync(ct);
        await DoUserAuthAsync(ct);
        _log.LogInformation("WebSSH authenticated to {Host}:{Port} as '{User}'", _host, _port, _username);
    }

    // Phase 2: Open session channel with PTY + shell
    internal async Task OpenShellAsync(ushort cols, ushort rows, CancellationToken ct)
    {
        // CHANNEL_OPEN
        using var openMs = new MemoryStream();
        WB(openMs, 90); WStr(openMs, "session");
        WU32(openMs, ClientChanId); WU32(openMs, 1024 * 1024); WU32(openMs, 32768);
        await _pkt!.SendAsync(openMs.ToArray(), ct);

        var r = await _pkt.ReadAsync(ct);
        if (r[0] != 91) throw new SshWebException("Channel open rejected by target");
        int p = 1; RU32(r, ref p); // our chan id
        _serverChanId = RU32(r, ref p);

        // PTY-REQ
        using var ptyMs = new MemoryStream();
        WB(ptyMs, 98); WU32(ptyMs, _serverChanId); WStr(ptyMs, "pty-req"); ptyMs.WriteByte(1);
        WStr(ptyMs, "xterm-256color");
        WU32(ptyMs, cols); WU32(ptyMs, rows);
        WU32(ptyMs, 0); WU32(ptyMs, 0); // pixel dims
        WU32(ptyMs, 0); // empty modes string
        await _pkt.SendAsync(ptyMs.ToArray(), ct);
        var ptyR = await _pkt.ReadAsync(ct);
        if (ptyR[0] == 100)
            _log.LogWarning("PTY request rejected by {Host}:{Port}, continuing without PTY", _host, _port);

        // SHELL
        using var shMs = new MemoryStream();
        WB(shMs, 98); WU32(shMs, _serverChanId); WStr(shMs, "shell"); shMs.WriteByte(1);
        await _pkt.SendAsync(shMs.ToArray(), ct);
        var shR = await _pkt.ReadAsync(ct);
        if (shR[0] == 100) throw new SshWebException("Shell request rejected by target");
    }

    // Phase 3: Bidirectional relay — WebSocket <-> SSH channel
    internal async Task RelayAsync(WebSocket ws, CancellationToken ct)
    {
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var t1 = Task.Run(() => SshToWsLoop(ws, cts.Token), cts.Token);
        var t2 = Task.Run(() => WsToSshLoop(ws, cts.Token), cts.Token);
        await Task.WhenAny(t1, t2);
        cts.Cancel();

        try
        {
            using var closeMs = new MemoryStream();
            WB(closeMs, 97); WU32(closeMs, _serverChanId); // CHANNEL_CLOSE
            await _pkt!.SendAsync(closeMs.ToArray(), CancellationToken.None);
        }
        catch { /* best-effort */ }
    }

    // SSH output (CHANNEL_DATA) -> WebSocket binary frames
    private async Task SshToWsLoop(WebSocket ws, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
        {
            byte[] pkt;
            try { pkt = await _pkt!.ReadAsync(ct); }
            catch { return; }

            switch (pkt[0])
            {
                case 94: // CHANNEL_DATA
                {
                    int pos = 1; RU32(pkt, ref pos);
                    var data = RBStr(pkt, ref pos);
                    if (ws.State == WebSocketState.Open)
                        await ws.SendAsync(data, WebSocketMessageType.Binary, true, ct);
                    // Replenish remote window
                    using var adj = new MemoryStream();
                    WB(adj, 93); WU32(adj, _serverChanId); WU32(adj, (uint)data.Length);
                    await _pkt!.SendAsync(adj.ToArray(), ct);
                    break;
                }
                case 95: // CHANNEL_EXT_DATA (stderr)
                {
                    int pos = 1; RU32(pkt, ref pos); RU32(pkt, ref pos);
                    var data = RBStr(pkt, ref pos);
                    if (ws.State == WebSocketState.Open)
                        await ws.SendAsync(data, WebSocketMessageType.Binary, true, ct);
                    break;
                }
                case 96: case 97: // CHANNEL_EOF / CHANNEL_CLOSE
                    return;
                case 93: case 98: case 99: case 100: // WIN_ADJ / CHANNEL_REQUEST / SUCCESS / FAILURE
                    break;
                default:
                    _log.LogDebug("WebSSH: unhandled SSH message type {Type}", pkt[0]);
                    break;
            }
        }
    }

    // WebSocket text frames (JSON) -> SSH CHANNEL_DATA / window-change
    private async Task WsToSshLoop(WebSocket ws, CancellationToken ct)
    {
        var buf = new byte[64 * 1024];
        while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
        {
            WebSocketReceiveResult result;
            try { result = await ws.ReceiveAsync(buf, ct); }
            catch { return; }

            if (result.MessageType == WebSocketMessageType.Close) return;
            if (result.MessageType != WebSocketMessageType.Text) continue;

            try
            {
                using var doc = JsonDocument.Parse(buf.AsMemory(0, result.Count));
                var t = doc.RootElement.GetProperty("t").GetString();

                if (t == "i") // stdin input
                {
                    var data = Convert.FromBase64String(doc.RootElement.GetProperty("d").GetString()!);
                    using var ms = new MemoryStream();
                    WB(ms, 94); WU32(ms, _serverChanId); WBStr(ms, data);
                    await _pkt!.SendAsync(ms.ToArray(), ct);
                }
                else if (t == "r") // terminal resize
                {
                    var cols = (uint)doc.RootElement.GetProperty("c").GetInt32();
                    var rows = (uint)doc.RootElement.GetProperty("r").GetInt32();
                    using var ms = new MemoryStream();
                    WB(ms, 98); WU32(ms, _serverChanId); WStr(ms, "window-change"); ms.WriteByte(0);
                    WU32(ms, cols); WU32(ms, rows); WU32(ms, 0); WU32(ms, 0);
                    await _pkt!.SendAsync(ms.ToArray(), ct);
                }
            }
            catch (Exception ex)
            {
                _log.LogDebug(ex, "WebSSH: error parsing client WebSocket message");
            }
        }
    }

    // --- Key Exchange (RFC 4253) -----------------------------------------

    private async Task DoKeyExchangeAsync(CancellationToken ct)
    {
        var clientKex = BuildKexInit();
        await _pkt!.SendAsync(clientKex, ct);

        var serverKex = await _pkt.ReadAsync(ct);
        if (serverKex[0] != 20) throw new SshWebException("Expected KEXINIT from target");

        // DH ephemeral key pair
        var xBytes = new byte[32]; RandomNumberGenerator.Fill(xBytes);
        var x = new BigInteger(xBytes, isUnsigned: true, isBigEndian: false) % (DhPrime - 1) + 1;
        var e = BigInteger.ModPow(DhGenerator, x, DhPrime);

        using var dhMs = new MemoryStream();
        WB(dhMs, 30); WMpInt(dhMs, e); // KEXDH_INIT
        await _pkt.SendAsync(dhMs.ToArray(), ct);

        var reply = await _pkt.ReadAsync(ct);
        if (reply[0] != 31) throw new SshWebException("Expected KEXDH_REPLY from target");

        int pos = 1;
        var hostKeyBlob = RBStr(reply, ref pos);
        var f           = RMpInt(reply, ref pos);
        var sigBlob     = RBStr(reply, ref pos);

        var K = BigInteger.ModPow(f, x, DhPrime);
        var H = ComputeExchangeHash(clientKex, serverKex, hostKeyBlob, e, f, K);
        VerifyHostKeySignature(hostKeyBlob, sigBlob, H);
        _sessionId ??= H;

        await _pkt.SendAsync([21], ct); // NEWKEYS
        var nk = await _pkt.ReadAsync(ct);
        if (nk[0] != 21) throw new SshWebException("Expected NEWKEYS from target");

        var keys = DeriveSessionKeys(K, H, _sessionId);
        _pkt.EnableEncryption(
            rxKey: keys.EkS2C, rxIv: keys.IvS2C, rxMac: keys.MkS2C,
            txKey: keys.EkC2S, txIv: keys.IvC2S, txMac: keys.MkC2S);
    }

    private byte[] BuildKexInit()
    {
        using var ms = new MemoryStream();
        WB(ms, 20); // MSG_KEXINIT
        var cookie = new byte[16]; RandomNumberGenerator.Fill(cookie); ms.Write(cookie);
        WStr(ms, "diffie-hellman-group14-sha256");          // kex
        WStr(ms, "rsa-sha2-256,ssh-rsa,ecdsa-sha2-nistp256"); // host key
        WStr(ms, "aes256-ctr"); WStr(ms, "aes256-ctr");     // ciphers c2s, s2c
        WStr(ms, "hmac-sha2-256"); WStr(ms, "hmac-sha2-256"); // MACs c2s, s2c
        WStr(ms, "none"); WStr(ms, "none");                   // compression
        WStr(ms, ""); WStr(ms, "");                           // languages
        ms.WriteByte(0); WU32(ms, 0);                         // first_kex_follows=false, reserved
        return ms.ToArray();
    }

    private byte[] ComputeExchangeHash(byte[] clientKex, byte[] serverKex,
        byte[] hostKeyBlob, BigInteger e, BigInteger f, BigInteger K)
    {
        using var sha = SHA256.Create();
        using var ms = new MemoryStream();
        WBStr(ms, Encoding.ASCII.GetBytes(ClientVersion));
        WBStr(ms, Encoding.ASCII.GetBytes(_serverVersion));
        WBStr(ms, clientKex); WBStr(ms, serverKex);
        WBStr(ms, hostKeyBlob);
        WMpInt(ms, e); WMpInt(ms, f); WMpInt(ms, K);
        return sha.ComputeHash(ms.ToArray());
    }

    private static void VerifyHostKeySignature(byte[] hostKeyBlob, byte[] sigBlob, byte[] H)
    {
        int kp = 0;
        var keyType = RStr(hostKeyBlob, ref kp);
        if (keyType is not ("ssh-rsa" or "rsa-sha2-256"))
            throw new SshWebException($"Unsupported host key type: {keyType}");
        var e = RMpInt(hostKeyBlob, ref kp);
        var n = RMpInt(hostKeyBlob, ref kp);

        int sp = 0;
        var sigType = RStr(sigBlob, ref sp);
        var rawSig  = RBStr(sigBlob, ref sp);

        using var rsa = RSA.Create();
        rsa.ImportParameters(new RSAParameters
        {
            Exponent = e.ToByteArray(isUnsigned: true, isBigEndian: true),
            Modulus  = n.ToByteArray(isUnsigned: true, isBigEndian: true)
        });
        var alg = sigType == "rsa-sha2-256" ? HashAlgorithmName.SHA256 : HashAlgorithmName.SHA1;
        if (!rsa.VerifyData(H, rawSig, alg, RSASignaturePadding.Pkcs1))
            throw new SshWebException("Host key signature verification failed — possible MITM");
    }

    // --- Session Key Derivation (RFC 4253 §7.2) --------------------------

    private record SessionKeys(byte[] IvC2S, byte[] IvS2C,
        byte[] EkC2S, byte[] EkS2C, byte[] MkC2S, byte[] MkS2C);

    private static SessionKeys DeriveSessionKeys(BigInteger K, byte[] H, byte[] sessionId)
    {
        // K must be SSH mpint-encoded before hashing
        using var kMs = new MemoryStream(); WMpInt(kMs, K);
        var kMpint = kMs.ToArray();

        byte[] Derive(char magic, int need)
        {
            var result = new byte[need];
            int filled = 0; byte[]? prev = null;
            while (filled < need)
            {
                using var sha = SHA256.Create();
                sha.TransformBlock(kMpint, 0, kMpint.Length, null, 0);
                sha.TransformBlock(H, 0, H.Length, null, 0);
                if (prev == null)
                { sha.TransformBlock([(byte)magic], 0, 1, null, 0); sha.TransformFinalBlock(sessionId, 0, sessionId.Length); }
                else
                { sha.TransformFinalBlock(prev, 0, prev.Length); }
                prev = sha.Hash!;
                int copy = Math.Min(need - filled, prev.Length);
                Array.Copy(prev, 0, result, filled, copy);
                filled += copy;
            }
            return result;
        }

        return new SessionKeys(Derive('A', 16), Derive('B', 16),
            Derive('C', 32), Derive('D', 32), Derive('E', 32), Derive('F', 32));
    }

    // --- User Auth (password, RFC 4252) ----------------------------------

    private async Task DoUserAuthAsync(CancellationToken ct)
    {
        using var svcMs = new MemoryStream();
        WB(svcMs, 5); WStr(svcMs, "ssh-userauth"); // SERVICE_REQUEST
        await _pkt!.SendAsync(svcMs.ToArray(), ct);
        var svcR = await _pkt.ReadAsync(ct);
        if (svcR[0] != 6) throw new SshWebException("ssh-userauth service not accepted by target");

        using var authMs = new MemoryStream();
        WB(authMs, 50); // USERAUTH_REQUEST
        WStr(authMs, _username); WStr(authMs, "ssh-connection"); WStr(authMs, "password");
        authMs.WriteByte(0); // change-password = false
        WStr(authMs, _password);
        await _pkt.SendAsync(authMs.ToArray(), ct);

        for (int i = 0; i < 5; i++)
        {
            var r = await _pkt.ReadAsync(ct);
            if (r[0] == 52) return;  // USERAUTH_SUCCESS
            if (r[0] == 53) continue; // USERAUTH_BANNER - skip
            if (r[0] == 51) throw new SshWebException($"Target rejected auth for user '{_username}'");
        }
        throw new SshWebException("Auth failed after retries");
    }

    // --- SSH encoding helpers --------------------------------------------

    private static uint RU32(byte[] b, ref int p)
    { var v = ((uint)b[p] << 24) | ((uint)b[p+1] << 16) | ((uint)b[p+2] << 8) | b[p+3]; p += 4; return v; }

    private static byte[] RBStr(byte[] b, ref int p)
    { int n = (int)RU32(b, ref p); var d = new byte[n]; Array.Copy(b, p, d, 0, n); p += n; return d; }

    private static string RStr(byte[] b, ref int p) => Encoding.UTF8.GetString(RBStr(b, ref p));

    private static BigInteger RMpInt(byte[] b, ref int p)
    { var d = RBStr(b, ref p); return d.Length == 0 ? BigInteger.Zero : new BigInteger(d, isUnsigned: false, isBigEndian: true); }

    private static void WB(MemoryStream ms, byte v) => ms.WriteByte(v);

    private static void WU32(MemoryStream ms, uint v)
    => ms.Write(new byte[] { (byte)(v >> 24), (byte)(v >> 16), (byte)(v >> 8), (byte)v });

    private static void WStr(MemoryStream ms, string s)
    { var d = Encoding.UTF8.GetBytes(s); WU32(ms, (uint)d.Length); ms.Write(d); }

    private static void WBStr(MemoryStream ms, byte[] d)
    { WU32(ms, (uint)d.Length); ms.Write(d); }

    private static void WMpInt(MemoryStream ms, BigInteger v)
    { if (v == BigInteger.Zero) { WU32(ms, 0); return; } WBStr(ms, v.ToByteArray(isUnsigned: false, isBigEndian: true)); }

    public async ValueTask DisposeAsync()
    {
        if (_pkt != null) await _pkt.DisposeAsync();
        _tcp?.Dispose();
    }

    // --- AES-256-CTR stream cipher ---------------------------------------

    private sealed class AesCtr : IDisposable
    {
        private readonly Aes _aes;
        private readonly byte[] _counter = new byte[16];
        private readonly byte[] _ks = new byte[16];
        private int _ksPos = 16;

        internal AesCtr(byte[] key, byte[] iv)
        {
            _aes = Aes.Create();
            _aes.Key = key[..32];
            _aes.Mode = CipherMode.ECB;
            _aes.Padding = PaddingMode.None;
            iv[..16].CopyTo(_counter, 0);
        }

        internal void Transform(byte[] buf, int offset, int count)
        {
            for (int i = 0; i < count; i++)
            {
                if (_ksPos == 16) Refill();
                buf[offset + i] ^= _ks[_ksPos++];
            }
        }

        private void Refill()
        {
            using var enc = _aes.CreateEncryptor();
            enc.TransformBlock(_counter, 0, 16, _ks, 0);
            for (int j = 15; j >= 0; j--) if (++_counter[j] != 0) break;
            _ksPos = 0;
        }

        public void Dispose()
        {
            _aes.Dispose();
            CryptographicOperations.ZeroMemory(_counter);
            CryptographicOperations.ZeroMemory(_ks);
        }
    }

    // --- SSH packet framing (RFC 4253 §6) --------------------------------

    private sealed class SshPackets : IAsyncDisposable
    {
        private readonly Stream _s;
        private readonly SemaphoreSlim _wLock = new(1, 1);
        private AesCtr? _rxCipher, _txCipher;
        private byte[]? _rxMac, _txMac;
        private uint _rxSeq, _txSeq;

        internal SshPackets(Stream s) => _s = s;

        internal void EnableEncryption(
            byte[] rxKey, byte[] rxIv, byte[] rxMac,
            byte[] txKey, byte[] txIv, byte[] txMac)
        {
            _rxCipher = new AesCtr(rxKey, rxIv);
            _txCipher = new AesCtr(txKey, txIv);
            _rxMac = rxMac; _txMac = txMac;
        }

        internal async Task<byte[]> ReadAsync(CancellationToken ct)
        {
            var lenBuf = await ReadExact(4, ct);
            _rxCipher?.Transform(lenBuf, 0, 4);
            uint pktLen = ((uint)lenBuf[0] << 24) | ((uint)lenBuf[1] << 16) |
                          ((uint)lenBuf[2] << 8) | lenBuf[3];
            if (pktLen > 65536) throw new SshWebException($"SSH packet too large: {pktLen}");

            var rest = await ReadExact((int)pktLen, ct);
            _rxCipher?.Transform(rest, 0, rest.Length);

            if (_rxMac != null)
            {
                var mac = await ReadExact(32, ct);
                var seq = new byte[] { (byte)(_rxSeq >> 24), (byte)(_rxSeq >> 16), (byte)(_rxSeq >> 8), (byte)_rxSeq };
                using var hmac = new HMACSHA256(_rxMac);
                hmac.TransformBlock(seq, 0, 4, null, 0);
                hmac.TransformBlock(lenBuf, 0, 4, null, 0);
                hmac.TransformFinalBlock(rest, 0, rest.Length);
                if (!CryptographicOperations.FixedTimeEquals(hmac.Hash!, mac))
                    throw new SshWebException("MAC verification failed");
            }
            _rxSeq++;

            int padLen = rest[0];
            int payLen = (int)pktLen - 1 - padLen;
            var payload = new byte[payLen];
            Array.Copy(rest, 1, payload, 0, payLen);
            return payload;
        }

        internal async Task SendAsync(byte[] payload, CancellationToken ct)
        {
            await _wLock.WaitAsync(ct);
            try
            {
                int pad = 8 - ((5 + payload.Length) % 8);
                if (pad < 4) pad += 8;
                uint pktLen = (uint)(1 + payload.Length + pad);
                var pkt = new byte[4 + 1 + payload.Length + pad];
                pkt[0] = (byte)(pktLen >> 24); pkt[1] = (byte)(pktLen >> 16);
                pkt[2] = (byte)(pktLen >> 8); pkt[3] = (byte)pktLen;
                pkt[4] = (byte)pad;
                Array.Copy(payload, 0, pkt, 5, payload.Length);
                RandomNumberGenerator.Fill(pkt.AsSpan(5 + payload.Length, pad));

                byte[] mac = [];
                if (_txMac != null)
                {
                    var seq = new byte[] { (byte)(_txSeq >> 24), (byte)(_txSeq >> 16), (byte)(_txSeq >> 8), (byte)_txSeq };
                    using var hmac = new HMACSHA256(_txMac);
                    hmac.TransformBlock(seq, 0, 4, null, 0);
                    hmac.TransformFinalBlock(pkt, 0, pkt.Length);
                    mac = hmac.Hash!;
                }
                _txCipher?.Transform(pkt, 0, pkt.Length);
                _txSeq++;
                await _s.WriteAsync(pkt, ct);
                if (mac.Length > 0) await _s.WriteAsync(mac, ct);
                await _s.FlushAsync(ct);
            }
            finally { _wLock.Release(); }
        }

        internal async Task<string> ExchangeVersionsAsync(string ours, CancellationToken ct)
        {
            await _s.WriteAsync(Encoding.ASCII.GetBytes(ours + "\r\n"), ct);
            await _s.FlushAsync(ct);
            var sb = new StringBuilder();
            string? ver = null;
            while (ver == null)
            {
                sb.Clear();
                while (true)
                {
                    var b = new byte[1];
                    int n = await _s.ReadAsync(b.AsMemory(0, 1), ct);
                    if (n == 0) throw new SshWebException("Connection closed during version exchange");
                    if (b[0] == '\n') break;
                    if (b[0] != '\r') sb.Append((char)b[0]);
                }
                var line = sb.ToString();
                if (line.StartsWith("SSH-")) ver = line;
            }
            return ver;
        }

        private async Task<byte[]> ReadExact(int n, CancellationToken ct)
        {
            var buf = new byte[n]; int read = 0;
            while (read < n)
            {
                int r = await _s.ReadAsync(buf.AsMemory(read, n - read), ct);
                if (r == 0) throw new SshWebException("Connection closed unexpectedly");
                read += r;
            }
            return buf;
        }

        public async ValueTask DisposeAsync()
        {
            _rxCipher?.Dispose(); _txCipher?.Dispose();
            _wLock.Dispose();
            await _s.DisposeAsync();
        }
    }
}
