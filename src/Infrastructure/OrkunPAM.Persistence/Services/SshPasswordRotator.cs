using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// SSH password rotator using the native SSH protocol (same pattern as SshTargetClient).
/// Connects via SSH, authenticates with current credentials, then executes
/// chpasswd or passwd to change the user's password on the remote host.
/// No third-party SSH packages — native protocol implementation.
/// </summary>
public sealed class SshPasswordRotator : IPasswordRotator
{
    private const int DefaultPort = 22;
    private const int ConnectTimeoutMs = 15_000;
    private const int CommandTimeoutMs = 30_000;

    private readonly ILogger<SshPasswordRotator> _logger;

    public SshPasswordRotator(ILogger<SshPasswordRotator> logger)
    {
        _logger = logger;
    }

    public RotationConnector ConnectorType => RotationConnector.Ssh;

    public async Task<RotationResult> RotatePasswordAsync(RotationTarget target, CancellationToken ct)
    {
        var port = target.Port > 0 ? target.Port : DefaultPort;
        _logger.LogInformation("SSH rotation starting for {User}@{Host}:{Port}",
            target.Username, target.Host, port);

        byte[]? passwordBytes = null;
        byte[]? newPasswordBytes = null;

        try
        {
            passwordBytes = Encoding.UTF8.GetBytes(target.CurrentPassword ?? "");
            newPasswordBytes = Encoding.UTF8.GetBytes(target.NewPassword);

            using var tcp = new TcpClient();
            var connectTask = tcp.ConnectAsync(target.Host, port, ct).AsTask();
            if (await Task.WhenAny(connectTask, Task.Delay(ConnectTimeoutMs, ct)) != connectTask)
                return new RotationResult(false, $"SSH connection timeout to {target.Host}:{port}", "SSH");
            await connectTask;

            using var stream = tcp.GetStream();

            // 1. Version exchange
            var clientVersion = "SSH-2.0-OrkunPAM_Rotator_1.0";
            var versionLine = clientVersion + "\r\n";
            await stream.WriteAsync(Encoding.ASCII.GetBytes(versionLine), ct);
            await stream.FlushAsync(ct);

            var serverVersion = await ReadVersionLineAsync(stream, ct);
            if (!serverVersion.StartsWith("SSH-2.0"))
                return new RotationResult(false, $"Unsupported SSH version: {serverVersion}", "SSH");

            _logger.LogDebug("SSH target version: {Ver}", serverVersion);

            // 2. Key exchange (simplified Diffie-Hellman group14-sha256)
            var (sessionId, conn) = await DoKeyExchangeAsync(stream, clientVersion, serverVersion, ct);

            // 3. User authentication (password)
            await DoPasswordAuthAsync(conn, target.Username, passwordBytes, ct);

            _logger.LogDebug("SSH authenticated to {Host} as {User}", target.Host, target.Username);

            // 4. Open channel and exec password change command
            // Use chpasswd which reads from stdin (no interactive prompts)
            var escapedUser = target.Username.Replace("'", "'\\''");
            // chpasswd reads username:password from stdin — works on most Linux distros
            var command = $"echo '{escapedUser}:{EscapeForShell(target.NewPassword)}' | chpasswd";

            var (exitCode, output) = await ExecCommandAsync(conn, command, ct);

            // Zero the command string bytes
            var cmdBytes = Encoding.UTF8.GetBytes(command);
            CryptographicOperations.ZeroMemory(cmdBytes);

            if (exitCode == 0)
            {
                _logger.LogInformation("SSH password rotation succeeded for {User}@{Host}",
                    target.Username, target.Host);
                return new RotationResult(true, "Password changed via SSH chpasswd", "SSH");
            }

            // Fallback: try passwd with expect-style input if chpasswd failed
            _logger.LogDebug("chpasswd failed (exit {Code}), trying passwd fallback", exitCode);

            // Use usermod as alternative
            var fallbackCmd = $"echo '{EscapeForShell(target.NewPassword)}' | passwd --stdin {escapedUser} 2>/dev/null || " +
                              $"echo '{escapedUser}:{EscapeForShell(target.NewPassword)}' | chpasswd 2>&1";

            var (exitCode2, output2) = await ExecCommandAsync(conn, fallbackCmd, ct);

            var fbBytes = Encoding.UTF8.GetBytes(fallbackCmd);
            CryptographicOperations.ZeroMemory(fbBytes);

            if (exitCode2 == 0)
            {
                _logger.LogInformation("SSH password rotation succeeded (fallback) for {User}@{Host}",
                    target.Username, target.Host);
                return new RotationResult(true, "Password changed via SSH passwd fallback", "SSH");
            }

            return new RotationResult(false,
                $"SSH password change failed (exit code {exitCode2}). " +
                "Ensure the PAM account has sudo/root privileges for password changes.",
                "SSH");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "SSH rotation failed for {User}@{Host}", target.Username, target.Host);
            return new RotationResult(false, $"SSH rotation error: {ex.Message}", "SSH");
        }
        finally
        {
            if (passwordBytes != null) CryptographicOperations.ZeroMemory(passwordBytes);
            if (newPasswordBytes != null) CryptographicOperations.ZeroMemory(newPasswordBytes);
        }
    }

    // --- SSH protocol helpers (simplified from SshTargetClient pattern) ---

    private static async Task<string> ReadVersionLineAsync(NetworkStream stream, CancellationToken ct)
    {
        var sb = new StringBuilder();
        var buf = new byte[1];
        while (true)
        {
            int n = await stream.ReadAsync(buf, ct);
            if (n == 0) throw new IOException("SSH connection closed during version exchange");
            if (buf[0] == '\n')
            {
                var line = sb.ToString().TrimEnd('\r');
                if (line.StartsWith("SSH-")) return line;
                sb.Clear(); // skip pre-banner lines
            }
            else
            {
                sb.Append((char)buf[0]);
                if (sb.Length > 1024) throw new IOException("SSH version line too long");
            }
        }
    }

    private static async Task<(byte[] sessionId, SshRotatorConnection conn)> DoKeyExchangeAsync(
        NetworkStream stream, string clientVersion, string serverVersion, CancellationToken ct)
    {
        var conn = new SshRotatorConnection(stream);

        // Build and send KEXINIT
        var clientKexInit = BuildKexInit();
        await conn.SendPacketAsync(clientKexInit, ct);

        // Read server KEXINIT
        var serverKexInit = await conn.ReadPacketAsync(ct);
        if (serverKexInit[0] != 20) // SSH_MSG_KEXINIT
            throw new IOException("Expected KEXINIT from SSH server");

        // DH Group14 key exchange
        // Generate DH keypair: p = group14 prime, g = 2
        var p = DhGroup14Prime();
        var g = new BigInteger(2);
        var x = GenerateDhPrivateKey();
        var e = BigInteger.ModPow(g, x, p);

        // Send KEX_DH_INIT (type 30)
        using var dhInitMs = new MemoryStream();
        dhInitMs.WriteByte(30); // SSH_MSG_KEXDH_INIT
        WriteMpInt(dhInitMs, e);
        await conn.SendPacketAsync(dhInitMs.ToArray(), ct);

        // Read KEX_DH_REPLY (type 31)
        var reply = await conn.ReadPacketAsync(ct);
        if (reply[0] != 31)
            throw new IOException("Expected KEXDH_REPLY from SSH server");

        int pos = 1;
        var hostKeyBlob = ReadByteString(reply, ref pos);
        var f = ReadMpInt(reply, ref pos);
        var sigBlob = ReadByteString(reply, ref pos);

        var K = BigInteger.ModPow(f, x, p);

        // Compute exchange hash H
        var H = ComputeExchangeHash(clientVersion, serverVersion,
            clientKexInit, serverKexInit, hostKeyBlob, e, f, K);

        // Send NEWKEYS
        await conn.SendPacketAsync([21], ct); // SSH_MSG_NEWKEYS

        var newkeys = await conn.ReadPacketAsync(ct);
        if (newkeys[0] != 21)
            throw new IOException("Expected NEWKEYS from SSH server");

        // Derive encryption keys
        var keys = DeriveKeys(K, H, H);
        conn.EnableEncryption(keys);

        return (H, conn);
    }

    private static async Task DoPasswordAuthAsync(
        SshRotatorConnection conn, string username, byte[] password, CancellationToken ct)
    {
        // SSH_MSG_SERVICE_REQUEST for ssh-userauth
        using var svcMs = new MemoryStream();
        svcMs.WriteByte(5); // SSH_MSG_SERVICE_REQUEST
        WriteString(svcMs, "ssh-userauth");
        await conn.SendPacketAsync(svcMs.ToArray(), ct);

        var svcResp = await conn.ReadPacketAsync(ct);
        if (svcResp[0] != 6) // SSH_MSG_SERVICE_ACCEPT
            throw new IOException("Service ssh-userauth not accepted");

        // SSH_MSG_USERAUTH_REQUEST with password
        using var authMs = new MemoryStream();
        authMs.WriteByte(50); // SSH_MSG_USERAUTH_REQUEST
        WriteString(authMs, username);
        WriteString(authMs, "ssh-connection");
        WriteString(authMs, "password");
        authMs.WriteByte(0); // false (no old password)
        WriteByteString(authMs, password);
        await conn.SendPacketAsync(authMs.ToArray(), ct);

        for (int i = 0; i < 5; i++)
        {
            var resp = await conn.ReadPacketAsync(ct);
            if (resp[0] == 52) return; // SSH_MSG_USERAUTH_SUCCESS
            if (resp[0] == 53) continue; // SSH_MSG_USERAUTH_BANNER
            if (resp[0] == 51) // SSH_MSG_USERAUTH_FAILURE
                throw new IOException($"SSH password authentication failed for '{username}'");
        }
        throw new IOException("SSH auth failed after retries");
    }

    private static async Task<(int exitCode, string output)> ExecCommandAsync(
        SshRotatorConnection conn, string command, CancellationToken ct)
    {
        // Open session channel
        uint clientChanId = 1;

        using var openMs = new MemoryStream();
        openMs.WriteByte(90); // SSH_MSG_CHANNEL_OPEN
        WriteString(openMs, "session");
        WriteUInt32(openMs, clientChanId);
        WriteUInt32(openMs, 1024 * 1024); // initial window
        WriteUInt32(openMs, 32768); // max packet
        await conn.SendPacketAsync(openMs.ToArray(), ct);

        var openResp = await conn.ReadPacketAsync(ct);
        if (openResp[0] != 91) // SSH_MSG_CHANNEL_OPEN_CONFIRMATION
            throw new IOException("SSH channel open rejected");

        int cpos = 1;
        var _recipientChan = ReadUInt32(openResp, ref cpos);
        var serverChanId = ReadUInt32(openResp, ref cpos);

        // Exec command
        using var execMs = new MemoryStream();
        execMs.WriteByte(98); // SSH_MSG_CHANNEL_REQUEST
        WriteUInt32(execMs, serverChanId);
        WriteString(execMs, "exec");
        execMs.WriteByte(1); // want reply
        WriteString(execMs, command);
        await conn.SendPacketAsync(execMs.ToArray(), ct);

        // Read response
        var outputSb = new StringBuilder();
        int exitCode = -1;

        using var timeoutCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        timeoutCts.CancelAfter(CommandTimeoutMs);

        try
        {
            while (true)
            {
                var pkt = await conn.ReadPacketAsync(timeoutCts.Token);

                switch (pkt[0])
                {
                    case 94: // SSH_MSG_CHANNEL_DATA
                    {
                        int dpos = 1;
                        var _ch = ReadUInt32(pkt, ref dpos);
                        var data = ReadByteString(pkt, ref dpos);
                        outputSb.Append(Encoding.UTF8.GetString(data));

                        // Send window adjust
                        using var adjMs = new MemoryStream();
                        adjMs.WriteByte(93); // SSH_MSG_CHANNEL_WINDOW_ADJUST
                        WriteUInt32(adjMs, serverChanId);
                        WriteUInt32(adjMs, (uint)data.Length);
                        await conn.SendPacketAsync(adjMs.ToArray(), timeoutCts.Token);
                        break;
                    }
                    case 95: // SSH_MSG_CHANNEL_EXTENDED_DATA (stderr)
                    {
                        int dpos = 1;
                        var _ch = ReadUInt32(pkt, ref dpos);
                        var _dt = ReadUInt32(pkt, ref dpos);
                        var data = ReadByteString(pkt, ref dpos);
                        outputSb.Append(Encoding.UTF8.GetString(data));
                        break;
                    }
                    case 98: // SSH_MSG_CHANNEL_REQUEST (exit-status)
                    {
                        int rpos = 1;
                        var _ch = ReadUInt32(pkt, ref rpos);
                        var reqType = ReadString(pkt, ref rpos);
                        var _wantReply = pkt[rpos++];
                        if (reqType == "exit-status" && rpos + 4 <= pkt.Length)
                            exitCode = (int)ReadUInt32(pkt, ref rpos);
                        break;
                    }
                    case 99: // SSH_MSG_CHANNEL_SUCCESS
                    case 100: // SSH_MSG_CHANNEL_FAILURE
                        break;
                    case 96: // SSH_MSG_CHANNEL_EOF
                        break;
                    case 97: // SSH_MSG_CHANNEL_CLOSE
                        // Send close back
                        using (var closeMs = new MemoryStream())
                        {
                            closeMs.WriteByte(97);
                            WriteUInt32(closeMs, serverChanId);
                            await conn.SendPacketAsync(closeMs.ToArray(), ct);
                        }
                        return (exitCode, outputSb.ToString());
                }
            }
        }
        catch (OperationCanceledException) when (timeoutCts.IsCancellationRequested && !ct.IsCancellationRequested)
        {
            return (exitCode, outputSb.ToString() + " [command timed out]");
        }
    }

    private static string EscapeForShell(string value) =>
        value.Replace("'", "'\\''");

    // --- SSH encoding helpers ---

    private static byte[] BuildKexInit()
    {
        using var ms = new MemoryStream();
        ms.WriteByte(20); // SSH_MSG_KEXINIT
        var cookie = new byte[16];
        RandomNumberGenerator.Fill(cookie);
        ms.Write(cookie);
        WriteNameList(ms, "diffie-hellman-group14-sha256");
        WriteNameList(ms, "rsa-sha2-256");
        WriteNameList(ms, "aes256-ctr", "aes128-ctr");
        WriteNameList(ms, "aes256-ctr", "aes128-ctr");
        WriteNameList(ms, "hmac-sha2-256");
        WriteNameList(ms, "hmac-sha2-256");
        WriteNameList(ms, "none");
        WriteNameList(ms, "none");
        WriteString(ms, "");
        WriteString(ms, "");
        ms.WriteByte(0); // false
        WriteUInt32(ms, 0);
        return ms.ToArray();
    }

    private static void WriteNameList(MemoryStream ms, params string[] names)
    {
        WriteString(ms, string.Join(",", names));
    }

    private static void WriteString(MemoryStream ms, string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        WriteByteString(ms, bytes);
    }

    private static void WriteByteString(MemoryStream ms, byte[] data)
    {
        WriteUInt32(ms, (uint)data.Length);
        ms.Write(data);
    }

    private static void WriteUInt32(MemoryStream ms, uint value)
    {
        var buf = new byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(buf, value);
        ms.Write(buf);
    }

    private static void WriteMpInt(MemoryStream ms, BigInteger value)
    {
        var bytes = value.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (bytes.Length > 0 && (bytes[0] & 0x80) != 0)
        {
            WriteUInt32(ms, (uint)(bytes.Length + 1));
            ms.WriteByte(0);
        }
        else
        {
            WriteUInt32(ms, (uint)bytes.Length);
        }
        ms.Write(bytes);
    }

    private static byte[] ReadByteString(byte[] data, ref int pos)
    {
        uint len = ReadUInt32(data, ref pos);
        if (len > data.Length - pos) throw new IOException("Invalid byte string length in SSH packet");
        var result = data[pos..(pos + (int)len)];
        pos += (int)len;
        return result;
    }

    private static string ReadString(byte[] data, ref int pos)
    {
        var bytes = ReadByteString(data, ref pos);
        return Encoding.UTF8.GetString(bytes);
    }

    private static uint ReadUInt32(byte[] data, ref int pos)
    {
        var val = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(data.AsSpan(pos));
        pos += 4;
        return val;
    }

    private static BigInteger ReadMpInt(byte[] data, ref int pos)
    {
        var bytes = ReadByteString(data, ref pos);
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }

    private static byte[] ComputeExchangeHash(
        string clientVersion, string serverVersion,
        byte[] clientKexInit, byte[] serverKexInit,
        byte[] hostKeyBlob, BigInteger e, BigInteger f, BigInteger K)
    {
        using var ms = new MemoryStream();
        WriteByteString(ms, Encoding.ASCII.GetBytes(clientVersion));
        WriteByteString(ms, Encoding.ASCII.GetBytes(serverVersion));
        WriteByteString(ms, clientKexInit);
        WriteByteString(ms, serverKexInit);
        WriteByteString(ms, hostKeyBlob);
        WriteMpInt(ms, e);
        WriteMpInt(ms, f);
        WriteMpInt(ms, K);
        return SHA256.HashData(ms.ToArray());
    }

    private static BigInteger GenerateDhPrivateKey()
    {
        var bytes = RandomNumberGenerator.GetBytes(32);
        return new BigInteger(bytes, isUnsigned: true, isBigEndian: true);
    }

    private static EncryptionKeys DeriveKeys(BigInteger K, byte[] H, byte[] sessionId)
    {
        byte[] DeriveKey(char letter, int length)
        {
            using var ms = new MemoryStream();
            WriteMpInt(ms, K);
            ms.Write(H);
            ms.WriteByte((byte)letter);
            ms.Write(sessionId);
            var hash = SHA256.HashData(ms.ToArray());
            if (hash.Length >= length) return hash[..length];

            // Extend key if needed
            using var ext = new MemoryStream();
            ext.Write(hash);
            while (ext.Length < length)
            {
                using var ms2 = new MemoryStream();
                WriteMpInt(ms2, K);
                ms2.Write(H);
                ms2.Write(ext.ToArray());
                ext.Write(SHA256.HashData(ms2.ToArray()));
            }
            return ext.ToArray()[..length];
        }

        return new EncryptionKeys(
            IvC2S: DeriveKey('A', 16),
            IvS2C: DeriveKey('B', 16),
            EkC2S: DeriveKey('C', 32),
            EkS2C: DeriveKey('D', 32),
            MkC2S: DeriveKey('E', 32),
            MkS2C: DeriveKey('F', 32));
    }

    private static BigInteger DhGroup14Prime()
    {
        // RFC 3526 Group 14 (2048-bit MODP)
        return BigInteger.Parse(
            "32317006071311007300338913926423828462" +
            "20206024226040959767104906380983894004" +
            "23377350244352249105986901461668688623" +
            "27891716840894945612710394816461548210" +
            "14666150643589029095412648564916684797" +
            "24612021723981337880733989474925079941" +
            "61688941548890255691013809063530279338" +
            "73858104490881037529428429838639033548" +
            "93811010776079909368108443367093895395" +
            "49182570168252029617680783740125230054" +
            "09336880614809822514546638105555105170" +
            "89303087376806353294137529440077362584" +
            "63684800092460286701024794673802706916" +
            "53988866452160348534044612396580564205" +
            "24028895927716003098925060735773810643" +
            "04830714521355654286886878109968692606" +
            "52688514521340502543562017881299247584" +
            "7319");
    }

    internal record EncryptionKeys(
        byte[] IvC2S, byte[] IvS2C,
        byte[] EkC2S, byte[] EkS2C,
        byte[] MkC2S, byte[] MkS2C);

    /// <summary>
    /// Lightweight SSH connection wrapper for the rotator.
    /// Handles packet framing and optional encryption.
    /// </summary>
    internal sealed class SshRotatorConnection
    {
        private readonly NetworkStream _stream;
        private Aes? _rxCipher;
        private Aes? _txCipher;
        private ICryptoTransform? _rxTransform;
        private ICryptoTransform? _txTransform;
        private byte[]? _rxMacKey;
        private byte[]? _txMacKey;
        private uint _rxSeq;
        private uint _txSeq;

        public SshRotatorConnection(NetworkStream stream) => _stream = stream;

        public void EnableEncryption(EncryptionKeys keys)
        {
            _txCipher = Aes.Create();
            _txCipher.KeySize = 256;
            _txCipher.Mode = CipherMode.ECB; // CTR mode uses ECB internally
            _txCipher.Padding = PaddingMode.None;
            _txTransform = _txCipher.CreateEncryptor(keys.EkC2S, new byte[16]);
            _txMacKey = keys.MkC2S;

            _rxCipher = Aes.Create();
            _rxCipher.KeySize = 256;
            _rxCipher.Mode = CipherMode.ECB;
            _rxCipher.Padding = PaddingMode.None;
            _rxTransform = _rxCipher.CreateEncryptor(keys.EkS2C, new byte[16]);
            _rxMacKey = keys.MkS2C;

            _rxCounter = (byte[])keys.IvS2C.Clone();
            _txCounter = (byte[])keys.IvC2S.Clone();
        }

        private byte[]? _rxCounter;
        private byte[]? _txCounter;

        public async Task SendPacketAsync(byte[] payload, CancellationToken ct)
        {
            if (_txTransform == null)
            {
                // Unencrypted
                int paddingLen = 8 - ((5 + payload.Length) % 8);
                if (paddingLen < 4) paddingLen += 8;
                int packetLen = 1 + payload.Length + paddingLen;

                var packet = new byte[4 + packetLen];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(packet, (uint)packetLen);
                packet[4] = (byte)paddingLen;
                payload.CopyTo(packet.AsSpan(5));
                RandomNumberGenerator.Fill(packet.AsSpan(5 + payload.Length, paddingLen));

                await _stream.WriteAsync(packet, ct);
                await _stream.FlushAsync(ct);
                _txSeq++;
                return;
            }

            // Encrypted (AES-256-CTR + HMAC-SHA-256)
            {
                int blockSize = 16;
                int paddingLen = blockSize - ((5 + payload.Length) % blockSize);
                if (paddingLen < 4) paddingLen += blockSize;
                int packetLen = 1 + payload.Length + paddingLen;

                var plainPacket = new byte[4 + packetLen];
                System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(plainPacket, (uint)packetLen);
                plainPacket[4] = (byte)paddingLen;
                payload.CopyTo(plainPacket.AsSpan(5));
                RandomNumberGenerator.Fill(plainPacket.AsSpan(5 + payload.Length, paddingLen));

                // CTR encrypt
                var encrypted = CtrTransform(_txTransform!, _txCounter!, plainPacket);

                // HMAC
                var mac = ComputeMac(_txMacKey!, _txSeq, plainPacket);

                await _stream.WriteAsync(encrypted, ct);
                await _stream.WriteAsync(mac, ct);
                await _stream.FlushAsync(ct);
                _txSeq++;
            }
        }

        public async Task<byte[]> ReadPacketAsync(CancellationToken ct)
        {
            if (_rxTransform == null)
            {
                // Unencrypted
                var header = await ReadExactAsync(4, ct);
                uint packetLen = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(header);
                if (packetLen > 256 * 1024)
                    throw new IOException("SSH packet too large");

                var body = await ReadExactAsync((int)packetLen, ct);
                byte paddingLen = body[0];
                var payload = body[1..^paddingLen];
                _rxSeq++;
                return payload;
            }

            // Encrypted
            {
                int blockSize = 16;
                // Read first block to get packet length
                var firstBlockEnc = await ReadExactAsync(blockSize, ct);
                var firstBlock = CtrTransform(_rxTransform!, _rxCounter!, firstBlockEnc);

                uint packetLen = System.Buffers.Binary.BinaryPrimitives.ReadUInt32BigEndian(firstBlock);
                if (packetLen > 256 * 1024)
                    throw new IOException("SSH encrypted packet too large");

                int remaining = (int)(4 + packetLen) - blockSize;
                byte[] allPlain;

                if (remaining > 0)
                {
                    var restEnc = await ReadExactAsync(remaining, ct);
                    var restPlain = CtrTransform(_rxTransform!, _rxCounter!, restEnc);

                    allPlain = new byte[firstBlock.Length + restPlain.Length];
                    firstBlock.CopyTo(allPlain, 0);
                    restPlain.CopyTo(allPlain, firstBlock.Length);
                }
                else
                {
                    allPlain = firstBlock;
                }

                // Read and verify MAC (32 bytes for HMAC-SHA-256)
                var receivedMac = await ReadExactAsync(32, ct);
                var expectedMac = ComputeMac(_rxMacKey!, _rxSeq, allPlain);

                if (!CryptographicOperations.FixedTimeEquals(receivedMac, expectedMac))
                    throw new IOException("SSH MAC verification failed");

                byte paddingLen = allPlain[4];
                var payload = allPlain[5..((int)(5 + packetLen - 1 - paddingLen))];
                _rxSeq++;
                return payload;
            }
        }

        private async Task<byte[]> ReadExactAsync(int count, CancellationToken ct)
        {
            var buffer = new byte[count];
            int read = 0;
            while (read < count)
            {
                int n = await _stream.ReadAsync(buffer.AsMemory(read, count - read), ct);
                if (n == 0) throw new IOException("SSH connection closed");
                read += n;
            }
            return buffer;
        }

        private static byte[] CtrTransform(ICryptoTransform cipher, byte[] counter, byte[] data)
        {
            var result = new byte[data.Length];
            var block = new byte[16];
            var keystream = new byte[16];

            for (int offset = 0; offset < data.Length; offset += 16)
            {
                cipher.TransformBlock(counter, 0, 16, keystream, 0);

                int len = Math.Min(16, data.Length - offset);
                for (int i = 0; i < len; i++)
                    result[offset + i] = (byte)(data[offset + i] ^ keystream[i]);

                // Increment counter (big-endian)
                for (int i = 15; i >= 0; i--)
                {
                    if (++counter[i] != 0) break;
                }
            }

            return result;
        }

        private static byte[] ComputeMac(byte[] key, uint seqNum, byte[] packet)
        {
            var seqBytes = new byte[4];
            System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(seqBytes, seqNum);

            using var hmac = new HMACSHA256(key);
            hmac.TransformBlock(seqBytes, 0, 4, null, 0);
            hmac.TransformFinalBlock(packet, 0, packet.Length);
            return hmac.Hash!;
        }
    }
}
