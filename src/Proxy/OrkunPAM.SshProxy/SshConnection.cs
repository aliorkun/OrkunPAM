using System.Security.Cryptography;
using OrkunPAM.SshProxy.Crypto;
using OrkunPAM.SshProxy.Protocol;

namespace OrkunPAM.SshProxy;

/// <summary>
/// Low-level SSH packet transport over a TCP stream.
/// Handles binary packet protocol (RFC 4253 §6), encryption (AES-256-CTR),
/// and MAC (HMAC-SHA256). Works for both server-side and client-side connections.
/// </summary>
internal sealed class SshConnection : IAsyncDisposable
{
    private readonly Stream _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    // Cryptographic state (null = plaintext, set after NEWKEYS)
    private AesCtrCipher? _rxCipher;
    private AesCtrCipher? _txCipher;
    private byte[]? _rxMacKey;
    private byte[]? _txMacKey;
    private uint _rxSeq;
    private uint _txSeq;

    internal SshConnection(Stream stream) => _stream = stream;

    // --- Plaintext before NEWKEYS, encrypted after ---

    internal void EnableEncryption(
        byte[] rxKey, byte[] rxIv, byte[] rxMacKey,
        byte[] txKey, byte[] txIv, byte[] txMacKey)
    {
        _rxCipher = new AesCtrCipher(rxKey, rxIv);
        _txCipher = new AesCtrCipher(txKey, txIv);
        _rxMacKey = rxMacKey;
        _txMacKey = txMacKey;
    }

    // --- Read one SSH packet, returns payload ---
    internal async Task<byte[]> ReadPacketAsync(CancellationToken ct)
    {
        const int macLen = 32; // hmac-sha2-256

        // Read 4 bytes (packet_length field)
        var lenBuf = await ReadExactAsync(4, ct);

        if (_rxCipher != null)
            _rxCipher.Transform(lenBuf, 0, 4);

        uint packetLength = ((uint)lenBuf[0] << 24) | ((uint)lenBuf[1] << 16) |
                            ((uint)lenBuf[2] << 8) | lenBuf[3];

        if (packetLength > 65536)
            throw new SshException("Packet too large: " + packetLength);

        // Read rest of packet (padding_length + payload + padding)
        var rest = await ReadExactAsync((int)packetLength, ct);
        if (_rxCipher != null)
            _rxCipher.Transform(rest, 0, rest.Length);

        byte[] mac = [];
        if (_rxMacKey != null)
            mac = await ReadExactAsync(macLen, ct);

        // Verify MAC
        if (_rxMacKey != null)
        {
            var seqBytes = new byte[] {
                (byte)(_rxSeq >> 24), (byte)(_rxSeq >> 16), (byte)(_rxSeq >> 8), (byte)_rxSeq
            };
            using var hmac = new HMACSHA256(_rxMacKey);
            hmac.TransformBlock(seqBytes, 0, 4, null, 0);
            hmac.TransformBlock(lenBuf, 0, 4, null, 0);
            hmac.TransformFinalBlock(rest, 0, rest.Length);
            var expected = hmac.Hash!;
            if (!CryptographicOperations.FixedTimeEquals(expected, mac))
                throw new SshException("MAC verification failed");
        }

        _rxSeq++;

        // Extract payload: rest[0] = padding_length, rest[1..payload_end] = payload
        byte paddingLen = rest[0];
        int payloadLen = (int)packetLength - 1 - paddingLen;
        var payload = new byte[payloadLen];
        Array.Copy(rest, 1, payload, 0, payloadLen);
        return payload;
    }

    // --- Send one SSH packet with given payload ---
    internal async Task SendPacketAsync(byte[] payload, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            // Minimum padding: 4, aligned to 8 bytes (AES-CTR is stream so block=1, use 8)
            int blockSize = 8;
            int paddingLen = blockSize - ((5 + payload.Length) % blockSize);
            if (paddingLen < 4) paddingLen += blockSize;

            uint packetLength = (uint)(1 + payload.Length + paddingLen);

            // Build packet: [packet_length(4) | padding_length(1) | payload | padding]
            var packet = new byte[4 + 1 + payload.Length + paddingLen];
            packet[0] = (byte)(packetLength >> 24);
            packet[1] = (byte)(packetLength >> 16);
            packet[2] = (byte)(packetLength >> 8);
            packet[3] = (byte)packetLength;
            packet[4] = (byte)paddingLen;
            Array.Copy(payload, 0, packet, 5, payload.Length);
            RandomNumberGenerator.Fill(packet.AsSpan(5 + payload.Length, paddingLen));

            // Compute MAC over plaintext packet
            byte[] mac = [];
            if (_txMacKey != null)
            {
                var seqBytes = new byte[] {
                    (byte)(_txSeq >> 24), (byte)(_txSeq >> 16), (byte)(_txSeq >> 8), (byte)_txSeq
                };
                using var hmac = new HMACSHA256(_txMacKey);
                hmac.TransformBlock(seqBytes, 0, 4, null, 0);
                hmac.TransformFinalBlock(packet, 0, packet.Length);
                mac = hmac.Hash!;
            }

            // Encrypt packet (in-place)
            _txCipher?.Transform(packet, 0, packet.Length);

            _txSeq++;

            await _stream.WriteAsync(packet, ct);
            if (mac.Length > 0)
                await _stream.WriteAsync(mac, ct);
            await _stream.FlushAsync(ct);
        }
        finally
        {
            _writeLock.Release();
        }
    }

    // --- Convenience: build and send packet from MemoryStream ---
    internal Task SendAsync(MemoryStream ms, CancellationToken ct) =>
        SendPacketAsync(ms.ToArray(), ct);

    // --- Version string exchange ---
    internal async Task<string> ExchangeVersionsAsync(string ourVersion, CancellationToken ct)
    {
        // Send our version
        var versionLine = ourVersion + "\r\n";
        await _stream.WriteAsync(System.Text.Encoding.ASCII.GetBytes(versionLine), ct);
        await _stream.FlushAsync(ct);

        // Read peer's version (may be preceded by banner lines)
        var sb = new System.Text.StringBuilder();
        string? peerVersion = null;
        while (peerVersion == null)
        {
            sb.Clear();
            while (true)
            {
                var buf = new byte[1];
                int n = await _stream.ReadAsync(buf.AsMemory(0, 1), ct);
                if (n == 0) throw new SshException("Connection closed during version exchange");
                if (buf[0] == '\n') break;
                if (buf[0] != '\r') sb.Append((char)buf[0]);
            }
            var line = sb.ToString();
            if (line.StartsWith("SSH-")) peerVersion = line;
        }
        return peerVersion;
    }

    // --- Read exactly n bytes ---
    private async Task<byte[]> ReadExactAsync(int count, CancellationToken ct)
    {
        var buf = new byte[count];
        int read = 0;
        while (read < count)
        {
            int n = await _stream.ReadAsync(buf.AsMemory(read, count - read), ct);
            if (n == 0) throw new SshException("Connection closed unexpectedly");
            read += n;
        }
        return buf;
    }

    public async ValueTask DisposeAsync()
    {
        _rxCipher?.Dispose();
        _txCipher?.Dispose();
        _writeLock.Dispose();
        await _stream.DisposeAsync();
    }
}

internal sealed class SshException : IOException
{
    internal SshException(string message) : base(message) { }
}
