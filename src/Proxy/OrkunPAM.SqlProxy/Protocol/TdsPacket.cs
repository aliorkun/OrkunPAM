namespace OrkunPAM.SqlProxy.Protocol;

/// <summary>
/// TDS (Tabular Data Stream) packet I/O primitives.
///
/// TDS Packet Header (8 bytes):
///   [0]     Type    — packet type (0x01=SQLBatch, 0x10=Login7, 0x12=PreLogin, ...)
///   [1]     Status  — 0x00=continue, 0x01=EOM (end of message)
///   [2..3]  Length  — total packet length including header (big-endian)
///   [4..5]  SPID    — server process ID
///   [6]     PacketId
///   [7]     Window  — unused
/// </summary>
internal static class TdsPacket
{
    public const int HeaderSize = 8;

    // Packet types
    public const byte TypeSqlBatch  = 0x01;
    public const byte TypeRpc       = 0x03;
    public const byte TypeLogin7    = 0x10;
    public const byte TypePreLogin  = 0x12;
    public const byte TypeSspi      = 0x11;

    // Status flags
    public const byte StatusEom     = 0x01;

    /// <summary>
    /// Read one TDS packet from the stream.
    /// Returns null when the stream is closed / peer disconnected.
    /// </summary>
    public static async Task<(byte type, byte status, byte[] payload)?> ReadAsync(
        Stream s, CancellationToken ct)
    {
        var header = new byte[HeaderSize];
        if (!await ReadExactAsync(s, header, ct)) return null;

        var type   = header[0];
        var status = header[1];
        var length = (header[2] << 8) | header[3]; // big-endian

        if (length < HeaderSize) return null;

        var payload = new byte[length - HeaderSize];
        if (payload.Length > 0 && !await ReadExactAsync(s, payload, ct)) return null;

        return (type, status, payload);
    }

    /// <summary>
    /// Read a complete TDS message, potentially spanning multiple continuation packets.
    /// Returns the message type and the concatenated payload of all packets.
    /// Returns null on stream close.
    /// </summary>
    public static async Task<(byte type, byte[] fullPayload, byte[][] rawPackets)?> ReadMessageAsync(
        Stream s, CancellationToken ct)
    {
        var payloadChunks = new List<byte[]>();
        var rawPackets    = new List<byte[]>();
        byte messageType  = 0;

        while (true)
        {
            var pkt = await ReadAsync(s, ct);
            if (pkt == null) return null;

            messageType = pkt.Value.type;
            payloadChunks.Add(pkt.Value.payload);

            // Reconstruct raw packet bytes for pass-through relay
            var raw = new byte[HeaderSize + pkt.Value.payload.Length];
            raw[0] = pkt.Value.type;
            raw[1] = pkt.Value.status;
            var pktLen = raw.Length;
            raw[2] = (byte)(pktLen >> 8);
            raw[3] = (byte)(pktLen & 0xFF);
            pkt.Value.payload.CopyTo(raw, HeaderSize);
            rawPackets.Add(raw);

            if ((pkt.Value.status & StatusEom) != 0) break;
        }

        var fullPayload = payloadChunks.Count == 1
            ? payloadChunks[0]
            : ConcatArrays(payloadChunks);

        return (messageType, fullPayload, [.. rawPackets]);
    }

    /// <summary>Write a single EOM TDS packet to the stream.</summary>
    public static async Task WritePacketAsync(Stream s, byte type, byte[] payload, CancellationToken ct,
        byte packetId = 1)
    {
        var header = new byte[HeaderSize];
        header[0] = type;
        header[1] = StatusEom;
        var length = HeaderSize + payload.Length;
        header[2] = (byte)(length >> 8);
        header[3] = (byte)(length & 0xFF);
        header[6] = packetId;

        await s.WriteAsync(header, ct);
        if (payload.Length > 0)
            await s.WriteAsync(payload, ct);
    }

    private static async Task<bool> ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int offset = 0;
        while (offset < buf.Length)
        {
            int read = await s.ReadAsync(buf.AsMemory(offset), ct);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }

    private static byte[] ConcatArrays(List<byte[]> arrays)
    {
        int total = arrays.Sum(a => a.Length);
        var result = new byte[total];
        int offset = 0;
        foreach (var a in arrays) { a.CopyTo(result, offset); offset += a.Length; }
        return result;
    }
}
