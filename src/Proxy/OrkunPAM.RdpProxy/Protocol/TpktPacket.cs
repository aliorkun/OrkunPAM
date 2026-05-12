using System.Net.Sockets;

namespace OrkunPAM.RdpProxy.Protocol;

/// <summary>
/// TPKT framing per RFC 1006.
/// Header: [version=3][reserved=0][length_hi][length_lo] (4 bytes, big-endian length including header).
/// </summary>
internal static class TpktPacket
{
    public const byte Version = 3;
    public const int HeaderSize = 4;
    public const int MaxPacketSize = 65535;

    /// <summary>Reads a complete TPKT packet. Returns null on EOF or protocol error.</summary>
    public static async Task<byte[]?> ReadAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[HeaderSize];
        if (!await ReadExactAsync(stream, header, ct)) return null;

        if (header[0] != Version) return null;

        int totalLength = (header[2] << 8) | header[3];
        if (totalLength < HeaderSize || totalLength > MaxPacketSize) return null;

        var packet = new byte[totalLength];
        header.CopyTo(packet, 0);

        if (totalLength > HeaderSize && !await ReadExactAsync(stream, packet.AsMemory(HeaderSize), ct))
            return null;

        return packet;
    }

    /// <summary>Writes a TPKT-framed payload.</summary>
    public static async Task WriteAsync(Stream stream, ReadOnlyMemory<byte> payload, CancellationToken ct)
    {
        int total = HeaderSize + payload.Length;
        var packet = new byte[total];
        packet[0] = Version;
        packet[1] = 0;
        packet[2] = (byte)(total >> 8);
        packet[3] = (byte)(total & 0xFF);
        payload.Span.CopyTo(packet.AsSpan(HeaderSize));
        await stream.WriteAsync(packet, ct);
    }

    /// <summary>Returns only the TPDU payload (strips the 4-byte TPKT header).</summary>
    public static ReadOnlySpan<byte> Payload(byte[] packet) =>
        packet.Length > HeaderSize ? packet.AsSpan(HeaderSize) : ReadOnlySpan<byte>.Empty;

    private static async Task<bool> ReadExactAsync(Stream stream, Memory<byte> buffer, CancellationToken ct)
    {
        int offset = 0;
        while (offset < buffer.Length)
        {
            int read = await stream.ReadAsync(buffer[offset..], ct);
            if (read == 0) return false;
            offset += read;
        }
        return true;
    }
}
