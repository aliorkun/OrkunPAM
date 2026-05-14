using System.Buffers.Binary;

namespace OrkunPAM.TacacsProxy.Protocol;

/// <summary>
/// TACACS+ packet header — 12 bytes (RFC 1492 / draft-grant-tacacs).
/// All multi-byte integers are big-endian.
/// </summary>
internal sealed class TacacsHeader
{
    // version byte: major = 0xC (4 bits), minor = 0 or 1 (4 bits)
    public const byte VersionDefault  = 0xC0; // minor=0
    public const byte VersionOne      = 0xC1; // minor=1 (most common)

    public const byte TypeAuthentication = 0x01;
    public const byte TypeAuthorization  = 0x02;
    public const byte TypeAccounting     = 0x03;

    public const byte FlagUnencrypted   = 0x04;
    public const byte FlagSingleConnect = 0x08;

    public const int Size = 12;

    public byte   Version   { get; set; }
    public byte   Type      { get; set; }
    public byte   SeqNo     { get; set; }
    public byte   Flags     { get; set; }
    public uint   SessionId { get; set; }
    public int    Length    { get; set; }

    public bool IsEncrypted => (Flags & FlagUnencrypted) == 0;

    public static TacacsHeader Parse(ReadOnlySpan<byte> data)
    {
        if (data.Length < Size)
            throw new TacacsProtocolException("Header too short");

        return new TacacsHeader
        {
            Version   = data[0],
            Type      = data[1],
            SeqNo     = data[2],
            Flags     = data[3],
            SessionId = BinaryPrimitives.ReadUInt32BigEndian(data[4..]),
            Length    = (int)BinaryPrimitives.ReadUInt32BigEndian(data[8..])
        };
    }

    public void WriteTo(Span<byte> dest)
    {
        dest[0] = Version;
        dest[1] = Type;
        dest[2] = SeqNo;
        dest[3] = Flags;
        BinaryPrimitives.WriteUInt32BigEndian(dest[4..], SessionId);
        BinaryPrimitives.WriteUInt32BigEndian(dest[8..], (uint)Length);
    }

    public byte[] ToArray()
    {
        var buf = new byte[Size];
        WriteTo(buf);
        return buf;
    }
}

internal sealed class TacacsProtocolException : Exception
{
    public TacacsProtocolException(string msg) : base(msg) { }
}
