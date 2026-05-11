using System.Numerics;
using System.Text;

namespace OrkunPAM.SshProxy.Protocol;

// SSH message type constants (RFC 4253, 4252, 4254)
internal static class Msg
{
    internal const byte Disconnect      = 1;
    internal const byte Ignore          = 2;
    internal const byte Unimplemented   = 3;
    internal const byte Debug           = 4;
    internal const byte ServiceRequest  = 5;
    internal const byte ServiceAccept   = 6;
    internal const byte KexInit         = 20;
    internal const byte NewKeys         = 21;
    internal const byte KexDhInit       = 30;
    internal const byte KexDhReply      = 31;
    internal const byte UserauthRequest = 50;
    internal const byte UserauthFailure = 51;
    internal const byte UserauthSuccess = 52;
    internal const byte UserauthBanner  = 53;
    internal const byte GlobalRequest   = 80;
    internal const byte RequestSuccess  = 81;
    internal const byte RequestFailure  = 82;
    internal const byte ChannelOpen     = 90;
    internal const byte ChannelOpenConf = 91;
    internal const byte ChannelOpenFail = 92;
    internal const byte ChannelWinAdj   = 93;
    internal const byte ChannelData     = 94;
    internal const byte ChannelExtData  = 95;
    internal const byte ChannelEof      = 96;
    internal const byte ChannelClose    = 97;
    internal const byte ChannelRequest  = 98;
    internal const byte ChannelSuccess  = 99;
    internal const byte ChannelFailure  = 100;
}

// Algorithms supported by this implementation
internal static class Alg
{
    internal const string Kex         = "diffie-hellman-group14-sha256";
    internal const string HostKey     = "rsa-sha2-256,ssh-rsa";
    internal const string Cipher      = "aes256-ctr";
    internal const string Mac         = "hmac-sha2-256";
    internal const string Compression = "none";
}

// SSH binary data type encoder/decoder (all static, operates on byte spans)
internal static class SshEncoding
{
    // --- Writers ---

    internal static void WriteUInt32(Span<byte> dest, int offset, uint value)
    {
        dest[offset]     = (byte)(value >> 24);
        dest[offset + 1] = (byte)(value >> 16);
        dest[offset + 2] = (byte)(value >> 8);
        dest[offset + 3] = (byte)value;
    }

    // Build a packet payload in a MemoryStream
    internal static void WriteBool(MemoryStream ms, bool value) =>
        ms.WriteByte(value ? (byte)1 : (byte)0);

    internal static void WriteByte(MemoryStream ms, byte value) =>
        ms.WriteByte(value);

    internal static void WriteUInt32(MemoryStream ms, uint value)
    {
        ms.WriteByte((byte)(value >> 24));
        ms.WriteByte((byte)(value >> 16));
        ms.WriteByte((byte)(value >> 8));
        ms.WriteByte((byte)value);
    }

    internal static void WriteBytes(MemoryStream ms, byte[] data) =>
        ms.Write(data, 0, data.Length);

    internal static void WriteString(MemoryStream ms, string s)
    {
        var bytes = Encoding.UTF8.GetBytes(s);
        WriteUInt32(ms, (uint)bytes.Length);
        ms.Write(bytes);
    }

    internal static void WriteByteString(MemoryStream ms, byte[] data)
    {
        WriteUInt32(ms, (uint)data.Length);
        ms.Write(data);
    }

    internal static void WriteNameList(MemoryStream ms, params string[] names) =>
        WriteString(ms, string.Join(",", names));

    // Encode BigInteger as SSH mpint: uint32(len) + big-endian bytes, with leading 0x00 if MSB set
    internal static void WriteMpInt(MemoryStream ms, BigInteger value)
    {
        if (value == BigInteger.Zero)
        {
            WriteUInt32(ms, 0);
            return;
        }
        // ToByteArray with isUnsigned:false, isBigEndian:true adds 0x00 prefix if needed
        var bytes = value.ToByteArray(isUnsigned: false, isBigEndian: true);
        WriteByteString(ms, bytes);
    }

    // --- Readers (operate on ReadOnlySpan with ref offset) ---

    internal static uint ReadUInt32(ReadOnlySpan<byte> data, ref int offset)
    {
        uint v = ((uint)data[offset] << 24) | ((uint)data[offset+1] << 16) |
                 ((uint)data[offset+2] << 8)  |  data[offset+3];
        offset += 4;
        return v;
    }

    internal static bool ReadBool(ReadOnlySpan<byte> data, ref int offset) =>
        data[offset++] != 0;

    internal static byte ReadByte(ReadOnlySpan<byte> data, ref int offset) =>
        data[offset++];

    internal static byte[] ReadByteString(ReadOnlySpan<byte> data, ref int offset)
    {
        int len = (int)ReadUInt32(data, ref offset);
        var result = data.Slice(offset, len).ToArray();
        offset += len;
        return result;
    }

    internal static string ReadString(ReadOnlySpan<byte> data, ref int offset) =>
        Encoding.UTF8.GetString(ReadByteString(data, ref offset));

    internal static string[] ReadNameList(ReadOnlySpan<byte> data, ref int offset)
    {
        var s = ReadString(data, ref offset);
        return s.Length == 0 ? [] : s.Split(',');
    }

    internal static BigInteger ReadMpInt(ReadOnlySpan<byte> data, ref int offset)
    {
        var bytes = ReadByteString(data, ref offset);
        if (bytes.Length == 0) return BigInteger.Zero;
        return new BigInteger(bytes, isUnsigned: false, isBigEndian: true);
    }

    internal static void SkipBytes(ref int offset, int count) => offset += count;
}
