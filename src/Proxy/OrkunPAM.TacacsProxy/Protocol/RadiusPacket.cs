using System.Buffers.Binary;
using System.Security.Cryptography;
using System.Text;

namespace OrkunPAM.TacacsProxy.Protocol;

/// <summary>RADIUS packet codes (RFC 2865/2866).</summary>
internal static class RadiusCode
{
    public const byte AccessRequest      = 1;
    public const byte AccessAccept       = 2;
    public const byte AccessReject       = 3;
    public const byte AccountingRequest  = 4;
    public const byte AccountingResponse = 5;
}

/// <summary>RADIUS attribute types (RFC 2865 / RFC 3579).</summary>
internal static class RadiusAttr
{
    public const byte UserName            = 1;
    public const byte UserPassword        = 2;
    public const byte NasIpAddress        = 4;
    public const byte NasPort             = 5;
    public const byte ReplyMessage        = 18;
    public const byte NasIdentifier       = 32;
    public const byte AcctStatusType      = 40;
    public const byte AcctSessionId       = 44;
    public const byte MessageAuthenticator = 80; // RFC 3579 §3.2 — BlastRADIUS protection
}

/// <summary>
/// RADIUS packet parser/builder per RFC 2865.
/// Wire format: Code(1) | Id(1) | Length(2 BE) | Authenticator(16) | Attrs(var)
/// </summary>
internal sealed class RadiusPacket
{
    public byte   Code          { get; set; }
    public byte   Id            { get; set; }
    public byte[] Authenticator { get; set; } = new byte[16];

    private readonly List<(byte Type, byte[] Value)> _attrs = [];
    private byte[] _rawBytes = Array.Empty<byte>(); // kept for Message-Authenticator HMAC validation

    /// <summary>Parses a RADIUS packet from raw UDP payload. Returns null on malformed input.</summary>
    public static RadiusPacket? TryParse(ReadOnlySpan<byte> data)
    {
        if (data.Length < 20) return null;
        int length = BinaryPrimitives.ReadUInt16BigEndian(data[2..]);
        if (length < 20 || length > data.Length) return null;

        var pkt = new RadiusPacket { Code = data[0], Id = data[1] };
        data[4..20].CopyTo(pkt.Authenticator);
        pkt._rawBytes = data[..length].ToArray(); // preserve for Message-Authenticator HMAC validation

        int pos = 20;
        while (pos + 2 <= length)
        {
            byte type = data[pos];
            byte len  = data[pos + 1];
            if (len < 2 || pos + len > length) break;
            pkt._attrs.Add((type, data.Slice(pos + 2, len - 2).ToArray()));
            pos += len;
        }
        return pkt;
    }

    public string? GetString(byte attrType)
    {
        foreach (var (t, v) in _attrs)
            if (t == attrType) return Encoding.UTF8.GetString(v);
        return null;
    }

    /// <summary>Decrypts User-Password attribute per RFC 2865 §5.2.</summary>
    public string? DecryptPassword(string sharedSecret, byte[] requestAuth)
    {
        byte[]? cipher = null;
        foreach (var (t, v) in _attrs)
            if (t == RadiusAttr.UserPassword) { cipher = v; break; }

        if (cipher == null || cipher.Length == 0) return null;

        var key   = Encoding.ASCII.GetBytes(sharedSecret);
        var plain = new byte[cipher.Length];
        var prev  = requestAuth;

        for (int i = 0; i < cipher.Length; i += 16)
        {
            // bi = MD5(S || prev_block)
            var hashIn = new byte[key.Length + prev.Length];
            key.CopyTo(hashIn, 0);
            prev.CopyTo(hashIn, key.Length);
            var bi    = MD5.HashData(hashIn);
            int block = Math.Min(16, cipher.Length - i);
            for (int j = 0; j < block; j++)
                plain[i + j] = (byte)(cipher[i + j] ^ bi[j]);
            prev = cipher.AsSpan(i, block).ToArray();
        }

        // Strip null padding
        int realLen = plain.Length;
        while (realLen > 0 && plain[realLen - 1] == 0) realLen--;
        return Encoding.UTF8.GetString(plain, 0, realLen);
    }

    /// <summary>
    /// Validates Message-Authenticator (RFC 3579 §3.2 / BlastRADIUS mitigation).
    /// Returns false when attribute is absent or HMAC-MD5 does not match.
    /// </summary>
    public bool ValidateMessageAuthenticator(string sharedSecret)
    {
        if (_rawBytes.Length < 20) return false;

        int length = BinaryPrimitives.ReadUInt16BigEndian(_rawBytes.AsSpan(2));
        int msgAuthValueOffset = -1;
        int pos = 20;
        while (pos + 2 <= length)
        {
            byte type = _rawBytes[pos];
            byte len  = _rawBytes[pos + 1];
            if (len < 2 || pos + len > length) break;
            if (type == RadiusAttr.MessageAuthenticator) { msgAuthValueOffset = pos + 2; break; }
            pos += len;
        }

        if (msgAuthValueOffset < 0 || msgAuthValueOffset + 16 > length) return false;

        var received = _rawBytes.AsSpan(msgAuthValueOffset, 16).ToArray();
        var workCopy = _rawBytes.AsSpan(0, length).ToArray();
        Array.Clear(workCopy, msgAuthValueOffset, 16); // zero out HMAC for re-computation

        var expected = HMACMD5.HashData(Encoding.ASCII.GetBytes(sharedSecret), workCopy);
        return CryptographicOperations.FixedTimeEquals(received, expected);
    }

    /// <summary>
    /// Builds Access-Accept or Access-Reject with correct ResponseAuth and
    /// Message-Authenticator (RFC 3579 §3.2) to guard against BlastRADIUS.
    /// </summary>
    public byte[] BuildResponse(byte code, string sharedSecret, string? replyMessage = null)
    {
        var replyAttr   = EncodeReplyAttr(replyMessage);
        const int msgAuthAttrSize = 18; // type(1) + len(1) + hmac16(16)
        int total       = 20 + replyAttr.Length + msgAuthAttrSize;
        var secretBytes = Encoding.ASCII.GetBytes(sharedSecret);

        // Build packet with zero-filled ResponseAuth and zero Message-Authenticator placeholder
        var pkt = new byte[total];
        pkt[0] = code;
        pkt[1] = Id;
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(2), (ushort)total);
        // pkt[4..19] = zeros (ResponseAuth placeholder, filled below)
        replyAttr.CopyTo(pkt, 20);
        int msgAuthPos      = 20 + replyAttr.Length;
        pkt[msgAuthPos]     = RadiusAttr.MessageAuthenticator;
        pkt[msgAuthPos + 1] = 18;
        // pkt[msgAuthPos+2..+17] = zeros (HMAC placeholder, filled below)

        // 1. ResponseAuth = MD5(Code|Id|Length|RequestAuth|Attrs+ZeroMsgAuth|Secret)
        var hashIn = new byte[total + secretBytes.Length];
        Buffer.BlockCopy(pkt, 0, hashIn, 0, total);
        Authenticator.CopyTo(hashIn, 4); // insert RequestAuth (was zero placeholder)
        secretBytes.CopyTo(hashIn, total);
        var responseAuth = MD5.HashData(hashIn.AsSpan(0, total + secretBytes.Length));
        responseAuth.CopyTo(pkt, 4);

        // 2. HMAC-MD5 over complete packet (ResponseAuth set, Message-Auth still zeros)
        var msgAuth = HMACMD5.HashData(secretBytes, pkt);
        msgAuth.CopyTo(pkt, msgAuthPos + 2);

        return pkt;
    }

    /// <summary>Builds Accounting-Response per RFC 2866.</summary>
    public byte[] BuildAccountingResponse(string sharedSecret)
    {
        const int total = 20;
        var secret = Encoding.ASCII.GetBytes(sharedSecret);

        // ResponseAuth = MD5(Code || Id || Length || 16×0x00 || Secret)  (RFC 2866 §3)
        var hashIn = new byte[total + secret.Length];
        hashIn[0] = RadiusCode.AccountingResponse;
        hashIn[1] = Id;
        BinaryPrimitives.WriteUInt16BigEndian(hashIn.AsSpan(2), total);
        // bytes 4-19 remain zero
        secret.CopyTo(hashIn, 20);
        var responseAuth = MD5.HashData(hashIn);

        var pkt = new byte[total];
        pkt[0] = RadiusCode.AccountingResponse;
        pkt[1] = Id;
        BinaryPrimitives.WriteUInt16BigEndian(pkt.AsSpan(2), total);
        responseAuth.CopyTo(pkt, 4);
        return pkt;
    }

    private static byte[] EncodeReplyAttr(string? message)
    {
        if (string.IsNullOrEmpty(message)) return Array.Empty<byte>();
        var msg  = Encoding.UTF8.GetBytes(message);
        int len  = Math.Min(msg.Length, 253);
        var attr = new byte[len + 2];
        attr[0] = RadiusAttr.ReplyMessage;
        attr[1] = (byte)(len + 2);
        msg.AsSpan(0, len).CopyTo(attr.AsSpan(2));
        return attr;
    }
}
