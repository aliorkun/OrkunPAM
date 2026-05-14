using System.Text;

namespace OrkunPAM.TacacsProxy.Protocol;

// ──────────────────────────────────────────
// Authorization packet types (AUTHOR = 0x02)
// ──────────────────────────────────────────

internal static class AuthorMethod
{
    public const byte NotSet   = 0x00;
    public const byte None     = 0x01;
    public const byte Krb5     = 0x02;
    public const byte Line     = 0x03;
    public const byte Enable   = 0x04;
    public const byte Local    = 0x05;
    public const byte TacacsPlus = 0x06;
    public const byte Guest    = 0x08;
    public const byte Radius   = 0x10;
    public const byte KrbMsg   = 0x11;
    public const byte If_needed = 0x12;
}

internal static class AuthorStatus
{
    public const byte PassAdd  = 0x01;
    public const byte PassRepl = 0x02;
    public const byte Fail     = 0x10;
    public const byte Error    = 0x11;
    public const byte Follow   = 0x21;
}

/// <summary>Authorization REQUEST sent by NAS. Contains AV pairs describing the action.</summary>
internal sealed class AuthorRequestPacket
{
    public byte AuthenMethod   { get; set; }
    public byte PrivLvl        { get; set; }
    public byte AuthenType     { get; set; }
    public byte AuthenService  { get; set; }
    public string User         { get; set; } = string.Empty;
    public string Port         { get; set; } = string.Empty;
    public string RemAddr      { get; set; } = string.Empty;
    public List<string> Args   { get; set; } = new();

    public static AuthorRequestPacket Parse(ReadOnlySpan<byte> body)
    {
        if (body.Length < 8)
            throw new TacacsProtocolException("AuthorRequest body too short");

        byte authenMethod  = body[0];
        byte privLvl       = body[1];
        byte authenType    = body[2];
        byte authenService = body[3];
        int  userLen       = body[4];
        int  portLen       = body[5];
        int  remAddrLen    = body[6];
        int  argCnt        = body[7];

        if (body.Length < 8 + argCnt)
            throw new TacacsProtocolException("AuthorRequest arg lengths missing");

        var argLens = new int[argCnt];
        for (int i = 0; i < argCnt; i++)
            argLens[i] = body[8 + i];

        int offset = 8 + argCnt;
        string user    = Encoding.UTF8.GetString(body.Slice(offset, userLen));    offset += userLen;
        string port    = Encoding.UTF8.GetString(body.Slice(offset, portLen));    offset += portLen;
        string remAddr = Encoding.UTF8.GetString(body.Slice(offset, remAddrLen)); offset += remAddrLen;

        var args = new List<string>(argCnt);
        for (int i = 0; i < argCnt; i++)
        {
            args.Add(Encoding.UTF8.GetString(body.Slice(offset, argLens[i])));
            offset += argLens[i];
        }

        return new AuthorRequestPacket
        {
            AuthenMethod  = authenMethod,
            PrivLvl       = privLvl,
            AuthenType    = authenType,
            AuthenService = authenService,
            User          = user,
            Port          = port,
            RemAddr       = remAddr,
            Args          = args
        };
    }

    /// <summary>Returns the AV-pair value for a given attribute (e.g. "cmd").</summary>
    public string? GetArgValue(string attribute)
    {
        foreach (var arg in Args)
        {
            var sep = arg.IndexOf('=');
            if (sep < 0) sep = arg.IndexOf('*');
            if (sep < 0) continue;
            if (arg[..sep].Equals(attribute, StringComparison.OrdinalIgnoreCase))
                return arg[(sep + 1)..];
        }
        return null;
    }
}

/// <summary>Authorization RESPONSE sent by the PAM TACACS+ server.</summary>
internal sealed class AuthorResponsePacket
{
    public byte Status        { get; set; }
    public string ServerMsg   { get; set; } = string.Empty;
    public string Data        { get; set; } = string.Empty;
    public List<string> Args  { get; set; } = new();

    public byte[] Serialize()
    {
        var msgBytes  = Encoding.UTF8.GetBytes(ServerMsg);
        var dataBytes = Encoding.UTF8.GetBytes(Data);
        var argBufs   = Args.Select(a => Encoding.UTF8.GetBytes(a)).ToList();

        int bodyLen = 6 + argBufs.Count + msgBytes.Length + dataBytes.Length
                      + argBufs.Sum(b => b.Length);
        var buf = new byte[bodyLen];
        int offset = 0;

        buf[offset++] = Status;
        buf[offset++] = (byte)argBufs.Count;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(offset), (ushort)msgBytes.Length); offset += 2;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(offset), (ushort)dataBytes.Length); offset += 2;

        foreach (var b in argBufs)
            buf[offset++] = (byte)b.Length;

        msgBytes.CopyTo(buf, offset);  offset += msgBytes.Length;
        dataBytes.CopyTo(buf, offset); offset += dataBytes.Length;
        foreach (var b in argBufs)
        {
            b.CopyTo(buf, offset);
            offset += b.Length;
        }

        return buf;
    }
}
