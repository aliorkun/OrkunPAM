using System.Text;

namespace OrkunPAM.TacacsProxy.Protocol;

// ──────────────────────────────────────────
// Authentication packet types (AUTHEN = 0x01)
// ──────────────────────────────────────────

internal static class AuthenAction
{
    public const byte Login  = 0x01;
    public const byte Chpass = 0x02;
    public const byte Sendauth = 0x04;
}

internal static class AuthenType
{
    public const byte Ascii    = 0x01;
    public const byte Pap      = 0x02;
    public const byte Chap     = 0x03;
    public const byte MsChap   = 0x05;
    public const byte MsChapV2 = 0x06;
}

internal static class AuthenService
{
    public const byte None   = 0x00;
    public const byte Login  = 0x01;
    public const byte Enable = 0x02;
    public const byte Ppp    = 0x03;
}

internal static class AuthenStatus
{
    public const byte Pass     = 0x01;
    public const byte Fail     = 0x02;
    public const byte Getdata  = 0x03;
    public const byte Getuser  = 0x04;
    public const byte Getpass  = 0x05;
    public const byte Restart  = 0x06;
    public const byte Error    = 0x07;
    public const byte Follow   = 0x21;
}

internal static class AuthenReplyFlag
{
    public const byte Noecho = 0x01;
}

internal static class AuthenContinueFlag
{
    public const byte Abort = 0x01;
}

/// <summary>Authentication START packet sent by the NAS device.</summary>
internal sealed class AuthenStartPacket
{
    public byte Action         { get; set; }
    public byte PrivLvl        { get; set; }
    public byte AuthenType     { get; set; }
    public byte AuthenService  { get; set; }
    public string User         { get; set; } = string.Empty;
    public string Port         { get; set; } = string.Empty;
    public string RemAddr      { get; set; } = string.Empty;
    public byte[] Data         { get; set; } = Array.Empty<byte>();

    public static AuthenStartPacket Parse(ReadOnlySpan<byte> body)
    {
        if (body.Length < 8)
            throw new TacacsProtocolException("AuthenStart body too short");

        byte action        = body[0];
        byte privLvl       = body[1];
        byte authenType    = body[2];
        byte authenService = body[3];
        int userLen        = body[4];
        int portLen        = body[5];
        int remAddrLen     = body[6];
        int dataLen        = body[7];

        int offset = 8;
        string user    = Encoding.UTF8.GetString(body.Slice(offset, userLen)); offset += userLen;
        string port    = Encoding.UTF8.GetString(body.Slice(offset, portLen)); offset += portLen;
        string remAddr = Encoding.UTF8.GetString(body.Slice(offset, remAddrLen)); offset += remAddrLen;
        byte[] data    = body.Slice(offset, dataLen).ToArray();

        return new AuthenStartPacket
        {
            Action        = action,
            PrivLvl       = privLvl,
            AuthenType    = authenType,
            AuthenService = authenService,
            User          = user,
            Port          = port,
            RemAddr       = remAddr,
            Data          = data
        };
    }
}

/// <summary>Authentication REPLY packet sent by the PAM TACACS+ server.</summary>
internal sealed class AuthenReplyPacket
{
    public byte Status        { get; set; }
    public byte Flags         { get; set; }
    public string ServerMsg   { get; set; } = string.Empty;
    public byte[] Data        { get; set; } = Array.Empty<byte>();

    public byte[] Serialize()
    {
        var msgBytes  = Encoding.UTF8.GetBytes(ServerMsg);
        var totalBody = 6 + msgBytes.Length + Data.Length;
        var buf       = new byte[totalBody];

        buf[0] = Status;
        buf[1] = Flags;
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), (ushort)msgBytes.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(4), (ushort)Data.Length);
        msgBytes.CopyTo(buf, 6);
        Data.CopyTo(buf, 6 + msgBytes.Length);
        return buf;
    }
}

/// <summary>Authentication CONTINUE packet sent by the NAS after a GETUSER/GETPASS reply.</summary>
internal sealed class AuthenContinuePacket
{
    public byte Flags     { get; set; }
    public string UserMsg { get; set; } = string.Empty;
    public byte[] Data    { get; set; } = Array.Empty<byte>();

    public bool IsAbort => (Flags & AuthenContinueFlag.Abort) != 0;

    public static AuthenContinuePacket Parse(ReadOnlySpan<byte> body)
    {
        if (body.Length < 5)
            throw new TacacsProtocolException("AuthenContinue body too short");

        int userMsgLen = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(body);
        int dataLen    = System.Buffers.Binary.BinaryPrimitives.ReadUInt16BigEndian(body[2..]);
        byte flags     = body[4];

        int offset   = 5;
        string msg   = Encoding.UTF8.GetString(body.Slice(offset, userMsgLen)); offset += userMsgLen;
        byte[] data  = body.Slice(offset, dataLen).ToArray();

        return new AuthenContinuePacket { Flags = flags, UserMsg = msg, Data = data };
    }
}
