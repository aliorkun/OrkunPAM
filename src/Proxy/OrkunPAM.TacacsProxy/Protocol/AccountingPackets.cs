using System.Text;

namespace OrkunPAM.TacacsProxy.Protocol;

// ──────────────────────────────────────────
// Accounting packet types (ACCT = 0x03)
// ──────────────────────────────────────────

internal static class AcctFlag
{
    public const byte More      = 0x01;
    public const byte Start     = 0x02;
    public const byte Stop      = 0x04;
    public const byte Watchdog  = 0x08;
}

internal static class AcctStatus
{
    public const byte Success = 0x01;
    public const byte Error   = 0x02;
    public const byte Follow  = 0x21;
}

/// <summary>Accounting REQUEST sent by NAS.</summary>
internal sealed class AcctRequestPacket
{
    public byte AcctFlags      { get; set; }
    public byte AuthenMethod   { get; set; }
    public byte PrivLvl        { get; set; }
    public byte AuthenType     { get; set; }
    public byte AuthenService  { get; set; }
    public string User         { get; set; } = string.Empty;
    public string Port         { get; set; } = string.Empty;
    public string RemAddr      { get; set; } = string.Empty;
    public List<string> Args   { get; set; } = new();

    public bool IsStart    => (AcctFlags & AcctFlag.Start) != 0;
    public bool IsStop     => (AcctFlags & AcctFlag.Stop)  != 0;
    public bool IsWatchdog => (AcctFlags & AcctFlag.Watchdog) != 0;

    public static AcctRequestPacket Parse(ReadOnlySpan<byte> body)
    {
        if (body.Length < 9)
            throw new TacacsProtocolException("AcctRequest body too short");

        byte acctFlags     = body[0];
        byte authenMethod  = body[1];
        byte privLvl       = body[2];
        byte authenType    = body[3];
        byte authenService = body[4];
        int  userLen       = body[5];
        int  portLen       = body[6];
        int  remAddrLen    = body[7];
        int  argCnt        = body[8];

        if (body.Length < 9 + argCnt)
            throw new TacacsProtocolException("AcctRequest arg lengths missing");

        var argLens = new int[argCnt];
        for (int i = 0; i < argCnt; i++)
            argLens[i] = body[9 + i];

        int offset = 9 + argCnt;
        string user    = Encoding.UTF8.GetString(body.Slice(offset, userLen));    offset += userLen;
        string port    = Encoding.UTF8.GetString(body.Slice(offset, portLen));    offset += portLen;
        string remAddr = Encoding.UTF8.GetString(body.Slice(offset, remAddrLen)); offset += remAddrLen;

        var args = new List<string>(argCnt);
        for (int i = 0; i < argCnt; i++)
        {
            args.Add(Encoding.UTF8.GetString(body.Slice(offset, argLens[i])));
            offset += argLens[i];
        }

        return new AcctRequestPacket
        {
            AcctFlags     = acctFlags,
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

/// <summary>Accounting REPLY sent by the PAM TACACS+ server.</summary>
internal sealed class AcctReplyPacket
{
    public string ServerMsg { get; set; } = string.Empty;
    public string Data      { get; set; } = string.Empty;
    public byte Status      { get; set; }

    public byte[] Serialize()
    {
        var msgBytes  = Encoding.UTF8.GetBytes(ServerMsg);
        var dataBytes = Encoding.UTF8.GetBytes(Data);
        var buf = new byte[5 + msgBytes.Length + dataBytes.Length];

        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(0), (ushort)msgBytes.Length);
        System.Buffers.Binary.BinaryPrimitives.WriteUInt16BigEndian(buf.AsSpan(2), (ushort)dataBytes.Length);
        buf[4] = Status;
        msgBytes.CopyTo(buf, 5);
        dataBytes.CopyTo(buf, 5 + msgBytes.Length);
        return buf;
    }
}
