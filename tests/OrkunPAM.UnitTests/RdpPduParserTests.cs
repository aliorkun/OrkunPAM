using System.Buffers.Binary;
using System.Text;
using OrkunPAM.RdpProxy.Protocol;

namespace OrkunPAM.UnitTests;

/// <summary>
/// Tests RDP PDU parsing: TPKT framing, X.224 detection,
/// CLIENT_INFO_PDU field extraction, credential injection into PDU.
/// </summary>
public class RdpPduParserTests
{
    [Fact]
    public void TpktPayload_StripsHeader()
    {
        var packet = new byte[] { 3, 0, 0, 8, 0x11, 0x22, 0x33, 0x44 };
        var payload = TpktPacket.Payload(packet);

        Assert.Equal(4, payload.Length);
        Assert.Equal(0x11, payload[0]);
        Assert.Equal(0x44, payload[3]);
    }

    [Fact]
    public void TpktPayload_EmptyPacket_ReturnsEmpty()
    {
        var packet = new byte[] { 3, 0, 0, 4 }; // header only
        var payload = TpktPacket.Payload(packet);
        Assert.True(payload.IsEmpty);
    }

    [Fact]
    public void IdentifyPdu_TooShort_ReturnsUnknown()
    {
        var result = RdpPduParser.IdentifyPdu(new byte[] { 3, 0, 0, 5, 0x00 });
        Assert.Equal(RdpPduType.Unknown, result);
    }

    [Fact]
    public void IdentifyPdu_McsConnectInitial_Detected()
    {
        // TPKT(4) + X.224 with MCS Connect Initial (0x7F 0x65)
        var packet = new byte[20];
        packet[0] = 3; // TPKT version
        packet[2] = 0; packet[3] = 20; // length
        // X.224 CR header would normally be here but MCS Connect Initial
        // sits directly in the TPDU for initial connection
        packet[4] = 0x02; // LI (dummy)
        packet[5] = 0xF0; // X.224 Data... no, MCS Connect Initial is BER encoded
        // For MCS Connect Initial, the TPDU starts with 0x7F 0x65
        packet[4] = 0x7F;
        packet[5] = 0x65;

        var result = RdpPduParser.IdentifyPdu(packet);
        Assert.Equal(RdpPduType.McsConnectInitial, result);
    }

    [Fact]
    public void IdentifyPdu_McsConnectResponse_Detected()
    {
        var packet = new byte[20];
        packet[0] = 3; packet[3] = 20;
        packet[4] = 0x7F;
        packet[5] = 0x66;

        var result = RdpPduParser.IdentifyPdu(packet);
        Assert.Equal(RdpPduType.McsConnectResponse, result);
    }

    [Fact]
    public void ReadBerLength_ShortForm_ParsesCorrectly()
    {
        var data = new byte[] { 0x42 }; // length = 66
        var (length, offset) = RdpPduParser.ReadBerLength(data, 0);

        Assert.Equal(66, length);
        Assert.Equal(1, offset);
    }

    [Fact]
    public void ReadBerLength_LongForm_OneByte_ParsesCorrectly()
    {
        var data = new byte[] { 0x81, 0xC0 }; // length = 192
        var (length, offset) = RdpPduParser.ReadBerLength(data, 0);

        Assert.Equal(192, length);
        Assert.Equal(2, offset);
    }

    [Fact]
    public void ReadBerLength_LongForm_TwoBytes_ParsesCorrectly()
    {
        var data = new byte[] { 0x82, 0x01, 0x00 }; // length = 256
        var (length, offset) = RdpPduParser.ReadBerLength(data, 0);

        Assert.Equal(256, length);
        Assert.Equal(3, offset);
    }

    [Fact]
    public void ReadBerLength_OutOfBounds_ReturnsMinusOne()
    {
        var data = new byte[] { 0x82, 0x01 }; // claims 2 length bytes but only 1 available
        var (length, offset) = RdpPduParser.ReadBerLength(data, 0);

        Assert.Equal(-1, length);
        Assert.Equal(-1, offset);
    }

    [Fact]
    public void ParseInfoPacket_ExtractsFields_Unicode()
    {
        // Build a minimal TS_INFO_PACKET with Unicode flag set
        var domain = "CONTOSO";
        var userName = "admin";
        var password = "P@ssw0rd!";
        var altShell = "";
        var workDir = "";

        uint flags = 0x00000010; // INFO_UNICODE
        var encoding = Encoding.Unicode;
        int nullTermSize = 2;

        byte[] domainBytes = encoding.GetBytes(domain);
        byte[] userBytes = encoding.GetBytes(userName);
        byte[] passBytes = encoding.GetBytes(password);
        byte[] shellBytes = encoding.GetBytes(altShell);
        byte[] wdBytes = encoding.GetBytes(workDir);

        int totalLen = 18
            + domainBytes.Length + nullTermSize
            + userBytes.Length + nullTermSize
            + passBytes.Length + nullTermSize
            + shellBytes.Length + nullTermSize
            + wdBytes.Length + nullTermSize;

        var data = new byte[totalLen];
        int pos = 0;

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(pos), 0); pos += 4; // CodePage
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(pos), flags); pos += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)domainBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)userBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)passBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)shellBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)wdBytes.Length); pos += 2;

        // Variable fields with null terminators
        domainBytes.CopyTo(data, pos); pos += domainBytes.Length; pos += nullTermSize;
        userBytes.CopyTo(data, pos); pos += userBytes.Length; pos += nullTermSize;
        passBytes.CopyTo(data, pos); pos += passBytes.Length; pos += nullTermSize;
        shellBytes.CopyTo(data, pos); pos += shellBytes.Length; pos += nullTermSize;
        wdBytes.CopyTo(data, pos); pos += wdBytes.Length; pos += nullTermSize;

        var result = RdpPduParser.ParseInfoPacket(data);

        Assert.NotNull(result);
        Assert.Equal("CONTOSO", result.Domain);
        Assert.Equal("admin", result.UserName);
        Assert.Equal("P@ssw0rd!", result.Password);
        Assert.Equal(flags, result.Flags);
    }

    [Fact]
    public void ParseInfoPacket_TooShort_ReturnsNull()
    {
        var result = RdpPduParser.ParseInfoPacket(new byte[10]);
        Assert.Null(result);
    }

    [Fact]
    public void BuildInfoPacket_ReplacesCredentials()
    {
        // Build an original info packet
        uint flags = 0x00000010; // INFO_UNICODE
        var encoding = Encoding.Unicode;
        int nullTermSize = 2;

        string origDomain = "OLD";
        string origUser = "olduser";
        string origPass = "oldpass";

        byte[] dBytes = encoding.GetBytes(origDomain);
        byte[] uBytes = encoding.GetBytes(origUser);
        byte[] pBytes = encoding.GetBytes(origPass);
        byte[] empty = Array.Empty<byte>();

        int totalLen = 18 + dBytes.Length + nullTermSize + uBytes.Length + nullTermSize
                       + pBytes.Length + nullTermSize + nullTermSize + nullTermSize;
        var data = new byte[totalLen];
        int pos = 0;

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(pos), 0); pos += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(pos), flags); pos += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)dBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)uBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)pBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), 0); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), 0); pos += 2;

        dBytes.CopyTo(data, pos); pos += dBytes.Length; pos += nullTermSize;
        uBytes.CopyTo(data, pos); pos += uBytes.Length; pos += nullTermSize;
        pBytes.CopyTo(data, pos); pos += pBytes.Length; pos += nullTermSize;
        pos += nullTermSize; // altShell null term
        pos += nullTermSize; // workDir null term

        var parsed = RdpPduParser.ParseInfoPacket(data);
        Assert.NotNull(parsed);

        // Rebuild with new credentials
        var newData = RdpPduParser.BuildInfoPacket(parsed, data, "NEWDOMAIN", "newadmin", "NewP@ss!");

        // Parse the rebuilt packet
        var reparsed = RdpPduParser.ParseInfoPacket(newData);
        Assert.NotNull(reparsed);
        Assert.Equal("NEWDOMAIN", reparsed.Domain);
        Assert.Equal("newadmin", reparsed.UserName);
        Assert.Equal("NewP@ss!", reparsed.Password);
    }

    [Fact]
    public void X224_BuildConnectionConfirm_HasCorrectStructure()
    {
        var packet = X224Packet.BuildConnectionConfirm(X224Packet.ProtocolSsl);

        // Should be a TPKT packet
        Assert.Equal(TpktPacket.Version, packet[0]);

        // Length should match
        int totalLen = (packet[2] << 8) | packet[3];
        Assert.Equal(packet.Length, totalLen);

        // X.224 CC type
        Assert.Equal(X224Packet.PduTypeCC, packet[TpktPacket.HeaderSize + 1]);

        // RDP_NEG_RSP type
        Assert.Equal(X224Packet.RdpNegRsp, packet[TpktPacket.HeaderSize + 7]);
    }

    [Fact]
    public void X224_BuildConnectionFailure_HasNegFailureType()
    {
        var packet = X224Packet.BuildConnectionFailure(0x00000001);

        Assert.Equal(X224Packet.PduTypeCC, packet[TpktPacket.HeaderSize + 1]);
        Assert.Equal(X224Packet.RdpNegFailure, packet[TpktPacket.HeaderSize + 7]);
    }

    [Fact]
    public void ParseInfoPacket_AsciiMode_ExtractsFields()
    {
        // Build a minimal TS_INFO_PACKET WITHOUT Unicode flag
        string domain = "CORP";
        string userName = "root";
        string password = "Secret!";
        uint flags = 0x00000000; // no INFO_UNICODE -> ASCII

        var encoding = Encoding.ASCII;
        int nullTermSize = 1;

        byte[] dBytes = encoding.GetBytes(domain);
        byte[] uBytes = encoding.GetBytes(userName);
        byte[] pBytes = encoding.GetBytes(password);

        int totalLen = 18 + dBytes.Length + nullTermSize + uBytes.Length + nullTermSize
                       + pBytes.Length + nullTermSize + nullTermSize + nullTermSize;
        var data = new byte[totalLen];
        int pos = 0;

        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(pos), 0); pos += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(data.AsSpan(pos), flags); pos += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)dBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)uBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), (ushort)pBytes.Length); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), 0); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(data.AsSpan(pos), 0); pos += 2;

        dBytes.CopyTo(data, pos); pos += dBytes.Length; pos += nullTermSize;
        uBytes.CopyTo(data, pos); pos += uBytes.Length; pos += nullTermSize;
        pBytes.CopyTo(data, pos); pos += pBytes.Length; pos += nullTermSize;
        pos += nullTermSize; pos += nullTermSize;

        var result = RdpPduParser.ParseInfoPacket(data);
        Assert.NotNull(result);
        Assert.Equal("CORP", result.Domain);
        Assert.Equal("root", result.UserName);
        Assert.Equal("Secret!", result.Password);
    }
}
