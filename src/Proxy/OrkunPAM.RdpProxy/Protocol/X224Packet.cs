using System.Text;

namespace OrkunPAM.RdpProxy.Protocol;

/// <summary>
/// X.224 (ISO 8073) transport layer PDUs embedded in TPKT.
/// We implement only the Connection Request (CR=0xE0) and Connection Confirm (CC=0xD0) needed for RDP proxying.
/// </summary>
internal static class X224Packet
{
    public const byte PduTypeCR = 0xE0; // Connection Request
    public const byte PduTypeCC = 0xD0; // Connection Confirm
    public const byte PduTypeDT = 0xF0; // Data

    // RDP Negotiation Request/Response types (follow X.224 user data)
    public const byte RdpNegReq = 0x01;
    public const byte RdpNegRsp = 0x02;
    public const byte RdpNegFailure = 0x03;

    // Requested protocol flags
    public const uint ProtocolRdp = 0x00000000;
    public const uint ProtocolSsl = 0x00000001;
    public const uint ProtocolHybrid = 0x00000002;  // NLA/CredSSP

    /// <summary>
    /// Parses an X.224 Connection Request TPDU and extracts the RDP cookie (session token).
    /// The cookie field contains "Cookie: mstshash=TOKEN\r\n".
    /// Returns null if no cookie is present.
    /// </summary>
    public static (string? sessionToken, uint requestedProtocols) ParseConnectionRequest(byte[] tpktPacket)
    {
        var tpdu = TpktPacket.Payload(tpktPacket);
        if (tpdu.Length < 7) return (null, ProtocolRdp);

        // byte 0: LI (length indicator)
        // byte 1: type (0xE0 for CR)
        if ((tpdu[1] & 0xF0) != PduTypeCR) return (null, ProtocolRdp);

        int liBytes = tpdu[0] + 1; // LI does not count itself, variable header ends here
        // Variable header follows at offset liBytes
        var userData = tpdu[liBytes..];

        string? cookie = null;
        uint requestedProtocols = ProtocolRdp;

        int pos = 0;
        // RDP cookie is ASCII text ending with \r\n
        var rawText = Encoding.ASCII.GetString(userData.ToArray());
        const string prefix = "Cookie: mstshash=";
        int cookieIdx = rawText.IndexOf(prefix, StringComparison.Ordinal);
        if (cookieIdx >= 0)
        {
            int start = cookieIdx + prefix.Length;
            int end = rawText.IndexOf('\r', start);
            if (end > start)
                cookie = rawText[start..end];

            pos = end + 2; // skip \r\n
        }

        // RDP Negotiation Request (type=1) follows the cookie
        if (pos < userData.Length && userData[pos] == RdpNegReq && pos + 8 <= userData.Length)
        {
            requestedProtocols =
                (uint)(userData[pos + 4] | (userData[pos + 5] << 8) |
                       (userData[pos + 6] << 16) | (userData[pos + 7] << 24));
        }

        return (cookie, requestedProtocols);
    }

    /// <summary>
    /// Builds an X.224 Connection Confirm TPDU inside a TPKT packet.
    /// Advertises the selected protocol in the RDP_NEG_RSP.
    /// </summary>
    public static byte[] BuildConnectionConfirm(uint selectedProtocol)
    {
        // X.224 CC header (7 bytes: LI, type=0xD0, dst-ref[2], src-ref[2], class)
        // RDP_NEG_RSP (8 bytes): type=2, flags=0, length=8, selectedProtocol[4]
        byte[] tpdu = new byte[7 + 8];
        tpdu[0] = (byte)(tpdu.Length - 1); // LI
        tpdu[1] = PduTypeCC;
        // dst-ref / src-ref / class = 0
        // RDP_NEG_RSP
        tpdu[7]  = RdpNegRsp;
        tpdu[8]  = 0x00; // flags
        tpdu[9]  = 0x08; // length lo
        tpdu[10] = 0x00; // length hi
        tpdu[11] = (byte)(selectedProtocol & 0xFF);
        tpdu[12] = (byte)((selectedProtocol >> 8) & 0xFF);
        tpdu[13] = (byte)((selectedProtocol >> 16) & 0xFF);
        tpdu[14] = (byte)((selectedProtocol >> 24) & 0xFF);

        // Wrap in TPKT
        var result = new byte[TpktPacket.HeaderSize + tpdu.Length];
        result[0] = TpktPacket.Version;
        result[1] = 0;
        int total = result.Length;
        result[2] = (byte)(total >> 8);
        result[3] = (byte)(total & 0xFF);
        tpdu.CopyTo(result, TpktPacket.HeaderSize);
        return result;
    }

    /// <summary>
    /// Builds an X.224 Connection Confirm rejecting the connection (RDP_NEG_FAILURE).
    /// </summary>
    public static byte[] BuildConnectionFailure(uint failureCode)
    {
        byte[] tpdu = new byte[7 + 8];
        tpdu[0] = (byte)(tpdu.Length - 1);
        tpdu[1] = PduTypeCC;
        tpdu[7]  = RdpNegFailure;
        tpdu[11] = (byte)(failureCode & 0xFF);
        tpdu[12] = (byte)((failureCode >> 8) & 0xFF);
        tpdu[13] = (byte)((failureCode >> 16) & 0xFF);
        tpdu[14] = (byte)((failureCode >> 24) & 0xFF);

        var result = new byte[TpktPacket.HeaderSize + tpdu.Length];
        result[0] = TpktPacket.Version; result[1] = 0;
        int total = result.Length;
        result[2] = (byte)(total >> 8); result[3] = (byte)(total & 0xFF);
        tpdu.CopyTo(result, TpktPacket.HeaderSize);
        return result;
    }
}
