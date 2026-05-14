using System.Buffers.Binary;
using System.Text;

namespace OrkunPAM.RdpProxy.Protocol;

/// <summary>
/// Parses key RDP PDUs after the X.224/TLS layer:
///   - MCS Connect Initial / Response (T.125)
///   - CLIENT_INFO_PDU (TS_INFO_PACKET)
///   - Server License PDU
///   - Virtual channel data (for audit)
///
/// RDP PDU flow after TLS:
///   Client → MCS Connect Initial (with GCC Conference Create Request)
///   Server → MCS Connect Response (with GCC Conference Create Response)
///   ... MCS Erect Domain / Attach User / Channel Joins ...
///   Client → Security Exchange PDU (if standard RDP security)
///   Client → CLIENT_INFO_PDU (contains credentials)
///   Server → License PDU
///   Server → Demand Active PDU
///   ... capability exchange, then active session ...
/// </summary>
internal static class RdpPduParser
{
    // MCS Connect Initial/Response (T.125 BER-encoded)
    public const byte McsConnectInitialTag = 0x7F; // followed by 0x65
    public const byte McsConnectResponseTag = 0x7F; // followed by 0x66

    // MCS domain PDU types (first byte >> 2)
    public const byte McsSendDataRequest = 0x64;    // 25 << 2 = 100
    public const byte McsSendDataIndication = 0x68; // 26 << 2 = 104
    public const byte McsErectDomainRequest = 0x04;
    public const byte McsAttachUserRequest = 0x28;
    public const byte McsAttachUserConfirm = 0x2E;
    public const byte McsChannelJoinRequest = 0x38;
    public const byte McsChannelJoinConfirm = 0x3E;

    // Security header flags (LE uint16 at start of security header)
    public const ushort SecExchangePkt = 0x0001;
    public const ushort SecInfoPkt = 0x0040;      // CLIENT_INFO_PDU
    public const ushort SecLicensePkt = 0x0080;
    public const ushort SecEncryptFlag = 0x0008;
    public const ushort SecRedirectionPkt = 0x0400;

    /// <summary>
    /// Identifies the type of an RDP PDU received over X.224 Data TPDU.
    /// The input is the full TPKT packet (including TPKT header).
    /// </summary>
    public static RdpPduType IdentifyPdu(ReadOnlySpan<byte> tpktPacket)
    {
        if (tpktPacket.Length < 7) return RdpPduType.Unknown;

        var tpdu = tpktPacket[TpktPacket.HeaderSize..];
        if (tpdu.Length < 3) return RdpPduType.Unknown;

        // X.224 Data TPDU: LI=2, type=0xF0, EOT=0x80
        if (tpdu[1] == X224Packet.PduTypeDT)
        {
            int x224HeaderLen = tpdu[0] + 1; // LI + 1
            if (x224HeaderLen >= tpdu.Length) return RdpPduType.Unknown;
            var mcsData = tpdu[x224HeaderLen..];
            return IdentifyMcsPdu(mcsData);
        }

        // MCS Connect Initial/Response are BER-encoded directly in the TPDU
        if (tpdu.Length >= 2 && tpdu[0] == 0x7F)
        {
            if (tpdu[1] == 0x65) return RdpPduType.McsConnectInitial;
            if (tpdu[1] == 0x66) return RdpPduType.McsConnectResponse;
        }

        return RdpPduType.Unknown;
    }

    private static RdpPduType IdentifyMcsPdu(ReadOnlySpan<byte> mcsData)
    {
        if (mcsData.IsEmpty) return RdpPduType.Unknown;

        byte tag = mcsData[0];

        // MCS Send Data Request/Indication carry the security-layer PDUs
        if (tag == McsSendDataRequest || tag == McsSendDataIndication)
        {
            // Parse MCS Send Data header to get to the security header
            // Format: tag(1) + userId(2) + channelId(2) + dataPriority+segmentation(1) + userData length(variable BER)
            if (mcsData.Length < 7) return RdpPduType.McsData;

            int offset = 1; // skip tag
            offset += 2;    // skip userId (PER encoded, 2 bytes)
            int channelId = (mcsData[offset] << 8) | mcsData[offset + 1];
            offset += 2;    // skip channelId
            offset += 1;    // skip dataPriority + segmentation

            // Parse BER length of user data
            int userDataLen;
            (userDataLen, offset) = ReadBerLength(mcsData, offset);
            if (offset < 0 || offset >= mcsData.Length) return RdpPduType.McsData;

            var securityData = mcsData[offset..];

            // The I/O channel (typically 1003) carries CLIENT_INFO_PDU and licensing
            // Check security header flags
            if (securityData.Length >= 4)
            {
                ushort secFlags = BinaryPrimitives.ReadUInt16LittleEndian(securityData);

                if ((secFlags & SecInfoPkt) != 0) return RdpPduType.ClientInfoPdu;
                if ((secFlags & SecLicensePkt) != 0) return RdpPduType.ServerLicensePdu;
                if ((secFlags & SecExchangePkt) != 0) return RdpPduType.SecurityExchangePdu;
            }

            return RdpPduType.McsData;
        }

        return tag switch
        {
            McsErectDomainRequest => RdpPduType.McsErectDomain,
            McsAttachUserRequest => RdpPduType.McsAttachUserRequest,
            McsAttachUserConfirm => RdpPduType.McsAttachUserConfirm,
            McsChannelJoinRequest => RdpPduType.McsChannelJoinRequest,
            McsChannelJoinConfirm => RdpPduType.McsChannelJoinConfirm,
            _ => RdpPduType.Unknown
        };
    }

    /// <summary>
    /// Extracts the TS_INFO_PACKET from a CLIENT_INFO_PDU TPKT packet.
    /// Returns the offset and length of the info packet within the TPKT data,
    /// or (-1, 0) if parsing fails.
    /// </summary>
    public static (int offset, int length) FindInfoPacket(ReadOnlySpan<byte> tpktPacket)
    {
        if (tpktPacket.Length < TpktPacket.HeaderSize + 3)
            return (-1, 0);

        var tpdu = tpktPacket[TpktPacket.HeaderSize..];
        int x224HeaderLen = tpdu[0] + 1;
        if (x224HeaderLen >= tpdu.Length) return (-1, 0);

        var mcsData = tpdu[x224HeaderLen..];
        if (mcsData.Length < 7) return (-1, 0);

        int offset = 1; // tag
        offset += 2;    // userId
        offset += 2;    // channelId
        offset += 1;    // dataPriority + segmentation

        int userDataLen;
        (userDataLen, offset) = ReadBerLength(mcsData, offset);
        if (offset < 0) return (-1, 0);

        // Security header: flags(2) + flagsHi(2) = 4 bytes (basic security header)
        if (offset + 4 > mcsData.Length) return (-1, 0);

        ushort secFlags = BinaryPrimitives.ReadUInt16LittleEndian(mcsData[offset..]);
        if ((secFlags & SecInfoPkt) == 0) return (-1, 0);

        int secHeaderSize = 4; // basic security header for standard RDP security with no encryption
        int infoOffset = TpktPacket.HeaderSize + x224HeaderLen + offset + secHeaderSize;
        int infoLength = tpktPacket.Length - infoOffset;

        return (infoOffset, infoLength);
    }

    /// <summary>
    /// Parses TS_INFO_PACKET fields from raw bytes.
    /// MS-RDPBCGR 2.2.1.11.1.1
    /// </summary>
    public static TsInfoPacket? ParseInfoPacket(ReadOnlySpan<byte> data)
    {
        // TS_INFO_PACKET:
        //   CodePage(4) + Flags(4) + cbDomain(2) + cbUserName(2) + cbPassword(2) + cbAlternateShell(2) + cbWorkingDir(2)
        //   = 18 bytes fixed header, then variable-length fields
        if (data.Length < 18) return null;

        uint codePage = BinaryPrimitives.ReadUInt32LittleEndian(data);
        uint flags = BinaryPrimitives.ReadUInt32LittleEndian(data[4..]);
        ushort cbDomain = BinaryPrimitives.ReadUInt16LittleEndian(data[8..]);
        ushort cbUserName = BinaryPrimitives.ReadUInt16LittleEndian(data[10..]);
        ushort cbPassword = BinaryPrimitives.ReadUInt16LittleEndian(data[12..]);
        ushort cbAlternateShell = BinaryPrimitives.ReadUInt16LittleEndian(data[14..]);
        ushort cbWorkingDir = BinaryPrimitives.ReadUInt16LittleEndian(data[16..]);

        bool isUnicode = (flags & 0x00000010) != 0; // INFO_UNICODE flag
        int offset = 18;

        string domain = ReadInfoString(data, ref offset, cbDomain, isUnicode);
        string userName = ReadInfoString(data, ref offset, cbUserName, isUnicode);
        string password = ReadInfoString(data, ref offset, cbPassword, isUnicode);
        string alternateShell = ReadInfoString(data, ref offset, cbAlternateShell, isUnicode);
        string workingDir = ReadInfoString(data, ref offset, cbWorkingDir, isUnicode);

        return new TsInfoPacket(
            codePage, flags, domain, userName, password,
            alternateShell, workingDir, offset, data.Length);
    }

    /// <summary>
    /// Builds a new TS_INFO_PACKET with replaced credentials.
    /// Preserves original flags and extended data.
    /// </summary>
    public static byte[] BuildInfoPacket(
        TsInfoPacket original,
        ReadOnlySpan<byte> originalData,
        string newDomain,
        string newUserName,
        string newPassword)
    {
        bool isUnicode = (original.Flags & 0x00000010) != 0;
        var encoding = isUnicode ? Encoding.Unicode : Encoding.ASCII;
        int nullTermSize = isUnicode ? 2 : 1;

        // Encode new credential strings (without null terminator for cbLength, but with null terminator in data)
        byte[] domainBytes = encoding.GetBytes(newDomain);
        byte[] userNameBytes = encoding.GetBytes(newUserName);
        byte[] passwordBytes = encoding.GetBytes(newPassword);
        byte[] altShellBytes = encoding.GetBytes(original.AlternateShell);
        byte[] workingDirBytes = encoding.GetBytes(original.WorkingDir);

        // cbX fields represent length WITHOUT the mandatory null terminator
        ushort cbDomain = (ushort)domainBytes.Length;
        ushort cbUserName = (ushort)userNameBytes.Length;
        ushort cbPassword = (ushort)passwordBytes.Length;
        ushort cbAlternateShell = (ushort)altShellBytes.Length;
        ushort cbWorkingDir = (ushort)workingDirBytes.Length;

        // Extended data after the parsed variable fields
        int extendedDataLen = originalData.Length > original.ParsedLength
            ? originalData.Length - original.ParsedLength
            : 0;

        int totalLen = 18
            + cbDomain + nullTermSize
            + cbUserName + nullTermSize
            + cbPassword + nullTermSize
            + cbAlternateShell + nullTermSize
            + cbWorkingDir + nullTermSize
            + extendedDataLen;

        var result = new byte[totalLen];
        int pos = 0;

        // Fixed header
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(pos), original.CodePage); pos += 4;
        BinaryPrimitives.WriteUInt32LittleEndian(result.AsSpan(pos), original.Flags); pos += 4;
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(pos), cbDomain); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(pos), cbUserName); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(pos), cbPassword); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(pos), cbAlternateShell); pos += 2;
        BinaryPrimitives.WriteUInt16LittleEndian(result.AsSpan(pos), cbWorkingDir); pos += 2;

        // Variable fields (each followed by null terminator)
        WriteInfoField(result, ref pos, domainBytes, nullTermSize);
        WriteInfoField(result, ref pos, userNameBytes, nullTermSize);
        WriteInfoField(result, ref pos, passwordBytes, nullTermSize);
        WriteInfoField(result, ref pos, altShellBytes, nullTermSize);
        WriteInfoField(result, ref pos, workingDirBytes, nullTermSize);

        // Copy extended data (extraInfo, etc.)
        if (extendedDataLen > 0)
        {
            originalData[original.ParsedLength..].CopyTo(result.AsSpan(pos));
        }

        return result;
    }

    /// <summary>
    /// Identifies the virtual channel ID from an MCS Send Data PDU.
    /// Returns the channel ID, or -1 if unable to parse.
    /// </summary>
    public static int GetMcsChannelId(ReadOnlySpan<byte> tpktPacket)
    {
        if (tpktPacket.Length < TpktPacket.HeaderSize + 3) return -1;
        var tpdu = tpktPacket[TpktPacket.HeaderSize..];
        int x224HeaderLen = tpdu[0] + 1;
        if (x224HeaderLen >= tpdu.Length) return -1;
        var mcsData = tpdu[x224HeaderLen..];
        if (mcsData.Length < 5) return -1;

        byte tag = mcsData[0];
        if (tag != McsSendDataRequest && tag != McsSendDataIndication) return -1;

        // channelId at offset 3-4 (after tag + userId)
        return (mcsData[3] << 8) | mcsData[4];
    }

    /// <summary>
    /// Reads a BER-encoded length from the given span at the specified offset.
    /// Returns (length, newOffset) or (-1, -1) on failure.
    /// </summary>
    internal static (int length, int newOffset) ReadBerLength(ReadOnlySpan<byte> data, int offset)
    {
        if (offset >= data.Length) return (-1, -1);

        byte first = data[offset++];
        if ((first & 0x80) == 0)
        {
            return (first, offset);
        }

        int numBytes = first & 0x7F;
        if (numBytes == 0 || numBytes > 4 || offset + numBytes > data.Length)
            return (-1, -1);

        int length = 0;
        for (int i = 0; i < numBytes; i++)
        {
            length = (length << 8) | data[offset++];
        }

        return (length, offset);
    }

    private static string ReadInfoString(ReadOnlySpan<byte> data, ref int offset, int cbLength, bool isUnicode)
    {
        if (offset + cbLength > data.Length)
        {
            offset = data.Length;
            return string.Empty;
        }

        var encoding = isUnicode ? Encoding.Unicode : Encoding.ASCII;
        string result = encoding.GetString(data.Slice(offset, cbLength));
        offset += cbLength;

        // Skip the mandatory null terminator
        int nullTermSize = isUnicode ? 2 : 1;
        if (offset + nullTermSize <= data.Length)
            offset += nullTermSize;

        return result;
    }

    private static void WriteInfoField(byte[] buffer, ref int pos, byte[] fieldData, int nullTermSize)
    {
        fieldData.CopyTo(buffer, pos);
        pos += fieldData.Length;
        // null terminator (already zeroed by array init)
        pos += nullTermSize;
    }
}

/// <summary>PDU type classification for the RDP proxy.</summary>
internal enum RdpPduType
{
    Unknown,
    McsConnectInitial,
    McsConnectResponse,
    McsErectDomain,
    McsAttachUserRequest,
    McsAttachUserConfirm,
    McsChannelJoinRequest,
    McsChannelJoinConfirm,
    McsData,
    SecurityExchangePdu,
    ClientInfoPdu,
    ServerLicensePdu,
}

/// <summary>Parsed TS_INFO_PACKET fields.</summary>
internal sealed record TsInfoPacket(
    uint CodePage,
    uint Flags,
    string Domain,
    string UserName,
    string Password,
    string AlternateShell,
    string WorkingDir,
    int ParsedLength,
    int TotalLength);
