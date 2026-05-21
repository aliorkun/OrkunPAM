using System.Buffers.Binary;
using System.Text;
using OrkunPAM.RdpProxy;

namespace OrkunPAM.RdpProxy.Protocol;

/// <summary>
/// Audits RDP virtual channel activity for security-relevant operations:
///   - Clipboard transfers (CLIPRDR channel)
///   - Drive/file redirections (RDPDR channel)
///   - Printer redirections (RDPDR channel)
///
/// Virtual channels are multiplexed over MCS channels. During the MCS Connect
/// phase, the client and server negotiate channel IDs. This auditor tracks
/// those mappings and inspects data PDUs on monitored channels.
///
/// All audit events are logged via structured Serilog logging so they
/// flow to the SIEM event bus.
/// </summary>
internal sealed class RdpCommandAuditor
{
    private readonly string _sessionId;
    private readonly ILogger _log;

    // Well-known static virtual channel names (MS-RDPBCGR 2.2.1.3.4.1)
    private const string CliprdChannelName = "cliprdr";
    private const string RdpdrChannelName = "rdpdr";

    // Channel ID mappings discovered during MCS negotiation
    private readonly Dictionary<int, string> _channelMap = new();

    // CLIPRDR PDU types (MS-RDPECLIP)
    private const ushort CB_MONITOR_READY = 0x0001;
    private const ushort CB_FORMAT_LIST = 0x0002;
    private const ushort CB_FORMAT_LIST_RESPONSE = 0x0003;
    private const ushort CB_FORMAT_DATA_REQUEST = 0x0004;
    private const ushort CB_FORMAT_DATA_RESPONSE = 0x0005;
    private const ushort CB_FILECONTENTS_REQUEST = 0x0008;
    private const ushort CB_FILECONTENTS_RESPONSE = 0x0009;

    // RDPDR PDU types (MS-RDPEFS)
    private const ushort CYCLED_CORE = 0x4472;      // "rD" - Server/Client Core
    private const ushort CYCLED_CLIENTID = 0x4343;   // "CC" - Client ID
    private const ushort PAKID_CORE_SERVER_ANNOUNCE = 0x496E;
    private const ushort CYCLED_ANNOUNCE = 0x416E;

    // RDPDR device types
    private const uint CYCLED_DISK = 0x00000008;
    private const uint CYCLED_PRINT = 0x00000004;

    // Clipboard format IDs
    private const uint CF_TEXT = 1;
    private const uint CF_UNICODETEXT = 13;
    private const uint CF_HDROP = 15;

    private long _clipboardTransferCount;
    private long _driveRedirectionCount;
    private long _printerRedirectionCount;

    private PeripheralPolicy _policy = new(false, false, true, false, false, true);

    public RdpCommandAuditor(string sessionId, ILogger log)
    {
        _sessionId = sessionId;
        _log = log;
    }

    /// <summary>Sets the peripheral redirection policy for this session.</summary>
    public void SetPeripheralPolicy(PeripheralPolicy policy) => _policy = policy;

    /// <summary>Clipboard transfer count during this session.</summary>
    public long ClipboardTransferCount => Interlocked.Read(ref _clipboardTransferCount);
    /// <summary>Drive redirection count during this session.</summary>
    public long DriveRedirectionCount => Interlocked.Read(ref _driveRedirectionCount);
    /// <summary>Printer redirection count during this session.</summary>
    public long PrinterRedirectionCount => Interlocked.Read(ref _printerRedirectionCount);

    /// <summary>
    /// Registers a virtual channel name-to-ID mapping discovered during MCS negotiation.
    /// Called when parsing MCS Connect Initial/Response GCC data.
    /// </summary>
    public void RegisterChannel(int channelId, string channelName)
    {
        _channelMap[channelId] = channelName.ToLowerInvariant();
        _log.LogDebug("Session {SessionId}: registered virtual channel {ChannelName} = MCS channel {ChannelId}",
            _sessionId, channelName, channelId);
    }

    /// <summary>
    /// Registers multiple virtual channels from the channel definition list.
    /// Channel IDs are assigned starting from the base channel ID (typically 1004).
    /// </summary>
    public void RegisterChannelsFromNames(IReadOnlyList<string> channelNames, int baseChannelId = 1004)
    {
        for (int i = 0; i < channelNames.Count; i++)
        {
            RegisterChannel(baseChannelId + i, channelNames[i]);
        }
    }

    /// <summary>
    /// Returns true if the PDU should be blocked (dropped) based on peripheral policy.
    /// Logs an audit event on first block for each channel type.
    /// </summary>
    public bool ShouldBlockPdu(byte[] tpktPacket, bool fromTarget)
    {
        try
        {
            int channelId = RdpPduParser.GetMcsChannelId(tpktPacket);
            if (channelId < 0 || !_channelMap.TryGetValue(channelId, out var channelName))
                return false;

            return channelName switch
            {
                CliprdChannelName when !_policy.AllowClipboard => LogAndBlock("CLIPBOARD_REDIRECTION_BLOCKED", channelName),
                RdpdrChannelName when !_policy.AllowDriveRedirection && !_policy.AllowPrinterRedirection => LogAndBlock("DRIVE_REDIRECTION_BLOCKED", channelName),
                "rdpsnd" when !_policy.AllowAudioRedirection => LogAndBlock("AUDIO_REDIRECTION_BLOCKED", channelName),
                _ => false
            };
        }
        catch { return false; }
    }

    private bool LogAndBlock(string auditEvent, string channelName)
    {
        _log.LogWarning(
            "Session {SessionId} POLICY: {AuditEvent} — channel={Channel} blocked by peripheral policy",
            _sessionId, auditEvent, channelName);
        return true;
    }

    /// <summary>
    /// Inspects an RDP PDU for audit-worthy virtual channel activity.
    /// Should be called for every PDU flowing in both directions.
    /// </summary>
    public void InspectPdu(byte[] tpktPacket, bool fromTarget)
    {
        try
        {
            int channelId = RdpPduParser.GetMcsChannelId(tpktPacket);
            if (channelId < 0 || !_channelMap.TryGetValue(channelId, out var channelName))
                return;

            // Extract user data from the MCS Send Data PDU
            var userData = ExtractMcsUserData(tpktPacket);
            if (userData.IsEmpty) return;

            switch (channelName)
            {
                case CliprdChannelName:
                    AuditClipboard(userData, fromTarget);
                    break;
                case RdpdrChannelName:
                    AuditDeviceRedirection(userData, fromTarget);
                    break;
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Session {SessionId}: failed to inspect PDU for audit", _sessionId);
        }
    }

    /// <summary>
    /// Attempts to parse channel names from an MCS Connect Initial PDU.
    /// This is a best-effort extraction of the GCC Conference Create Request
    /// client network data (CS_NET) to discover virtual channel names.
    /// </summary>
    public void TryParseChannelDefinitions(byte[] tpktPacket)
    {
        try
        {
            var data = tpktPacket.AsSpan();
            // Search for channel name patterns in the GCC data
            // Channel names are 8-byte null-padded ASCII strings in CS_NET
            var channelNames = new List<string>();

            // Look for well-known channel name patterns
            for (int i = 0; i < data.Length - 12; i++)
            {
                // Each channel def entry is 12 bytes: name[8] + options[4]
                if (IsAsciiChannelName(data.Slice(i, 8)))
                {
                    string name = Encoding.ASCII.GetString(data.Slice(i, 8)).TrimEnd('\0');
                    if (name.Length > 0 && IsKnownChannelName(name))
                    {
                        channelNames.Add(name);
                        _log.LogDebug("Session {SessionId}: discovered channel name '{ChannelName}' in MCS Connect Initial",
                            _sessionId, name);
                    }
                }
            }

            if (channelNames.Count > 0)
            {
                RegisterChannelsFromNames(channelNames);
            }
        }
        catch (Exception ex)
        {
            _log.LogDebug(ex, "Session {SessionId}: failed to parse channel definitions", _sessionId);
        }
    }

    /// <summary>
    /// Logs a summary of all audit events for this session.
    /// Should be called when the session ends.
    /// </summary>
    public void LogSessionSummary()
    {
        _log.LogInformation(
            "Session {SessionId} audit summary: clipboard={ClipboardCount}, drive={DriveCount}, printer={PrinterCount}",
            _sessionId,
            Interlocked.Read(ref _clipboardTransferCount),
            Interlocked.Read(ref _driveRedirectionCount),
            Interlocked.Read(ref _printerRedirectionCount));
    }

    private void AuditClipboard(ReadOnlySpan<byte> userData, bool fromTarget)
    {
        // CLIPRDR PDU header: msgType(2) + msgFlags(2) + dataLen(4)
        if (userData.Length < 8) return;

        ushort msgType = BinaryPrimitives.ReadUInt16LittleEndian(userData);
        ushort msgFlags = BinaryPrimitives.ReadUInt16LittleEndian(userData[2..]);
        uint dataLen = BinaryPrimitives.ReadUInt32LittleEndian(userData[4..]);

        string direction = fromTarget ? "server->client" : "client->server";

        switch (msgType)
        {
            case CB_FORMAT_LIST:
                _log.LogInformation(
                    "Session {SessionId} AUDIT: clipboard format list advertised ({Direction}), dataLen={DataLen}",
                    _sessionId, direction, dataLen);
                break;

            case CB_FORMAT_DATA_REQUEST:
                Interlocked.Increment(ref _clipboardTransferCount);
                uint formatId = userData.Length >= 12
                    ? BinaryPrimitives.ReadUInt32LittleEndian(userData[8..])
                    : 0;
                string formatName = FormatIdToName(formatId);
                _log.LogWarning(
                    "Session {SessionId} AUDIT: clipboard data requested ({Direction}), format={Format}",
                    _sessionId, direction, formatName);
                break;

            case CB_FORMAT_DATA_RESPONSE:
                _log.LogInformation(
                    "Session {SessionId} AUDIT: clipboard data response ({Direction}), size={Size} bytes",
                    _sessionId, direction, dataLen);
                break;

            case CB_FILECONTENTS_REQUEST:
                Interlocked.Increment(ref _clipboardTransferCount);
                _log.LogWarning(
                    "Session {SessionId} AUDIT: clipboard FILE transfer requested ({Direction})",
                    _sessionId, direction);
                break;

            case CB_FILECONTENTS_RESPONSE:
                _log.LogWarning(
                    "Session {SessionId} AUDIT: clipboard FILE transfer response ({Direction}), size={Size} bytes",
                    _sessionId, direction, dataLen);
                break;
        }
    }

    private void AuditDeviceRedirection(ReadOnlySpan<byte> userData, bool fromTarget)
    {
        // RDPDR PDU header: Component(2) + PacketId(2)
        if (userData.Length < 4) return;

        ushort component = BinaryPrimitives.ReadUInt16LittleEndian(userData);
        ushort packetId = BinaryPrimitives.ReadUInt16LittleEndian(userData[2..]);

        // Client Announce Reply or Device List Announce
        // Device List Announce: Component=CYCLED_CORE(0x4472), PacketId=0x4441 ("DA")
        if (component == CYCLED_CORE && packetId == 0x4441 && !fromTarget)
        {
            // Device list announce from client
            // Header(4) + DeviceCount(4) + DeviceList
            if (userData.Length < 8) return;
            uint deviceCount = BinaryPrimitives.ReadUInt32LittleEndian(userData[4..]);

            int offset = 8;
            for (uint i = 0; i < deviceCount && offset + 20 <= userData.Length; i++)
            {
                uint deviceType = BinaryPrimitives.ReadUInt32LittleEndian(userData[offset..]);
                uint deviceId = BinaryPrimitives.ReadUInt32LittleEndian(userData[(offset + 4)..]);

                // Device name: 8 bytes, null-padded ASCII
                string deviceName = offset + 12 + 8 <= userData.Length
                    ? Encoding.ASCII.GetString(userData.Slice(offset + 12, 8)).TrimEnd('\0')
                    : "unknown";

                uint deviceDataLen = offset + 24 <= userData.Length
                    ? BinaryPrimitives.ReadUInt32LittleEndian(userData[(offset + 20)..])
                    : 0;

                if (deviceType == CYCLED_DISK)
                {
                    Interlocked.Increment(ref _driveRedirectionCount);
                    _log.LogWarning(
                        "Session {SessionId} AUDIT: drive redirection announced — device={DeviceName} id={DeviceId}",
                        _sessionId, deviceName, deviceId);
                }
                else if (deviceType == CYCLED_PRINT)
                {
                    Interlocked.Increment(ref _printerRedirectionCount);
                    _log.LogWarning(
                        "Session {SessionId} AUDIT: printer redirection announced — device={DeviceName} id={DeviceId}",
                        _sessionId, deviceName, deviceId);
                }

                offset += 20 + (int)deviceDataLen;
            }
        }
    }

    private static ReadOnlySpan<byte> ExtractMcsUserData(byte[] tpktPacket)
    {
        if (tpktPacket.Length < TpktPacket.HeaderSize + 3) return ReadOnlySpan<byte>.Empty;

        var tpdu = tpktPacket.AsSpan(TpktPacket.HeaderSize);
        int x224HeaderLen = tpdu[0] + 1;
        if (x224HeaderLen >= tpdu.Length) return ReadOnlySpan<byte>.Empty;

        var mcsData = tpdu[x224HeaderLen..];
        if (mcsData.Length < 7) return ReadOnlySpan<byte>.Empty;

        byte tag = mcsData[0];
        if (tag != RdpPduParser.McsSendDataRequest && tag != RdpPduParser.McsSendDataIndication)
            return ReadOnlySpan<byte>.Empty;

        int offset = 1 + 2 + 2 + 1; // tag + userId + channelId + flags
        var (_, dataStart) = RdpPduParser.ReadBerLength(mcsData, offset);
        if (dataStart < 0 || dataStart >= mcsData.Length)
            return ReadOnlySpan<byte>.Empty;

        return mcsData[dataStart..];
    }

    private static bool IsAsciiChannelName(ReadOnlySpan<byte> data)
    {
        if (data.Length < 4) return false;
        // Must start with printable ASCII
        for (int i = 0; i < data.Length; i++)
        {
            byte b = data[i];
            if (b == 0) break; // null terminator
            if (b < 0x20 || b > 0x7E) return false;
        }
        // Must have at least 3 printable chars
        int printable = 0;
        for (int i = 0; i < data.Length && data[i] != 0; i++) printable++;
        return printable >= 3;
    }

    private static bool IsKnownChannelName(string name)
    {
        var lower = name.ToLowerInvariant();
        return lower is CliprdChannelName or RdpdrChannelName
            or "rdpsnd" or "drdynvc" or "rail" or "rdpinpt";
    }

    private static string FormatIdToName(uint formatId) => formatId switch
    {
        CF_TEXT => "CF_TEXT",
        CF_UNICODETEXT => "CF_UNICODETEXT",
        CF_HDROP => "CF_HDROP(files)",
        _ => $"0x{formatId:X4}"
    };
}
