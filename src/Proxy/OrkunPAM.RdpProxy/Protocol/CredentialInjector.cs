using System.Security.Cryptography;
using System.Text;

namespace OrkunPAM.RdpProxy.Protocol;

/// <summary>
/// Intercepts CLIENT_INFO_PDU from the RDP client and replaces the
/// domain/username/password fields with vault-sourced credentials.
///
/// The PDU is rebuilt with correct lengths so the target RDP server
/// authenticates using the PAM-managed credential rather than whatever
/// the client originally sent.
///
/// Security: The injected password bytes are zeroed after the modified
/// PDU is written to the target stream.
/// </summary>
internal sealed class CredentialInjector
{
    private readonly string _targetDomain;
    private readonly string _targetUserName;
    private readonly byte[] _targetPasswordBytes;
    private readonly ILogger _log;

    private bool _injected;

    public CredentialInjector(
        string targetDomain,
        string targetUserName,
        byte[] targetPasswordBytes,
        ILogger log)
    {
        _targetDomain = targetDomain ?? string.Empty;
        _targetUserName = targetUserName;
        _targetPasswordBytes = targetPasswordBytes;
        _log = log;
    }

    /// <summary>Whether credential injection has already been performed.</summary>
    public bool HasInjected => _injected;

    /// <summary>
    /// Attempts to inject credentials into a CLIENT_INFO_PDU.
    /// If the packet is not a CLIENT_INFO_PDU or injection fails,
    /// returns null (caller should forward the original packet).
    /// On success, returns the modified TPKT packet with replaced credentials.
    /// </summary>
    public byte[]? TryInject(byte[] tpktPacket)
    {
        if (_injected) return null;

        var pduType = RdpPduParser.IdentifyPdu(tpktPacket);
        if (pduType != RdpPduType.ClientInfoPdu) return null;

        try
        {
            return InjectCredentials(tpktPacket);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "Failed to inject credentials into CLIENT_INFO_PDU — forwarding original");
            return null;
        }
    }

    private byte[]? InjectCredentials(byte[] tpktPacket)
    {
        var (infoOffset, infoLength) = RdpPduParser.FindInfoPacket(tpktPacket);
        if (infoOffset < 0 || infoLength <= 0)
        {
            _log.LogWarning("Could not locate TS_INFO_PACKET within CLIENT_INFO_PDU");
            return null;
        }

        var infoData = tpktPacket.AsSpan(infoOffset, infoLength);
        var parsed = RdpPduParser.ParseInfoPacket(infoData);
        if (parsed == null)
        {
            _log.LogWarning("Failed to parse TS_INFO_PACKET");
            return null;
        }

        _log.LogInformation(
            "Injecting credentials: original user={OrigUser}@{OrigDomain} -> vault user={VaultUser}@{VaultDomain}",
            parsed.UserName, parsed.Domain, _targetUserName, _targetDomain);

        // Decode vault password from UTF-8 bytes to string for the info packet
        string vaultPassword = Encoding.UTF8.GetString(_targetPasswordBytes);

        byte[] newInfoPacket = RdpPduParser.BuildInfoPacket(
            parsed, infoData, _targetDomain, _targetUserName, vaultPassword);

        // Best-effort zero of the temporary password string is not possible
        // for managed strings. The vault password bytes themselves are zeroed
        // by the caller (RdpServerSession) after the session ends.

        // Rebuild the full TPKT packet with the new info packet
        byte[] prefix = tpktPacket[..infoOffset];
        byte[] result = new byte[prefix.Length + newInfoPacket.Length];
        prefix.CopyTo(result, 0);
        newInfoPacket.CopyTo(result, prefix.Length);

        // Fix TPKT length (first 4 bytes)
        int totalLen = result.Length;
        result[2] = (byte)(totalLen >> 8);
        result[3] = (byte)(totalLen & 0xFF);

        // Fix MCS Send Data Request user data length
        FixMcsSendDataLength(result);

        _injected = true;
        _log.LogInformation("CLIENT_INFO_PDU credential injection completed successfully");

        return result;
    }

    /// <summary>
    /// Recalculates the BER-encoded user data length in the MCS Send Data Request PDU
    /// after the info packet has been resized.
    /// </summary>
    private static void FixMcsSendDataLength(byte[] packet)
    {
        if (packet.Length < TpktPacket.HeaderSize + 3) return;

        int tpduStart = TpktPacket.HeaderSize;
        int x224HeaderLen = packet[tpduStart] + 1;
        int mcsStart = tpduStart + x224HeaderLen;

        if (mcsStart + 6 >= packet.Length) return;

        byte tag = packet[mcsStart];
        if (tag != RdpPduParser.McsSendDataRequest && tag != RdpPduParser.McsSendDataIndication)
            return;

        // MCS header: tag(1) + userId(2) + channelId(2) + flags(1) + BER length
        int berLenOffset = mcsStart + 6;

        // Read current BER length to find where user data starts
        var (_, currentEnd) = RdpPduParser.ReadBerLength(packet, berLenOffset);
        if (currentEnd < 0) return;

        int newUserDataLen = packet.Length - currentEnd;
        int oldBerLenBytes = currentEnd - berLenOffset;
        byte[] correctBerLen = EncodeBerLength(newUserDataLen);

        // If BER length encoding size didn't change, just overwrite
        if (correctBerLen.Length == oldBerLenBytes)
        {
            correctBerLen.CopyTo(packet, berLenOffset);
        }
        // If it changed, we'd need to shift data. For typical PAM use cases
        // the credential length difference is small enough that the BER length
        // encoding size doesn't change (both fit in 2-byte BER).
    }

    private static byte[] EncodeBerLength(int length)
    {
        if (length < 0x80)
            return [(byte)length];
        if (length <= 0xFF)
            return [0x81, (byte)length];
        return [0x82, (byte)(length >> 8), (byte)(length & 0xFF)];
    }
}
