using System.Buffers.Binary;
using System.Net.Sockets;
using System.Text;

namespace OrkunPAM.VncProxy.Protocol;

/// <summary>
/// RFB 3.8 handshake for PAM VNC proxy.
///
/// Client-facing: VeNCrypt security type (19) with Plain sub-authentication (258).
///   Username format: "pamuser@targethost" or "pamuser@targethost:port"
///   Password: PAM password
///
/// Target-facing: supports RFB 3.3 / 3.7 / 3.8 with VNC auth (type 2) or None (type 1).
///   VNC auth uses DES challenge-response with VNC-spec bit-reversed key.
/// </summary>
internal static class RfbHandshake
{
    private static readonly byte[] ServerVersionBytes = Encoding.ASCII.GetBytes("RFB 003.008\n");
    private const byte SecurityTypeVeNCrypt = 19;
    private const uint VeNCryptPlain = 258;

    /// <summary>
    /// Perform VeNCrypt Plain handshake with the incoming VNC client.
    /// Returns (pamUser, pamPassword, targetHost, targetPort).
    /// </summary>
    public static async Task<(string pamUser, string pamPassword, string targetHost, int targetPort)>
        HandshakeClientAsync(Stream stream, CancellationToken ct)
    {
        // ── 1. Version ──────────────────────────────────────────────────────────────
        await stream.WriteAsync(ServerVersionBytes, ct);
        var verBuf = new byte[12];
        await ReadExactlyAsync(stream, verBuf, ct);
        // Accept any version string; we always operate as 3.8

        // ── 2. Security types: advertise VeNCrypt only ──────────────────────────────
        await stream.WriteAsync(new byte[] { 1, SecurityTypeVeNCrypt }, ct);

        var secChoice = new byte[1];
        await ReadExactlyAsync(stream, secChoice, ct);
        if (secChoice[0] != SecurityTypeVeNCrypt)
        {
            await SendSecurityResultAsync(stream, false, "Only VeNCrypt security (type 19) is supported.", ct);
            throw new InvalidOperationException($"Client chose unsupported security type: {secChoice[0]}");
        }

        // ── 3. VeNCrypt version exchange (0.2) ─────────────────────────────────────
        await stream.WriteAsync(new byte[] { 0, 2 }, ct);
        var clientVer = new byte[2];
        await ReadExactlyAsync(stream, clientVer, ct);
        await stream.WriteAsync(new byte[] { 0 }, ct); // 0 = version accepted

        // ── 4. Sub-type negotiation: offer Plain (258) only ─────────────────────────
        var subPayload = new byte[8];
        BinaryPrimitives.WriteUInt32BigEndian(subPayload.AsSpan(0, 4), 1);
        BinaryPrimitives.WriteUInt32BigEndian(subPayload.AsSpan(4, 4), VeNCryptPlain);
        await stream.WriteAsync(subPayload, ct);

        var clientSubType = new byte[4];
        await ReadExactlyAsync(stream, clientSubType, ct);
        if (BinaryPrimitives.ReadUInt32BigEndian(clientSubType) != VeNCryptPlain)
            throw new InvalidOperationException("Client chose unsupported VeNCrypt sub-type (only Plain=258 supported)");

        // Signal sub-type accepted
        await stream.WriteAsync(new byte[] { 1 }, ct);

        // ── 5. Read Plain credentials ────────────────────────────────────────────────
        // [uint32 usernameLen][uint32 passwordLen][username][password]
        var lenBuf = new byte[8];
        await ReadExactlyAsync(stream, lenBuf, ct);
        uint uLen = BinaryPrimitives.ReadUInt32BigEndian(lenBuf.AsSpan(0, 4));
        uint pLen = BinaryPrimitives.ReadUInt32BigEndian(lenBuf.AsSpan(4, 4));

        if (uLen > 512 || pLen > 512)
            throw new InvalidOperationException("VeNCrypt Plain credentials exceed maximum allowed length (512 bytes)");

        var userBuf = uLen > 0 ? new byte[uLen] : Array.Empty<byte>();
        var passBuf = pLen > 0 ? new byte[pLen] : Array.Empty<byte>();
        if (uLen > 0) await ReadExactlyAsync(stream, userBuf, ct);
        if (pLen > 0) await ReadExactlyAsync(stream, passBuf, ct);

        var rawUsername = Encoding.UTF8.GetString(userBuf);
        var pamPassword = Encoding.UTF8.GetString(passBuf);

        // ── 6. Parse "pamuser@targethost[:port]" ─────────────────────────────────────
        var atIdx = rawUsername.IndexOf('@');
        if (atIdx <= 0)
            throw new InvalidOperationException(
                "VeNCrypt username must be in format 'pamuser@targethost' or 'pamuser@targethost:port'");

        var pamUser = rawUsername[..atIdx];
        var hostPart = rawUsername[(atIdx + 1)..];
        var targetHost = hostPart;
        int targetPort = 5900;

        var colonIdx = hostPart.LastIndexOf(':');
        if (colonIdx > 0 && int.TryParse(hostPart[(colonIdx + 1)..], out int parsedPort))
        {
            targetHost = hostPart[..colonIdx];
            targetPort = parsedPort;
        }

        if (string.IsNullOrEmpty(pamUser) || string.IsNullOrEmpty(targetHost))
            throw new InvalidOperationException("Empty PAM username or target host in VeNCrypt credentials");

        return (pamUser, pamPassword, targetHost, targetPort);
    }

    /// <summary>
    /// Connect to target VNC server, authenticate with vault password, read ServerInit.
    /// Caller owns the returned TcpClient and is responsible for disposal.
    /// </summary>
    public static async Task<(TcpClient client, byte[] serverInitPayload)>
        ConnectTargetAsync(string targetIp, int targetPort, string vaultPassword, CancellationToken ct)
    {
        var targetClient = new TcpClient { NoDelay = true };
        await targetClient.ConnectAsync(targetIp, targetPort, ct);
        var stream = targetClient.GetStream();

        // Read target version
        var verBuf = new byte[12];
        await ReadExactlyAsync(stream, verBuf, ct);
        var targetVer = Encoding.ASCII.GetString(verBuf).Trim();

        bool isV33 = targetVer.StartsWith("RFB 003.003");
        bool isV37 = targetVer.StartsWith("RFB 003.007");

        // Propose 3.8 regardless of target version
        await stream.WriteAsync(ServerVersionBytes, ct);

        byte chosenSec;
        if (isV33)
        {
            // RFB 3.3: server decides security type as 4-byte big-endian uint
            var secBuf = new byte[4];
            await ReadExactlyAsync(stream, secBuf, ct);
            uint sec33 = BinaryPrimitives.ReadUInt32BigEndian(secBuf);
            if (sec33 == 0)
            {
                targetClient.Dispose();
                throw new InvalidOperationException("Target VNC 3.3 server refused connection");
            }
            chosenSec = (byte)(sec33 & 0xFF);
        }
        else
        {
            // RFB 3.7/3.8: [uint8 count][uint8... types]
            var countBuf = new byte[1];
            await ReadExactlyAsync(stream, countBuf, ct);
            if (countBuf[0] == 0)
            {
                targetClient.Dispose();
                throw new InvalidOperationException("Target VNC server refused connection");
            }
            var secTypes = new byte[countBuf[0]];
            await ReadExactlyAsync(stream, secTypes, ct);

            chosenSec = secTypes.Contains((byte)2) ? (byte)2 :
                        secTypes.Contains((byte)1) ? (byte)1 :
                        throw new InvalidOperationException(
                            $"Target VNC server offers no supported security types (offered: [{string.Join(",", secTypes)}])");

            await stream.WriteAsync(new byte[] { chosenSec }, ct);
        }

        // VNC auth (type 2): DES challenge-response
        if (chosenSec == 2)
        {
            var challenge = new byte[16];
            await ReadExactlyAsync(stream, challenge, ct);
            var response = ComputeVncDesResponse(challenge, vaultPassword);
            await stream.WriteAsync(response, ct);

            // SecurityResult only in 3.7 and 3.8 (not 3.3)
            if (!isV33)
            {
                var result = new byte[4];
                await ReadExactlyAsync(stream, result, ct);
                if (BinaryPrimitives.ReadUInt32BigEndian(result) != 0)
                {
                    targetClient.Dispose();
                    throw new InvalidOperationException("Target VNC server rejected vault VNC credential");
                }
            }
        }
        // Security type 1 (None): no auth needed

        // ClientInit: 1 = shared session
        await stream.WriteAsync(new byte[] { 1 }, ct);

        // Read ServerInit: width(2)+height(2)+pixelFormat(16)+nameLen(4)+name(N)
        var siHeader = new byte[24];
        await ReadExactlyAsync(stream, siHeader, ct);
        uint nameLen = BinaryPrimitives.ReadUInt32BigEndian(siHeader.AsSpan(20, 4));
        if (nameLen > 4096)
        {
            targetClient.Dispose();
            throw new InvalidOperationException($"Target ServerInit desktop-name length ({nameLen}) is unreasonable");
        }

        var nameBuf = nameLen > 0 ? new byte[nameLen] : Array.Empty<byte>();
        if (nameLen > 0) await ReadExactlyAsync(stream, nameBuf, ct);

        var serverInit = new byte[siHeader.Length + nameBuf.Length];
        siHeader.CopyTo(serverInit, 0);
        nameBuf.CopyTo(serverInit, siHeader.Length);

        return (targetClient, serverInit);
    }

    /// <summary>Send RFB SecurityResult to client (0=OK, 1=Failed with optional reason string).</summary>
    public static async Task SendSecurityResultAsync(Stream stream, bool success, string? reason, CancellationToken ct)
    {
        var buf = new byte[4];
        BinaryPrimitives.WriteUInt32BigEndian(buf, success ? 0u : 1u);
        await stream.WriteAsync(buf, ct);

        if (!success && !string.IsNullOrEmpty(reason))
        {
            var msgBytes = Encoding.UTF8.GetBytes(reason);
            var lenBuf = new byte[4];
            BinaryPrimitives.WriteUInt32BigEndian(lenBuf, (uint)msgBytes.Length);
            await stream.WriteAsync(lenBuf, ct);
            await stream.WriteAsync(msgBytes, ct);
        }
    }

    /// <summary>
    /// VNC DES challenge-response (RFC 6143 §7.2.2).
    /// Key = 8-byte password with each byte bit-reversed; cipher = DES-ECB.
    /// </summary>
    internal static byte[] ComputeVncDesResponse(byte[] challenge, string password)
    {
        var key = new byte[8];
        var pwBytes = Encoding.ASCII.GetBytes(password ?? "");
        for (int i = 0; i < Math.Min(8, pwBytes.Length); i++)
            key[i] = pwBytes[i];

        // VNC quirk: reverse bit order in each key byte (MSB ↔ LSB)
        for (int i = 0; i < 8; i++)
        {
            byte b = key[i];
            key[i] = (byte)(
                ((b & 0x01) << 7) | ((b & 0x02) << 5) | ((b & 0x04) << 3) | ((b & 0x08) << 1) |
                ((b & 0x10) >> 1) | ((b & 0x20) >> 3) | ((b & 0x40) >> 5) | ((b & 0x80) >> 7));
        }

        using var des = System.Security.Cryptography.DES.Create();
        des.Mode = System.Security.Cryptography.CipherMode.ECB;
        des.Padding = System.Security.Cryptography.PaddingMode.None;
        des.Key = key;

        var result = new byte[16];
        using var enc = des.CreateEncryptor();
        enc.TransformBlock(challenge, 0, 8, result, 0);
        enc.TransformBlock(challenge, 8, 8, result, 8);
        return result;
    }

    internal static async Task ReadExactlyAsync(Stream stream, byte[] buf, CancellationToken ct)
    {
        int read = 0;
        while (read < buf.Length)
        {
            int n = await stream.ReadAsync(buf.AsMemory(read), ct);
            if (n == 0) throw new EndOfStreamException("RFB stream closed during handshake");
            read += n;
        }
    }
}
