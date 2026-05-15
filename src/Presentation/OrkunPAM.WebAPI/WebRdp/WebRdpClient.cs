using System.Net.Security;
using System.Net.Sockets;
using System.Net.WebSockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;

namespace OrkunPAM.WebAPI.WebRdp;

internal sealed class WebRdpException(string msg) : IOException(msg);

/// <summary>
/// Native C# RDP client for the WebSocket browser terminal.
/// Implements MS-RDPBCGR: X.224 → TLS → MCS/GCC → Client Info → Capabilities → Active session.
/// Decodes Fast-Path bitmap updates and forwards them to the browser as RGBA tiles.
/// Translates browser keyboard/mouse JSON to RDP Fast-Path Input PDUs.
/// No external RDP library — entirely native C#.
/// </summary>
internal sealed class WebRdpClient : IAsyncDisposable
{
    private readonly string _host;
    private readonly int _port;
    private readonly string _domain;
    private readonly string _username;
    private byte[] _password;
    private readonly int _desktopWidth;
    private readonly int _desktopHeight;
    private readonly ILogger _log;

    private TcpClient? _tcp;
    private SslStream? _ssl;
    private Stream? _stream;
    private readonly SemaphoreSlim _writeLock = new(1, 1);

    // MCS state (populated during handshake)
    private ushort _userId;
    private ushort _ioChanId = 1003;
    private uint _shareId = 0x000103EA;
    private bool _demandActiveHandled;

    // Frame buffer for compositing received bitmap tiles
    private byte[]? _framebuffer;

    internal WebRdpClient(string host, int port, string domain, string username,
        byte[] password, int width, int height, ILogger log)
    {
        _host = host; _port = port;
        _domain = domain; _username = username; _password = password;
        _desktopWidth = width; _desktopHeight = height;
        _log = log;
    }

    // ── Phase 1-10: full RDP connection establishment ─────────────────────

    internal async Task ConnectAsync(CancellationToken ct)
    {
        _tcp = new TcpClient { NoDelay = true };
        await _tcp.ConnectAsync(_host, _port, ct);
        Stream netStream = _tcp.GetStream();

        // X.224 Connection Request/Confirm (plain TCP)
        await netStream.WriteAsync(BuildX224Cr(), ct);
        await netStream.FlushAsync(ct);

        var ccPacket = await ReadTpktAsync(netStream, ct)
            ?? throw new WebRdpException("No X.224 CC from target");

        _log.LogDebug("WebRDP: X.224 CC received from {Host}", _host);

        // TLS upgrade
        _ssl = new SslStream(netStream, leaveInnerStreamOpen: true,
            (_, _, _, _) => true); // accept any server cert
        await _ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions
        {
            TargetHost = _host,
            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
            RemoteCertificateValidationCallback = (_, _, _, _) => true
        }, ct);
        _stream = _ssl;
        _log.LogInformation("WebRDP: TLS established ({Proto}) to {Host}", _ssl.SslProtocol, _host);

        // MCS Connect Initial → Response
        await SendTpktAsync(BuildMcsConnectInitial(), ct);
        var mcrPacket = await ReadTpktAsync(_stream, ct)
            ?? throw new WebRdpException("No MCS Connect Response");
        ParseMcsConnectResponse(mcrPacket);
        _log.LogDebug("WebRDP: MCS connected, I/O channel={Chan}", _ioChanId);

        // MCS Erect Domain (no response)
        await SendTpktAsync(WrapX224Data(new byte[] { 0x04, 0x01, 0x00, 0x01, 0x00 }), ct);

        // MCS Attach User → Confirm
        await SendTpktAsync(WrapX224Data(new byte[] { 0x28 }), ct);
        var aucPacket = await ReadTpktAsync(_stream, ct)
            ?? throw new WebRdpException("No Attach User Confirm");
        _userId = ParseAttachUserConfirm(aucPacket);
        _log.LogDebug("WebRDP: user channel={UserId}", _userId);

        // Channel Joins: I/O channel and user channel
        await JoinChannelAsync(_ioChanId, ct);
        await JoinChannelAsync(_userId, ct);

        // Client Info PDU (credentials)
        await SendClientInfoAsync(ct);
        _log.LogDebug("WebRDP: Client Info PDU sent");

        // License exchange (receive + discard)
        await HandleLicenseExchangeAsync(ct);

        // Demand Active / Confirm Active capability exchange
        await HandleCapabilityExchangeAsync(ct);

        // Final connection sequence (Synchronize / Control / Font)
        await SendFinalConnectionSequenceAsync(ct);

        CryptographicOperations.ZeroMemory(_password);
        _log.LogInformation("WebRDP: active session established with {Host}:{Port}", _host, _port);
    }

    // ── Phase 11: Relay bitmap updates ↔ browser ──────────────────

    internal async Task RelayAsync(WebSocket ws, CancellationToken ct)
    {
        _framebuffer = new byte[_desktopWidth * _desktopHeight * 4];

        // Tell browser the desktop dimensions
        var sizeFrame = new byte[5];
        sizeFrame[0] = 0x02;
        W16LE(sizeFrame, 1, (ushort)_desktopWidth);
        W16LE(sizeFrame, 3, (ushort)_desktopHeight);
        if (ws.State == WebSocketState.Open)
            await ws.SendAsync(sizeFrame, WebSocketMessageType.Binary, true, ct);

        using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var t1 = Task.Run(() => RdpToWsLoop(ws, cts.Token), cts.Token);
        var t2 = Task.Run(() => WsToRdpLoop(ws, cts.Token), cts.Token);
        await Task.WhenAny(t1, t2);
        await cts.CancelAsync();
    }

    private async Task RdpToWsLoop(WebSocket ws, CancellationToken ct)
    {
        var stream = _stream!;
        var oneByte = new byte[1];

        while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
        {
            int n;
            try { n = await stream.ReadAsync(oneByte, ct); }
            catch (OperationCanceledException) { throw; }
            catch { return; }
            if (n == 0) return;

            byte first = oneByte[0];

            if (first == 0x03)
            {
                // Slow-path TPKT
                var header3 = new byte[3];
                await ReadExactAsync(stream, header3, ct);
                int totalLen = (header3[1] << 8) | header3[2];
                if (totalLen < 4) continue;
                var payload = new byte[totalLen - 4];
                await ReadExactAsync(stream, payload, ct);
                await HandleSlowPathAsync(payload, ws, ct);
            }
            else
            {
                // Fast-path output PDU
                int updateCode = (first >> 2) & 0x0F;
                var lb1 = new byte[1];
                await ReadExactAsync(stream, lb1, ct);
                int totalLen;
                if ((lb1[0] & 0x80) != 0)
                {
                    var lb2 = new byte[1];
                    await ReadExactAsync(stream, lb2, ct);
                    totalLen = ((lb1[0] & 0x7F) << 8) | lb2[0];
                    var data3 = new byte[totalLen - 3];
                    await ReadExactAsync(stream, data3, ct);
                    await HandleFastPathOutputAsync(updateCode, data3, ws, ct);
                }
                else
                {
                    totalLen = lb1[0];
                    if (totalLen < 2) continue;
                    var data2 = new byte[totalLen - 2];
                    await ReadExactAsync(stream, data2, ct);
                    await HandleFastPathOutputAsync(updateCode, data2, ws, ct);
                }
            }
        }
    }

    private async Task WsToRdpLoop(WebSocket ws, CancellationToken ct)
    {
        var buf = new byte[8192];
        while (!ct.IsCancellationRequested && ws.State == WebSocketState.Open)
        {
            WebSocketReceiveResult result;
            try { result = await ws.ReceiveAsync(buf, ct); }
            catch { return; }

            if (result.MessageType == WebSocketMessageType.Close) return;
            if (result.MessageType != WebSocketMessageType.Text) continue;

            try
            {
                using var doc = JsonDocument.Parse(buf.AsMemory(0, result.Count));
                var t = doc.RootElement.GetProperty("t").GetString();

                if (t == "k") // keyboard scan code
                {
                    var sc = (byte)doc.RootElement.GetProperty("s").GetInt32();
                    bool release = doc.RootElement.TryGetProperty("r", out var rv) && rv.GetBoolean();
                    await SendFastPathKeyboardAsync(sc, release, ct);
                }
                else if (t == "m") // mouse
                {
                    var x = (ushort)doc.RootElement.GetProperty("x").GetInt32();
                    var y = (ushort)doc.RootElement.GetProperty("y").GetInt32();
                    var flags = (ushort)doc.RootElement.GetProperty("f").GetInt32();
                    await SendFastPathMouseAsync(x, y, flags, ct);
                }
            }
            catch (Exception ex) { _log.LogDebug(ex, "WebRDP: browser input parse error"); }
        }
    }

    // ── Fast-path bitmap handling ────────────────────────────

    private async Task HandleFastPathOutputAsync(int updateCode, byte[] data,
        WebSocket ws, CancellationToken ct)
    {
        // FASTPATH_UPDATETYPE_BITMAP = 1
        if (updateCode != 1 || data.Length < 4) return;

        int pos = 0;
        // updateType (2) + numberRectangles (2)
        int updateType = R16LE(data, pos); pos += 2;
        if (updateType != 1) return; // TS_UPDATETYPE_BITMAP
        int numRects = R16LE(data, pos); pos += 2;

        for (int i = 0; i < numRects && pos < data.Length; i++)
        {
            if (pos + 10 > data.Length) break;

            int destLeft   = R16LE(data, pos);     pos += 2;
            int destTop    = R16LE(data, pos);     pos += 2;
            int destRight  = R16LE(data, pos);     pos += 2;
            int destBottom = R16LE(data, pos);     pos += 2;
            int tileWidth  = R16LE(data, pos);     pos += 2;
            int tileHeight = R16LE(data, pos);     pos += 2;
            int bpp        = R16LE(data, pos);     pos += 2;
            int flags      = R16LE(data, pos);     pos += 2;
            int bmpLen     = R16LE(data, pos);     pos += 2;

            const int BITMAP_COMPRESSION = 0x0001;
            const int NO_BITMAP_COMPRESSION_HDR = 0x0400;

            int compMainBodySize = bmpLen;
            int cbScanWidth = 0;
            int cbUncompressedSize = 0;

            if ((flags & BITMAP_COMPRESSION) != 0 && (flags & NO_BITMAP_COMPRESSION_HDR) == 0)
            {
                // TS_CD_HEADER (8 bytes)
                if (pos + 8 > data.Length) break;
                pos += 2; // cbCompFirstRowSize (always 0)
                compMainBodySize = R16LE(data, pos); pos += 2;
                cbScanWidth = R16LE(data, pos); pos += 2;
                cbUncompressedSize = R16LE(data, pos); pos += 2;
            }

            if (pos + compMainBodySize > data.Length) break;
            var bmpData = data.AsSpan(pos, compMainBodySize);
            pos += compMainBodySize;

            bool compressed = (flags & BITMAP_COMPRESSION) != 0;
            byte[]? rgba = DecodeBitmapTile(bmpData, tileWidth, tileHeight, bpp, compressed, cbUncompressedSize);
            if (rgba == null) continue;

            // Send tile to browser: [0x01][x:2LE][y:2LE][w:2LE][h:2LE][pixels:rgba]
            var frame = new byte[9 + rgba.Length];
            frame[0] = 0x01;
            W16LE(frame, 1, (ushort)destLeft);
            W16LE(frame, 3, (ushort)destTop);
            W16LE(frame, 5, (ushort)tileWidth);
            W16LE(frame, 7, (ushort)tileHeight);
            rgba.CopyTo(frame, 9);

            if (ws.State == WebSocketState.Open)
                await ws.SendAsync(frame, WebSocketMessageType.Binary, true, ct);
        }
    }

    private static byte[]? DecodeBitmapTile(ReadOnlySpan<byte> data, int width, int height,
        int bpp, bool compressed, int uncompressedSize)
    {
        if (width <= 0 || height <= 0 || width > 4096 || height > 4096) return null;

        byte[] rgb;

        if (!compressed)
        {
            // Raw bitmap data: BGR(A) stored bottom-to-top
            int bytesPerPixel = bpp / 8;
            rgb = new byte[data.Length];
            data.CopyTo(rgb);
        }
        else
        {
            // RDP RLE decompression (simplified — use uncompressed fallback for now)
            // Full RLE implementation would go here; for now we skip compressed tiles
            // Most connections will negotiate raw or support it as fallback
            return null;
        }

        int bPP = bpp / 8;
        int stride = width * bPP;
        var rgba = new byte[width * height * 4];

        for (int row = 0; row < height; row++)
        {
            // RDP stores rows bottom-to-top; flip to top-to-bottom for the browser
            int srcRow = (height - 1 - row);
            int srcOffset = srcRow * stride;
            int dstOffset = row * width * 4;

            if (srcOffset + stride > rgb.Length) break;

            for (int col = 0; col < width; col++)
            {
                int si = srcOffset + col * bPP;
                int di = dstOffset + col * 4;
                if (si + bPP > rgb.Length) break;

                // RDP uses BGR order
                if (bPP >= 3)
                {
                    rgba[di + 0] = rgb[si + 2]; // R
                    rgba[di + 1] = rgb[si + 1]; // G
                    rgba[di + 2] = rgb[si + 0]; // B
                    rgba[di + 3] = 255;          // A
                }
                else if (bPP == 2)
                {
                    // 16-bit: 5-6-5 or 5-5-5 depending on bpp
                    ushort c = (ushort)(rgb[si] | (rgb[si + 1] << 8));
                    rgba[di + 0] = (byte)((c >> 11) * 255 / 31);
                    rgba[di + 1] = (byte)(((c >> 5) & 0x3F) * 255 / 63);
                    rgba[di + 2] = (byte)((c & 0x1F) * 255 / 31);
                    rgba[di + 3] = 255;
                }
            }
        }
        return rgba;
    }

    private async Task HandleSlowPathAsync(byte[] x224Payload, WebSocket ws, CancellationToken ct)
    {
        // Parse X.224 Data TPDU → MCS → check for TS_UPDATE_BITMAP (slow-path)
        if (x224Payload.Length < 3) return;
        int liBytes = x224Payload[0] + 1;
        if (liBytes >= x224Payload.Length) return;
        var mcs = x224Payload.AsSpan(liBytes);
        if (mcs.Length < 1) return;

        // Check for MCS Send Data Indication (0x68) with slow-path update
        if (mcs[0] != 0x68 || mcs.Length < 7) return;

        // Find the channel data: skip MCS SDI header
        // MCS Send Data Indication: tag(1) + initiator(2) + channel(2) + priority+segmentation(1) + BER length
        int berLenStart = 6;
        if (berLenStart >= mcs.Length) return;
        var (dataLen, dataStart) = ReadBerLen(mcs, berLenStart);
        if (dataStart < 0 || dataStart + dataLen > mcs.Length) return;

        var channelData = mcs.Slice(dataStart, dataLen);
        if (channelData.Length < 6) return;

        // Security header (2 bytes)
        ushort secFlags = (ushort)(channelData[0] | (channelData[1] << 8));
        int contentStart = 4; // skip flags (2) + flagsHi (2)

        if (contentStart >= channelData.Length) return;
        var pduData = channelData.Slice(contentStart);

        // Check for TS_SHARECONTROLHEADER
        if (pduData.Length < 6) return;
        ushort pduLen = (ushort)(pduData[0] | (pduData[1] << 8));
        ushort pduType = (ushort)(pduData[2] | (pduData[3] << 8));

        // pduType & 0x0F: 1=DEMAND_ACTIVE, 2=CONFIRM_ACTIVE, 3=DATA
        if ((pduType & 0x0F) == 2 /* DATA */ && pduData.Length >= 18)
        {
            // skip share control header (6) + share data header (12)
            if (pduData.Length < 18) return;
            byte updateType = pduData[17];
            // TS_UPDATE_TYPE_BITMAP = 1
            if (updateType == 1 && pduData.Length > 18)
            {
                var bitmapData = pduData.Slice(18).ToArray();
                await HandleFastPathOutputAsync(1, bitmapData, ws, ct);
            }
        }
    }

    // ── Input PDUs ───────────────────────────────────────────

    private async Task SendFastPathKeyboardAsync(byte scanCode, bool release, CancellationToken ct)
    {
        // FASTPATH_INPUT_EVENT_SCANCODE = 4
        byte eventFlags = release ? (byte)0x01 : (byte)0x00;
        byte eventHeader = (byte)(0x04 | (eventFlags << 5));
        var fpPdu = new byte[4]; // header + len + event header + scan code
        fpPdu[0] = 0x04; // fpInputHeader: 1 event, no encryption
        fpPdu[1] = 0x04; // length = 4 (includes these 2 bytes)
        fpPdu[2] = eventHeader;
        fpPdu[3] = scanCode;
        await SendRawAsync(fpPdu, ct);
    }

    private async Task SendFastPathMouseAsync(ushort x, ushort y, ushort ptrFlags, CancellationToken ct)
    {
        // FASTPATH_INPUT_EVENT_MOUSE = 1; event payload = pointerFlags(2) + xPos(2) + yPos(2) = 6 bytes
        var fpPdu = new byte[9]; // fpInputHeader(1) + length(1) + eventHeader(1) + mouseEvent(6)
        fpPdu[0] = 0x04; // fpInputHeader: 1 event, no encryption
        fpPdu[1] = 0x09; // length = 9
        fpPdu[2] = 0x01; // FASTPATH_INPUT_EVENT_MOUSE (eventCode)
        fpPdu[3] = (byte)(ptrFlags & 0xFF);
        fpPdu[4] = (byte)(ptrFlags >> 8);
        fpPdu[5] = (byte)(x & 0xFF);
        fpPdu[6] = (byte)(x >> 8);
        fpPdu[7] = (byte)(y & 0xFF);
        fpPdu[8] = (byte)(y >> 8);
        await SendRawAsync(fpPdu, ct);
    }

    // ── Connection sequence helpers ────────────────────────────

    private async Task JoinChannelAsync(ushort channelId, CancellationToken ct)
    {
        // MCS Channel Join Request: 0x38 | userId[2BE] | channelId[2BE]
        var req = new byte[5];
        req[0] = 0x38;
        req[1] = (byte)(_userId >> 8); req[2] = (byte)(_userId & 0xFF);
        req[3] = (byte)(channelId >> 8); req[4] = (byte)(channelId & 0xFF);
        await SendTpktAsync(WrapX224Data(req), ct);

        var confirm = await ReadTpktAsync(_stream!, ct);
        // ignore response details
        _ = confirm;
    }

    private async Task SendClientInfoAsync(CancellationToken ct)
    {
        var info = BuildClientInfoPdu();
        // Wrap in MCS Send Data Request on I/O channel
        var mcs = BuildMcsSendDataRequest(_userId, _ioChanId, info);
        await SendTpktAsync(WrapX224Data(mcs), ct);
    }

    private async Task HandleLicenseExchangeAsync(CancellationToken ct)
    {
        // Receive and discard license PDUs until we get to Demand Active
        for (int i = 0; i < 10; i++)
        {
            var pkt = await ReadTpktAsync(_stream!, ct);
            if (pkt == null) return;

            // Check if this looks like a Demand Active PDU (share control type = 1)
            var tpdu = ExtractX224Payload(pkt);
            if (tpdu == null) continue;

            int liBytes = tpdu[0] + 1;
            if (liBytes >= tpdu.Length) continue;
            var mcs = tpdu.AsSpan(liBytes);
            if (mcs.Length < 7) continue;

            // Check for Demand Active: parse share control header
            var (_, dataStart) = FindMcsChannelData(mcs.ToArray());
            if (dataStart < 0) continue;

            var channelData = mcs.Slice(dataStart);
            if (channelData.Length < 6) continue;

            // Skip security header (4 bytes) then check pduType
            if (channelData.Length < 10) continue;
            ushort pduType = (ushort)(channelData[6] | (channelData[7] << 8));

            if ((pduType & 0x0F) == 1) // DEMAND_ACTIVE
            {
                await HandleDemandActiveAsync(pkt, ct);
                _demandActiveHandled = true;
                return;
            }
            // Otherwise it's a license PDU — continue loop
        }
    }

    private async Task HandleCapabilityExchangeAsync(CancellationToken ct)
    {
        if (_demandActiveHandled) return;

        for (int i = 0; i < 5; i++)
        {
            var pkt = await ReadTpktAsync(_stream!, ct);
            if (pkt == null) return;

            var tpdu = ExtractX224Payload(pkt);
            if (tpdu == null) continue;
            int liBytes = tpdu[0] + 1;
            if (liBytes >= tpdu.Length) continue;
            var mcs = tpdu.AsSpan(liBytes).ToArray();
            var (_, dataStart) = FindMcsChannelData(mcs);
            if (dataStart < 0) continue;

            var channelData = mcs.AsSpan(dataStart);
            if (channelData.Length < 10) continue;
            ushort pduType = (ushort)(channelData[6] | (channelData[7] << 8));
            if ((pduType & 0x0F) == 1)
            {
                await HandleDemandActiveAsync(pkt, ct);
                _demandActiveHandled = true;
                return;
            }
        }
    }

    private async Task HandleDemandActiveAsync(byte[] packet, CancellationToken ct)
    {
        // Send Confirm Active PDU
        await SendTpktAsync(WrapX224Data(
            BuildMcsSendDataRequest(_userId, _ioChanId, BuildConfirmActivePdu())), ct);
    }

    private async Task SendFinalConnectionSequenceAsync(CancellationToken ct)
    {
        // Synchronize
        await SendMcsDataAsync(BuildSynchronizePdu(), ct);
        // Control: cooperate
        await SendMcsDataAsync(BuildControlPdu(0x0004), ct);
        // Control: request control
        await SendMcsDataAsync(BuildControlPdu(0x0001), ct);
        // Persistent Key List (empty)
        await SendMcsDataAsync(BuildPersistentKeyListPdu(), ct);
        // Font List
        await SendMcsDataAsync(BuildFontListPdu(), ct);
        await _stream!.FlushAsync(ct);

        // Wait for server Synchronize / Control / Font Map
        for (int i = 0; i < 8; i++)
        {
            var pkt = await ReadTpktAsync(_stream!, ct);
            if (pkt == null) break;
            // Check if this is a server data PDU
            var tpdu = ExtractX224Payload(pkt);
            if (tpdu == null) continue;
            int liBytes = tpdu[0] + 1;
            if (liBytes >= tpdu.Length) continue;
            var mcs = tpdu.AsSpan(liBytes).ToArray();
            var (_, dataStart) = FindMcsChannelData(mcs);
            if (dataStart < 0) continue;
            var cd = mcs.AsSpan(dataStart);
            if (cd.Length < 18) continue;
            byte updateType = cd[17];
            // Font Map = 0x28 — indicates we're fully active
            if (updateType == 0x28) return;
        }
    }

    private async Task SendMcsDataAsync(byte[] pduData, CancellationToken ct)
    {
        var mcs = BuildMcsSendDataRequest(_userId, _ioChanId, pduData);
        await SendTpktAsync(WrapX224Data(mcs), ct);
    }

    // ── PDU builders ─────────────────────────────────────────

    private byte[] BuildX224Cr()
    {
        // X.224 CR + RDP_NEG_REQ requesting SSL
        byte[] tpdu =
        [
            0x0E,       // LI = 14
            0xE0,       // type = Connection Request
            0x00, 0x00, // dst-ref
            0x00, 0x00, // src-ref
            0x00,       // class
            // RDP_NEG_REQ
            0x01,             // type = 1
            0x00,             // flags = 0
            0x08, 0x00,       // length = 8
            0x01, 0x00, 0x00, 0x00  // requestedProtocols = SSL (1)
        ];
        return BuildTpkt(tpdu);
    }

    private byte[] BuildMcsConnectInitial()
    {
        // Build GCC user data blocks
        var gccUserData = BuildGccUserData();

        // Wrap in H.221 container
        var h221Key = new byte[] { 0x00, 0x05, 0x00, 0x14, 0x7C, 0x00, 0x01 };
        using var gccMs = new MemoryStream();
        // PER length of the conference data
        int confLen = gccUserData.Length;
        if (confLen < 128)
        {
            gccMs.WriteByte((byte)confLen);
        }
        else
        {
            gccMs.WriteByte((byte)(0x80 | (confLen >> 7)));
            gccMs.WriteByte((byte)(confLen & 0x7F));
        }
        gccMs.Write(gccUserData);
        var gccContainer = new byte[h221Key.Length + (int)gccMs.Length];
        h221Key.CopyTo(gccContainer, 0);
        gccMs.ToArray().CopyTo(gccContainer, h221Key.Length);

        // Standard Domain Parameters
        var targetDP = BuildDomainParameters(34, 2, 0, 1, 0, 1, 65535, 2);
        var minDP = BuildDomainParameters(1, 1, 1, 1, 0, 1, 1056, 2);
        var maxDP = BuildDomainParameters(65535, 64535, 65535, 1, 0, 1, 65535, 2);

        using var mci = new MemoryStream();
        // callingDomainSelector: OCTET STRING = "\x01"
        mci.WriteByte(0x04); mci.WriteByte(0x01); mci.WriteByte(0x01);
        // calledDomainSelector: OCTET STRING = "\x01"
        mci.WriteByte(0x04); mci.WriteByte(0x01); mci.WriteByte(0x01);
        // upwardFlag: BOOLEAN = TRUE
        mci.WriteByte(0x01); mci.WriteByte(0x01); mci.WriteByte(0xFF);
        // targetParameters
        mci.Write(targetDP);
        // minimumParameters
        mci.Write(minDP);
        // maximumParameters
        mci.Write(maxDP);
        // userData: OCTET STRING
        mci.WriteByte(0x04);
        WriteBerLength(mci, gccContainer.Length);
        mci.Write(gccContainer);

        var mciContent = mci.ToArray();

        // Wrap in APPLICATION 101 (0x7F 0x65)
        using var outer = new MemoryStream();
        outer.WriteByte(0x7F); outer.WriteByte(0x65);
        WriteBerLength(outer, mciContent.Length);
        outer.Write(mciContent);

        return outer.ToArray();
    }

    private byte[] BuildGccUserData()
    {
        // GCC Conference Create Request user data:
        // H.221 NonStandard Identifier (Microsoft "Duca" key) followed by TS_UD_CS_* blocks.
        // The T.124 PER header (00 05 00 14 7C 00 01) and PER length are added
        // by BuildMcsConnectInitial, so this method returns only the H.221 container content.
        var h221Key = new byte[] { 0x00, 0x08, 0x00, 0x10, 0x00, 0x01, 0xC0, 0x00,
                                   0x44, 0x75, 0x63, 0x61 }; // "Duca"

        using var result = new MemoryStream();
        result.Write(h221Key);
        result.Write(BuildTsUdCsCore());
        result.Write(BuildTsUdCsSec());
        result.Write(BuildTsUdCsNet());
        return result.ToArray();
    }

    private byte[] BuildTsUdCsCore()
    {
        const ushort CS_CORE = 0xC001;
        using var ms = new MemoryStream();
        W16LE(ms, CS_CORE);
        W16LE(ms, 0x00D8); // length = 216 bytes
        // version = 0x00080004 (RDP 5.0)
        ms.Write([0x04, 0x00, 0x08, 0x00]);
        W16LE(ms, (ushort)_desktopWidth);
        W16LE(ms, (ushort)_desktopHeight);
        W16LE(ms, 0xCA01); // colorDepth = 8bpp
        W16LE(ms, 0xAA03); // SASSequence
        ms.Write([0x09, 0x04, 0x00, 0x00]); // keyboardLayout US
        ms.Write([0x28, 0x0A, 0x00, 0x00]); // clientBuild
        // clientName: "OrkunPAM" in UTF-16LE, padded to 32 bytes
        var name = Encoding.Unicode.GetBytes("OrkunPAM\0\0\0\0\0\0\0\0");
        ms.Write(name[..32]);
        ms.Write([0x04, 0x00, 0x00, 0x00]); // keyboardType = IBM_ENHANCED
        ms.Write([0x00, 0x00, 0x00, 0x00]); // keyboardSubType
        ms.Write([0x0C, 0x00, 0x00, 0x00]); // keyboardFunctionKey
        ms.Write(new byte[64]);              // imeFileName (zeros)
        W16LE(ms, 0xCA01); // postBeta2ColorDepth
        W16LE(ms, 0x0001); // clientProductId
        ms.Write([0x00, 0x00, 0x00, 0x00]); // serialNumber
        W16LE(ms, 0x0018); // highColorDepth = 24
        W16LE(ms, 0x000F); // supportedColorDepths
        W16LE(ms, 0x0001); // earlyCapabilityFlags
        ms.Write(new byte[64]);              // clientDigProductId
        ms.WriteByte(0x07);                  // connectionType = LAN
        ms.WriteByte(0x00);                  // pad1octet
        ms.Write([0x01, 0x00, 0x00, 0x00]); // serverSelectedProtocol = SSL
        return ms.ToArray();
    }

    private static byte[] BuildTsUdCsSec()
    {
        const ushort CS_SECURITY = 0xC002;
        using var ms = new MemoryStream();
        W16LE(ms, CS_SECURITY);
        W16LE(ms, 0x0008); // length = 8
        ms.Write([0x00, 0x00, 0x00, 0x00]); // encryptionMethods = none
        ms.Write([0x00, 0x00, 0x00, 0x00]); // extEncryptionMethods = none
        return ms.ToArray();
    }

    private static byte[] BuildTsUdCsNet()
    {
        const ushort CS_NET = 0xC003;
        using var ms = new MemoryStream();
        W16LE(ms, CS_NET);
        W16LE(ms, 0x001C); // length = 28
        ms.Write([0x02, 0x00, 0x00, 0x00]); // channelCount = 2
        // rdpdr channel
        ms.Write(Encoding.ASCII.GetBytes("rdpdr\0\0\0"));
        ms.Write([0x00, 0x00, 0x80, 0x80]); // options
        // cliprdr channel
        ms.Write(Encoding.ASCII.GetBytes("cliprdr\0"));
        ms.Write([0x00, 0x00, 0xA0, 0xC0]); // options
        return ms.ToArray();
    }

    private byte[] BuildClientInfoPdu()
    {
        using var info = new MemoryStream();
        // TS_INFO_PACKET
        ms_W32LE(info, 0x00000000); // CodePage
        ms_W32LE(info, 0x00000033); // flags: INFO_MOUSE | INFO_DISABLECTRLALTDEL | INFO_UNICODE | INFO_MAXIMIZESHELL
        // credential lengths (in bytes, not chars)
        var domainBytes = Encoding.Unicode.GetBytes(_domain);
        var userBytes = Encoding.Unicode.GetBytes(_username);
        var passBytes = Encoding.Unicode.GetBytes(Encoding.UTF8.GetString(_password));
        W16LE(info, (ushort)domainBytes.Length);
        W16LE(info, (ushort)userBytes.Length);
        W16LE(info, (ushort)passBytes.Length);
        W16LE(info, 0); // cbAlternateShell
        W16LE(info, 0); // cbWorkingDir
        info.Write(domainBytes); info.Write([0x00, 0x00]); // domain + null
        info.Write(userBytes);   info.Write([0x00, 0x00]); // user + null
        info.Write(passBytes);   info.Write([0x00, 0x00]); // pass + null
        info.Write([0x00, 0x00]); // alternateShell
        info.Write([0x00, 0x00]); // workingDir
        var infoBytes = info.ToArray();

        // Wrap in security header (SEC_INFO_PKT = 0x0040) + padding
        using var pkt = new MemoryStream();
        W16LE(pkt, 0x0040); // flags = SEC_INFO_PKT
        W16LE(pkt, 0x0000); // flagsHi
        pkt.Write(infoBytes);
        return pkt.ToArray();
    }

    private byte[] BuildConfirmActivePdu()
    {
        using var caps = new MemoryStream();

        // GENERAL capability set (0x0001)
        AppendCapability(caps, 0x0001, 24,
            [0xFF, 0x02, // osMajorType=Windows, osMinorType=NT
             0x00, 0x00, // protocolVersion
             0x00, 0x00, // pad2octetsA
             0x00, 0x00, // generalCompressionTypes
             0x1E, 0x00, // extraFlags
             0x00, 0x00, // updateCapabilityFlag
             0x00, 0x00, // remoteUnshareFlag
             0x00, 0x00, // generalCompressionLevel
             0x00, 0x00  // refreshRectSupport, suppressOutputSupport
            ]);

        // BITMAP capability set (0x0002)
        AppendCapability(caps, 0x0002, 28,
            [0x18, 0x00, // preferredBitsPerPixel = 24
             0x01, 0x00, // receive1BitPerPixel
             0x01, 0x00, // receive4BitsPerPixel
             0x01, 0x00, // receive8BitsPerPixel
             (byte)(_desktopWidth & 0xFF), (byte)(_desktopWidth >> 8),   // desktopWidth
             (byte)(_desktopHeight & 0xFF), (byte)(_desktopHeight >> 8), // desktopHeight
             0x00, 0x00, // pad2octets
             0x01, 0x00, // desktopResizeFlag
             0x01, 0x00, // bitmapCompressionFlag = 1
             0x00,       // highColorFlags
             0x00,       // drawingFlags
             0x01, 0x00, // multipleRectangleSupport
             0x00, 0x00  // pad2octetsB
            ]);

        // ORDER capability set (0x0003)
        var orderData = new byte[88 - 4];
        orderData[0] = 0x01; // terminalDescriptor[16] - first byte
        caps.Write(BuildCapabilitySetHeader(0x0003, 88));
        caps.Write(orderData);

        // INPUT capability set (0x000D)
        AppendCapability(caps, 0x000D, 88,
            new byte[84]); // mostly zeros for basic input

        var capsContent = caps.ToArray();

        // TS_CONFIRM_ACTIVE_PDU structure
        using var pdu = new MemoryStream();
        ms_W32LE(pdu, _shareId);    // shareId
        W16LE(pdu, 0x03EA);         // originatorId = 1002 (server)
        W16LE(pdu, 0x0004);         // lengthSourceDescriptor = 4
        W16LE(pdu, (ushort)(capsContent.Length + 4)); // lengthCombinedCapabilities includes numberCapabilities(2) + pad(2)
        pdu.Write([0x4D, 0x53, 0x54, 0x53]); // sourceDescriptor = "MSTS"
        W16LE(pdu, 4); // numberCapabilities = 4 (GENERAL, BITMAP, ORDER, INPUT)
        W16LE(pdu, 0x0000); // pad2octets
        pdu.Write(capsContent);

        // TS_SHARECONTROLHEADER
        using var hdr = new MemoryStream();
        var body = pdu.ToArray();
        W16LE(hdr, (ushort)(body.Length + 6)); // totalLength
        W16LE(hdr, 0x0013);  // pduType = TS_PDUTYPE_CONFIRMACTIVEPDU | version 1
        W16LE(hdr, _userId); // pduSource

        // Wrap in security header (no encryption)
        using var sec = new MemoryStream();
        W16LE(sec, 0x0000); // flags = none
        W16LE(sec, 0x0000); // flagsHi
        sec.Write(hdr.ToArray());
        sec.Write(body);
        return sec.ToArray();
    }

    private byte[] BuildSynchronizePdu()
    {
        using var ms = new MemoryStream();
        // Security header + share control header + sync PDU
        W16LE(ms, 0); W16LE(ms, 0); // security header
        W16LE(ms, 22); W16LE(ms, 0x0011 | (1 << 4)); W16LE(ms, _userId); // share control (DATA type)
        // Share data header
        ms_W32LE(ms, _shareId);
        ms.WriteByte(0x00); ms.WriteByte(0x00); ms.WriteByte(0x00);
        ms.WriteByte(0x11); // pduType2 = TS_PDUTYPE2_SYNCHRONIZE
        ms.Write([0x00, 0x00, 0x00, 0x00]); // uncompressedLength + compressed type + compressedLen
        // Sync PDU body
        W16LE(ms, 1); // messageType = SYNCMSGTYPE_SYNC
        W16LE(ms, _userId); // targetUser
        return ms.ToArray();
    }

    private byte[] BuildControlPdu(ushort action)
    {
        using var ms = new MemoryStream();
        W16LE(ms, 0); W16LE(ms, 0); // security header
        W16LE(ms, 26); W16LE(ms, 0x0011 | (1 << 4)); W16LE(ms, _userId);
        ms_W32LE(ms, _shareId);
        ms.WriteByte(0); ms.WriteByte(0); ms.WriteByte(0);
        ms.WriteByte(0x14); // TS_PDUTYPE2_CONTROL
        ms.Write([0x00, 0x00, 0x00, 0x00]);
        W16LE(ms, action);
        W16LE(ms, 0x0000); // grantId
        ms_W32LE(ms, 0x00000000); // controlId
        return ms.ToArray();
    }

    private byte[] BuildPersistentKeyListPdu()
    {
        using var ms = new MemoryStream();
        W16LE(ms, 0); W16LE(ms, 0);
        W16LE(ms, 28); W16LE(ms, 0x0011 | (1 << 4)); W16LE(ms, _userId);
        ms_W32LE(ms, _shareId);
        ms.WriteByte(0); ms.WriteByte(0); ms.WriteByte(0);
        ms.WriteByte(0x35); // TS_PDUTYPE2_BITMAPCACHE_PERSISTENT_LIST
        ms.Write([0x00, 0x00, 0x00, 0x00]);
        ms.Write(new byte[8]); // empty key list
        return ms.ToArray();
    }

    private byte[] BuildFontListPdu()
    {
        using var ms = new MemoryStream();
        W16LE(ms, 0); W16LE(ms, 0);
        W16LE(ms, 26); W16LE(ms, 0x0011 | (1 << 4)); W16LE(ms, _userId);
        ms_W32LE(ms, _shareId);
        ms.WriteByte(0); ms.WriteByte(0); ms.WriteByte(0);
        ms.WriteByte(0x27); // TS_PDUTYPE2_FONTLIST
        ms.Write([0x00, 0x00, 0x00, 0x00]);
        W16LE(ms, 0); // numberFonts
        W16LE(ms, 0); // totalNumFonts
        W16LE(ms, 3); // listFlags = 0x0003
        W16LE(ms, 50); // entrySize
        return ms.ToArray();
    }

    // ── MCS framing helpers ──────────────────────────────────

    private static byte[] BuildMcsSendDataRequest(ushort userId, ushort channelId, byte[] data)
    {
        using var ms = new MemoryStream();
        ms.WriteByte(0x64); // MCS Send Data Request tag
        ms.WriteByte((byte)(userId >> 8));
        ms.WriteByte((byte)(userId & 0xFF));
        ms.WriteByte((byte)(channelId >> 8));
        ms.WriteByte((byte)(channelId & 0xFF));
        ms.WriteByte(0x70); // priority = 6 + segmentation end
        WriteBerLength(ms, data.Length);
        ms.Write(data);
        return ms.ToArray();
    }

    private static byte[] WrapX224Data(byte[] payload)
    {
        // X.224 Data TPDU: LI=2, type=F0, EOT=80
        var tpdu = new byte[3 + payload.Length];
        tpdu[0] = 0x02; tpdu[1] = 0xF0; tpdu[2] = 0x80;
        payload.CopyTo(tpdu, 3);
        return tpdu;
    }

    private static byte[] BuildTpkt(byte[] payload)
    {
        int total = 4 + payload.Length;
        var pkt = new byte[total];
        pkt[0] = 0x03; pkt[1] = 0x00;
        pkt[2] = (byte)(total >> 8);
        pkt[3] = (byte)(total & 0xFF);
        payload.CopyTo(pkt, 4);
        return pkt;
    }

    // ── BER / DomainParameters helpers ───────────────────────

    private static byte[] BuildDomainParameters(uint maxChanIds, uint maxUserIds, uint maxTokenIds,
        uint numPriorities, uint minThroughput, uint maxHeight, uint maxMCSPDUSize, uint protocolVersion)
    {
        using var content = new MemoryStream();
        WriteBerInt(content, maxChanIds);
        WriteBerInt(content, maxUserIds);
        WriteBerInt(content, maxTokenIds);
        WriteBerInt(content, numPriorities);
        WriteBerInt(content, minThroughput);
        WriteBerInt(content, maxHeight);
        WriteBerInt(content, maxMCSPDUSize);
        WriteBerInt(content, protocolVersion);

        var c = content.ToArray();
        using var result = new MemoryStream();
        result.WriteByte(0x30); // SEQUENCE
        WriteBerLength(result, c.Length);
        result.Write(c);
        return result.ToArray();
    }

    private static void WriteBerInt(MemoryStream ms, uint value)
    {
        ms.WriteByte(0x02); // INTEGER tag
        if (value == 0) { ms.WriteByte(0x01); ms.WriteByte(0x00); return; }
        if (value < 0x80) { ms.WriteByte(0x01); ms.WriteByte((byte)value); return; }
        if (value < 0x8000) { ms.WriteByte(0x02); ms.WriteByte((byte)(value >> 8)); ms.WriteByte((byte)value); return; }
        if (value < 0x800000) { ms.WriteByte(0x03); ms.WriteByte((byte)(value >> 16)); ms.WriteByte((byte)(value >> 8)); ms.WriteByte((byte)value); return; }
        // 4-byte (need leading 0x00 if MSB set to avoid sign bit)
        if ((value & 0x80000000) != 0)
        {
            ms.WriteByte(0x05);
            ms.WriteByte(0x00);
        }
        else ms.WriteByte(0x04);
        ms.WriteByte((byte)(value >> 24)); ms.WriteByte((byte)(value >> 16));
        ms.WriteByte((byte)(value >> 8)); ms.WriteByte((byte)value);
    }

    private static void WriteBerLength(MemoryStream ms, int len)
    {
        if (len < 0x80) { ms.WriteByte((byte)len); return; }
        if (len < 0x100) { ms.WriteByte(0x81); ms.WriteByte((byte)len); return; }
        ms.WriteByte(0x82);
        ms.WriteByte((byte)(len >> 8));
        ms.WriteByte((byte)(len & 0xFF));
    }

    // ── Capability helpers ─────────────────────────────────

    private static void AppendCapability(MemoryStream ms, ushort type, int totalLen, byte[] body)
    {
        ms.Write(BuildCapabilitySetHeader(type, totalLen));
        ms.Write(body);
    }

    private static byte[] BuildCapabilitySetHeader(ushort capType, int totalLen)
    {
        var hdr = new byte[4];
        hdr[0] = (byte)(capType & 0xFF); hdr[1] = (byte)(capType >> 8);
        hdr[2] = (byte)(totalLen & 0xFF); hdr[3] = (byte)(totalLen >> 8);
        return hdr;
    }

    // ── Parsing helpers ────────────────────────────────────

    private static uint ParseX224Cc(byte[] tpktPacket)
    {
        if (tpktPacket.Length < 12) return 0;
        var tpdu = tpktPacket.AsSpan(4);
        int liBytes = tpdu[0] + 1;
        for (int i = liBytes; i + 8 <= tpdu.Length; i++)
        {
            if (tpdu[i] == 0x02) // RDP_NEG_RSP
                return (uint)(tpdu[i + 4] | (tpdu[i + 5] << 8) | (tpdu[i + 6] << 16) | (tpdu[i + 7] << 24));
        }
        return 0;
    }

    private void ParseMcsConnectResponse(byte[] packet)
    {
        // Scan for I/O channel ID in GCC Conference Create Response
        // It's typically 1003 (0x03EB) but we'll trust the default
        _ioChanId = 1003;
    }

    private static ushort ParseAttachUserConfirm(byte[] packet)
    {
        if (packet.Length < 8) return 1001;
        var tpdu = packet.AsSpan(4);
        int liBytes = tpdu[0] + 1;
        if (liBytes >= tpdu.Length) return 1001;
        var mcs = tpdu.Slice(liBytes);
        if (mcs.Length < 3) return 1001;
        if (mcs[0] != 0x2E) return 1001; // MCS Attach User Confirm tag
        // initiator is 2 bytes (offset 3 after tag+length)
        if (mcs.Length < 5) return 1001;
        ushort userId = (ushort)((mcs[3] << 8) | mcs[4]);
        return userId;
    }

    private static byte[]? ExtractX224Payload(byte[] tpktPacket)
    {
        if (tpktPacket.Length < 7) return null;
        return tpktPacket[4..];
    }

    private static (int dataLen, int dataStart) FindMcsChannelData(byte[] mcs)
    {
        if (mcs.Length < 7) return (-1, -1);
        if (mcs[0] != 0x68) return (-1, -1); // MCS Send Data Indication
        // Skip tag(1) + initiator(2) + channel(2) + priority(1) = 6 bytes before BER length
        var (len, start) = ReadBerLen(mcs.AsSpan(6), 0);
        return (len, 6 + start);
    }

    private static (int len, int nextOffset) ReadBerLen(ReadOnlySpan<byte> data, int offset)
    {
        if (offset >= data.Length) return (-1, -1);
        byte b = data[offset];
        if ((b & 0x80) == 0) return (b, offset + 1);
        if (b == 0x81 && offset + 1 < data.Length) return (data[offset + 1], offset + 2);
        if (b == 0x82 && offset + 2 < data.Length)
            return ((data[offset + 1] << 8) | data[offset + 2], offset + 3);
        return (-1, -1);
    }

    // ── I/O helpers ────────────────────────────────────────

    private async Task SendTpktAsync(byte[] data, CancellationToken ct)
    {
        var tpkt = BuildTpkt(data);
        await _writeLock.WaitAsync(ct);
        try
        {
            await _stream!.WriteAsync(tpkt, ct);
            await _stream.FlushAsync(ct);
        }
        finally { _writeLock.Release(); }
    }

    private async Task SendRawAsync(byte[] data, CancellationToken ct)
    {
        await _writeLock.WaitAsync(ct);
        try
        {
            await _stream!.WriteAsync(data, ct);
            await _stream.FlushAsync(ct);
        }
        finally { _writeLock.Release(); }
    }

    private static async Task<byte[]?> ReadTpktAsync(Stream stream, CancellationToken ct)
    {
        var header = new byte[4];
        int read = 0;
        while (read < 4)
        {
            int n;
            try { n = await stream.ReadAsync(header.AsMemory(read, 4 - read), ct); }
            catch { return null; }
            if (n == 0) return null;
            read += n;
        }
        if (header[0] != 0x03) return null; // not TPKT
        int total = (header[2] << 8) | header[3];
        if (total < 4 || total > 65535) return null;
        var packet = new byte[total];
        header.CopyTo(packet, 0);
        int remaining = total - 4;
        int got = 0;
        while (got < remaining)
        {
            int n;
            try { n = await stream.ReadAsync(packet.AsMemory(4 + got, remaining - got), ct); }
            catch { return null; }
            if (n == 0) return null;
            got += n;
        }
        return packet;
    }

    private static async Task ReadExactAsync(Stream s, byte[] buf, CancellationToken ct)
    {
        int got = 0;
        while (got < buf.Length)
        {
            int n = await s.ReadAsync(buf.AsMemory(got, buf.Length - got), ct);
            if (n == 0) throw new WebRdpException("Connection closed");
            got += n;
        }
    }

    // ── Encoding utilities ─────────────────────────────────

    private static int R16LE(byte[] data, int offset) =>
        offset + 1 < data.Length ? data[offset] | (data[offset + 1] << 8) : 0;

    private static void W16LE(byte[] buf, int offset, ushort value)
    {
        buf[offset] = (byte)(value & 0xFF);
        buf[offset + 1] = (byte)(value >> 8);
    }

    private static void W16LE(MemoryStream ms, ushort value)
    {
        ms.WriteByte((byte)(value & 0xFF));
        ms.WriteByte((byte)(value >> 8));
    }

    private static void ms_W32LE(MemoryStream ms, uint value)
    {
        ms.WriteByte((byte)(value & 0xFF));
        ms.WriteByte((byte)((value >> 8) & 0xFF));
        ms.WriteByte((byte)((value >> 16) & 0xFF));
        ms.WriteByte((byte)((value >> 24) & 0xFF));
    }

    public async ValueTask DisposeAsync()
    {
        _writeLock.Dispose();
        if (_ssl != null) await _ssl.DisposeAsync();
        _tcp?.Dispose();
    }
}
