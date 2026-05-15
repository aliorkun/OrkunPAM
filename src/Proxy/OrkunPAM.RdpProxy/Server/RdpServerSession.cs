using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using OrkunPAM.RdpProxy.Protocol;
using OrkunPAM.RdpProxy.Session;

namespace OrkunPAM.RdpProxy.Server;

/// <summary>
/// Handles a single RDP proxied session with TLS termination and credential injection:
///   1. Parse X.224 CR — extract PAM session token from RDP cookie.
///   2. Validate token via PAM API -> get target IP + credentials.
///   3. Send X.224 CC to client (accepting TLS or standard RDP security).
///   4. Terminate TLS on the client side (SslStream).
///   5. Connect to target, forward X.224 CR, receive CC.
///   6. Establish TLS to target (SslStream).
///   7. Parse RDP PDUs: inject vault credentials at CLIENT_INFO_PDU.
///   8. Audit virtual channel activity (clipboard, drives, printers).
///   9. Relay remaining traffic bidirectionally while recording.
///
/// If NLA/CredSSP is requested but not supported by target, falls back to standard TLS.
/// If TLS handshake fails, falls back to plain TCP relay (legacy behavior).
/// </summary>
internal sealed class RdpServerSession
{
    private readonly TcpClient _client;
    private readonly PamApiClient _api;
    private readonly RdpProxyOptions _opts;
    private readonly ILogger _log;
    private readonly CancellationToken _ct;

    private static readonly TimeSpan RelayTimeout = TimeSpan.FromHours(8);

    public RdpServerSession(
        TcpClient client,
        PamApiClient api,
        RdpProxyOptions opts,
        ILogger log,
        CancellationToken ct)
    {
        _client = client;
        _api    = api;
        _opts   = opts;
        _log    = log;
        _ct     = ct;
    }

    public async Task RunAsync()
    {
        var clientIp = _client.Client.RemoteEndPoint?.ToString() ?? "unknown";
        _log.LogInformation("RDP connection from {ClientIp}", clientIp);

        await using var clientStream = _client.GetStream();
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(_ct);
        sessionCts.CancelAfter(RelayTimeout);
        var ct = sessionCts.Token;

        // 1. Read the initial X.224 CR (plain TCP -- sent before TLS)
        byte[]? crPacket;
        try { crPacket = await TpktPacket.ReadAsync(clientStream, ct); }
        catch { return; }

        if (crPacket == null)
        {
            _log.LogWarning("RDP from {ClientIp}: no initial TPKT packet", clientIp);
            return;
        }

        var (sessionToken, requestedProtocols) = X224Packet.ParseConnectionRequest(crPacket);

        if (string.IsNullOrEmpty(sessionToken))
        {
            _log.LogWarning("RDP from {ClientIp}: no session token in cookie", clientIp);
            await clientStream.WriteAsync(X224Packet.BuildConnectionFailure(2), ct);
            return;
        }

        _log.LogInformation("RDP from {ClientIp}: session token={Token}, requestedProtocols=0x{Protocols:X}",
            clientIp, sessionToken[..Math.Min(8, sessionToken.Length)], requestedProtocols);

        // 2. Validate the session token against PAM API
        RdpSessionInfo sessionInfo;
        try { sessionInfo = await _api.ValidateSessionTokenAsync(sessionToken, ct); }
        catch (Exception ex)
        {
            _log.LogWarning(ex, "RDP from {ClientIp}: session token validation failed", clientIp);
            await clientStream.WriteAsync(X224Packet.BuildConnectionFailure(5), ct);
            return;
        }

        _log.LogInformation("RDP session {SessionId}: {ClientIp} -> {TargetIp}:{TargetPort}",
            sessionInfo.SessionId, clientIp, sessionInfo.TargetIp, sessionInfo.TargetPort);

        // 3. Determine which protocol to accept
        //    We always prefer TLS (ProtocolSsl) even if client requests NLA (ProtocolHybrid).
        //    NLA/CredSSP would require the PAM proxy to perform NTLM/Kerberos auth to the
        //    client, which means exposing a machine credential. Instead we downgrade NLA
        //    requests to standard TLS — the credential injection happens at CLIENT_INFO_PDU level.
        uint selectedProtocol;
        if ((requestedProtocols & X224Packet.ProtocolHybrid) != 0 ||
            (requestedProtocols & X224Packet.ProtocolSsl) != 0)
        {
            selectedProtocol = X224Packet.ProtocolSsl;
        }
        else
        {
            // Client only supports standard RDP security (no TLS)
            selectedProtocol = X224Packet.ProtocolRdp;
        }

        var ccPacket = X224Packet.BuildConnectionConfirm(selectedProtocol);
        await clientStream.WriteAsync(ccPacket, ct);

        // 4. Connect to target server
        TcpClient? targetClient = null;
        try
        {
            targetClient = new TcpClient();
            targetClient.NoDelay = true;
            await targetClient.ConnectAsync(sessionInfo.TargetIp, sessionInfo.TargetPort, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "RDP session {SessionId}: cannot connect to target {TargetIp}:{TargetPort}",
                sessionInfo.SessionId, sessionInfo.TargetIp, sessionInfo.TargetPort);
            targetClient?.Dispose();
            return;
        }

        _log.LogInformation("RDP session {SessionId}: target connection established", sessionInfo.SessionId);

        var (idleTimeoutMinutes, _) = await _api.GetSessionPolicyAsync(ct);

        var masterKey = string.IsNullOrEmpty(_opts.RecordingEncryptionKeyBase64)
            ? null : Convert.FromBase64String(_opts.RecordingEncryptionKeyBase64);
        await using var recorder = await RdpSessionRecorder.CreateAsync(
            _opts.RecordingDirectory, sessionInfo.SessionId, masterKey);

        using (targetClient)
        await using (var targetStream = targetClient.GetStream())
        {
            // 5. Forward the client's X.224 CR to the target, then consume target's CC
            await targetStream.WriteAsync(crPacket, ct);
            var targetCcPacket = await TpktPacket.ReadAsync(targetStream, ct);
            uint targetSelectedProtocol = X224Packet.ProtocolRdp;

            if (targetCcPacket != null)
            {
                targetSelectedProtocol = ParseTargetSelectedProtocol(targetCcPacket);
            }

            _log.LogInformation("RDP session {SessionId}: target selected protocol=0x{Protocol:X}",
                sessionInfo.SessionId, targetSelectedProtocol);

            // 6. Establish TLS on both sides if applicable
            Stream clientSide = clientStream;
            Stream targetSide = targetStream;
            SslStream? clientSsl = null;
            SslStream? targetSsl = null;

            bool useTls = selectedProtocol == X224Packet.ProtocolSsl &&
                          (targetSelectedProtocol == X224Packet.ProtocolSsl ||
                           targetSelectedProtocol == X224Packet.ProtocolHybrid);

            if (useTls)
            {
                try
                {
                    // TLS to client (proxy acts as server)
                    var proxyCert = LoadOrGenerateProxyCertificate();
                    clientSsl = new SslStream(clientStream, leaveInnerStreamOpen: true);
                    await clientSsl.AuthenticateAsServerAsync(
                        new SslServerAuthenticationOptions
                        {
                            ServerCertificate = proxyCert,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                            ClientCertificateRequired = false,
                        }, ct);

                    _log.LogInformation("RDP session {SessionId}: TLS established to client ({Protocol})",
                        sessionInfo.SessionId, clientSsl.SslProtocol);

                    // TLS to target (proxy acts as client)
                    targetSsl = new SslStream(targetStream, leaveInnerStreamOpen: true);
                    await targetSsl.AuthenticateAsClientAsync(
                        new SslClientAuthenticationOptions
                        {
                            TargetHost = sessionInfo.TargetIp,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13,
                            RemoteCertificateValidationCallback = ValidateTargetCertificate,
                        }, ct);

                    _log.LogInformation("RDP session {SessionId}: TLS established to target ({Protocol})",
                        sessionInfo.SessionId, targetSsl.SslProtocol);

                    clientSide = clientSsl;
                    targetSide = targetSsl;
                }
                catch (Exception ex)
                {
                    _log.LogWarning(ex,
                        "RDP session {SessionId}: TLS handshake failed, falling back to TCP relay",
                        sessionInfo.SessionId);
                    clientSsl?.Dispose();
                    targetSsl?.Dispose();
                    clientSsl = null;
                    targetSsl = null;
                    // Fall back to raw TCP relay (legacy behavior)
                    clientSide = clientStream;
                    targetSide = targetStream;
                    useTls = false;
                }
            }

            try
            {
                var startTime = DateTimeOffset.UtcNow;

                if (useTls)
                {
                    // TLS terminated: parse PDUs, inject credentials, audit channels
                    await RunTlsTerminatedSessionAsync(
                        clientSide, targetSide, recorder, sessionInfo, idleTimeoutMinutes, ct);
                }
                else
                {
                    // Legacy: plain TCP relay (no credential injection or auditing)
                    _log.LogWarning("RDP session {SessionId}: running in TCP relay mode (no TLS termination)",
                        sessionInfo.SessionId);
                    await RelayRawAsync(clientSide, targetSide, recorder, ct, idleTimeoutMinutes);
                }

                var duration = (int)(DateTimeOffset.UtcNow - startTime).TotalSeconds;
                _log.LogInformation("RDP session {SessionId} ended -- duration {Sec}s, recording={Path}",
                    sessionInfo.SessionId, duration, recorder.FilePath);

                Array.Clear(sessionInfo.TargetPasswordBytes, 0, sessionInfo.TargetPasswordBytes.Length);

                _ = _api.ReportSessionEndedAsync(sessionInfo.SessionId, duration, recorder.FilePath, CancellationToken.None);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) when (IsExpectedDisconnect(ex))
            {
                _log.LogDebug("RDP session {SessionId}: client disconnected", sessionInfo.SessionId);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "RDP session {SessionId}: session error", sessionInfo.SessionId);
            }
            finally
            {
                if (clientSsl != null) await clientSsl.DisposeAsync();
                if (targetSsl != null) await targetSsl.DisposeAsync();
            }
        }
    }

    /// <summary>
    /// Runs the TLS-terminated session with PDU-level parsing,
    /// credential injection, and virtual channel auditing.
    /// </summary>
    private async Task RunTlsTerminatedSessionAsync(
        Stream clientSide,
        Stream targetSide,
        RdpSessionRecorder recorder,
        RdpSessionInfo sessionInfo,
        int idleTimeoutMinutes,
        CancellationToken ct)
    {
        var injector = new CredentialInjector(
            sessionInfo.TargetDomain ?? string.Empty,
            sessionInfo.TargetUsername,
            sessionInfo.TargetPasswordBytes,
            _log);

        var auditor = new RdpCommandAuditor(sessionInfo.SessionId, _log);
        bool negotiationComplete = false;

        // Phase 1: PDU-by-PDU relay during RDP negotiation
        // We need to intercept MCS Connect Initial (for channel discovery),
        // CLIENT_INFO_PDU (for credential injection), and then switch to
        // bulk relay mode after licensing is complete.

        _log.LogInformation("RDP session {SessionId}: entering PDU parsing phase", sessionInfo.SessionId);

        try
        {
            while (!ct.IsCancellationRequested && !negotiationComplete)
            {
                // Read next TPKT from client
                var clientPdu = await TpktPacket.ReadAsync(clientSide, ct);
                if (clientPdu == null)
                {
                    _log.LogDebug("RDP session {SessionId}: client stream ended during negotiation",
                        sessionInfo.SessionId);
                    return;
                }

                var pduType = RdpPduParser.IdentifyPdu(clientPdu);
                _log.LogDebug("RDP session {SessionId}: client PDU type={PduType}, len={Len}",
                    sessionInfo.SessionId, pduType, clientPdu.Length);

                // Try to discover virtual channels from MCS Connect Initial
                if (pduType == RdpPduType.McsConnectInitial)
                {
                    auditor.TryParseChannelDefinitions(clientPdu);
                }

                // Try credential injection on CLIENT_INFO_PDU
                byte[] pduToSend = clientPdu;
                if (pduType == RdpPduType.ClientInfoPdu && !injector.HasInjected)
                {
                    var modified = injector.TryInject(clientPdu);
                    if (modified != null)
                    {
                        pduToSend = modified;
                    }
                }

                // Record and forward to target
                await recorder.WriteAsync(false, pduToSend);
                await targetSide.WriteAsync(pduToSend, ct);

                // Read response(s) from target
                var targetPdu = await TpktPacket.ReadAsync(targetSide, ct);
                if (targetPdu == null)
                {
                    _log.LogDebug("RDP session {SessionId}: target stream ended during negotiation",
                        sessionInfo.SessionId);
                    return;
                }

                var targetPduType = RdpPduParser.IdentifyPdu(targetPdu);
                _log.LogDebug("RDP session {SessionId}: target PDU type={PduType}, len={Len}",
                    sessionInfo.SessionId, targetPduType, targetPdu.Length);

                await recorder.WriteAsync(true, targetPdu);
                await clientSide.WriteAsync(targetPdu, ct);

                // After Server License PDU, the negotiation phase is essentially complete.
                // The next PDUs are Demand Active / Confirm Active which start the graphics pipeline.
                // Switch to bulk relay mode for performance.
                if (targetPduType == RdpPduType.ServerLicensePdu)
                {
                    _log.LogInformation(
                        "RDP session {SessionId}: negotiation complete, credential injected={Injected}, switching to relay mode",
                        sessionInfo.SessionId, injector.HasInjected);
                    negotiationComplete = true;
                }

                // Also switch to relay after credential injection + a few more PDUs
                // (some servers may not send a distinct license PDU)
                if (injector.HasInjected && pduType == RdpPduType.McsData)
                {
                    // Give it a few more rounds then switch
                    negotiationComplete = true;
                }
            }
        }
        catch (Exception ex) when (IsExpectedDisconnect(ex))
        {
            _log.LogDebug("RDP session {SessionId}: disconnect during negotiation", sessionInfo.SessionId);
            return;
        }

        // Phase 2: Bulk relay with audit inspection
        _log.LogInformation("RDP session {SessionId}: entering bulk relay with audit mode", sessionInfo.SessionId);

        using var idleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        long[] lastActivity = [DateTime.UtcNow.Ticks];

        var clientToTarget = PumpWithAuditAsync(
            clientSide, targetSide, fromTarget: false, recorder, auditor, idleCts.Token, lastActivity);
        var targetToClient = PumpWithAuditAsync(
            targetSide, clientSide, fromTarget: true, recorder, auditor, idleCts.Token, lastActivity);
        var idleWatcher = IdleWatchAsync(idleTimeoutMinutes, lastActivity, idleCts);

        await Task.WhenAny(clientToTarget, targetToClient, idleWatcher);
        await idleCts.CancelAsync();

        auditor.LogSessionSummary();
    }

    /// <summary>
    /// Pumps data between streams with audit inspection on each TPKT packet.
    /// Falls back to raw byte pumping if TPKT framing is lost.
    /// </summary>
    private static async Task PumpWithAuditAsync(
        Stream from,
        Stream to,
        bool fromTarget,
        RdpSessionRecorder recorder,
        RdpCommandAuditor auditor,
        CancellationToken ct,
        long[] lastActivityTicks)
    {
        const int BufSize = 65536;
        var buf = new byte[BufSize];

        while (!ct.IsCancellationRequested)
        {
            // Try to read as TPKT first for audit
            byte[]? tpktPacket = null;
            try
            {
                tpktPacket = await TpktPacket.ReadAsync(from, ct);
            }
            catch (OperationCanceledException) { throw; }
            catch
            {
                // TPKT framing lost, fall back to raw read
                tpktPacket = null;
            }

            if (tpktPacket == null)
            {
                // Try raw read - stream may have ended or non-TPKT data
                int read;
                try { read = await from.ReadAsync(buf, ct); }
                catch (OperationCanceledException) { throw; }
                catch { break; }

                if (read == 0) break;

                Interlocked.Exchange(ref lastActivityTicks[0], DateTime.UtcNow.Ticks);
                await recorder.WriteAsync(fromTarget, buf.AsMemory(0, read));
                await to.WriteAsync(buf.AsMemory(0, read), ct);
                continue;
            }

            Interlocked.Exchange(ref lastActivityTicks[0], DateTime.UtcNow.Ticks);

            // Audit the packet (non-blocking, best-effort)
            try { auditor.InspectPdu(tpktPacket, fromTarget); }
            catch { /* audit failure must not break the session */ }

            await recorder.WriteAsync(fromTarget, tpktPacket);
            await to.WriteAsync(tpktPacket, ct);
        }
    }

    /// <summary>Legacy raw TCP relay (no TLS termination, no credential injection).</summary>
    private static async Task RelayRawAsync(
        Stream client,
        Stream target,
        RdpSessionRecorder recorder,
        CancellationToken ct,
        int idleTimeoutMinutes)
    {
        const int BufSize = 65536;
        var buf1 = new byte[BufSize];
        var buf2 = new byte[BufSize];
        long[] lastActivity = [DateTime.UtcNow.Ticks];

        using var idleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);
        var clientToTarget = PumpRawAsync(client, target, buf1, fromTarget: false, recorder, idleCts.Token, lastActivity);
        var targetToClient = PumpRawAsync(target, client, buf2, fromTarget: true,  recorder, idleCts.Token, lastActivity);
        var idleWatcher    = IdleWatchAsync(idleTimeoutMinutes, lastActivity, idleCts);

        await Task.WhenAny(clientToTarget, targetToClient, idleWatcher);
        await idleCts.CancelAsync();
    }

    private static async Task PumpRawAsync(
        Stream from,
        Stream to,
        byte[] buf,
        bool fromTarget,
        RdpSessionRecorder recorder,
        CancellationToken ct,
        long[] lastActivityTicks)
    {
        while (!ct.IsCancellationRequested)
        {
            int read = await from.ReadAsync(buf, ct);
            if (read == 0) break;

            Interlocked.Exchange(ref lastActivityTicks[0], DateTime.UtcNow.Ticks);
            await recorder.WriteAsync(fromTarget, buf.AsMemory(0, read));
            await to.WriteAsync(buf.AsMemory(0, read), ct);
        }
    }

    private static async Task IdleWatchAsync(int timeoutMinutes, long[] lastActivityTicks, CancellationTokenSource cts)
    {
        var timeout = TimeSpan.FromMinutes(timeoutMinutes);
        try
        {
            while (!cts.IsCancellationRequested)
            {
                await Task.Delay(30_000, cts.Token);
                var idleFor = TimeSpan.FromTicks(DateTime.UtcNow.Ticks - Interlocked.Read(ref lastActivityTicks[0]));
                if (idleFor >= timeout)
                {
                    cts.Cancel();
                    return;
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>
    /// Parses the selected protocol from a target's X.224 Connection Confirm packet.
    /// </summary>
    private static uint ParseTargetSelectedProtocol(byte[] ccPacket)
    {
        var tpdu = TpktPacket.Payload(ccPacket);
        if (tpdu.Length < 15) return X224Packet.ProtocolRdp;

        // Check for RDP_NEG_RSP (type=2) at offset 7 in TPDU
        int liBytes = tpdu[0] + 1;

        // The RDP negotiation response may be at the end of the X.224 CC header
        // Scan for it
        for (int i = 7; i + 8 <= tpdu.Length; i++)
        {
            if (tpdu[i] == X224Packet.RdpNegRsp)
            {
                return (uint)(tpdu[i + 4] | (tpdu[i + 5] << 8) |
                              (tpdu[i + 6] << 16) | (tpdu[i + 7] << 24));
            }
        }

        return X224Packet.ProtocolRdp;
    }

    /// <summary>
    /// Loads the proxy TLS certificate from the configured path,
    /// or generates a self-signed certificate if none is configured.
    /// </summary>
    private X509Certificate2 LoadOrGenerateProxyCertificate()
    {
        if (!string.IsNullOrEmpty(_opts.TlsCertificatePath))
        {
            try
            {
                if (!string.IsNullOrEmpty(_opts.TlsCertificatePassword))
                    return new X509Certificate2(_opts.TlsCertificatePath, _opts.TlsCertificatePassword);
                return new X509Certificate2(_opts.TlsCertificatePath);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "Failed to load TLS certificate from {Path}, generating self-signed",
                    _opts.TlsCertificatePath);
            }
        }

        return GenerateSelfSignedCertificate();
    }

    /// <summary>
    /// Generates a self-signed X.509 certificate for the RDP proxy TLS termination.
    /// Valid for 1 year. Uses RSA 2048-bit key.
    /// </summary>
    private static X509Certificate2 GenerateSelfSignedCertificate()
    {
        using var rsa = System.Security.Cryptography.RSA.Create(2048);
        var request = new CertificateRequest(
            "CN=OrkunPAM RDP Proxy",
            rsa,
            System.Security.Cryptography.HashAlgorithmName.SHA256,
            System.Security.Cryptography.RSASignaturePadding.Pkcs1);

        // Add SAN for localhost
        var sanBuilder = new SubjectAlternativeNameBuilder();
        sanBuilder.AddDnsName("localhost");
        sanBuilder.AddIpAddress(System.Net.IPAddress.Loopback);
        request.CertificateExtensions.Add(sanBuilder.Build());

        // Key usage
        request.CertificateExtensions.Add(
            new X509KeyUsageExtension(
                X509KeyUsageFlags.DigitalSignature | X509KeyUsageFlags.KeyEncipherment,
                critical: false));

        request.CertificateExtensions.Add(
            new X509EnhancedKeyUsageExtension(
                new OidCollection { new("1.3.6.1.5.5.7.3.1") }, // Server Authentication
                critical: false));

        var cert = request.CreateSelfSigned(
            DateTimeOffset.UtcNow.AddMinutes(-5),
            DateTimeOffset.UtcNow.AddYears(1));

        // Export and re-import to associate the private key properly on Windows
        var pfxBytes = cert.Export(X509ContentType.Pfx, string.Empty);
        return new X509Certificate2(pfxBytes, string.Empty,
            X509KeyStorageFlags.MachineKeySet | X509KeyStorageFlags.Exportable);
    }

    private static bool IsExpectedDisconnect(Exception ex) =>
        ex is IOException or SocketException;

    private bool ValidateTargetCertificate(
        object sender, X509Certificate? cert, X509Chain? chain, SslPolicyErrors errors)
    {
        if (errors == SslPolicyErrors.None) return true;
        if (_opts.SkipTargetCertValidation) return true;
        if (cert != null && _opts.AllowedTargetThumbprints.Length > 0)
            return _opts.AllowedTargetThumbprints.Contains(
                cert.GetCertHashString(), StringComparer.OrdinalIgnoreCase);
        return false;
    }
}
