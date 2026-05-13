using System.Net.Sockets;
using System.Text;
using OrkunPAM.SqlProxy.Protocol;

namespace OrkunPAM.SqlProxy.Session;

/// <summary>
/// Handles a single DBA privileged SQL session:
///
///   1. TDS PreLogin exchange with client — force ENCRYPT_NOT_SUP so Login7 is plaintext.
///   2. Read Login7 from client — extract PAM username + password + target SQL Server.
///   3. Authenticate PAM user against PAM API.
///   4. Retrieve vault SQL credentials for the target SQL Server.
///   5. Connect to real SQL Server, complete TDS PreLogin/Login7 with vault credentials.
///   6. Forward SQL Server's login response to client.
///   7. Relay subsequent TDS traffic bidirectionally:
///      - Client→target: SQL Batch packets are inspected; dangerous DDL is blocked.
///      - Target→client: relayed verbatim.
///   8. Log all SQL Batch queries to a per-session JSONL file.
///
/// Design note: The proxy forces plaintext (ENCRYPT_NOT_SUP) on both legs so it can
/// intercept credentials and inject vault credentials. This is appropriate for internal
/// PAM deployments where the proxy-to-target network segment is a trusted VLAN. DBA
/// clients must use Encrypt=False in their connection string when pointing to the proxy.
/// </summary>
internal sealed class SqlServerSession
{
    private readonly TcpClient  _client;
    private readonly PamApiClient _api;
    private readonly SqlProxyOptions _opts;
    private readonly ILogger    _log;
    private readonly CancellationToken _ct;

    private static readonly TimeSpan SessionTimeout = TimeSpan.FromHours(8);
    private static readonly Encoding Ucs2Le = Encoding.Unicode;

    // Dangerous DDL / OS-exec keywords — matched case-insensitively at statement start or anywhere
    private static readonly string[] BlockedPrefixes =
    [
        "DROP TABLE", "DROP DATABASE", "DROP SCHEMA", "DROP VIEW",
        "DROP PROCEDURE", "DROP FUNCTION", "DROP INDEX", "DROP TRIGGER",
        "DROP TYPE", "DROP SYNONYM", "DROP SEQUENCE", "DROP ASSEMBLY",
        "TRUNCATE TABLE", "TRUNCATE",
        "ALTER DATABASE",
        "SHUTDOWN",
    ];
    private const string BlockedSubstring = "XP_CMDSHELL";

    public SqlServerSession(
        TcpClient client, PamApiClient api,
        SqlProxyOptions opts, ILogger log, CancellationToken ct)
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
        _log.LogInformation("SQL connection from {ClientIp}", clientIp);

        await using var clientStream = _client.GetStream();
        using var sessionCts = CancellationTokenSource.CreateLinkedTokenSource(_ct);
        sessionCts.CancelAfter(SessionTimeout);
        var ct = sessionCts.Token;

        // ── 1. PreLogin with client ───────────────────────────────────────
        var clientPrelogin = await TdsPacket.ReadMessageAsync(clientStream, ct);
        if (clientPrelogin == null)
        {
            _log.LogDebug("SQL from {ClientIp}: no PreLogin packet", clientIp);
            return;
        }

        // Respond with ENCRYPT_NOT_SUP — forces client to send Login7 in plaintext
        var preLoginResponse = TdsPreLogin.BuildResponseNotSup();
        await TdsPacket.WritePacketAsync(clientStream, TdsPacket.TypePreLogin, preLoginResponse, ct);

        // ── 2. Read Login7 from client (plaintext) ──────────────────────────────────────────────
        var clientLogin = await TdsPacket.ReadMessageAsync(clientStream, ct);
        if (clientLogin == null || clientLogin.Value.type != TdsPacket.TypeLogin7)
        {
            _log.LogWarning("SQL from {ClientIp}: expected Login7, got type={Type}",
                clientIp, clientLogin?.type.ToString("X2") ?? "null");
            return;
        }

        var loginPayload = clientLogin.Value.fullPayload;
        var pamUser      = TdsLogin7.ExtractUsername(loginPayload);
        var pamPassword  = TdsLogin7.ExtractPassword(loginPayload);
        var targetHost   = TdsLogin7.ExtractServerName(loginPayload);
        var database     = TdsLogin7.ExtractDatabase(loginPayload) ?? "";

        if (string.IsNullOrEmpty(pamUser))
        {
            _log.LogWarning("SQL from {ClientIp}: no username in Login7 (SSPI/Windows Auth not supported)", clientIp);
            await SendLoginErrorAsync(clientStream, "Windows Integrated Authentication is not supported via OrkunPAM SQL Proxy. Use SQL authentication with your PAM credentials.", ct);
            return;
        }

        if (string.IsNullOrEmpty(targetHost))
        {
            _log.LogWarning("SQL from {ClientIp}: no server name in Login7 — cannot determine target", clientIp);
            await SendLoginErrorAsync(clientStream, "Target SQL Server name must be specified in the connection string.", ct);
            return;
        }

        _log.LogInformation("SQL from {ClientIp}: user={User} target={Target} db={Db}",
            clientIp, pamUser, targetHost, database);

        // ── 3. Authenticate PAM user ───────────────────────────────────────────
        if (string.IsNullOrEmpty(pamPassword) ||
            !await _api.ValidateUserAsync(pamUser, pamPassword, ct))
        {
            _log.LogWarning("SQL from {ClientIp}: PAM authentication failed for user '{User}'", clientIp, pamUser);
            await SendLoginErrorAsync(clientStream, $"Login failed for user '{pamUser}'.", ct);
            return;
        }

        // ── 4. Get vault credentials ─────────────────────────────────────────
        string targetIp, sqlUser, sqlPassword;
        int    targetPort;
        try
        {
            (targetIp, targetPort, sqlUser, sqlPassword) =
                await _api.GetTargetCredentialAsync(pamUser, targetHost, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "SQL session {User}→{Target}: vault credential retrieval failed", pamUser, targetHost);
            await SendLoginErrorAsync(clientStream, $"No SQL Server credential found for '{targetHost}' in vault.", ct);
            return;
        }

        _log.LogInformation("SQL session {User}→{TargetIp}:{TargetPort} db={Db}", pamUser, targetIp, targetPort, database);

        // ── 5. Connect to real SQL Server ──────────────────────────────────────────────────────
        TcpClient? targetClient = null;
        try
        {
            targetClient = new TcpClient();
            targetClient.NoDelay = true;
            await targetClient.ConnectAsync(targetIp, targetPort, ct);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "SQL session: cannot connect to {TargetIp}:{TargetPort}", targetIp, targetPort);
            targetClient?.Dispose();
            await SendLoginErrorAsync(clientStream, $"Cannot connect to SQL Server at '{targetHost}'.", ct);
            return;
        }

        var sessionId = Guid.NewGuid().ToString("N");
        await using var queryLogger = await SqlQueryLogger.CreateAsync(_opts.QueryLogDirectory, sessionId);

        using (targetClient)
        await using (var targetStream = targetClient.GetStream())
        {
            // ── 5a. PreLogin with target ───────────────────────────────────────────────
            var targetPreLoginReq = TdsPreLogin.BuildRequestNotSup();
            await TdsPacket.WritePacketAsync(targetStream, TdsPacket.TypePreLogin, targetPreLoginReq, ct);

            var targetPreLoginResp = await TdsPacket.ReadMessageAsync(targetStream, ct);
            if (targetPreLoginResp == null)
            {
                _log.LogError("SQL session {SessionId}: target {TargetIp} did not respond to PreLogin", sessionId, targetIp);
                await SendLoginErrorAsync(clientStream, "SQL Server did not respond to connection handshake.", ct);
                return;
            }

            var targetEncryption = TdsPreLogin.ParseEncryption(targetPreLoginResp.Value.fullPayload);
            if (targetEncryption == TdsPreLogin.EncryptReq)
            {
                _log.LogError("SQL session {SessionId}: target {TargetIp} requires TLS — plaintext not allowed", sessionId, targetIp);
                await SendLoginErrorAsync(clientStream, $"Target SQL Server '{targetHost}' requires encryption. Configure 'Force Encryption=No' on the target instance for PAM proxy access.", ct);
                return;
            }

            // ── 5b. Login7 with vault credentials to target ───────────────────────────────────────────
            var vaultLogin7 = TdsLogin7.BuildWithCredentials(
                loginPayload, sqlUser, sqlPassword,
                targetServerName: targetIp,
                targetDatabase:   string.IsNullOrEmpty(database) ? null : database);

            await TdsPacket.WritePacketAsync(targetStream, TdsPacket.TypeLogin7, vaultLogin7, ct);

            // Zero vault password from memory
            Array.Clear(vaultLogin7, 0, vaultLogin7.Length);

            // ── 6. Forward target's login response to client ──────────────────────────────────────────────
            var loginAck = await TdsPacket.ReadMessageAsync(targetStream, ct);
            if (loginAck == null)
            {
                _log.LogError("SQL session {SessionId}: no login response from target", sessionId);
                await SendLoginErrorAsync(clientStream, "SQL Server login timeout.", ct);
                return;
            }

            // Forward the raw login-ack packets verbatim to client
            foreach (var rawPkt in loginAck.Value.rawPackets)
                await clientStream.WriteAsync(rawPkt, ct);

            _log.LogInformation("SQL session {SessionId} established: {PamUser}→{TargetIp}:{TargetPort} db={Db}",
                sessionId, pamUser, targetIp, targetPort, database);

            var (idleTimeoutMinutes, _) = await _api.GetSessionPolicyAsync(ct);
            var startTime = DateTimeOffset.UtcNow;

            // ── 7 & 8. Relay + inspect ───────────────────────────────────────────────────────────────────────────────────
            try
            {
                await RelayAsync(clientStream, targetStream, sessionId, pamUser,
                    targetHost, database, queryLogger, ct, idleTimeoutMinutes);
            }
            catch (OperationCanceledException) { }
            catch (Exception ex) when (ex is IOException or SocketException)
            {
                _log.LogDebug("SQL session {SessionId}: client disconnected", sessionId);
            }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "SQL session {SessionId}: relay error", sessionId);
            }

            var duration = (int)(DateTimeOffset.UtcNow - startTime).TotalSeconds;
            _log.LogInformation("SQL session {SessionId} ended — duration {Sec}s user={PamUser}",
                sessionId, duration, pamUser);

            _ = _api.ReportSessionEndedAsync(sessionId, duration,
                queryLogger.FilePath ?? "", CancellationToken.None);
        }
    }

    // ── Relay loop ──────────────────────────────────────────────────────────────────────────────

    private async Task RelayAsync(
        NetworkStream clientStream,
        NetworkStream targetStream,
        string sessionId,
        string pamUser,
        string targetHost,
        string database,
        SqlQueryLogger queryLogger,
        CancellationToken ct,
        int idleTimeoutMinutes)
    {
        long[] lastActivityTicks = [DateTime.UtcNow.Ticks];
        using var idleCts = CancellationTokenSource.CreateLinkedTokenSource(ct);

        var clientToTarget = ClientPumpAsync(
            clientStream, targetStream, sessionId, pamUser, targetHost, database,
            queryLogger, idleCts, lastActivityTicks);

        var targetToClient = PumpRawAsync(targetStream, clientStream, idleCts.Token, lastActivityTicks);
        var idleWatcher    = IdleWatchAsync(idleTimeoutMinutes, lastActivityTicks, idleCts);

        await Task.WhenAny(clientToTarget, targetToClient, idleWatcher);
        await idleCts.CancelAsync();
        // Await both pumps to let them exit cleanly
        try { await Task.WhenAll(clientToTarget, targetToClient); }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is IOException or SocketException) { }
    }

    /// <summary>Client→target pump: inspects SQL Batch packets for DDL blocking and query logging.</summary>
    private async Task ClientPumpAsync(
        NetworkStream src,
        NetworkStream dst,
        string sessionId,
        string pamUser,
        string targetHost,
        string database,
        SqlQueryLogger queryLogger,
        CancellationTokenSource idleCts,
        long[] lastActivityTicks)
    {
        var ct = idleCts.Token;
        try
        {
            while (!ct.IsCancellationRequested)
            {
                var msg = await TdsPacket.ReadMessageAsync(src, ct);
                if (msg == null) break;

                Interlocked.Exchange(ref lastActivityTicks[0], DateTime.UtcNow.Ticks);

                if (msg.Value.type == TdsPacket.TypeSqlBatch)
                {
                    var sql = ExtractSqlText(msg.Value.fullPayload);

                    if (_opts.BlockDangerousDdl && IsDangerousDdl(sql))
                    {
                        queryLogger.LogQuery(sessionId, pamUser, targetHost, database, sql, blocked: true);
                        _log.LogWarning("SQL session: DDL blocked for {PamUser} — '{Sql}'",
                            pamUser, sql.Length > 100 ? sql[..100] + "..." : sql);
                        await SendDdlBlockedErrorAsync(src, ct);
                        continue; // do NOT forward to target
                    }

                    queryLogger.LogQuery(sessionId, pamUser, targetHost, database, sql, blocked: false);
                }

                // Forward all raw packets to target
                foreach (var rawPkt in msg.Value.rawPackets)
                    await dst.WriteAsync(rawPkt, ct);
            }
        }
        catch (OperationCanceledException) { }
    }

    /// <summary>Target→client pump: raw relay with idle tracking.</summary>
    private static async Task PumpRawAsync(Stream src, Stream dst, CancellationToken ct, long[] lastActivityTicks)
    {
        var buf = new byte[65536];
        try
        {
            while (!ct.IsCancellationRequested)
            {
                int read = await src.ReadAsync(buf, ct);
                if (read == 0) break;
                Interlocked.Exchange(ref lastActivityTicks[0], DateTime.UtcNow.Ticks);
                await dst.WriteAsync(buf.AsMemory(0, read), ct);
            }
        }
        catch (OperationCanceledException) { }
    }

    private static async Task IdleWatchAsync(int timeoutMinutes, long[] lastActivityTicks,
        CancellationTokenSource cts)
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
                    await cts.CancelAsync();
                    return;
                }
            }
        }
        catch (OperationCanceledException) { }
    }

    // ── SQL text extraction ────────────────────────────────────────────────────────────────────────────

    private static string ExtractSqlText(byte[] payload)
    {
        if (payload.Length < 2) return "";

        // TDS 7.3+ SQL Batch may start with AllHeaders:
        //   TotalLength(4) [transaction descriptor headers...]
        // We detect this by checking if the first 4 bytes (LE uint32) are a plausible header size
        int offset = 0;
        if (payload.Length >= 4)
        {
            uint totalHeaderLen = BitConverter.ToUInt32(payload, 0);
            if (totalHeaderLen >= 4 && totalHeaderLen < payload.Length)
                offset = (int)totalHeaderLen;
        }

        // Remaining bytes are UCS-2 LE SQL text
        if (offset >= payload.Length || (payload.Length - offset) < 2) return "";

        // Ensure we have an even number of bytes for UCS-2
        int byteCount = payload.Length - offset;
        if (byteCount % 2 != 0) byteCount--;

        return Ucs2Le.GetString(payload, offset, byteCount).Trim();
    }

    // ── DDL blocking ─────────────────────────────────────────────────────────────────────────────

    private static readonly System.Text.RegularExpressions.Regex LeadingBlockComment =
        new(@"^(/\*.*?\*/\s*)+", System.Text.RegularExpressions.RegexOptions.Singleline | System.Text.RegularExpressions.RegexOptions.Compiled);

    private static bool IsDangerousDdl(string sql)
    {
        if (string.IsNullOrWhiteSpace(sql)) return false;

        // XP_CMDSHELL check is global — present anywhere in the query
        if (sql.Contains(BlockedSubstring, StringComparison.OrdinalIgnoreCase)) return true;

        // Check every semicolon-separated statement individually to prevent multi-statement bypass
        foreach (var segment in sql.Split(';', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
        {
            // Strip leading block comments (/* ... */) before prefix matching
            var stripped = LeadingBlockComment.Replace(segment.ToUpperInvariant(), "").TrimStart();

            foreach (var prefix in BlockedPrefixes)
                if (stripped.StartsWith(prefix, StringComparison.Ordinal)) return true;
        }

        return false;
    }

    // ── TDS error responses ──────────────────────────────────────────────────────────────────────────────────────

    /// <summary>
    /// Send a TDS login failure (Error token 0xAA + Done token 0xFD) to the client.
    /// </summary>
    private static async Task SendLoginErrorAsync(NetworkStream stream, string message, CancellationToken ct)
    {
        try
        {
            var payload = BuildErrorResponse(message, isFatal: true);
            // Tabular result packet (0x04) — standard container for TDS error tokens
            await TdsPacket.WritePacketAsync(stream, 0x04, payload, ct);
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Send a non-fatal DDL-blocked error to the client while keeping the connection open.
    /// </summary>
    private static async Task SendDdlBlockedErrorAsync(NetworkStream stream, CancellationToken ct)
    {
        try
        {
            var msg = "Statement blocked by OrkunPAM policy: dangerous DDL is not permitted in privileged sessions. Contact your DBA or raise a PAM approval request.";
            var payload = BuildErrorResponse(msg, isFatal: false);
            await TdsPacket.WritePacketAsync(stream, 0x04, payload, ct);
        }
        catch { /* best-effort */ }
    }

    /// <summary>
    /// Build the binary payload for a TDS Error token (0xAA) followed by a Done token (0xFD).
    /// </summary>
    private static byte[] BuildErrorResponse(string message, bool isFatal)
    {
        const string serverName = "OrkunPAM";
        const int errorNumber   = 18456; // Standard SQL login failed error number

        var msgBytes    = Ucs2Le.GetBytes(message);
        var srvBytes    = Ucs2Le.GetBytes(serverName);

        // ErrorToken (0xAA):
        //   TokenType(1) Length(2) Number(4) State(1) Class(1)
        //   cchMsgText(2) MsgText(N*2) cchServerName(1) ServerName(M*2) cchProcName(1) LineNumber(4)
        int errorTokenBodyLen = 4 + 1 + 1 + 2 + msgBytes.Length + 1 + srvBytes.Length + 1 + 4;
        // DoneToken (0xFD): marker(1) Status(2) CurCmd(2) DoneRowCount(8) = 13 bytes
        const int doneTokenLen = 13;

        var buf = new byte[3 + errorTokenBodyLen + doneTokenLen];
        int pos = 0;

        // ErrorToken header
        buf[pos++] = 0xAA; // token type
        buf[pos++] = (byte)(errorTokenBodyLen & 0xFF);
        buf[pos++] = (byte)(errorTokenBodyLen >> 8);

        // Number (error code)
        BitConverter.GetBytes(errorNumber).CopyTo(buf, pos); pos += 4;

        // State
        buf[pos++] = 1;

        // Severity class: 18 = fatal login, 14 = non-fatal user error
        buf[pos++] = isFatal ? (byte)18 : (byte)14;

        // Message
        BitConverter.GetBytes((short)(message.Length)).CopyTo(buf, pos); pos += 2;
        msgBytes.CopyTo(buf, pos); pos += msgBytes.Length;

        // Server name
        buf[pos++] = (byte)serverName.Length;
        srvBytes.CopyTo(buf, pos); pos += srvBytes.Length;

        // Proc name (empty)
        buf[pos++] = 0;

        // Line number
        BitConverter.GetBytes(1).CopyTo(buf, pos); pos += 4;

        // DoneToken (0xFD): marker + status + curCmd + 8 bytes rowcount (zeroed)
        buf[pos++] = 0xFD;
        // Status: 0x0001 = error
        buf[pos++] = 0x01; buf[pos++] = 0x00;
        // CurCmd: 0x00C1 (SQL Batch)
        buf[pos++] = 0xC1; buf[pos++] = 0x00;
        // DoneRowCount (8 bytes) = 0, already zeroed by new byte[]

        return buf;
    }
}
