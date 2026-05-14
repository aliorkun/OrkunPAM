using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Native PostgreSQL protocol (v3) password rotator.
/// Implements StartupMessage, handles MD5 and cleartext authentication,
/// then executes ALTER ROLE to change the password.
/// No Npgsql or any third-party package — raw TCP only.
/// </summary>
public sealed class PostgreSqlPasswordRotator : IPasswordRotator
{
    private const int DefaultPort = 5432;
    private const int ConnectTimeoutMs = 10_000;
    private const int ReadTimeoutMs = 15_000;

    private readonly ILogger<PostgreSqlPasswordRotator> _logger;

    public PostgreSqlPasswordRotator(ILogger<PostgreSqlPasswordRotator> logger)
    {
        _logger = logger;
    }

    public RotationConnector ConnectorType => RotationConnector.PostgreSql;

    public async Task<RotationResult> RotatePasswordAsync(RotationTarget target, CancellationToken ct)
    {
        var port = target.Port > 0 ? target.Port : DefaultPort;
        _logger.LogInformation("PostgreSQL rotation starting for {User}@{Host}:{Port}",
            target.Username, target.Host, port);

        try
        {
            using var tcp = new TcpClient();
            var connectTask = tcp.ConnectAsync(target.Host, port, ct).AsTask();
            if (await Task.WhenAny(connectTask, Task.Delay(ConnectTimeoutMs, ct)) != connectTask)
                return new RotationResult(false, $"Connection timeout to {target.Host}:{port}", "PostgreSQL");
            await connectTask;

            using var stream = tcp.GetStream();
            stream.ReadTimeout = ReadTimeoutMs;
            stream.WriteTimeout = ReadTimeoutMs;

            // 1. Send StartupMessage (protocol v3.0)
            var startupParams = new Dictionary<string, string>
            {
                ["user"] = target.Username,
                ["client_encoding"] = "UTF8"
            };
            if (!string.IsNullOrEmpty(target.DatabaseName))
                startupParams["database"] = target.DatabaseName;

            await SendStartupMessageAsync(stream, startupParams, ct);

            // 2. Handle authentication
            var authResult = await HandleAuthenticationAsync(stream, target, ct);
            if (!authResult.Success)
                return authResult;

            // 3. Read until ReadyForQuery ('Z')
            if (!await WaitForReadyAsync(stream, ct))
                return new RotationResult(false, "PostgreSQL server did not become ready after auth", "PostgreSQL");

            _logger.LogDebug("PostgreSQL authenticated for {User}@{Host}", target.Username, target.Host);

            // 4. Execute ALTER ROLE to change password
            // Use dollar-quoting to avoid SQL injection with special characters
            var tag = $"$$";
            var alterSql = $"ALTER ROLE \"{target.Username}\" WITH PASSWORD {tag}{target.NewPassword}{tag}";
            await SendQueryAsync(stream, alterSql, ct);

            // Zero the SQL string from memory
            var alterBytes = Encoding.UTF8.GetBytes(alterSql);
            CryptographicOperations.ZeroMemory(alterBytes);

            // Read query result
            var queryOk = await ReadQueryResultAsync(stream, ct);
            if (!queryOk.ok)
                return new RotationResult(false, $"ALTER ROLE failed: {queryOk.error}", "PostgreSQL");

            _logger.LogInformation("PostgreSQL password rotation succeeded for {User}@{Host}",
                target.Username, target.Host);

            return new RotationResult(true, "Password changed via PostgreSQL native protocol", "PostgreSQL");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "PostgreSQL rotation failed for {User}@{Host}", target.Username, target.Host);
            return new RotationResult(false, $"PostgreSQL rotation error: {ex.Message}", "PostgreSQL");
        }
    }

    // --- PostgreSQL v3 protocol helpers ---

    private static async Task SendStartupMessageAsync(
        NetworkStream stream, Dictionary<string, string> parameters, CancellationToken ct)
    {
        using var ms = new MemoryStream();
        // Length placeholder (4 bytes)
        ms.Write(new byte[4]);
        // Protocol version 3.0
        WriteBigEndianInt32(ms, 196608); // 3 << 16 | 0
        // Parameters
        foreach (var (key, value) in parameters)
        {
            ms.Write(Encoding.UTF8.GetBytes(key));
            ms.WriteByte(0);
            ms.Write(Encoding.UTF8.GetBytes(value));
            ms.WriteByte(0);
        }
        ms.WriteByte(0); // terminator

        var data = ms.ToArray();
        // Write length at offset 0
        BinaryPrimitives.WriteInt32BigEndian(data.AsSpan(0), data.Length);

        await stream.WriteAsync(data, ct);
        await stream.FlushAsync(ct);
    }

    private async Task<RotationResult> HandleAuthenticationAsync(
        NetworkStream stream, RotationTarget target, CancellationToken ct)
    {
        while (true)
        {
            var (msgType, payload) = await ReadMessageAsync(stream, ct);

            switch (msgType)
            {
                case (byte)'R': // Authentication
                    if (payload.Length < 4)
                        return new RotationResult(false, "Invalid auth message from PostgreSQL", "PostgreSQL");

                    var authType = BinaryPrimitives.ReadInt32BigEndian(payload.AsSpan(0));

                    switch (authType)
                    {
                        case 0: // AuthenticationOk
                            return new RotationResult(true, "Authenticated", "PostgreSQL");

                        case 3: // AuthenticationCleartextPassword
                            await SendPasswordMessageAsync(stream, target.CurrentPassword ?? "", ct);
                            break;

                        case 5: // AuthenticationMD5Password
                            if (payload.Length < 8)
                                return new RotationResult(false, "Invalid MD5 auth: missing salt", "PostgreSQL");
                            var salt = payload.AsSpan(4, 4).ToArray();
                            var md5Response = ComputeMd5Password(target.Username, target.CurrentPassword ?? "", salt);
                            await SendPasswordMessageAsync(stream, md5Response, ct);
                            CryptographicOperations.ZeroMemory(salt);
                            break;

                        case 10: // AuthenticationSASL (SCRAM-SHA-256)
                            return new RotationResult(false,
                                "SCRAM-SHA-256 authentication not yet supported in native rotator. " +
                                "Configure PostgreSQL pg_hba.conf to use md5 or password for the PAM service account.",
                                "PostgreSQL");

                        default:
                            return new RotationResult(false,
                                $"Unsupported PostgreSQL auth method: {authType}", "PostgreSQL");
                    }
                    break;

                case (byte)'E': // ErrorResponse
                    var error = ParseErrorResponse(payload);
                    return new RotationResult(false, $"PostgreSQL auth error: {error}", "PostgreSQL");

                default:
                    // Skip other messages during auth phase
                    break;
            }
        }
    }

    private static async Task SendPasswordMessageAsync(NetworkStream stream, string password, CancellationToken ct)
    {
        var pwdBytes = Encoding.UTF8.GetBytes(password);
        var length = 4 + pwdBytes.Length + 1;

        var packet = new byte[1 + length];
        packet[0] = (byte)'p';
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(1), length);
        pwdBytes.CopyTo(packet.AsSpan(5));
        packet[^1] = 0; // null terminator

        await stream.WriteAsync(packet, ct);
        await stream.FlushAsync(ct);

        CryptographicOperations.ZeroMemory(pwdBytes);
        CryptographicOperations.ZeroMemory(packet);
    }

    private static async Task SendQueryAsync(NetworkStream stream, string sql, CancellationToken ct)
    {
        var sqlBytes = Encoding.UTF8.GetBytes(sql);
        var length = 4 + sqlBytes.Length + 1;

        var packet = new byte[1 + length];
        packet[0] = (byte)'Q';
        BinaryPrimitives.WriteInt32BigEndian(packet.AsSpan(1), length);
        sqlBytes.CopyTo(packet.AsSpan(5));
        packet[^1] = 0;

        await stream.WriteAsync(packet, ct);
        await stream.FlushAsync(ct);

        CryptographicOperations.ZeroMemory(sqlBytes);
        CryptographicOperations.ZeroMemory(packet);
    }

    private static async Task<(byte msgType, byte[] payload)> ReadMessageAsync(
        NetworkStream stream, CancellationToken ct)
    {
        // Read type (1 byte) + length (4 bytes)
        var header = new byte[5];
        int read = 0;
        while (read < 5)
        {
            int n = await stream.ReadAsync(header.AsMemory(read, 5 - read), ct);
            if (n == 0) throw new IOException("PostgreSQL connection closed during message read");
            read += n;
        }

        byte msgType = header[0];
        int length = BinaryPrimitives.ReadInt32BigEndian(header.AsSpan(1));
        int payloadLength = length - 4;

        byte[] payload;
        if (payloadLength > 0)
        {
            payload = new byte[payloadLength];
            read = 0;
            while (read < payloadLength)
            {
                int n = await stream.ReadAsync(payload.AsMemory(read, payloadLength - read), ct);
                if (n == 0) throw new IOException("PostgreSQL connection closed during payload read");
                read += n;
            }
        }
        else
        {
            payload = [];
        }

        return (msgType, payload);
    }

    private static async Task<bool> WaitForReadyAsync(NetworkStream stream, CancellationToken ct)
    {
        for (int i = 0; i < 50; i++) // max 50 messages before ready
        {
            var (msgType, payload) = await ReadMessageAsync(stream, ct);

            if (msgType == (byte)'Z') // ReadyForQuery
                return true;

            if (msgType == (byte)'E') // ErrorResponse
                return false;

            // Skip parameter status ('S'), backend key data ('K'), notice ('N'), etc.
        }
        return false;
    }

    private static async Task<(bool ok, string? error)> ReadQueryResultAsync(
        NetworkStream stream, CancellationToken ct)
    {
        string? error = null;
        bool gotCommand = false;

        for (int i = 0; i < 50; i++)
        {
            var (msgType, payload) = await ReadMessageAsync(stream, ct);

            switch (msgType)
            {
                case (byte)'C': // CommandComplete
                    gotCommand = true;
                    break;
                case (byte)'E': // ErrorResponse
                    error = ParseErrorResponse(payload);
                    break;
                case (byte)'Z': // ReadyForQuery
                    return (error == null && gotCommand, error);
            }
        }

        return (false, error ?? "Timeout waiting for query result");
    }

    private static string ComputeMd5Password(string username, string password, byte[] salt)
    {
        // md5(md5(password + username) + salt)
        var innerBytes = Encoding.UTF8.GetBytes(password + username);
        var innerHash = MD5.HashData(innerBytes);
        var innerHex = Convert.ToHexString(innerHash).ToLowerInvariant();

        var outerBytes = new byte[innerHex.Length + salt.Length];
        Encoding.UTF8.GetBytes(innerHex).CopyTo(outerBytes, 0);
        salt.CopyTo(outerBytes, innerHex.Length);
        var outerHash = MD5.HashData(outerBytes);

        CryptographicOperations.ZeroMemory(innerBytes);
        CryptographicOperations.ZeroMemory(innerHash);
        CryptographicOperations.ZeroMemory(outerBytes);

        return "md5" + Convert.ToHexString(outerHash).ToLowerInvariant();
    }

    private static string ParseErrorResponse(byte[] payload)
    {
        var sb = new StringBuilder();
        int pos = 0;
        while (pos < payload.Length)
        {
            byte fieldType = payload[pos++];
            if (fieldType == 0) break;

            int start = pos;
            while (pos < payload.Length && payload[pos] != 0) pos++;
            var value = Encoding.UTF8.GetString(payload, start, pos - start);
            if (pos < payload.Length) pos++;

            switch ((char)fieldType)
            {
                case 'S': sb.Append($"Severity={value} "); break;
                case 'M': sb.Append($"Message={value} "); break;
                case 'C': sb.Append($"Code={value} "); break;
                case 'D': sb.Append($"Detail={value} "); break;
            }
        }
        return sb.ToString().TrimEnd();
    }

    private static void WriteBigEndianInt32(MemoryStream ms, int value)
    {
        var buf = new byte[4];
        BinaryPrimitives.WriteInt32BigEndian(buf, value);
        ms.Write(buf);
    }
}
