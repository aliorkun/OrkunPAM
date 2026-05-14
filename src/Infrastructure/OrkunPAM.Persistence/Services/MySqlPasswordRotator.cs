using System.Buffers.Binary;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Native MySQL protocol password rotator.
/// Implements the MySQL client/server handshake (v10 greeting), performs
/// secure password authentication, then executes ALTER USER to change the password.
/// No third-party MySQL packages — raw TCP only.
/// </summary>
public sealed class MySqlPasswordRotator : IPasswordRotator
{
    private const int DefaultPort = 3306;
    private const int ConnectTimeoutMs = 10_000;
    private const int ReadTimeoutMs = 15_000;

    private readonly ILogger<MySqlPasswordRotator> _logger;

    public MySqlPasswordRotator(ILogger<MySqlPasswordRotator> logger)
    {
        _logger = logger;
    }

    public RotationConnector ConnectorType => RotationConnector.MySql;

    public async Task<RotationResult> RotatePasswordAsync(RotationTarget target, CancellationToken ct)
    {
        var port = target.Port > 0 ? target.Port : DefaultPort;
        _logger.LogInformation("MySQL rotation starting for {User}@{Host}:{Port}",
            target.Username, target.Host, port);

        byte[]? authData = null;
        try
        {
            using var tcp = new TcpClient();
            var connectTask = tcp.ConnectAsync(target.Host, port, ct).AsTask();
            if (await Task.WhenAny(connectTask, Task.Delay(ConnectTimeoutMs, ct)) != connectTask)
                return new RotationResult(false, $"Connection timeout to {target.Host}:{port}", "MySQL");
            await connectTask; // propagate exception if any

            using var stream = tcp.GetStream();
            stream.ReadTimeout = ReadTimeoutMs;
            stream.WriteTimeout = ReadTimeoutMs;

            // 1. Read server greeting (HandshakeV10)
            var greeting = await ReadPacketAsync(stream, ct);
            if (greeting.Length < 4)
                return new RotationResult(false, "Invalid MySQL greeting packet", "MySQL");

            var protocolVersion = greeting[0];
            if (protocolVersion != 10)
                return new RotationResult(false, $"Unsupported MySQL protocol version: {protocolVersion}", "MySQL");

            // Parse greeting
            int pos = 1;
            var serverVersion = ReadNullTermString(greeting, ref pos);
            var connectionId = BinaryPrimitives.ReadUInt32LittleEndian(greeting.AsSpan(pos));
            pos += 4;

            // auth-plugin-data-part-1 (8 bytes)
            var authPluginData1 = greeting.AsSpan(pos, 8).ToArray();
            pos += 8;
            pos++; // filler

            var capFlags1 = BinaryPrimitives.ReadUInt16LittleEndian(greeting.AsSpan(pos));
            pos += 2;

            byte charset = 0;
            uint capFlags = capFlags1;
            int authPluginDataLen = 8;
            byte[] authPluginData2 = [];
            string authPlugin = "mysql_native_password";

            if (pos < greeting.Length)
            {
                charset = greeting[pos++];
                var statusFlags = BinaryPrimitives.ReadUInt16LittleEndian(greeting.AsSpan(pos));
                pos += 2;
                var capFlags2 = BinaryPrimitives.ReadUInt16LittleEndian(greeting.AsSpan(pos));
                pos += 2;
                capFlags = capFlags1 | ((uint)capFlags2 << 16);

                authPluginDataLen = greeting[pos++];
                pos += 10; // reserved

                // auth-plugin-data-part-2
                if (authPluginDataLen > 8)
                {
                    int part2Len = Math.Max(13, authPluginDataLen - 8);
                    if (pos + part2Len <= greeting.Length)
                    {
                        authPluginData2 = greeting.AsSpan(pos, part2Len).ToArray();
                        pos += part2Len;
                    }
                }

                // auth plugin name
                if (pos < greeting.Length)
                    authPlugin = ReadNullTermString(greeting, ref pos);
            }

            // Combine auth data (scramble)
            var scramble = new byte[authPluginData1.Length + authPluginData2.Length];
            authPluginData1.CopyTo(scramble, 0);
            authPluginData2.CopyTo(scramble, authPluginData1.Length);
            // Trim trailing null if present
            int scrambleLen = scramble.Length;
            if (scrambleLen > 0 && scramble[scrambleLen - 1] == 0) scrambleLen--;
            scramble = scramble[..scrambleLen];

            // 2. Send HandshakeResponse41
            authData = ComputeAuthResponse(authPlugin, target.CurrentPassword ?? "", scramble);

            var response = BuildHandshakeResponse(
                target.Username, authData, target.DatabaseName, authPlugin, charset, capFlags);
            await WritePacketAsync(stream, response, 1, ct);

            // 3. Read auth result
            var authResult = await ReadPacketAsync(stream, ct);
            if (authResult.Length == 0)
                return new RotationResult(false, "Empty auth response from MySQL server", "MySQL");

            // Handle auth switch request
            if (authResult[0] == 0xFE) // auth switch
            {
                int switchPos = 1;
                var newPlugin = ReadNullTermString(authResult, ref switchPos);
                var newScramble = authResult.AsSpan(switchPos).TrimEnd((byte)0).ToArray();

                CryptographicOperations.ZeroMemory(authData);
                authData = ComputeAuthResponse(newPlugin, target.CurrentPassword ?? "", newScramble);
                await WritePacketAsync(stream, authData, 3, ct);

                authResult = await ReadPacketAsync(stream, ct);
            }

            if (authResult[0] == 0xFF) // ERR
            {
                var errMsg = ParseErrorPacket(authResult);
                return new RotationResult(false, $"MySQL auth failed: {errMsg}", "MySQL");
            }
            if (authResult[0] != 0x00) // not OK
                return new RotationResult(false, $"Unexpected MySQL auth response: 0x{authResult[0]:X2}", "MySQL");

            _logger.LogDebug("MySQL authenticated, server v{Version}, conn#{ConnId}",
                serverVersion, connectionId);

            // 4. Execute ALTER USER to change password
            var escapedUser = target.Username.Replace("'", "\\'");
            var escapedNewPwd = target.NewPassword.Replace("'", "\\'");
            var alterSql = $"ALTER USER '{escapedUser}'@'%' IDENTIFIED BY '{escapedNewPwd}'";
            var alterBytes = Encoding.UTF8.GetBytes(alterSql);

            // COM_QUERY = 0x03
            var queryPacket = new byte[1 + alterBytes.Length];
            queryPacket[0] = 0x03;
            alterBytes.CopyTo(queryPacket, 1);

            await WritePacketAsync(stream, queryPacket, 0, ct);

            var queryResult = await ReadPacketAsync(stream, ct);
            // Zero the query packet containing the new password
            CryptographicOperations.ZeroMemory(queryPacket);
            CryptographicOperations.ZeroMemory(alterBytes);

            if (queryResult.Length > 0 && queryResult[0] == 0xFF)
            {
                var errMsg = ParseErrorPacket(queryResult);
                // If '%' host fails, try 'localhost'
                if (errMsg.Contains("does not exist", StringComparison.OrdinalIgnoreCase))
                {
                    var alterSql2 = $"ALTER USER '{escapedUser}'@'localhost' IDENTIFIED BY '{escapedNewPwd}'";
                    var alterBytes2 = Encoding.UTF8.GetBytes(alterSql2);
                    var queryPacket2 = new byte[1 + alterBytes2.Length];
                    queryPacket2[0] = 0x03;
                    alterBytes2.CopyTo(queryPacket2, 1);

                    await WritePacketAsync(stream, queryPacket2, 0, ct);
                    var result2 = await ReadPacketAsync(stream, ct);

                    CryptographicOperations.ZeroMemory(queryPacket2);
                    CryptographicOperations.ZeroMemory(alterBytes2);

                    if (result2.Length > 0 && result2[0] == 0xFF)
                    {
                        var errMsg2 = ParseErrorPacket(result2);
                        return new RotationResult(false, $"MySQL ALTER USER failed: {errMsg2}", "MySQL");
                    }
                }
                else
                {
                    return new RotationResult(false, $"MySQL ALTER USER failed: {errMsg}", "MySQL");
                }
            }

            // 5. Flush privileges
            var flushBytes = Encoding.UTF8.GetBytes("FLUSH PRIVILEGES");
            var flushPacket = new byte[1 + flushBytes.Length];
            flushPacket[0] = 0x03;
            flushBytes.CopyTo(flushPacket, 1);
            await WritePacketAsync(stream, flushPacket, 0, ct);
            await ReadPacketAsync(stream, ct); // consume result

            _logger.LogInformation("MySQL password rotation succeeded for {User}@{Host}",
                target.Username, target.Host);

            return new RotationResult(true, "Password changed via MySQL native protocol", "MySQL");
        }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            _logger.LogError(ex, "MySQL rotation failed for {User}@{Host}", target.Username, target.Host);
            return new RotationResult(false, $"MySQL rotation error: {ex.Message}", "MySQL");
        }
        finally
        {
            if (authData != null) CryptographicOperations.ZeroMemory(authData);
        }
    }

    // --- MySQL protocol helpers ---

    private static byte[] ComputeAuthResponse(string plugin, string password, byte[] scramble)
    {
        if (string.IsNullOrEmpty(password))
            return [];

        if (plugin is "mysql_native_password")
        {
            // SHA1(password) XOR SHA1(scramble + SHA1(SHA1(password)))
            var passHash = SHA1.HashData(Encoding.UTF8.GetBytes(password));
            var doubleHash = SHA1.HashData(passHash);

            var combined = new byte[scramble.Length + doubleHash.Length];
            scramble.CopyTo(combined, 0);
            doubleHash.CopyTo(combined, scramble.Length);
            var scrambleHash = SHA1.HashData(combined);

            var result = new byte[passHash.Length];
            for (int i = 0; i < result.Length; i++)
                result[i] = (byte)(passHash[i] ^ scrambleHash[i]);

            CryptographicOperations.ZeroMemory(passHash);
            CryptographicOperations.ZeroMemory(doubleHash);
            CryptographicOperations.ZeroMemory(combined);
            CryptographicOperations.ZeroMemory(scrambleHash);

            return result;
        }

        if (plugin is "caching_sha2_password")
        {
            // SHA256(password) XOR SHA256(SHA256(SHA256(password)) + scramble)
            var passBytes = Encoding.UTF8.GetBytes(password);
            var passHash = SHA256.HashData(passBytes);
            var doubleHash = SHA256.HashData(passHash);

            var combined = new byte[doubleHash.Length + scramble.Length];
            doubleHash.CopyTo(combined, 0);
            scramble.CopyTo(combined, doubleHash.Length);
            var scrambleHash = SHA256.HashData(combined);

            var result = new byte[passHash.Length];
            for (int i = 0; i < result.Length; i++)
                result[i] = (byte)(passHash[i] ^ scrambleHash[i]);

            CryptographicOperations.ZeroMemory(passBytes);
            CryptographicOperations.ZeroMemory(passHash);
            CryptographicOperations.ZeroMemory(doubleHash);
            CryptographicOperations.ZeroMemory(combined);
            CryptographicOperations.ZeroMemory(scrambleHash);

            return result;
        }

        throw new NotSupportedException($"MySQL auth plugin '{plugin}' not supported");
    }

    private static byte[] BuildHandshakeResponse(
        string username, byte[] authData, string? database, string authPlugin,
        byte charset, uint serverCaps)
    {
        // CLIENT_PROTOCOL_41 | CLIENT_SECURE_CONNECTION | CLIENT_PLUGIN_AUTH
        uint clientCaps = 0x00000200 | 0x00008000 | 0x00080000;
        if (!string.IsNullOrEmpty(database))
            clientCaps |= 0x00000008; // CLIENT_CONNECT_WITH_DB

        using var ms = new MemoryStream();
        // capability flags
        var buf4 = new byte[4];
        BinaryPrimitives.WriteUInt32LittleEndian(buf4, clientCaps);
        ms.Write(buf4);
        // max packet size
        BinaryPrimitives.WriteUInt32LittleEndian(buf4, 16 * 1024 * 1024);
        ms.Write(buf4);
        // charset (utf8mb4 = 45, fallback to server charset)
        ms.WriteByte(charset > 0 ? charset : (byte)45);
        // reserved 23 bytes
        ms.Write(new byte[23]);
        // username (null-terminated)
        ms.Write(Encoding.UTF8.GetBytes(username));
        ms.WriteByte(0);
        // auth response (length-encoded)
        ms.WriteByte((byte)authData.Length);
        ms.Write(authData);
        // database (if any)
        if (!string.IsNullOrEmpty(database))
        {
            ms.Write(Encoding.UTF8.GetBytes(database));
            ms.WriteByte(0);
        }
        // auth plugin name
        ms.Write(Encoding.UTF8.GetBytes(authPlugin));
        ms.WriteByte(0);

        return ms.ToArray();
    }

    private static async Task<byte[]> ReadPacketAsync(NetworkStream stream, CancellationToken ct)
    {
        var header = new byte[4];
        int read = 0;
        while (read < 4)
        {
            int n = await stream.ReadAsync(header.AsMemory(read, 4 - read), ct);
            if (n == 0) throw new IOException("MySQL connection closed during packet header read");
            read += n;
        }

        int length = header[0] | (header[1] << 8) | (header[2] << 16);
        // sequence number is header[3]

        var payload = new byte[length];
        read = 0;
        while (read < length)
        {
            int n = await stream.ReadAsync(payload.AsMemory(read, length - read), ct);
            if (n == 0) throw new IOException("MySQL connection closed during packet payload read");
            read += n;
        }

        return payload;
    }

    private static async Task WritePacketAsync(NetworkStream stream, byte[] payload, byte seqNum, CancellationToken ct)
    {
        var header = new byte[4];
        header[0] = (byte)(payload.Length & 0xFF);
        header[1] = (byte)((payload.Length >> 8) & 0xFF);
        header[2] = (byte)((payload.Length >> 16) & 0xFF);
        header[3] = seqNum;

        await stream.WriteAsync(header, ct);
        await stream.WriteAsync(payload, ct);
        await stream.FlushAsync(ct);
    }

    private static string ReadNullTermString(byte[] data, ref int pos)
    {
        int start = pos;
        while (pos < data.Length && data[pos] != 0) pos++;
        var s = Encoding.UTF8.GetString(data, start, pos - start);
        if (pos < data.Length) pos++; // skip null
        return s;
    }

    private static string ParseErrorPacket(byte[] packet)
    {
        if (packet.Length < 3) return "Unknown error";
        int pos = 1;
        var errCode = BinaryPrimitives.ReadUInt16LittleEndian(packet.AsSpan(pos));
        pos += 2;
        // Skip SQL state marker '#' and 5-char state if present
        if (pos < packet.Length && packet[pos] == (byte)'#')
            pos += 6;
        var msg = Encoding.UTF8.GetString(packet, pos, packet.Length - pos);
        return $"#{errCode}: {msg}";
    }
}
