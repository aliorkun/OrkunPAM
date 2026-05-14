using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Cryptography;
using Microsoft.Data.SqlClient;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

public interface IRotationService
{
    Task<RotationResult> RotatePasswordAsync(RotationConnector connector, RotationTarget target, CancellationToken ct = default);
    string GeneratePassword(int length = 24, bool upper = true, bool lower = true, bool digits = true, bool special = true);
}

public sealed class RotationService : IRotationService
{
    private readonly ILogger<RotationService> _logger;

    public RotationService(ILogger<RotationService> logger)
    {
        _logger = logger;
    }

    public async Task<RotationResult> RotatePasswordAsync(RotationConnector connector, RotationTarget target, CancellationToken ct = default)
    {
        _logger.LogInformation("Password rotation started. Connector: {Connector}, Host: {Host}, User: {User}",
            connector, target.Host, target.Username);

        var sw = System.Diagnostics.Stopwatch.StartNew();

        var result = connector switch
        {
            RotationConnector.Ldap => await RotateViaLdapAsync(target, ct),
            RotationConnector.SqlServer => await RotateViaSqlServerAsync(target, ct),
            RotationConnector.MySql => await RotateViaMySqlAsync(target, ct),
            RotationConnector.PostgreSql => await RotateViaPostgreSqlAsync(target, ct),
            RotationConnector.WinRm => await RotateViaWinRmAsync(target, ct),
            RotationConnector.Ssh => await RotateViaSshAsync(target, ct),
            RotationConnector.Wmi => await RotateViaWmiAsync(target, ct),
            _ => new RotationResult(false, $"Connector '{connector}' not yet implemented", connector.ToString())
        };

        sw.Stop();

        if (result.Success)
            _logger.LogInformation("Password rotation succeeded for {User}@{Host} via {Connector} in {Ms}ms",
                target.Username, target.Host, connector, sw.ElapsedMilliseconds);
        else
            _logger.LogWarning("Password rotation failed for {User}@{Host} via {Connector}: {Error}",
                target.Username, target.Host, connector, result.Message);

        return result with { ResponseTimeMs = (int)sw.ElapsedMilliseconds };
    }

    public string GeneratePassword(int length = 24, bool upper = true, bool lower = true, bool digits = true, bool special = true)
    {
        var charSets = new List<string>();
        if (upper) charSets.Add("ABCDEFGHIJKLMNOPQRSTUVWXYZ");
        if (lower) charSets.Add("abcdefghijklmnopqrstuvwxyz");
        if (digits) charSets.Add("0123456789");
        if (special) charSets.Add("!@#$%^&*()-_=+[]{}|;:,.<>?");

        if (charSets.Count == 0) charSets.Add("abcdefghijklmnopqrstuvwxyz0123456789");
        var allChars = string.Concat(charSets);

        var password = new char[length];
        var randomBytes = RandomNumberGenerator.GetBytes(length);

        // Ensure at least one char from each set
        for (int i = 0; i < Math.Min(charSets.Count, length); i++)
        {
            password[i] = charSets[i][randomBytes[i] % charSets[i].Length];
        }

        // Fill remaining
        for (int i = charSets.Count; i < length; i++)
        {
            password[i] = allChars[randomBytes[i] % allChars.Length];
        }

        // Shuffle using Fisher-Yates
        var shuffleBytes = RandomNumberGenerator.GetBytes(length);
        for (int i = length - 1; i > 0; i--)
        {
            int j = shuffleBytes[i] % (i + 1);
            (password[i], password[j]) = (password[j], password[i]);
        }

        return new string(password);
    }

    private async Task<RotationResult> RotateViaLdapAsync(RotationTarget target, CancellationToken ct)
    {
        return await Task.Run(() =>
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(target.Host, target.Port);
                using var connection = new LdapConnection(identifier);
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.SecureSocketLayer = target.Port == 636;

                if (target.Port == 636)
                    connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;

                connection.AuthType = AuthType.Basic;
                connection.Credential = new NetworkCredential(target.Username, target.CurrentPassword, target.Domain);
                connection.Bind();

                // AD password change requires the unicodePwd attribute with quoted password in UTF-16LE
                var newPasswordBytes = System.Text.Encoding.Unicode.GetBytes($"\"{target.NewPassword}\"");
                var oldPasswordBytes = System.Text.Encoding.Unicode.GetBytes($"\"{target.CurrentPassword}\"");

                // Find user DN
                var baseDn = target.Domain != null
                    ? string.Join(",", target.Domain.Split('.').Select(p => $"DC={p}"))
                    : "";

                var searchRequest = new SearchRequest(baseDn,
                    $"(sAMAccountName={EscapeLdapFilterValue(target.Username)})", SearchScope.Subtree, "distinguishedName");
                var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                if (searchResponse.Entries.Count == 0)
                    return new RotationResult(false, $"User '{target.Username}' not found in directory", "LDAP");

                var userDn = searchResponse.Entries[0].DistinguishedName;

                // Modify password
                var modRequest = new ModifyRequest(userDn,
                    DirectoryAttributeOperation.Delete, "unicodePwd", oldPasswordBytes);
                modRequest.Modifications.Add(
                    new DirectoryAttributeModification
                    {
                        Name = "unicodePwd",
                        Operation = DirectoryAttributeOperation.Add
                    });
                modRequest.Modifications[1].Add(newPasswordBytes);

                connection.SendRequest(modRequest);

                return new RotationResult(true, "Password changed via LDAP/AD", "LDAP");
            }
            catch (LdapException ex)
            {
                return new RotationResult(false, $"LDAP error ({ex.ErrorCode}): {ex.Message}", "LDAP");
            }
            catch (Exception ex)
            {
                return new RotationResult(false, $"LDAP rotation failed: {ex.Message}", "LDAP");
            }
        }, ct);
    }

    private async Task<RotationResult> RotateViaSqlServerAsync(RotationTarget target, CancellationToken ct)
    {
        try
        {
            var connStr = $"Server={target.Host},{target.Port};User Id={target.Username};Password={target.CurrentPassword};TrustServerCertificate=true;Encrypt=true";
            if (!string.IsNullOrEmpty(target.DatabaseName))
                connStr += $";Database={target.DatabaseName}";

            await using var connection = new SqlConnection(connStr);
            await connection.OpenAsync(ct);

            // Use parameterized approach - ALTER LOGIN doesn't support parameters directly,
            // but we use sp_password which is safer
            await using var cmd = connection.CreateCommand();
            cmd.CommandText = "ALTER LOGIN @username WITH PASSWORD = @newpwd OLD_PASSWORD = @oldpwd";

            // ALTER LOGIN doesn't support parameters, use a different approach
            cmd.CommandText = $"ALTER LOGIN [{target.Username.Replace("]", "]]")}] WITH PASSWORD = @newpwd OLD_PASSWORD = @oldpwd";
            cmd.Parameters.AddWithValue("@newpwd", target.NewPassword);
            cmd.Parameters.AddWithValue("@oldpwd", target.CurrentPassword ?? "");

            await cmd.ExecuteNonQueryAsync(ct);

            return new RotationResult(true, "Password changed via SQL Server ALTER LOGIN", "SqlServer");
        }
        catch (SqlException ex)
        {
            return new RotationResult(false, $"SQL Server error ({ex.Number}): {ex.Message}", "SqlServer");
        }
    }

    private async Task<RotationResult> RotateViaMySqlAsync(RotationTarget target, CancellationToken ct)
    {
        // Native MySQL protocol - will use raw TCP in proxy implementation
        // For now, basic TCP probe to verify connectivity
        return await Task.Run(() =>
        {
            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var connectResult = client.BeginConnect(target.Host, target.Port, null, null);
                if (!connectResult.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)))
                    return new RotationResult(false, $"Cannot connect to MySQL at {target.Host}:{target.Port}", "MySQL");

                client.EndConnect(connectResult);
                // Full MySQL protocol rotation will be implemented with native proxy
                return new RotationResult(false, "MySQL native protocol rotation pending proxy implementation", "MySQL");
            }
            catch (Exception ex)
            {
                return new RotationResult(false, $"MySQL connection failed: {ex.Message}", "MySQL");
            }
        }, ct);
    }

    private async Task<RotationResult> RotateViaPostgreSqlAsync(RotationTarget target, CancellationToken ct)
    {
        // Native PostgreSQL protocol - will use raw TCP in proxy implementation
        return await Task.Run(() =>
        {
            try
            {
                using var client = new System.Net.Sockets.TcpClient();
                var connectResult = client.BeginConnect(target.Host, target.Port, null, null);
                if (!connectResult.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(5)))
                    return new RotationResult(false, $"Cannot connect to PostgreSQL at {target.Host}:{target.Port}", "PostgreSQL");

                client.EndConnect(connectResult);
                return new RotationResult(false, "PostgreSQL native protocol rotation pending proxy implementation", "PostgreSQL");
            }
            catch (Exception ex)
            {
                return new RotationResult(false, $"PostgreSQL connection failed: {ex.Message}", "PostgreSQL");
            }
        }, ct);
    }

    private Task<RotationResult> RotateViaWinRmAsync(RotationTarget target, CancellationToken ct)
    {
        // WinRM native implementation - will be part of Windows proxy service
        return Task.FromResult(new RotationResult(false,
            "WinRM rotation pending native proxy implementation. Host reachable: " +
            IsPortOpen(target.Host, target.Port > 0 ? target.Port : 5985),
            "WinRM"));
    }

    private Task<RotationResult> RotateViaSshAsync(RotationTarget target, CancellationToken ct)
    {
        // SSH native implementation - will be part of SSH proxy service
        return Task.FromResult(new RotationResult(false,
            "SSH rotation pending native proxy implementation. Host reachable: " +
            IsPortOpen(target.Host, target.Port > 0 ? target.Port : 22),
            "SSH"));
    }

    private Task<RotationResult> RotateViaWmiAsync(RotationTarget target, CancellationToken ct)
    {
        // WMI rotation is handled by the dedicated WmiPasswordRotator via PasswordRotationOrchestrator.
        // This stub exists for backward compatibility with direct IRotationService callers.
        return Task.FromResult(new RotationResult(false,
            "WMI rotation should be invoked via PasswordRotationOrchestrator with a dedicated WmiPasswordRotator. " +
            "Host reachable: " + IsPortOpen(target.Host, target.Port > 0 ? target.Port : 135),
            "WMI"));
    }

    private static string EscapeLdapFilterValue(string input) =>
        input.Replace("\\", "\\5c")
             .Replace("*", "\\2a")
             .Replace("(", "\\28")
             .Replace(")", "\\29")
             .Replace("\0", "\\00")
             .Replace("/", "\\2f");

    private static bool IsPortOpen(string host, int port)
    {
        try
        {
            using var client = new System.Net.Sockets.TcpClient();
            var result = client.BeginConnect(host, port, null, null);
            var connected = result.AsyncWaitHandle.WaitOne(TimeSpan.FromSeconds(3));
            if (connected) client.EndConnect(result);
            return connected;
        }
        catch { return false; }
    }
}
