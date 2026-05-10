using System.DirectoryServices.Protocols;
using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

public interface IDiscoveryService
{
    Task<DiscoveryScanResult> RunScanAsync(DiscoveryType type, string? targetScopeJson, CancellationToken ct = default);
}

public record DiscoveryScanResult(bool Success, string Message, List<DiscoveredAccountInfo> Accounts);
public record DiscoveredAccountInfo(string AccountName, string AccountType, string? HostName, string? Dn, bool IsEnabled, string Source);

public sealed class DiscoveryService : IDiscoveryService
{
    private readonly ILogger<DiscoveryService> _logger;

    public DiscoveryService(ILogger<DiscoveryService> logger)
    {
        _logger = logger;
    }

    public async Task<DiscoveryScanResult> RunScanAsync(DiscoveryType type, string? targetScopeJson, CancellationToken ct = default)
    {
        _logger.LogInformation("Starting discovery scan. Type: {Type}, Scope: {Scope}", type, targetScopeJson);

        return type switch
        {
            DiscoveryType.ActiveDirectory => await ScanActiveDirectoryAsync(targetScopeJson, ct),
            DiscoveryType.WindowsLocal => await ScanWindowsLocalAsync(targetScopeJson, ct),
            DiscoveryType.Linux => await ScanLinuxAsync(targetScopeJson, ct),
            DiscoveryType.Database => await ScanDatabaseAsync(targetScopeJson, ct),
            _ => new DiscoveryScanResult(false, $"Discovery type '{type}' not yet supported", [])
        };
    }

    private async Task<DiscoveryScanResult> ScanActiveDirectoryAsync(string? scopeJson, CancellationToken ct)
    {
        return await Task.Run(() =>
        {
            var scope = ParseScope(scopeJson);
            var host = scope.GetValueOrDefault("host", "");
            var baseDn = scope.GetValueOrDefault("baseDn", "");
            var bindDn = scope.GetValueOrDefault("bindDn");
            var bindPassword = scope.GetValueOrDefault("bindPassword");
            var port = int.TryParse(scope.GetValueOrDefault("port", "389"), out var p) ? p : 389;
            var useSsl = bool.TryParse(scope.GetValueOrDefault("useSsl", "false"), out var ssl) && ssl;

            if (string.IsNullOrEmpty(host) || string.IsNullOrEmpty(baseDn))
                return new DiscoveryScanResult(false, "AD discovery requires 'host' and 'baseDn' in target scope", []);

            try
            {
                var identifier = new LdapDirectoryIdentifier(host, port);
                using var connection = new LdapConnection(identifier);
                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.SecureSocketLayer = useSsl;

                if (useSsl)
                    connection.SessionOptions.VerifyServerCertificate = (conn, cert) => true;

                if (!string.IsNullOrEmpty(bindDn))
                {
                    connection.AuthType = AuthType.Basic;
                    connection.Credential = new NetworkCredential(bindDn, bindPassword);
                }

                connection.Bind();

                var accounts = new List<DiscoveredAccountInfo>();

                // Find privileged accounts: Domain Admins, Enterprise Admins, local admins, service accounts
                var filters = new[]
                {
                    ("(&(objectClass=user)(memberOf=CN=Domain Admins,CN=Users," + baseDn + "))", "DomainAdmin"),
                    ("(&(objectClass=user)(memberOf=CN=Enterprise Admins,CN=Users," + baseDn + "))", "EnterpriseAdmin"),
                    ("(&(objectClass=user)(servicePrincipalName=*))", "ServiceAccount"),
                    ("(&(objectClass=user)(adminCount=1))", "PrivilegedUser"),
                };

                var seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);

                foreach (var (filter, accountType) in filters)
                {
                    try
                    {
                        var request = new SearchRequest(baseDn, filter, SearchScope.Subtree,
                            "sAMAccountName", "distinguishedName", "userAccountControl", "cn");
                        request.SizeLimit = 5000;

                        var response = (SearchResponse)connection.SendRequest(request);
                        foreach (SearchResultEntry entry in response.Entries)
                        {
                            var sam = GetAttr(entry, "sAMAccountName");
                            if (string.IsNullOrEmpty(sam) || !seen.Add(sam)) continue;

                            var uac = GetAttr(entry, "userAccountControl");
                            var isEnabled = true;
                            if (int.TryParse(uac, out var uacVal))
                                isEnabled = (uacVal & 0x2) == 0;

                            accounts.Add(new DiscoveredAccountInfo(
                                sam, accountType, host,
                                GetAttr(entry, "distinguishedName"),
                                isEnabled, "ActiveDirectory"));
                        }
                    }
                    catch (LdapException ex)
                    {
                        _logger.LogWarning("AD discovery filter '{Filter}' failed: {Error}", filter, ex.Message);
                    }
                }

                _logger.LogInformation("AD discovery completed. Found {Count} privileged accounts on {Host}",
                    accounts.Count, host);

                return new DiscoveryScanResult(true, $"Scan completed. Found {accounts.Count} privileged accounts.", accounts);
            }
            catch (LdapException ex)
            {
                _logger.LogError(ex, "AD discovery failed for {Host}", host);
                return new DiscoveryScanResult(false, $"AD connection failed: {ex.Message}", []);
            }
        }, ct);
    }

    private async Task<DiscoveryScanResult> ScanWindowsLocalAsync(string? scopeJson, CancellationToken ct)
    {
        return await Task.Run(() =>
        {
            var scope = ParseScope(scopeJson);
            var targets = (scope.GetValueOrDefault("targets") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (targets.Length == 0)
                return new DiscoveryScanResult(false, "Windows local discovery requires 'targets' (comma-separated hostnames) in scope", []);

            var accounts = new List<DiscoveredAccountInfo>();

            foreach (var target in targets)
            {
                try
                {
                    // Check if host is reachable via WinRM port (5985/5986)
                    if (!IsPortOpen(target, 5985, TimeSpan.FromSeconds(3)) &&
                        !IsPortOpen(target, 5986, TimeSpan.FromSeconds(3)))
                    {
                        _logger.LogWarning("WinRM not reachable on {Target}", target);
                        accounts.Add(new DiscoveredAccountInfo("(unreachable)", "Error", target, null, false, "WinRM"));
                        continue;
                    }

                    // Native WinRM local admin enumeration will be implemented with proxy services
                    // For now, add the target as pending scan
                    accounts.Add(new DiscoveredAccountInfo("Administrator", "LocalAdmin", target, null, true, "WinRM-Probe"));
                    _logger.LogInformation("Windows host {Target} is reachable via WinRM, queued for detailed scan", target);
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error probing Windows host {Target}", target);
                }
            }

            return new DiscoveryScanResult(true, $"Probed {targets.Length} hosts. Full WinRM enumeration available with proxy services.", accounts);
        }, ct);
    }

    private async Task<DiscoveryScanResult> ScanLinuxAsync(string? scopeJson, CancellationToken ct)
    {
        return await Task.Run(() =>
        {
            var scope = ParseScope(scopeJson);
            var targets = (scope.GetValueOrDefault("targets") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (targets.Length == 0)
                return new DiscoveryScanResult(false, "Linux discovery requires 'targets' (comma-separated hostnames) in scope", []);

            var accounts = new List<DiscoveredAccountInfo>();

            foreach (var target in targets)
            {
                try
                {
                    if (IsPortOpen(target, 22, TimeSpan.FromSeconds(3)))
                    {
                        accounts.Add(new DiscoveredAccountInfo("root", "RootAccount", target, null, true, "SSH-Probe"));
                        _logger.LogInformation("Linux host {Target} is reachable via SSH, queued for detailed scan", target);
                    }
                    else
                    {
                        _logger.LogWarning("SSH not reachable on {Target}", target);
                        accounts.Add(new DiscoveredAccountInfo("(unreachable)", "Error", target, null, false, "SSH"));
                    }
                }
                catch (Exception ex)
                {
                    _logger.LogWarning(ex, "Error probing Linux host {Target}", target);
                }
            }

            return new DiscoveryScanResult(true, $"Probed {targets.Length} hosts. Full SSH enumeration available with proxy services.", accounts);
        }, ct);
    }

    private async Task<DiscoveryScanResult> ScanDatabaseAsync(string? scopeJson, CancellationToken ct)
    {
        return await Task.Run(() =>
        {
            var scope = ParseScope(scopeJson);
            var targets = (scope.GetValueOrDefault("targets") ?? "").Split(',', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            if (targets.Length == 0)
                return new DiscoveryScanResult(false, "Database discovery requires 'targets' (comma-separated host:port) in scope", []);

            var accounts = new List<DiscoveredAccountInfo>();
            var defaultPorts = new[] { 1433, 3306, 5432, 1521 }; // MSSQL, MySQL, PostgreSQL, Oracle

            foreach (var target in targets)
            {
                var parts = target.Split(':');
                var host = parts[0];

                if (parts.Length > 1 && int.TryParse(parts[1], out var port))
                {
                    if (IsPortOpen(host, port, TimeSpan.FromSeconds(3)))
                    {
                        var dbType = port switch { 1433 => "MSSQL", 3306 => "MySQL", 5432 => "PostgreSQL", 1521 => "Oracle", _ => "Database" };
                        accounts.Add(new DiscoveredAccountInfo("sa/root", $"{dbType}-Admin", host, $"port:{port}", true, "DB-Probe"));
                    }
                }
                else
                {
                    foreach (var dp in defaultPorts)
                    {
                        if (IsPortOpen(host, dp, TimeSpan.FromSeconds(2)))
                        {
                            var dbType = dp switch { 1433 => "MSSQL", 3306 => "MySQL", 5432 => "PostgreSQL", 1521 => "Oracle", _ => "Database" };
                            accounts.Add(new DiscoveredAccountInfo("sa/root", $"{dbType}-Admin", host, $"port:{dp}", true, "DB-Probe"));
                        }
                    }
                }
            }

            return new DiscoveryScanResult(true, $"Probed {targets.Length} database targets. Full enumeration requires credentials.", accounts);
        }, ct);
    }

    private static bool IsPortOpen(string host, int port, TimeSpan timeout)
    {
        try
        {
            using var client = new TcpClient();
            var result = client.BeginConnect(host, port, null, null);
            var connected = result.AsyncWaitHandle.WaitOne(timeout);
            if (connected) client.EndConnect(result);
            return connected;
        }
        catch { return false; }
    }

    private static string? GetAttr(SearchResultEntry entry, string name)
    {
        if (!entry.Attributes.Contains(name)) return null;
        var vals = entry.Attributes[name].GetValues(typeof(string));
        return vals.Length > 0 ? (string)vals[0] : null;
    }

    private static Dictionary<string, string?> ParseScope(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try
        {
            return System.Text.Json.JsonSerializer.Deserialize<Dictionary<string, string?>>(json) ?? new();
        }
        catch { return new(); }
    }
}
