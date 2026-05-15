using System.DirectoryServices.Protocols;
using System.Net;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json;
using Microsoft.Extensions.Logging;
using OrkunPAM.Application.Contracts;

namespace OrkunPAM.Identity.Services;

public sealed class LdapService : ILdapService
{
    private readonly ILogger<LdapService> _logger;

    public LdapService(ILogger<LdapService> logger)
    {
        _logger = logger;
    }

    public async Task<LdapTestResult> TestConnectionAsync(string host, int port, bool useSsl, string? bindDn, string? bindPassword, string baseDn)
    {
        return await Task.Run(() =>
        {
            var sw = System.Diagnostics.Stopwatch.StartNew();
            try
            {
                var identifier = new LdapDirectoryIdentifier(host, port);
                using var connection = new LdapConnection(identifier);

                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.SecureSocketLayer = useSsl;
                connection.AuthType = AuthType.Basic;

                if (useSsl)
                {
                    connection.SessionOptions.VerifyServerCertificate = (conn, serverCert) =>
                    {
                        var cert = new X509Certificate2(serverCert);
                        using var chain = new X509Chain();
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        return chain.Build(cert);
                    };
                }

                if (!string.IsNullOrEmpty(bindDn) && !string.IsNullOrEmpty(bindPassword))
                {
                    connection.Credential = new NetworkCredential(bindDn, bindPassword);
                }
                else
                {
                    connection.AuthType = AuthType.Anonymous;
                }

                connection.Bind();
                sw.Stop();

                // Try a simple search to verify BaseDN
                var searchRequest = new SearchRequest(baseDn, "(objectClass=*)", SearchScope.Base, "objectClass");
                var searchResponse = (SearchResponse)connection.SendRequest(searchRequest);

                var serverType = "Unknown";
                if (searchResponse.Entries.Count > 0)
                {
                    var entry = searchResponse.Entries[0];
                    var objectClasses = entry.Attributes["objectClass"];
                    if (objectClasses != null)
                    {
                        var classes = objectClasses.GetValues(typeof(string)).Cast<string>().ToList();
                        serverType = classes.Any(c => c.Equals("domainDNS", StringComparison.OrdinalIgnoreCase))
                            ? "Active Directory"
                            : "LDAP";
                    }
                }

                _logger.LogInformation("LDAP connection test successful to {Host}:{Port} in {Ms}ms. Server: {ServerType}",
                    host, port, sw.ElapsedMilliseconds, serverType);

                return new LdapTestResult(true, $"Connection successful. BaseDN '{baseDn}' verified.", (int)sw.ElapsedMilliseconds, serverType);
            }
            catch (LdapException ex)
            {
                sw.Stop();
                _logger.LogWarning(ex, "LDAP connection test failed to {Host}:{Port}. Error: {Error}", host, port, ex.Message);
                var msg = ex.ErrorCode switch
                {
                    49 => "Invalid credentials (bind DN or password incorrect)",
                    81 => $"Server unreachable at {host}:{port}",
                    52 => "Server is not available",
                    32 => $"BaseDN '{baseDn}' not found on server",
                    _ => $"LDAP error ({ex.ErrorCode}): {ex.Message}"
                };
                return new LdapTestResult(false, msg, (int)sw.ElapsedMilliseconds);
            }
            catch (Exception ex)
            {
                sw.Stop();
                _logger.LogError(ex, "Unexpected error during LDAP connection test to {Host}:{Port}", host, port);
                return new LdapTestResult(false, $"Connection failed: {ex.Message}", (int)sw.ElapsedMilliseconds);
            }
        });
    }

    public async Task<LdapSyncResult> SyncUsersAndGroupsAsync(string host, int port, bool useSsl,
        string? bindDn, string? bindPassword, string baseDn,
        string userSearchFilter, string groupSearchFilter, string? attributeMapping)
    {
        return await Task.Run(() =>
        {
            try
            {
                var identifier = new LdapDirectoryIdentifier(host, port);
                using var connection = new LdapConnection(identifier);

                connection.SessionOptions.ProtocolVersion = 3;
                connection.SessionOptions.SecureSocketLayer = useSsl;
                connection.AuthType = AuthType.Basic;

                if (useSsl)
                {
                    connection.SessionOptions.VerifyServerCertificate = (conn, serverCert) =>
                    {
                        var cert = new X509Certificate2(serverCert);
                        using var chain = new X509Chain();
                        chain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;
                        return chain.Build(cert);
                    };
                }

                if (!string.IsNullOrEmpty(bindDn) && !string.IsNullOrEmpty(bindPassword))
                    connection.Credential = new NetworkCredential(bindDn, bindPassword);
                else
                    connection.AuthType = AuthType.Anonymous;

                connection.Bind();

                // Parse attribute mapping
                var attrMap = ParseAttributeMapping(attributeMapping);
                var samAttr = attrMap.GetValueOrDefault("username", "sAMAccountName");
                var displayAttr = attrMap.GetValueOrDefault("displayName", "displayName");
                var emailAttr = attrMap.GetValueOrDefault("email", "mail");

                // Sync users
                var users = new List<LdapSyncedUser>();
                var userRequest = new SearchRequest(baseDn, userSearchFilter.Replace("{0}", "*"),
                    SearchScope.Subtree, samAttr, displayAttr, emailAttr, "distinguishedName", "userAccountControl");
                userRequest.SizeLimit = 10000;

                var userResponse = (SearchResponse)connection.SendRequest(userRequest);
                foreach (SearchResultEntry entry in userResponse.Entries)
                {
                    var sam = GetAttribute(entry, samAttr);
                    if (string.IsNullOrEmpty(sam)) continue;

                    var uac = GetAttribute(entry, "userAccountControl");
                    var isEnabled = true;
                    if (int.TryParse(uac, out var uacVal))
                        isEnabled = (uacVal & 0x2) == 0; // ACCOUNTDISABLE flag

                    users.Add(new LdapSyncedUser(
                        sam,
                        GetAttribute(entry, displayAttr),
                        GetAttribute(entry, emailAttr),
                        GetAttribute(entry, "distinguishedName"),
                        isEnabled));
                }

                // Sync groups with member DNs
                var groups = new List<LdapSyncedGroup>();
                var groupRequest = new SearchRequest(baseDn, groupSearchFilter,
                    SearchScope.Subtree, "cn", "distinguishedName", "member");
                groupRequest.SizeLimit = 5000;

                var groupResponse = (SearchResponse)connection.SendRequest(groupRequest);
                foreach (SearchResultEntry entry in groupResponse.Entries)
                {
                    var cn = GetAttribute(entry, "cn");
                    if (string.IsNullOrEmpty(cn)) continue;

                    var memberDns = new List<string>();
                    if (entry.Attributes.Contains("member"))
                    {
                        var vals = entry.Attributes["member"].GetValues(typeof(string));
                        memberDns.AddRange(vals.Cast<string>());
                    }

                    groups.Add(new LdapSyncedGroup(cn, GetAttribute(entry, "distinguishedName") ?? "", memberDns.Count, memberDns));
                }

                _logger.LogInformation("LDAP sync completed from {Host}. Users: {UserCount}, Groups: {GroupCount}",
                    host, users.Count, groups.Count);

                return new LdapSyncResult(true, "Sync completed successfully", users.Count, groups.Count, users, groups);
            }
            catch (LdapException ex)
            {
                _logger.LogError(ex, "LDAP sync failed for {Host}:{Port}", host, port);
                return new LdapSyncResult(false, $"LDAP error ({ex.ErrorCode}): {ex.Message}", 0, 0, [], []);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, "Unexpected error during LDAP sync for {Host}:{Port}", host, port);
                return new LdapSyncResult(false, $"Sync failed: {ex.Message}", 0, 0, [], []);
            }
        });
    }

    private static string? GetAttribute(SearchResultEntry entry, string attributeName)
    {
        if (!entry.Attributes.Contains(attributeName)) return null;
        var values = entry.Attributes[attributeName].GetValues(typeof(string));
        return values.Length > 0 ? (string)values[0] : null;
    }

    private static Dictionary<string, string> ParseAttributeMapping(string? json)
    {
        if (string.IsNullOrEmpty(json)) return new();
        try { return JsonSerializer.Deserialize<Dictionary<string, string>>(json) ?? new(); }
        catch { return new(); }
    }
}
