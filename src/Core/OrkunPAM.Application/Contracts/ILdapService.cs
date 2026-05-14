namespace OrkunPAM.Application.Contracts;

public interface ILdapService
{
    Task<LdapTestResult> TestConnectionAsync(string host, int port, bool useSsl, string? bindDn, string? bindPassword, string baseDn);
    Task<LdapSyncResult> SyncUsersAndGroupsAsync(string host, int port, bool useSsl, string? bindDn, string? bindPassword,
        string baseDn, string userSearchFilter, string groupSearchFilter, string? attributeMapping);
}

public record LdapTestResult(bool Success, string Message, int? ResponseTimeMs = null, string? ServerType = null);

public record LdapSyncResult(bool Success, string Message, int UsersFound, int GroupsFound, List<LdapSyncedUser> Users, List<LdapSyncedGroup> Groups);
public record LdapSyncedUser(string SamAccountName, string? DisplayName, string? Email, string? Dn, bool IsEnabled);
public record LdapSyncedGroup(string Name, string Dn, int MemberCount);
