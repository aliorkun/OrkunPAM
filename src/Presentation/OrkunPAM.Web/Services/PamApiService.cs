global using SessionCommandDto = OrkunPAM.Web.Services.CommandLogDto;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OrkunPAM.Web.Services;

public sealed class PamApiService
{
    private readonly IHttpClientFactory _factory;
    private readonly AuthStateService   _auth;

    private static readonly JsonSerializerOptions JsonOpts =
        new() { PropertyNameCaseInsensitive = true };

    public PamApiService(IHttpClientFactory factory, AuthStateService auth)
    {
        _factory = factory;
        _auth    = auth;
    }

    public async Task<LoginResult?> LoginAsync(string username, string password, string? mfaCode = null)
    {
        var client = _factory.CreateClient("PamApi");
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { username, password, mfaCode });
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<LoginResult>(JsonOpts);
        }
        catch { return null; }
    }

    public async Task<PagedResult<UserDto>?> GetUsersAsync(
        string? search = null, string? status = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/users?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(search))  url += $"&search={Uri.EscapeDataString(search)}";
        if (!string.IsNullOrEmpty(status))  url += $"&status={status}";
        return await GetAsync<PagedResult<UserDto>>(url);
    }

    public async Task<bool> DeleteUserAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/users/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> SetUserStatusAsync(string id, string newStatus)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PatchAsJsonAsync($"/api/v1/users/{id}/status", new { status = newStatus });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<UserDto?> GetUserAsync(string id)
        => await GetAsync<UserDto>($"/api/v1/users/{id}");

    public async Task<UserDto?> CreateUserAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/users", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<UserDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> CreateUserAsync(string username, string? displayName, string? email, string password)
    {
        var result = await CreateUserAsync(new { username, displayName, email, password });
        return result != null;
    }

    public async Task<UserDto?> UpdateUserAsync(string id, object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/users/{id}", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<UserDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> UpdateUserAsync(string id, string? displayName, string? email)
    {
        var result = await UpdateUserAsync(id, (object)new { displayName, email });
        return result != null;
    }

    public async Task<bool> ResetUserPasswordAsync(string id, string newPassword)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/users/{id}/reset-password", new { newPassword });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UnlockUserAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/users/{id}/unlock", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<List<GroupDto>?> GetGroupsAsync(int page = 1, int pageSize = 50)
    {
        var result = await GetAsync<PagedResult<GroupDto>>($"/api/v1/users/groups?page={page}&pageSize={pageSize}");
        return result?.Data;
    }

    public async Task<GroupDto?> CreateGroupAsync(string name, string? description = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/users/groups", new { name, description });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<GroupDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteGroupAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/users/groups/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> AddUserToGroupAsync(string groupId, string userId)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/users/groups/{groupId}/members/{userId}", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> RemoveUserFromGroupAsync(string groupId, string userId)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/users/groups/{groupId}/members/{userId}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Roles ──────────────────────────────────────────────────────────────────
    public async Task<List<RoleDto>?> GetRolesAsync()
    {
        var result = await GetAsync<ListResult<RoleDto>>("/api/v1/users/roles");
        return result?.Data;
    }

    public async Task<bool> AssignRoleAsync(string userId, string roleId)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/users/{userId}/roles/{roleId}", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> RemoveRoleAsync(string userId, string roleId)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/users/{userId}/roles/{roleId}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Devices ────────────────────────────────────────────────────────────────
    public async Task<PagedResult<DeviceDto>?> GetDevicesAsync(
        string? search = null, string? type = null, string? status = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/devices?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(search)) url += $"&search={Uri.EscapeDataString(search)}";
        if (!string.IsNullOrEmpty(type))   url += $"&type={type}";
        if (!string.IsNullOrEmpty(status)) url += $"&status={status}";
        return await GetAsync<PagedResult<DeviceDto>>(url);
    }

    public async Task<DeviceDto?> GetDeviceAsync(string id)
        => await GetAsync<DeviceDto>($"/api/v1/devices/{id}");

    public async Task<bool> CreateDeviceAsync(
        string hostname, string? fqdn, string? ipAddress,
        string type, string protocol, int port, string? os,
        Guid? networkZoneId = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/devices", new
            {
                hostname, fqdn, ipAddress,
                deviceType = type, protocol, port,
                operatingSystem = os, networkZoneId
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdateDeviceAsync(
        string id, string hostname, string? fqdn, string? ipAddress,
        string type, string protocol, int port, string? os,
        Guid? networkZoneId = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/devices/{id}", new
            {
                hostname, fqdn, ipAddress,
                deviceType = type, protocol, port,
                operatingSystem = os, networkZoneId
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteDeviceAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/devices/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> TestDeviceConnectivityAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/devices/{id}/test-connectivity", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Network Zones ─────────────────────────────────────────────────────────
    public async Task<List<NetworkZoneDto>?> GetNetworkZonesAsync()
    {
        var result = await GetAsync<ListResult<NetworkZoneDto>>("/api/v1/system/network-zones");
        return result?.Data;
    }

    public async Task<bool> CreateNetworkZoneAsync(string name, string? description, string? ipRanges,
        string? jumpHostAddress, Guid? jumpHostCredentialId, string? jumpHostFingerprint,
        string? proxyBindAddress, bool isDefault, string? notes)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/network-zones", new
            {
                name, description, ipRangesJson = ipRanges,
                jumpHostAddress, jumpHostCredentialId, jumpHostFingerprint, proxyBindAddress, isDefault, notes
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdateNetworkZoneAsync(Guid id, string? name, string? description, string? ipRanges,
        string? jumpHostAddress, Guid? jumpHostCredentialId, string? jumpHostFingerprint,
        string? proxyBindAddress, bool? isDefault, string? notes)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/system/network-zones/{id}", new
            {
                name, description, ipRangesJson = ipRanges,
                jumpHostAddress, jumpHostCredentialId, jumpHostFingerprint, proxyBindAddress, isDefault, notes
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteNetworkZoneAsync(Guid id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            return (await client.DeleteAsync($"/api/v1/system/network-zones/{id}")).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<NetworkZoneTestResultDto?> TestNetworkZoneAsync(Guid id)
        => await PostAsync<NetworkZoneTestResultDto>($"/api/v1/system/network-zones/{id}/test", null);

    // ── External Vault Federation (#284 — PV #12) ────────────────────────────

    public async Task<List<ExternalVaultDto>?> GetExternalVaultsAsync()
    {
        var result = await GetAsync<ListResult<ExternalVaultDto>>("/api/v1/system/external-vaults");
        return result?.Data;
    }

    public async Task<bool> CreateExternalVaultAsync(string name, string vaultType, string endpoint,
        string authMethod, string? authSecret, string? ns, string? mountPath, string? keyVaultName,
        string? tenantId, string? clientId, bool syncEnabled, int syncIntervalMinutes)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/external-vaults", new
            {
                name, vaultType, endpoint, authMethod, authSecret,
                @namespace = ns, mountPath, keyVaultName, tenantId, clientId,
                syncEnabled, syncIntervalMinutes
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdateExternalVaultAsync(Guid id, string? name, string? endpoint,
        string? authSecret, string? ns, string? mountPath, string? keyVaultName,
        string? tenantId, string? clientId, bool syncEnabled, int syncIntervalMinutes, bool isEnabled)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/system/external-vaults/{id}", new
            {
                name, endpoint, authSecret,
                @namespace = ns, mountPath, keyVaultName, tenantId, clientId,
                syncEnabled, syncIntervalMinutes, isEnabled
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteExternalVaultAsync(Guid id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            return (await client.DeleteAsync($"/api/v1/system/external-vaults/{id}")).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<ExternalVaultTestResultDto?> TestExternalVaultAsync(Guid id, string? authSecret = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/system/external-vaults/{id}/test",
                new { authSecret });
            if (!resp.IsSuccessStatusCode) return null;
            var wrapper = await resp.Content.ReadFromJsonAsync<SingleResult<ExternalVaultTestResultDto>>();
            return wrapper?.Data;
        }
        catch { return null; }
    }

    public async Task<ExternalVaultSyncResultDto?> SyncExternalVaultAsync(Guid id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/system/external-vaults/{id}/sync", new { });
            if (!resp.IsSuccessStatusCode) return null;
            var wrapper = await resp.Content.ReadFromJsonAsync<SingleResult<ExternalVaultSyncResultDto>>();
            return wrapper?.Data;
        }
        catch { return null; }
    }

    public async Task<List<string>?> BrowseExternalVaultSecretsAsync(Guid id, string? path = null)
    {
        try
        {
            var url = $"/api/v1/system/external-vaults/{id}/secrets";
            if (!string.IsNullOrEmpty(path)) url += "?path=" + Uri.EscapeDataString(path);
            var result = await GetAsync<ListResult<string>>(url);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> AddExternalVaultMappingAsync(Guid connectionId, string externalPath,
        string? usernameField, string? passwordField, Guid? mappedCredentialId, string syncMode)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/system/external-vaults/{connectionId}/mappings",
                new { externalPath, usernameField, passwordField, mappedCredentialId, syncMode });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteExternalVaultMappingAsync(Guid connectionId, Guid mappingId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            return (await client.DeleteAsync(
                $"/api/v1/system/external-vaults/{connectionId}/mappings/{mappingId}")).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── SCIM 2.0 Token Management (#291) ──────────────────────────────────────
    public async Task<List<ScimTokenDto>?> GetScimTokensAsync()
    {
        var result = await GetAsync<ListResult<ScimTokenDto>>("/api/v1/system/scim-tokens");
        return result?.Data;
    }

    public async Task<ScimTokenCreatedDto?> CreateScimTokenAsync(string name, int? expiresInDays = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/scim-tokens",
                new { name, expiresInDays });
            if (!resp.IsSuccessStatusCode) return null;
            var wrapper = await resp.Content.ReadFromJsonAsync<SingleResult<ScimTokenCreatedDto>>(JsonOpts);
            return wrapper?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> RevokeScimTokenAsync(Guid id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/system/scim-tokens/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<List<ScimProvisioningLogDto>?> GetScimProvisioningLogAsync()
    {
        var result = await GetAsync<ListResult<ScimProvisioningLogDto>>("/api/v1/system/scim-tokens/log");
        return result?.Data;
    }

    // ── Device Groups ──────────────────────────────────────────────────────────
    public async Task<List<DeviceGroupDto>?> GetDeviceGroupsAsync()
    {
        var result = await GetAsync<ListResult<DeviceGroupDto>>("/api/v1/devices/groups");
        return result?.Data;
    }

    public async Task<DeviceGroupDto?> CreateDeviceGroupAsync(string name, string? description = null, Guid? parentId = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/devices/groups", new { name, description, parentId });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<DeviceGroupDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteDeviceGroupAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/devices/groups/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> AddDeviceToGroupAsync(string groupId, string deviceId)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/devices/groups/{groupId}/members/{deviceId}", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> RemoveDeviceFromGroupAsync(string groupId, string deviceId)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/devices/groups/{groupId}/members/{deviceId}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Credentials / Vault ────────────────────────────────────────────────────
    public async Task<PagedResult<CredentialDto>?> GetCredentialsAsync(
        string? search = null, string? type = null, string? deviceId = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/vault/credentials?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(search)) url += $"&search={Uri.EscapeDataString(search)}";
        if (!string.IsNullOrEmpty(type))   url += $"&type={type}";
        if (!string.IsNullOrEmpty(deviceId)) url += $"&deviceId={deviceId}";
        return await GetAsync<PagedResult<CredentialDto>>(url);
    }

    public async Task<CredentialDto?> GetCredentialAsync(string id)
        => await GetAsync<CredentialDto>($"/api/v1/vault/credentials/{id}");

    public async Task<bool> CreateCredentialAsync(string name, int type, string? username = null, string? password = null,
        string? folderId = null, string? deviceId = null, string? description = null,
        int maxCheckoutMinutes = 60, bool requiresApproval = false, string? privateKey = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/vault/credentials",
                new { name, type, username, password, folderId, deviceId, description, maxCheckoutMinutes, requiresApproval, privateKey });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<CredentialDto?> UpdateCredentialAsync(string id, object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/vault/credentials/{id}", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<CredentialDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteCredentialAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/vault/credentials/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<CheckoutResultDto?> CheckoutCredentialAsync(string id, string? reason = null, string? ticketNumber = null, int? durationMinutes = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/vault/credentials/{id}/checkout",
                new { reason, ticketNumber, durationMinutes });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<CheckoutResultDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> CheckinCredentialAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/vault/credentials/{id}/checkin", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> RotateCredentialAsync(string id, string? connector = null, string? host = null, int? port = null, string? domain = null)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsJsonAsync($"/api/v1/vault/credentials/{id}/rotate", new { connector, host, port, domain })).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Credential Groups ──────────────────────────────────────────────────────
    public async Task<List<CredentialGroupDto>?> GetCredentialGroupsAsync()
    {
        var result = await GetAsync<ListResult<CredentialGroupDto>>("/api/v1/vault/credential-groups");
        return result?.Data;
    }

    public async Task<CredentialGroupDto?> CreateCredentialGroupAsync(string name, string? description = null, Guid? parentId = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/vault/credential-groups", new { name, description, parentId });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<CredentialGroupDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteCredentialGroupAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/vault/credential-groups/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Access Assignments ─────────────────────────────────────────────────────
    public async Task<List<AccessAssignmentDto>?> GetAccessAssignmentsAsync()
    {
        var result = await GetAsync<ListResult<AccessAssignmentDto>>("/api/v1/access/assignments");
        return result?.Data;
    }

    public async Task<AccessAssignmentDto?> CreateAccessAssignmentAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/access/assignments", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<AccessAssignmentDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteAccessAssignmentAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/access/assignments/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Device Realms ──────────────────────────────────────────────────────────
    public async Task<List<DeviceRealmDto>?> GetDeviceRealmsAsync()
    {
        var result = await GetAsync<ListResult<DeviceRealmDto>>("/api/v1/access/realms");
        return result?.Data;
    }

    public async Task<DeviceRealmDto?> GetDeviceRealmAsync(string id)
        => await GetAsync<DeviceRealmDto>($"/api/v1/access/realms/{id}");

    public async Task<DeviceRealmDto?> CreateDeviceRealmAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/access/realms", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<DeviceRealmDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<DeviceRealmDto?> UpdateDeviceRealmAsync(string id, object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/access/realms/{id}", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<DeviceRealmDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteDeviceRealmAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/access/realms/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> CreateDeviceRealmAsync(string name, string? description, object? extra)
    {
        var result = await CreateDeviceRealmAsync(new { name, description });
        return result != null;
    }

    public async Task<bool> UpdateDeviceRealmAsync(string id, string name, string? description, object? extra)
    {
        var result = await UpdateDeviceRealmAsync(id, (object)new { name, description });
        return result != null;
    }

    public async Task<bool> ToggleDeviceRealmAsync(string id) => await PostBoolAsync($"/api/v1/device-realms/{id}/toggle", new { });

    public async Task<bool> AddUserGroupToRealmAsync(string realmId, string groupId) => await PostBoolAsync($"/api/v1/device-realms/{realmId}/user-groups/{groupId}", new { });
    public async Task<bool> AddDeviceGroupToRealmAsync(string realmId, string groupId) => await PostBoolAsync($"/api/v1/device-realms/{realmId}/device-groups/{groupId}", new { });
    public async Task<bool> RemoveUserGroupFromRealmAsync(string realmId, string groupId) => await DeleteBoolAsync($"/api/v1/device-realms/{realmId}/user-groups/{groupId}");
    public async Task<bool> RemoveDeviceGroupFromRealmAsync(string realmId, string groupId) => await DeleteBoolAsync($"/api/v1/device-realms/{realmId}/device-groups/{groupId}");

    // ── Sessions ───────────────────────────────────────────────────────────────
    public async Task<PagedResult<SessionDto>?> GetSessionsAsync(
        string? status = null, int page = 1, int pageSize = 20, Guid? userId = null, Guid? deviceId = null)
    {
        var url = $"/api/v1/sessions?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(status)) url += $"&status={status}";
        if (userId.HasValue)   url += $"&userId={userId.Value}";
        if (deviceId.HasValue) url += $"&deviceId={deviceId.Value}";
        return await GetAsync<PagedResult<SessionDto>>(url);
    }

    public async Task<SessionDto?> GetSessionAsync(string id)
        => await GetAsync<SessionDto>($"/api/v1/sessions/{id}");

    public async Task<SessionDto?> LaunchSessionAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/sessions/launch", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<SessionDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> TerminateSessionAsync(string id, string? reason = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/sessions/{id}/terminate", new { reason });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdateSessionTagsAsync(string id, string tags)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/sessions/{id}/tags", new { tags });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<List<SessionAnnotationDto>?> GetSessionAnnotationsAsync(string id)
        => await GetAsync<List<SessionAnnotationDto>>($"/api/v1/sessions/{id}/annotations");

    public async Task<SessionAnnotationDto?> AddSessionAnnotationAsync(string id, string note)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/sessions/{id}/annotations", new { note });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<SessionAnnotationDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<SessionComplianceSummaryDto?> GetSessionComplianceSummaryAsync(int days = 30)
        => await GetAsync<SessionComplianceSummaryDto>($"/api/v1/sessions/compliance/summary?days={days}");

    // ── Operational Reports (#278 — Reporting #39-41) ─────────────────────────
    public async Task<CapacityReportDto?> GetCapacityReportAsync(int months = 3)
        => await GetAsync<CapacityReportDto>($"/api/v1/reports/operational/capacity?months={months}");

    public async Task<PerformanceReportDto?> GetPerformanceReportAsync(DateTime? from = null, DateTime? to = null)
    {
        var url = "/api/v1/reports/operational/performance";
        if (from.HasValue || to.HasValue)
        {
            var parts = new List<string>();
            if (from.HasValue) parts.Add("from=" + Uri.EscapeDataString(from.Value.ToString("O")));
            if (to.HasValue)   parts.Add("to="   + Uri.EscapeDataString(to.Value.ToString("O")));
            url += "?" + string.Join("&", parts);
        }
        return await GetAsync<PerformanceReportDto>(url);
    }

    public async Task<SlaReportDto?> GetSlaReportAsync(DateTime? from = null, DateTime? to = null)
    {
        var url = "/api/v1/reports/operational/sla";
        if (from.HasValue || to.HasValue)
        {
            var parts = new List<string>();
            if (from.HasValue) parts.Add("from=" + Uri.EscapeDataString(from.Value.ToString("O")));
            if (to.HasValue)   parts.Add("to="   + Uri.EscapeDataString(to.Value.ToString("O")));
            url += "?" + string.Join("&", parts);
        }
        return await GetAsync<SlaReportDto>(url);
    }

    public async Task<string?> GetOperationalReportCsvAsync(string type, DateTime? from = null, DateTime? to = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var url = type switch
            {
                "performance" => "/api/v1/reports/operational/performance",
                "sla"         => "/api/v1/reports/operational/sla",
                _             => "/api/v1/reports/operational/capacity"
            };
            var resp = await client.GetAsync(url);
            if (!resp.IsSuccessStatusCode) return null;
            var json = await resp.Content.ReadAsStringAsync();
            return json;
        }
        catch { return null; }
    }

    public async Task<string?> GetSessionsExportCsvAsync()
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.GetAsync("/api/v1/sessions?pageSize=5000");
            if (!resp.IsSuccessStatusCode) return null;
            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc = await JsonDocument.ParseAsync(stream);
            if (!doc.RootElement.TryGetProperty("data", out var dataProp)) return null;
            var sessions = dataProp.Deserialize<List<SessionDto>>(JsonOpts);
            if (sessions == null) return null;
            var sb = new System.Text.StringBuilder();
            sb.AppendLine("Id,SessionType,Status,TargetIpAddress,TargetPort,ClientIpAddress,StartedAtUtc,EndedAtUtc,DurationSeconds,RiskScore,Tags");
            foreach (var s in sessions)
                sb.AppendLine($"{s.Id},{s.SessionType},{s.Status},{s.TargetIpAddress},{s.TargetPort},{s.ClientIpAddress},{s.StartedAtUtc:O},{s.EndedAtUtc:O},{s.DurationSeconds},{s.RiskScore},{s.Tags}");
            return sb.ToString();
        }
        catch { return null; }
    }

    // ── Live Session (join/leave/broadcast/stream/status) ──────────────────────
    public async Task<bool> JoinLiveSessionAsync(string sessionId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsync($"/api/v1/sessions/live/{sessionId}/join", null);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> LeaveLiveSessionAsync(string sessionId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsync($"/api/v1/sessions/live/{sessionId}/leave", null);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> BroadcastLiveMessageAsync(string sessionId, string message)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/sessions/live/{sessionId}/message", new { message });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<PagedResult<CommandLogDto>?> GetSessionCommandsAsync(
        string sessionId, int page = 1, int pageSize = 100)
        => await GetAsync<PagedResult<CommandLogDto>>(
            $"/api/v1/sessions/{sessionId}/commands?page={page}&pageSize={pageSize}");

    // ── Session Shadow ─────────────────────────────────────────────────────────
    public async Task<ShadowStartDto?> StartShadowAsync(string sessionId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsync($"/api/v1/sessions/{sessionId}/shadow", null);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<ShadowStartDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> StopShadowAsync(string sessionId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.DeleteAsync($"/api/v1/sessions/{sessionId}/shadow");
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<LiveStreamDto?> GetLiveStreamAsync(string sessionId, int offset)
        => await GetAsync<LiveStreamDto>($"/api/v1/sessions/live/{sessionId}/stream?offset={offset}");

    public async Task<LiveSessionStatusDto?> GetLiveSessionStatusAsync(string sessionId)
        => await GetAsync<LiveSessionStatusDto>($"/api/v1/sessions/live/{sessionId}/status");

    // ── Session Handoff ────────────────────────────────────────────────────────
    public async Task<HandoffCreatedDto?> RequestHandoffAsync(string sessionId, Guid targetUserId, string? notes)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/sessions/{sessionId}/handoff",
                new { targetUserId, notes });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<HandoffCreatedDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> AcceptHandoffAsync(string sessionId, Guid handoffId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/sessions/{sessionId}/handoff/accept",
                new { handoffId });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeclineHandoffAsync(string sessionId, Guid handoffId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/sessions/{sessionId}/handoff/decline",
                new { handoffId });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<List<PendingHandoffDto>?> GetPendingHandoffsAsync()
        => await GetAsync<List<PendingHandoffDto>>("/api/v1/sessions/handoff/pending");

    // ── Session Delegation (#269 RA #42) ───────────────────────────────────────
    public async Task<SessionDelegationDto?> CreateDelegationAsync(
        Guid delegateUserId, Guid? deviceId, Guid? deviceGroupId, Guid? credentialId,
        DateTime expiresAtUtc, int maxSessionCount, string? note)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/sessions/delegations", new
            {
                delegateUserId, deviceId, deviceGroupId, credentialId,
                expiresAtUtc, maxSessionCount, note
            });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<SessionDelegationDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<List<SessionDelegationDto>?> GetDelegationsAsync()
        => await GetAsync<List<SessionDelegationDto>>("/api/v1/sessions/delegations");

    public async Task<DelegationMyDto?> GetMyDelegationsAsync()
        => await GetAsync<DelegationMyDto>("/api/v1/sessions/delegations/my");

    public async Task<bool> RevokeDelegationAsync(Guid delegationId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.DeleteAsync($"/api/v1/sessions/delegations/{delegationId}");
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── Audit Logs ─────────────────────────────────────────────────────────────
    public async Task<PagedResult<AuditLogDto>?> GetAuditLogsAsync(
        string? action = null, string? userId = null, DateTime? from = null, DateTime? to = null,
        string? category = null, string? eventType = null,
        int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/audit?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(action)) url += $"&action={Uri.EscapeDataString(action)}";
        if (!string.IsNullOrEmpty(userId)) url += $"&userId={userId}";
        if (!string.IsNullOrEmpty(category)) url += $"&category={Uri.EscapeDataString(category)}";
        if (!string.IsNullOrEmpty(eventType)) url += $"&eventType={Uri.EscapeDataString(eventType)}";
        if (from.HasValue) url += $"&from={from.Value:O}";
        if (to.HasValue)   url += $"&to={to.Value:O}";
        return await GetAsync<PagedResult<AuditLogDto>>(url);
    }

    public async Task<AuditLogDto?> GetAuditLogAsync(string id)
        => await GetAsync<AuditLogDto>($"/api/v1/audit/{id}");

    // ── System Settings ────────────────────────────────────────────────────────
    public async Task<SystemSettingsDto?> GetSystemSettingsAsync()
        => await GetAsync<SystemSettingsDto>("/api/v1/system/settings");

    public async Task<bool> UpdateSystemSettingsAsync(object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/system/settings", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── LDAP / AD ──────────────────────────────────────────────────────────────
    public async Task<LdapConfigDto?> GetLdapConfigAsync()
        => await GetAsync<LdapConfigDto>("/api/v1/system/ldap");

    public async Task<bool> SaveLdapConfigAsync(object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/ldap", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> TestLdapAsync()
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/system/ldap/test", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<LdapSyncResultDto?> SyncLdapAsync()
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsync("/api/v1/system/ldap/sync", null);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<LdapSyncResultDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    // ── RADIUS ─────────────────────────────────────────────────────────────────
    public async Task<RadiusConfigDto?> GetRadiusConfigAsync()
        => await GetAsync<RadiusConfigDto>("/api/v1/system/radius");

    public async Task<bool> SaveRadiusConfigAsync(object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/radius", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> TestRadiusAsync()
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/system/radius/test", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── SIEM / Syslog ──────────────────────────────────────────────────────────
    public async Task<SiemConfigDto?> GetSiemConfigAsync()
        => await GetAsync<SiemConfigDto>("/api/v1/system/siem");

    public async Task<bool> SaveSiemConfigAsync(object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/siem", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> TestSiemAsync()
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/system/siem/test", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Webhooks ───────────────────────────────────────────────────────────────
    public async Task<List<WebhookDto>?> GetWebhooksAsync()
    {
        var result = await GetAsync<ListResult<WebhookDto>>("/api/v1/system/webhooks");
        return result?.Data;
    }

    public async Task<WebhookDto?> CreateWebhookAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/webhooks", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<WebhookDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> UpdateWebhookAsync(string id, object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync($"/api/v1/system/webhooks/{id}", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteWebhookAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/system/webhooks/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> TestWebhookAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/system/webhooks/{id}/test", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Password Policies ──────────────────────────────────────────────────────
    public async Task<List<PasswordPolicyDto>?> GetPasswordPoliciesAsync()
    {
        var result = await GetAsync<ListResult<PasswordPolicyDto>>("/api/v1/policies/password");
        return result?.Data;
    }

    public async Task<PasswordPolicyDto?> GetPasswordPolicyAsync(string id)
        => await GetAsync<PasswordPolicyDto>($"/api/v1/policies/password/{id}");

    public async Task<PasswordPolicyDto?> CreatePasswordPolicyAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/policies/password", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<PasswordPolicyDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<PasswordPolicyDto?> UpdatePasswordPolicyAsync(string id, object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/policies/password/{id}", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<PasswordPolicyDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeletePasswordPolicyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/policies/password/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> SetDefaultPasswordPolicyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/policies/password/{id}/set-default", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Session Policies ───────────────────────────────────────────────────────
    public async Task<List<SessionPolicyDto>?> GetSessionPoliciesAsync()
    {
        var result = await GetAsync<ListResult<SessionPolicyDto>>("/api/v1/policies/session");
        return result?.Data;
    }

    public async Task<SessionPolicyDto?> CreateSessionPolicyAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/policies/session", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<SessionPolicyDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<SessionPolicyDto?> UpdateSessionPolicyAsync(string id, object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/policies/session/{id}", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<SessionPolicyDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteSessionPolicyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/policies/session/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Approval Workflows ─────────────────────────────────────────────────────
    public async Task<PagedResult<ApprovalRequestDto>?> GetApprovalRequestsAsync(
        string? status = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/approvals?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(status)) url += $"&status={status}";
        return await GetAsync<PagedResult<ApprovalRequestDto>>(url);
    }

    public async Task<ApprovalRequestDto?> GetApprovalRequestAsync(string id)
        => await GetAsync<ApprovalRequestDto>($"/api/v1/approvals/{id}");

    public async Task<bool> ApproveRequestAsync(string id, string? comment = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/approvals/{id}/approve", new { comment });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> RejectRequestAsync(string id, string? comment = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/approvals/{id}/reject", new { comment });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<int> GetPendingApprovalCountAsync()
    {
        var result = await GetApprovalRequestsAsync(status: "Pending", page: 1, pageSize: 1);
        return result?.Meta?.TotalCount ?? 0;
    }

    // ── Reports ────────────────────────────────────────────────────────────────
    public async Task<DashboardStatsDto?> GetDashboardStatsAsync()
        => await GetAsync<DashboardStatsDto>("/api/v1/reports/dashboard");

    public async Task<ComplianceReportDto?> GetComplianceReportAsync(DateTime? from = null, DateTime? to = null)
    {
        var url = "/api/v1/reports/compliance";
        if (from.HasValue || to.HasValue)
        {
            url += "?";
            if (from.HasValue) url += $"from={from.Value:O}";
            if (from.HasValue && to.HasValue) url += "&";
            if (to.HasValue) url += $"to={to.Value:O}";
        }
        return await GetAsync<ComplianceReportDto>(url);
    }

    public async Task<List<ActivitySummaryDto>?> GetActivitySummaryAsync(int days = 7)
    {
        var result = await GetAsync<ListResult<ActivitySummaryDto>>($"/api/v1/reports/activity?days={days}");
        return result?.Data;
    }

    // ── Notifications ──────────────────────────────────────────────────────────
    public async Task<List<NotificationDto>?> GetNotificationsAsync(bool unreadOnly = false)
    {
        var result = await GetAsync<ListResult<NotificationDto>>($"/api/v1/notifications?unreadOnly={unreadOnly.ToString().ToLower()}");
        return result?.Data;
    }

    public async Task<bool> MarkNotificationReadAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/notifications/{id}/read", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> MarkAllNotificationsReadAsync()
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/notifications/read-all", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── MFA ────────────────────────────────────────────────────────────────────
    public async Task<MfaSetupDto?> GetMfaSetupAsync()
        => await GetAsync<MfaSetupDto>("/api/v1/auth/mfa/setup");

    public async Task<bool> EnableMfaAsync(string code)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/mfa/enable", new { code });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DisableMfaAsync(string code)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/mfa/disable", new { code });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<string[]?> GetMfaRecoveryCodesAsync(string code)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/mfa/recovery-codes", new { code });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<RecoveryCodesDto>>(JsonOpts);
            return result?.Data?.Codes;
        }
        catch { return null; }
    }

    // ── MFA Backup Codes (#289 — MFA #21) ─────────────────────────────────────
    public async Task<string[]?> GenerateBackupCodesAsync()
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsync("/api/v1/auth/mfa/backup-codes/generate", null);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<BackupCodesGeneratedDto>>(JsonOpts);
            return result?.Data?.Codes;
        }
        catch { return null; }
    }

    public async Task<BackupCodeStatusDto?> GetBackupCodeStatusAsync()
        => await GetAsync<BackupCodeStatusDto>("/api/v1/auth/mfa/backup-codes/status");

    public async Task<bool> AdminRevokeBackupCodesAsync(Guid userId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            return (await client.DeleteAsync("/api/v1/admin/users/" + userId + "/backup-codes")).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── MFA Trusted Sessions (#257) ────────────────────────────────────────────
    public async Task<MfaTrustPolicyDto?> GetMfaTrustPolicyAsync()
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var resp = await client.GetAsync("/api/v1/auth/mfa-trust-policy");
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<MfaTrustPolicyDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> CreateTrustedSessionAsync(string deviceLabel = "Browser")
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/trusted-sessions", new { deviceLabel });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<List<MfaTrustedSessionDto>?> GetTrustedSessionsAsync()
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.GetAsync("/api/v1/auth/trusted-sessions");
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<ListResult<MfaTrustedSessionDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> RevokeTrustedSessionAsync(Guid id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            return (await client.DeleteAsync("/api/v1/auth/trusted-sessions/" + id)).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── SSH Keys ───────────────────────────────────────────────────────────────
    public async Task<List<SshKeyDto>?> GetSshKeysAsync()
    {
        var result = await GetAsync<ListResult<SshKeyDto>>("/api/v1/system/ssh-keys");
        return result?.Data;
    }

    public async Task<SshKeyDto?> CreateSshKeyAsync(string name, string? description = null, string keyType = "RSA", int keySize = 4096)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/ssh-keys",
                new { name, description, keyType, keySize });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<SshKeyDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteSshKeyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/system/ssh-keys/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<string?> GetSshPublicKeyAsync(string id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.GetAsync($"/api/v1/system/ssh-keys/{id}/public");
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<SshPublicKeyDto>>(JsonOpts);
            return result?.Data?.PublicKey;
        }
        catch { return null; }
    }

    // ── Certificates ───────────────────────────────────────────────────────────
    public async Task<List<CertificateDto>?> GetCertificatesAsync()
    {
        var result = await GetAsync<ListResult<CertificateDto>>("/api/v1/system/certificates");
        return result?.Data;
    }

    public async Task<List<ManagedCertificateDto>?> GetManagedCertificatesAsync()
    {
        var result = await GetAsync<ListResult<ManagedCertificateDto>>("/api/v1/system/certificates");
        return result?.Data;
    }

    public async Task<CertificateDto?> UploadCertificateAsync(string name, string pemContent, string? description = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/certificates",
                new { name, description, pemContent });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<CertificateDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteCertificateAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/system/certificates/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── License ────────────────────────────────────────────────────────────────
    public async Task<LicenseDto?> GetLicenseAsync()
        => await GetAsync<LicenseDto>("/api/v1/system/license");

    public async Task<bool> ActivateLicenseAsync(string licenseKey)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/license/activate", new { licenseKey });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── Backup & Restore ───────────────────────────────────────────────────────
    public async Task<List<BackupRecordDto>?> GetBackupsAsync()
    {
        var result = await GetAsync<ListResult<BackupRecordDto>>("/api/v1/system/backups");
        return result?.Data;
    }

    public async Task<BackupRecordDto?> CreateBackupAsync(string scope, string passphrase)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/backups", new { scope, passphrase });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<BackupRecordDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<(bool, string?, int)> RestoreBackupAsync(byte[] fileBytes, string fileName, string passphrase, string conflictStrategy)
    {
        try
        {
            var client = await GetAuthClientAsync();
            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(fileBytes), "file", fileName);
            form.Add(new StringContent(passphrase), "passphrase");
            form.Add(new StringContent(conflictStrategy), "conflictStrategy");
            var resp = await client.PostAsync("/api/v1/system/backups/restore", form);
            if (!resp.IsSuccessStatusCode) { var err = await resp.Content.ReadAsStringAsync(); return (false, err, 0); }
            var result = await resp.Content.ReadFromJsonAsync<BackupRestoreResultDto>(JsonOpts);
            return (true, result?.Message, result?.RestoredCount ?? 0);
        }
        catch (Exception ex) { return (false, ex.Message, 0); }
    }

    public async Task<bool> DeleteBackupAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/system/backups/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Health ─────────────────────────────────────────────────────────────────
    public async Task<HealthDto?> GetHealthAsync()
    {
        var client = _factory.CreateClient("PamApi");
        try
        {
            var resp = await client.GetAsync("/health");
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<HealthDto>(JsonOpts);
        }
        catch { return null; }
    }

    // ── PKI / Smart Card ───────────────────────────────────────────────────────
    public async Task<PkiConfigDto?> GetPkiConfigAsync()
        => await GetAsync<PkiConfigDto>("/api/v1/system/pki");

    public async Task<bool> SavePkiConfigAsync(object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/pki", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── Emergency Access ───────────────────────────────────────────────────────
    public async Task<EmergencyAccessDto?> GetEmergencyAccessAsync()
        => await GetAsync<EmergencyAccessDto>("/api/v1/system/emergency-access");

    public async Task<bool> EnableEmergencyAccessAsync(string reason, int durationMinutes = 60)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/emergency-access/enable",
                new { reason, durationMinutes });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DisableEmergencyAccessAsync()
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/system/emergency-access/disable", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── RDP Proxy Settings ─────────────────────────────────────────────────────
    public async Task<RdpProxySettingsDto?> GetRdpProxySettingsAsync()
        => await GetAsync<RdpProxySettingsDto>("/api/v1/system/rdp-proxy");

    public async Task<bool> SaveRdpProxySettingsAsync(object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/system/rdp-proxy", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── SSH Proxy Settings ─────────────────────────────────────────────────────
    public async Task<SshProxySettingsDto?> GetSshProxySettingsAsync()
        => await GetAsync<SshProxySettingsDto>("/api/v1/system/ssh-proxy");

    public async Task<bool> SaveSshProxySettingsAsync(object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/system/ssh-proxy", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── MFA Enrollment ─────────────────────────────────────────────────────────
    public async Task<MfaEnrollmentTokenDto?> GenerateMfaEnrollmentTokenAsync(string userId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsync($"/api/v1/users/{userId}/mfa-enrollment-token", null);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<MfaEnrollmentTokenDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    // ── Password Reset (Admin) ─────────────────────────────────────────────────
    public async Task<PasswordResetTokenDto?> GeneratePasswordResetTokenAsync(string userId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsync($"/api/v1/users/{userId}/password-reset-token", null);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<PasswordResetTokenDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    // ── RADIUS Users ───────────────────────────────────────────────────────────
    public async Task<PagedResult<RadiusUserDto>?> GetRadiusUsersAsync(int page = 1, int pageSize = 20)
        => await GetAsync<PagedResult<RadiusUserDto>>($"/api/v1/system/radius-users?page={page}&pageSize={pageSize}");

    public async Task<RadiusUserDto?> CreateRadiusUserAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/radius-users", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<RadiusUserDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteRadiusUserAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/system/radius-users/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Vendor Management ──────────────────────────────────────────────────────
    public async Task<List<VendorUserDto>?> GetVendorUsersAsync(string? statusFilter = null)
    {
        var url = "/api/v1/users/vendors" + (statusFilter != null ? "?status=" + statusFilter : "");
        var result = await GetAsync<ListResult<VendorUserDto>>(url);
        return result?.Data;
    }

    public async Task<VendorUserDto?> CreateVendorUserAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/users/vendors", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<VendorUserDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> UpdateVendorUserAsync(string id, object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync($"/api/v1/users/vendors/{id}", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteVendorUserAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/users/vendors/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> ExtendVendorAccessAsync(string id, int extraDays)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/users/vendors/{id}/extend", new { extraDays });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── Orphan Detection ───────────────────────────────────────────────────────
    public async Task<List<OrphanedAccountDto>?> GetOrphanedAccountsAsync()
    {
        var result = await GetAsync<ListResult<OrphanedAccountDto>>("/api/v1/users/orphaned");
        return result?.Data;
    }

    public async Task<bool> ResolveOrphanAsync(string id, string action)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/users/orphaned/{id}/resolve", new { action });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── Approval Policies ──────────────────────────────────────────────────────
    public async Task<List<ApprovalPolicyDto>?> GetApprovalPoliciesAsync()
    {
        var result = await GetAsync<ListResult<ApprovalPolicyDto>>("/api/v1/policies/approval");
        return result?.Data;
    }

    public async Task<ApprovalPolicyDto?> CreateApprovalPolicyAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/policies/approval", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<ApprovalPolicyDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> UpdateApprovalPolicyAsync(string id, object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync($"/api/v1/policies/approval/{id}", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteApprovalPolicyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/policies/approval/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── MFA Policy ─────────────────────────────────────────────────────────────
    public async Task<MfaPolicyDto?> GetMfaPolicyAsync()
        => await GetAsync<MfaPolicyDto>("/api/v1/policies/mfa");

    public async Task<bool> SaveMfaPolicyAsync(object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/policies/mfa", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── Threat Intelligence ────────────────────────────────────────────────────
    public async Task<List<ThreatIndicatorDto>?> GetThreatIndicatorsAsync(int pageSize = 50)
    {
        var result = await GetAsync<ListResult<ThreatIndicatorDto>>("/api/v1/threat/indicators");
        return result?.Data;
    }

    public async Task<ThreatIndicatorDto?> AddThreatIndicatorAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/threat/indicators", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<ThreatIndicatorDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> RemoveThreatIndicatorAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/threat/indicators/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Anomaly Detection ──────────────────────────────────────────────────────
    public async Task<List<AnomalyAlertDto>?> GetAnomalyAlertsAsync(bool unresolvedOnly = false)
    {
        var result = await GetAsync<ListResult<AnomalyAlertDto>>($"/api/v1/threat/anomalies?unresolvedOnly={unresolvedOnly.ToString().ToLower()}");
        return result?.Data;
    }

    public async Task<bool> ResolveAnomalyAlertAsync(string id, string? note = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/threat/anomalies/{id}/resolve", new { note });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── Credential Rotation Rules ──────────────────────────────────────────────
    public async Task<List<RotationRuleDto>?> GetRotationRulesAsync()
    {
        var result = await GetAsync<ListResult<RotationRuleDto>>("/api/v1/vault/rotation-rules");
        return result?.Data;
    }

    public async Task<RotationRuleDto?> CreateRotationRuleAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/vault/rotation-rules", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<RotationRuleDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> UpdateRotationRuleAsync(string id, object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync($"/api/v1/vault/rotation-rules/{id}", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteRotationRuleAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/vault/rotation-rules/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Discovery Scan ─────────────────────────────────────────────────────────
    public async Task<List<DiscoveredDeviceDto>?> RunDiscoveryScanAsync(string ipRange)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/devices/discover", new { ipRange });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<ListResult<DiscoveredDeviceDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<DeviceDto?> ImportDiscoveredDeviceAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/devices/import", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<DeviceDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    // ── Jump Server / Bastion ──────────────────────────────────────────────────
    public async Task<List<JumpServerDto>?> GetJumpServersAsync()
    {
        var result = await GetAsync<ListResult<JumpServerDto>>("/api/v1/system/jump-servers");
        return result?.Data;
    }

    public async Task<JumpServerDto?> CreateJumpServerAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/jump-servers", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<JumpServerDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> UpdateJumpServerAsync(string id, object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync($"/api/v1/system/jump-servers/{id}", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteJumpServerAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/system/jump-servers/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Session Recording ──────────────────────────────────────────────────────
    public async Task<PagedResult<RecordingDto>?> GetRecordingsAsync(
        Guid? sessionId = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/sessions/recordings?page={page}&pageSize={pageSize}";
        if (sessionId.HasValue) url += $"&sessionId={sessionId.Value}";
        return await GetAsync<PagedResult<RecordingDto>>(url);
    }

    public async Task<string?> GetRecordingPlaybackUrlAsync(string id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.GetAsync($"/api/v1/sessions/recordings/{id}/playback-url");
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<PlaybackUrlDto>>(JsonOpts);
            return result?.Data?.Url;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteRecordingAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/sessions/recordings/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── HSM Configuration ──────────────────────────────────────────────────────
    public async Task<HsmConfigDto?> GetHsmConfigAsync()
        => await GetAsync<HsmConfigDto>("/api/v1/system/hsm");

    public async Task<bool> SaveHsmConfigAsync(object payload)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/hsm", payload);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> TestHsmConnectionAsync()
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/system/hsm/test", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Privileged Task Automation ─────────────────────────────────────────────
    public async Task<List<AutomationTaskDto>?> GetAutomationTasksAsync()
    {
        var result = await GetAsync<ListResult<AutomationTaskDto>>("/api/v1/automation/tasks");
        return result?.Data;
    }

    public async Task<AutomationTaskDto?> CreateAutomationTaskAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/automation/tasks", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<AutomationTaskDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> RunAutomationTaskAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/automation/tasks/{id}/run", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> DeleteAutomationTaskAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/automation/tasks/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Service Accounts ───────────────────────────────────────────────────────
    public async Task<PagedResult<UserDto>?> GetServiceAccountsAsync(int page = 1, int pageSize = 20)
        => await GetAsync<PagedResult<UserDto>>($"/api/v1/users?isServiceAccount=true&page={page}&pageSize={pageSize}");

    public async Task<UserDto?> CreateServiceAccountAsync(string username, string? displayName = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/users",
                new { username, displayName, isServiceAccount = true, authSource = "Local" });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<UserDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    // API Keys (#250)
    public async Task<List<ApiKeyDto>?> GetApiKeysAsync()
    {
        var result = await GetAsync<ListResult<ApiKeyDto>>("/api/v1/system/api-keys");
        return result?.Data;
    }

    public async Task<ApiKeyCreatedDto?> CreateApiKeyAsync(
        string name, string? description, string? serviceAccountName,
        List<string>? allowedIpCidrs, int? expiresAfterDays)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/api-keys",
                new { name, description, serviceAccountName, allowedIpCidrs, expiresAfterDays });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<ApiKeyCreatedDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> RevokeApiKeyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/system/api-keys/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<ApiKeyCreatedDto?> RotateApiKeyAsync(string id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsync($"/api/v1/system/api-keys/{id}/rotate", null);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<ApiKeyCreatedDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    // === Credential Orchestration (#251) ===
    public async Task<List<OrchestrationSetDto>?> GetOrchestrationSetsAsync()
        => (await GetAsync<ListResult<OrchestrationSetDto>>("/api/v1/vault/orchestration"))?.Data;

    public async Task<OrchestrationSetDetailDto?> GetOrchestrationSetAsync(string id)
        => (await GetAsync<SingleResult<OrchestrationSetDetailDto>>($"/api/v1/vault/orchestration/{id}"))?.Data;

    public async Task<(bool Ok, Guid Id)> CreateOrchestrationSetAsync(string name, string? description,
        string executionMode, bool rollbackOnFailure, bool notifyOnComplete, string? scheduleCron, List<Guid>? credentialIds)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/vault/orchestration",
                new { name, description, executionMode, rollbackOnFailure, notifyOnComplete, scheduleCron, credentialIds });
            if (!resp.IsSuccessStatusCode) return (false, Guid.Empty);
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<IdDto>>(JsonOpts);
            return (result?.Success == true, result?.Data?.Id ?? Guid.Empty);
        }
        catch { return (false, Guid.Empty); }
    }

    public async Task<bool> UpdateOrchestrationSetAsync(string id, string? name, string? executionMode,
        bool? rollbackOnFailure, bool? notifyOnComplete, string? scheduleCron, List<Guid>? credentialIds)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/vault/orchestration/{id}",
                new { name, executionMode, rollbackOnFailure, notifyOnComplete, scheduleCron, credentialIds });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteOrchestrationSetAsync(string id)
    {
        try { return (await (await GetAuthClientAsync()).DeleteAsync($"/api/v1/vault/orchestration/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<OrchestrationRunResultDto?> RunOrchestrationAsync(string id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsync($"/api/v1/vault/orchestration/{id}/run", null);
            if (!resp.IsSuccessStatusCode) return null;
            return (await resp.Content.ReadFromJsonAsync<SingleResult<OrchestrationRunResultDto>>(JsonOpts))?.Data;
        }
        catch { return null; }
    }

    public async Task<List<OrchestrationRunDto>?> GetOrchestrationRunsAsync(string id)
        => (await GetAsync<ListResult<OrchestrationRunDto>>($"/api/v1/vault/orchestration/{id}/runs"))?.Data;

    // ── Hardware Tokens (#261) ─────────────────────────────────────────────────

    public async Task<bool> ProvisionHardwareTokenAsync(
        string userId, string serialNumber, string secretKeyBase32,
        string tokenType, string algorithm, int digits, int periodSeconds, string? label)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var body = new
            {
                userId, serialNumber, secretKeyBase32,
                tokenType, algorithm, digits, periodSeconds, label
            };
            var resp = await client.PostAsJsonAsync("/api/v1/auth/hardware-tokens", body);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<List<HardwareTokenDto>?> GetHardwareTokensAsync(string userId)
        => await GetAsync<List<HardwareTokenDto>>($"/api/v1/auth/hardware-tokens?userId={userId}");

    public async Task<List<HardwareTokenDto>?> GetAllHardwareTokensAsync()
        => await GetAsync<List<HardwareTokenDto>>("/api/v1/auth/hardware-tokens?all=true");

    public async Task<bool> RevokeHardwareTokenAsync(Guid tokenId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.DeleteAsync($"/api/v1/auth/hardware-tokens/{tokenId}");
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // Hardware Token Resync (#277 — MFA #23)
    public async Task<List<HardwareTokenDto>?> GetMyHardwareTokensAsync()
        => await GetAsync<List<HardwareTokenDto>>("/api/v1/auth/hardware-tokens");

    public async Task<(bool Success, string? Error)> ResyncHardwareTokenAsync(Guid tokenId, string otp1, string otp2)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/auth/hardware-tokens/{tokenId}/resync",
                new { otp1, otp2 });
            if (resp.IsSuccessStatusCode) return (true, null);
            try
            {
                using var stream = await resp.Content.ReadAsStreamAsync();
                using var doc = await JsonDocument.ParseAsync(stream);
                if (doc.RootElement.TryGetProperty("errors", out var errProp))
                {
                    var first = errProp.EnumerateArray().FirstOrDefault();
                    return (false, first.GetString());
                }
            }
            catch { /* ignore */ }
            return (false, "Resync failed. Ensure the two OTPs are consecutive presses.");
        }
        catch { return (false, "Network error during resync."); }
    }

    public async Task<bool> AdminResyncHardwareTokenAsync(Guid tokenId, long newCounter)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/auth/hardware-tokens/{tokenId}/admin-resync",
                new { newCounter });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<List<TokenDriftReportItemDto>?> GetTokenDriftReportAsync()
        => await GetAsync<List<TokenDriftReportItemDto>>("/api/v1/auth/hardware-tokens/drift-report");

    public async Task<LoginResult?> VerifyHardwareOtpAsync(string username, string otp)
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var resp = await client.PostAsJsonAsync("/api/v1/auth/verify-hardware-otp",
                new { username, otp });
            if (!resp.IsSuccessStatusCode) return new LoginResult(false, null);
            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc    = await JsonDocument.ParseAsync(stream);
            var success = doc.RootElement.TryGetProperty("success", out var s) && s.GetBoolean();
            if (!success) return new LoginResult(false, null);
            if (doc.RootElement.TryGetProperty("data", out var data))
            {
                var loginData = data.Deserialize<LoginData>(JsonOpts);
                return new LoginResult(true, loginData);
            }
            return new LoginResult(false, null);
        }
        catch { return new LoginResult(false, null); }
    }

    // ── Command Filter Policy (#231) ──────────────────────────────────────────

    public async Task<List<CommandFilterPolicyDto>?> GetCommandFilterPoliciesAsync()
    {
        var result = await GetAsync<ListResult<CommandFilterPolicyDto>>("/api/v1/policies/command-filter");
        return result?.Data;
    }

    public async Task<CommandFilterPolicyDetailDto?> GetCommandFilterPolicyAsync(string id)
        => (await GetAsync<SingleResult<CommandFilterPolicyDetailDto>>($"/api/v1/policies/command-filter/{id}"))?.Data;

    public async Task<bool> ToggleCommandFilterPolicyAsync(string id, bool enable)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PutAsJsonAsync($"/api/v1/policies/command-filter/{id}/toggle", new { isEnabled = enable })).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> CreateCommandFilterPolicyAsync(string name, string? description, bool isEnabled, string mode, Guid? deviceGroupId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/policies/command-filter",
                new { name, description, isEnabled, mode, deviceGroupId });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteCommandFilterPolicyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/policies/command-filter/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> AddCommandFilterRuleAsync(string policyId, string pattern, bool isRegex, string action, int riskScore, string? justification)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/policies/command-filter/{policyId}/rules",
                new { pattern, isRegex, action, riskScore, justification });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteCommandFilterRuleAsync(string policyId, string ruleId)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/policies/command-filter/{policyId}/rules/{ruleId}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Peripheral Redirection Policy (#249) ──────────────────────────────────

    public async Task<List<PeripheralRedirectionPolicyDto>?> GetPeripheralPoliciesAsync()
    {
        var result = await GetAsync<ListResult<PeripheralRedirectionPolicyDto>>("/api/v1/policies/peripheral");
        return result?.Data;
    }

    public async Task<bool> CreatePeripheralPolicyAsync(
        string name, string? description, bool isEnabled,
        bool allowClipboard, bool allowDriveRedirection, bool allowPrinterRedirection,
        bool allowUsbRedirection, bool allowAudioRedirection, bool allowSmartCardRedirection,
        Guid? deviceGroupId)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/policies/peripheral",
                new { name, description, isEnabled, allowClipboard, allowDriveRedirection,
                      allowPrinterRedirection, allowUsbRedirection, allowAudioRedirection,
                      allowSmartCardRedirection, deviceGroupId });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdatePeripheralPolicyAsync(
        string id, string? name, bool? isEnabled,
        bool? allowClipboard, bool? allowDriveRedirection, bool? allowPrinterRedirection,
        bool? allowUsbRedirection, bool? allowAudioRedirection, bool? allowSmartCardRedirection)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/policies/peripheral/{id}",
                new { name, isEnabled, allowClipboard, allowDriveRedirection,
                      allowPrinterRedirection, allowUsbRedirection, allowAudioRedirection,
                      allowSmartCardRedirection });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeletePeripheralPolicyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/policies/peripheral/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Device MFA Policy (#270 — MFA #22) ────────────────────────────────────

    public async Task<List<DeviceMfaPolicyDto>?> GetDeviceMfaPoliciesAsync()
    {
        var result = await GetAsync<ListResult<DeviceMfaPolicyDto>>("/api/v1/policies/device-mfa");
        return result?.Data;
    }

    public async Task<bool> CreateDeviceMfaPolicyAsync(
        string name, string? description, string requiredMfaLevel,
        bool enforceAtSessionStart, bool isEnabled,
        Guid? deviceGroupId = null, Guid? deviceId = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/policies/device-mfa",
                new { name, description, requiredMfaLevel, enforceAtSessionStart, isEnabled, deviceGroupId, deviceId });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdateDeviceMfaPolicyAsync(
        string id, string? name, string? requiredMfaLevel,
        bool? enforceAtSessionStart, bool? isEnabled)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/policies/device-mfa/{id}",
                new { name, requiredMfaLevel, enforceAtSessionStart, isEnabled });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteDeviceMfaPolicyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/policies/device-mfa/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── OIDC Federation (#271 UM #48) ─────────────────────────────────────────

    public async Task<List<OidcProviderPublicDto>?> GetOidcProvidersPublicAsync()
    {
        try
        {
            var client = _factory.CreateClient("PamApi");
            var resp   = await client.GetAsync("/api/v1/auth/oidc/providers");
            if (!resp.IsSuccessStatusCode) return null;
            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc    = await JsonDocument.ParseAsync(stream);
            if (doc.RootElement.TryGetProperty("data", out var d))
                return d.Deserialize<List<OidcProviderPublicDto>>(JsonOpts);
            return null;
        }
        catch { return null; }
    }

    public async Task<List<OidcProviderDto>?> GetOidcProvidersAdminAsync()
        => (await GetAsync<ListResult<OidcProviderDto>>("/api/v1/system/oidc-providers"))?.Data;

    public async Task<bool> CreateOidcProviderAsync(
        string name, string displayName, string authority, string clientId, string? clientSecret,
        string? scopes, string? groupClaimType, string? groupRoleMapping,
        bool autoProvision, string defaultRole, bool isEnabled)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var body   = JsonSerializer.Serialize(new
            {
                name, displayName, authority, clientId, clientSecret,
                scopes, groupClaimType, groupRoleMapping,
                autoProvisionUsers = autoProvision, defaultRole, isEnabled
            }, JsonOpts);
            var resp = await client.PostAsync("/api/v1/system/oidc-providers",
                new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdateOidcProviderAsync(
        Guid id, string? displayName, string? authority, string? clientId, string? clientSecret,
        string? scopes, string? groupClaimType, string? groupRoleMapping,
        bool? autoProvision, string? defaultRole, bool? isEnabled)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var body   = JsonSerializer.Serialize(new
            {
                displayName, authority, clientId, clientSecret,
                scopes, groupClaimType, groupRoleMapping,
                autoProvisionUsers = autoProvision, defaultRole, isEnabled
            }, JsonOpts);
            var resp = await client.PutAsync("/api/v1/system/oidc-providers/" + id,
                new StringContent(body, System.Text.Encoding.UTF8, "application/json"));
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteOidcProviderAsync(Guid id)
    {
        try { return (await (await GetAuthClientAsync()).DeleteAsync("/api/v1/system/oidc-providers/" + id)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<OidcTestResultDto?> TestOidcProviderAsync(Guid id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp   = await client.PostAsync("/api/v1/system/oidc-providers/" + id + "/test", null);
            if (!resp.IsSuccessStatusCode) return null;
            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc    = await JsonDocument.ParseAsync(stream);
            return doc.RootElement.Deserialize<OidcTestResultDto>(JsonOpts);
        }
        catch { return null; }
    }

    // ── FIDO2 / Biometric Passkey ─────────────────────────────────────────────

    public async Task<object?> BeginFido2RegistrationAsync(string? type = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var url = "/api/v1/auth/fido2/register/begin" + (type != null ? $"?type={type}" : "");
            var resp = await client.PostAsync(url, null);
            if (!resp.IsSuccessStatusCode) return null;
            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc    = await JsonDocument.ParseAsync(stream);
            return doc.RootElement.TryGetProperty("data", out var d) ? d.Clone() : (object?)null;
        }
        catch { return null; }
    }

    public async Task<List<SecurityKeyDto>?> GetFido2CredentialsAsync()
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp   = await client.GetAsync("/api/v1/auth/fido2/credentials");
            if (!resp.IsSuccessStatusCode) return null;
            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc    = await JsonDocument.ParseAsync(stream);
            if (doc.RootElement.TryGetProperty("data", out var d))
                return d.Deserialize<List<SecurityKeyDto>>(JsonOpts);
            return null;
        }
        catch { return null; }
    }

    public async Task<bool> RevokeFido2DeviceAsync(string? credId)
    {
        if (string.IsNullOrEmpty(credId)) return false;
        try
        {
            var client = await GetAuthClientAsync();
            return (await client.DeleteAsync("/api/v1/auth/fido2/credentials/" + credId)).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── Private helpers ────────────────────────────────────────────────────────

    private async Task<HttpClient> GetAuthClientAsync()
    {
        var client = _factory.CreateClient("PamApi");
        var token = await _auth.GetTokenAsync();
        if (!string.IsNullOrEmpty(token))
            client.DefaultRequestHeaders.Authorization =
                new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    public Task<HttpClient> GetAuthHttpClientAsync() => GetAuthClientAsync();

    /// <summary>
    /// GET helper: tries to deserialize the `data` sub-field of the API envelope first.
    /// Falls back to reading the full root JSON for wrapper types (PagedResult/ListResult).
    /// </summary>
    private async Task<T?> PostAsync<T>(string url, object? payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            HttpResponseMessage resp;
            if (payload == null)
                resp = await client.PostAsync(url, null);
            else
                resp = await client.PostAsJsonAsync(url, payload, JsonOpts);
            if (!resp.IsSuccessStatusCode) return default;
            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc = await JsonDocument.ParseAsync(stream);
            if (doc.RootElement.TryGetProperty("data", out var dataProp))
            {
                try { return dataProp.Deserialize<T>(JsonOpts); }
                catch { /* fall through */ }
            }
            return doc.RootElement.Deserialize<T>(JsonOpts);
        }
        catch { return default; }
    }

    private async Task<T?> GetAsync<T>(string url)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.GetAsync(url);
            if (!resp.IsSuccessStatusCode) return default;
            using var stream = await resp.Content.ReadAsStreamAsync();
            using var doc    = await JsonDocument.ParseAsync(stream);
            if (doc.RootElement.TryGetProperty("data", out var dataProp))
            {
                try { return dataProp.Deserialize<T>(JsonOpts); }
                catch { /* fall through to root deserialization */ }
            }
            return doc.RootElement.Deserialize<T>(JsonOpts);
        }
        catch { return default; }
    }

    // ── Report Export — PDF / Excel (Sprint 63 / #290) ────────────────────────
    public async Task<byte[]?> ExportReportPdfAsync(string reportType, DateTime from, DateTime to)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var url = "/api/v1/reports/export/pdf?reportType=" + Uri.EscapeDataString(reportType) +
                      "&from=" + Uri.EscapeDataString(from.ToString("O")) +
                      "&to="   + Uri.EscapeDataString(to.ToString("O"));
            var resp = await client.GetAsync(url);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadAsByteArrayAsync();
        }
        catch { return null; }
    }

    public async Task<byte[]?> ExportReportExcelAsync(string reportType, DateTime from, DateTime to)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var url = "/api/v1/reports/export/excel?reportType=" + Uri.EscapeDataString(reportType) +
                      "&from=" + Uri.EscapeDataString(from.ToString("O")) +
                      "&to="   + Uri.EscapeDataString(to.ToString("O"));
            var resp = await client.GetAsync(url);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadAsByteArrayAsync();
        }
        catch { return null; }
    }

    // ══════════════════════════════════════════════════════════════════════
    // Stub methods — generated to fix build errors
    // ══════════════════════════════════════════════════════════════════════

    // ── GET methods returning DTOs / lists ────────────────────────────────
    public async Task<List<FolderDto>?> GetFoldersAsync() => await GetAsync<List<FolderDto>>("/api/v1/vault/folders");
    public async Task<List<CredentialDto>?> GetFolderCredentialsAsync(string folderId) => await GetAsync<List<CredentialDto>>($"/api/v1/vault/folders/{folderId}/credentials");
    public async Task<List<AssignedCredentialDto>?> GetAssignedCredentialsAsync() => await GetAsync<List<AssignedCredentialDto>>("/api/v1/vault/assigned-credentials");
    public async Task<List<AlertRuleDto>?> GetAlertRulesAsync() => await GetAsync<List<AlertRuleDto>>("/api/v1/threat-analytics/alert-rules");
    public async Task<PagedResult<ReportDto>?> GetReportsListAsync() => await GetAsync<PagedResult<ReportDto>>("/api/v1/reports");
    public async Task<PagedResult<ReportScheduleDto>?> GetReportSchedulesAsync() => await GetAsync<PagedResult<ReportScheduleDto>>("/api/v1/reports/schedules");
    public async Task<List<CustomReportDefinitionDto>?> GetCustomReportsAsync() => await GetAsync<List<CustomReportDefinitionDto>>("/api/v1/reports/custom");
    public async Task<PolicyListResult?> GetPoliciesAsync(string? typeFilter = null) { var list = await GetAsync<List<PolicyDto>>("/api/v1/policies" + (typeFilter != null ? $"?type={typeFilter}" : "")); return list != null ? new PolicyListResult(list) : null; }
    public async Task<List<SoarConfigDto>?> GetSoarConfigsAsync() => await GetAsync<List<SoarConfigDto>>("/api/v1/integrations/soar");
    public async Task<List<ItsmConfigDto>?> GetItsmConfigsAsync() => await GetAsync<List<ItsmConfigDto>>("/api/v1/integrations/itsm");
    public async Task<List<TrustedCaDto>?> GetTrustedCasAsync() => await GetAsync<List<TrustedCaDto>>("/api/v1/integrations/pki/cas");
    public async Task<List<PkiUserCertDto>?> GetPkiUserCertsAsync() => await GetAsync<List<PkiUserCertDto>>("/api/v1/integrations/pki/user-certs");
    public async Task<List<SiemTargetDto>?> GetSiemTargetsAsync() => await GetAsync<List<SiemTargetDto>>("/api/v1/integrations/siem");
    public async Task<List<PushDeviceDto>?> GetPushDevicesAsync() => await GetAsync<List<PushDeviceDto>>("/api/v1/mfa/push-devices");
    public async Task<SocDashboardDto?> GetSocDashboardAsync() => await GetAsync<SocDashboardDto>("/api/v1/threat-analytics/dashboard");
    public async Task<List<AnomalyDto>?> GetAnomaliesAsync(int? severity = null, string? type = null) => await GetAsync<List<AnomalyDto>>("/api/v1/threat-analytics/anomalies" + (type != null ? $"?type={type}" : ""));
    public async Task<List<RiskMapDto>?> GetSocRiskMapAsync() => await GetAsync<List<RiskMapDto>>("/api/v1/threat-analytics/risk-map");
    public async Task<List<BehaviorBaselineDto>?> GetBehaviorBaselinesAsync() => await GetAsync<List<BehaviorBaselineDto>>("/api/v1/threat-analytics/baselines");
    public async Task<SystemHealthSnapshotDto?> GetSystemHealthAsync() => await GetAsync<SystemHealthSnapshotDto>("/api/v1/system/health");
    public async Task<ListResult<SystemAlarmDto>?> GetSystemAlarmsAsync(string? status = null, string? severity = null) => await GetAsync<ListResult<SystemAlarmDto>>("/api/v1/system/alarms");
    public async Task<PagedResult<SystemLogEntryDto>?> GetSystemLogsAsync(string? activeTab = null, string? levelFilter = null, string? searchFilter = null, int page = 1, int pageSize = 50) => await GetAsync<PagedResult<SystemLogEntryDto>>("/api/v1/system/logs");
    public async Task<List<SessionDto>?> GetActiveSessionsAsync() => await GetAsync<List<SessionDto>>("/api/v1/sessions?status=Active");
    public async Task<List<CredentialTemplateDto>?> GetCredentialTemplatesAsync() => await GetAsync<List<CredentialTemplateDto>>("/api/v1/vault/credential-templates");
    public async Task<List<RotationScriptDto>?> GetRotationScriptsAsync() => await GetAsync<List<RotationScriptDto>>("/api/v1/vault/rotation-scripts");
    public async Task<RotationScriptDto?> GetRotationScriptAsync(string id) => await GetAsync<RotationScriptDto>($"/api/v1/vault/rotation-scripts/{id}");
    public async Task<List<DiscoveredAccountDto>?> GetDiscoveredAccountsAsync(string? status = null) => await GetAsync<List<DiscoveredAccountDto>>("/api/v1/discovery/accounts" + (!string.IsNullOrEmpty(status) ? $"?status={status}" : ""));
    public async Task<List<DiscoveryJobDto>?> GetDiscoveryJobsAsync() => await GetAsync<List<DiscoveryJobDto>>("/api/v1/discovery/jobs");
    public async Task<KeyStatusDto?> GetEncryptionStatusAsync() => await GetAsync<KeyStatusDto>("/api/v1/encryption/status");
    public async Task<FipsStatusDto?> GetFipsStatusAsync() => await GetAsync<FipsStatusDto>("/api/v1/encryption/fips");
    public async Task<CredentialRiskSummaryDto?> GetCredentialRiskSummaryAsync() => await GetAsync<CredentialRiskSummaryDto>("/api/v1/vault/risk-summary");
    public async Task<List<HighRiskCredentialDto>?> GetHighRiskCredentialsAsync() => await GetAsync<List<HighRiskCredentialDto>>("/api/v1/vault/high-risk");
    public async Task<RotationFailuresResponseDto?> GetRotationFailuresAsync() => await GetAsync<RotationFailuresResponseDto>("/api/v1/vault/rotation-failures");
    public async Task<CredentialGovernanceSummaryDto?> GetCredentialGovernanceSummaryAsync() => await GetAsync<CredentialGovernanceSummaryDto>("/api/v1/vault/governance/summary");
    public async Task<CredentialAccessMatrixResultDto?> GetCredentialAccessMatrixAsync(int page = 1, int pageSize = 50) => await GetAsync<CredentialAccessMatrixResultDto>($"/api/v1/vault/governance/access-matrix?page={page}&pageSize={pageSize}");
    public async Task<List<StaleCredentialAccessDto>?> GetStaleCredentialAccessAsync(int days = 90) => await GetAsync<List<StaleCredentialAccessDto>>($"/api/v1/vault/governance/stale?days={days}");
    public async Task<List<JitRequestDto>?> GetJitRequestsAsync(string? status = null) => await GetAsync<List<JitRequestDto>>("/api/v1/jit/requests" + (status != null ? "?status=" + status : ""));
    public async Task<List<JitRequestDto>?> GetMyJitRequestsAsync() => await GetAsync<List<JitRequestDto>>("/api/v1/jit/my-requests");
    public async Task<BreakGlassListResult?> GetBreakGlassEventsAsync(string? statusFilter = null) { var list = await GetAsync<List<BreakGlassDto>>("/api/v1/break-glass" + (statusFilter != null ? $"?status={statusFilter}" : "")); return list != null ? new BreakGlassListResult(list) : null; }
    public async Task<BreakGlassListResult?> GetMyBreakGlassEventsAsync() { var list = await GetAsync<List<BreakGlassDto>>("/api/v1/break-glass/my"); return list != null ? new BreakGlassListResult(list) : null; }
    public async Task<List<PendingApprovalDto>?> GetPendingApprovalsAsync(string? userId = null) => await GetAsync<List<PendingApprovalDto>>("/api/v1/approvals/pending" + (userId != null ? $"?userId={userId}" : ""));
    public async Task<PagedResult<ApprovalRequestDto>?> GetApprovalsAsync(string? status = null, int page = 1, int pageSize = 20) => await GetAsync<PagedResult<ApprovalRequestDto>>("/api/v1/approvals");
    public async Task<List<VendorAccessDto>?> GetVendorAccessListAsync(string? filter = null) => await GetAsync<List<VendorAccessDto>>("/api/v1/vendors/access" + (filter != null ? $"?filter={filter}" : ""));
    public async Task<List<AttestationCampaignDto>?> GetAttestationsAsync() => await GetAsync<List<AttestationCampaignDto>>("/api/v1/compliance/attestations");
    public async Task<AttestationDetailDto?> GetAttestationDetailAsync(string id) => await GetAsync<AttestationDetailDto>($"/api/v1/compliance/attestations/{id}");
    public async Task<List<ReconciliationDriftDto>?> GetReconciliationReportAsync() => await GetAsync<List<ReconciliationDriftDto>>("/api/v1/compliance/reconciliation/report");
    public async Task<List<ReconciliationHistoryDto>?> GetReconciliationHistoryAsync() => await GetAsync<List<ReconciliationHistoryDto>>("/api/v1/compliance/reconciliation/history");
    public async Task<CloudDashboardDto?> GetCloudDashboardAsync() => await GetAsync<CloudDashboardDto>("/api/v1/cloud/dashboard");
    public async Task<List<CloudAccountDto>?> GetCloudAccountsAsync() => await GetAsync<List<CloudAccountDto>>("/api/v1/cloud/accounts");
    public async Task<List<CloudResourceDto>?> GetCloudResourcesAsync(string? provider = null, string? resourceType = null) { var url = "/api/v1/cloud/resources"; var sep = "?"; if (provider != null) { url += sep + "provider=" + provider; sep = "&"; } if (resourceType != null) { url += sep + "resourceType=" + resourceType; } return await GetAsync<List<CloudResourceDto>>(url); }
    public async Task<List<CloudJitDto>?> GetCloudJitRequestsAsync(string? status = null) => await GetAsync<List<CloudJitDto>>("/api/v1/cloud/jit" + (status != null ? "?status=" + status : ""));
    public async Task<List<TrustedDeviceDto>?> GetMyTrustedDevicesAsync() => await GetAsync<List<TrustedDeviceDto>>("/api/v1/auth/trusted-devices");
    public async Task<List<MySessionDto>?> GetMySessionsAsync() => await GetAsync<List<MySessionDto>>("/api/v1/sessions/my");
    public async Task<UserProfileDto?> GetMyProfileAsync() => await GetAsync<UserProfileDto>("/api/v1/auth/profile");
    public async Task<List<MfaDeviceDto>?> GetMyMfaDevicesAsync() => await GetAsync<List<MfaDeviceDto>>("/api/v1/mfa/my-devices");
    public async Task<List<DeviceDto>?> GetMyAccessibleDevicesAsync() => await GetAsync<List<DeviceDto>>("/api/v1/devices/my");
    public async Task<CurrentUserDto?> GetCurrentUserAsync() => await GetAsync<CurrentUserDto>("/api/v1/auth/me");
    public async Task<RecordingMetadataDto?> GetRecordingMetadataAsync(string sessionId) => await GetAsync<RecordingMetadataDto>($"/api/v1/sessions/{sessionId}/recording/metadata");
    public async Task<RecordingStreamDto?> GetRecordingStreamAsync(string sessionId) => await GetAsync<RecordingStreamDto>($"/api/v1/sessions/{sessionId}/recording");
    public async Task<ListResult<RecordingSearchHitDto>?> SearchRecordingAsync(string sessionId, string query) => await GetAsync<ListResult<RecordingSearchHitDto>>($"/api/v1/sessions/{sessionId}/recording/search?q={Uri.EscapeDataString(query)}");
    public async Task<List<ScreenCaptureFrameDto>?> GetScreenCapturesAsync(string sessionId) => await GetAsync<List<ScreenCaptureFrameDto>>($"/api/v1/sessions/{sessionId}/recording/captures");
    public async Task<List<RdpHaNodeDto>?> GetRdpHaNodesAsync() => await GetAsync<List<RdpHaNodeDto>>("/api/v1/rdp/ha-nodes");
    public async Task<List<RemoteAppDto>?> GetRemoteAppsAsync() => await GetAsync<List<RemoteAppDto>>("/api/v1/rdp/remote-apps");
    public async Task<ExecutiveDashboardDto?> GetExecutiveDashboardAsync() => await GetAsync<ExecutiveDashboardDto>("/api/v1/reports/executive");
    public async Task<List<TacacsCommandPolicyDto>?> GetTacacsCommandPoliciesAsync() => await GetAsync<List<TacacsCommandPolicyDto>>("/api/v1/network-access/policies");
    public async Task<ThreatIntelReportDto?> GetThreatFeedReportAsync() => await GetAsync<ThreatIntelReportDto>("/api/v1/threat-analytics/threat-intel/report");
    public async Task<List<ThreatFeedConfigDto>?> GetThreatFeedConfigsAsync() => await GetAsync<List<ThreatFeedConfigDto>>("/api/v1/threat-analytics/threat-intel/feeds");
    public async Task<AccessPatternSummaryDto?> GetAccessPatternSummaryAsync(int days) => await GetAsync<AccessPatternSummaryDto>($"/api/v1/reports/access-patterns/summary?days={days}");
    public async Task<AccessPatternTimeOfDayDto?> GetAccessPatternTimeOfDayAsync(int days) => await GetAsync<AccessPatternTimeOfDayDto>($"/api/v1/reports/access-patterns/time-of-day?days={days}");
    public async Task<ApiUsageSummaryDto?> GetApiUsageSummaryAsync(int days) => await GetAsync<ApiUsageSummaryDto>($"/api/v1/reports/api-usage/summary?days={days}");
    public async Task<ApiUsageAnomaliesDto?> GetApiUsageAnomaliesAsync(int days) => await GetAsync<ApiUsageAnomaliesDto>($"/api/v1/reports/api-usage/anomalies?days={days}");
    public async Task<List<RestorableSessionDto>?> GetRestorableSessionsAsync() => await GetAsync<List<RestorableSessionDto>>("/api/v1/sessions/restorable");
    public async Task<ConnectionProfileResultDto?> GetConnectionProfileAsync(string deviceId, string credentialId, string? client = null) => await GetAsync<ConnectionProfileResultDto>($"/api/v1/sessions/connect/{deviceId}/{credentialId}" + (client != null ? $"?client={client}" : ""));
    public async Task<List<LdapConfigDto>?> GetLdapConfigsAsync() => await GetAsync<List<LdapConfigDto>>("/api/v1/integrations/ldap");
    public async Task<WindowsAuthSettingsDto?> GetWindowsAuthSettingsAsync() => await GetAsync<WindowsAuthSettingsDto>("/api/v1/integrations/windows-auth");
    public async Task<PasswordPolicySettingsDto?> GetPasswordPolicyAsync() => await GetAsync<PasswordPolicySettingsDto>("/api/v1/policies/password");
    public async Task<LockoutPolicySettingsDto?> GetLockoutPolicyAsync() => await GetAsync<LockoutPolicySettingsDto>("/api/v1/policies/lockout");
    public async Task<SessionPolicySettingsDto?> GetSessionPolicyAsync() => await GetAsync<SessionPolicySettingsDto>("/api/v1/policies/session");
    public async Task<MfaPolicySettingsDto?> GetMfaPolicySettingsAsync() => await GetAsync<MfaPolicySettingsDto>("/api/v1/policies/mfa-settings");
    public async Task<WatermarkPolicySettingsDto?> GetWatermarkPolicyAsync() => await GetAsync<WatermarkPolicySettingsDto>("/api/v1/policies/watermark");
    public async Task<AdaptiveMfaPolicySettingsDto?> GetAdaptiveMfaPolicyAsync() => await GetAsync<AdaptiveMfaPolicySettingsDto>("/api/v1/policies/adaptive-mfa");
    public async Task<DeviceTrustPolicySettingsDto?> GetDeviceTrustPolicyAsync() => await GetAsync<DeviceTrustPolicySettingsDto>("/api/v1/policies/device-trust");
    public async Task<GeolocationPolicySettingsDto?> GetGeolocationPolicyAsync() => await GetAsync<GeolocationPolicySettingsDto>("/api/v1/policies/geolocation");
    public async Task<BackupScheduleDto?> GetBackupScheduleAsync() => await GetAsync<BackupScheduleDto>("/api/v1/system/backup/schedule");
    public async Task<HealthAlarmConfigDto?> GetHealthAlarmConfigAsync() => await GetAsync<HealthAlarmConfigDto>("/api/v1/system/health/alarm-config");
    public async Task<SmsGatewayConfigDto?> GetSmsGatewayConfigAsync() => await GetAsync<SmsGatewayConfigDto>("/api/v1/integrations/sms/config");
    public async Task<MfaEnrollmentDto?> GetMfaEnrollmentAsync(string token) => await GetAsync<MfaEnrollmentDto>($"/api/v1/mfa/enrollment/{token}");
    public async Task<int> GetTotalCountAsync(string path) { var r = await GetAsync<PageMeta>(path); return r?.TotalCount ?? 0; }
    public string GetBackupDownloadUrl(string id) => $"/api/v1/system/backup/{id}/download";

    // ── Report running ────────────────────────────────────────────────────
    public async Task<ReportRunResult?> RunReportAsync(string reportId, DateTime from, DateTime to)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/reports/{reportId}/run", new { from, to });
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<ReportRunResult>(JsonOpts);
        }
        catch { return null; }
    }

    public async Task<ComplianceReportResultDto?> GenerateComplianceReportAsync(string framework, DateTime from, DateTime to)
        => await PostAsync<ComplianceReportResultDto>("/api/v1/reports/compliance/evaluate", new { framework, from, to });

    public async Task<AuditVerifyResult?> VerifyAuditIntegrityAsync()
        => await PostAsync<AuditVerifyResult>("/api/v1/audit/verify-integrity", new { });

    // ── Credential access request ────────────────────────────────────────
    public async Task<AccessRequestResultDto?> RequestCredentialAccessAsync(string credentialId, string reason, string? ticketNumber = null)
        => await PostAsync<AccessRequestResultDto>($"/api/v1/vault/credentials/{credentialId}/request-access", new { reason, ticketNumber });

    // ── Session / Launch ──────────────────────────────────────────────────
    public async Task<object?> GenerateLaunchTokenAsync(string deviceId, string credentialId)
        => await PostAsync<object>("/api/v1/sessions/launch-token", new { deviceId, credentialId });

    public async Task<RdpLaunchResultDto?> LaunchRdpSessionAsync(string deviceId, string credentialId)
        => await PostAsync<RdpLaunchResultDto>("/api/v1/sessions/launch/rdp", new { deviceId, credentialId });

    public async Task<RdpLaunchResultDto?> ShadowSessionAsync(string sessionId)
        => await PostAsync<RdpLaunchResultDto>($"/api/v1/sessions/{sessionId}/shadow", new { });

    // ── POST methods returning bool ───────────────────────────────────────
    public async Task<bool> CreateFolderAsync(string name, string? description = null, Guid? parentId = null) => await PostBoolAsync("/api/v1/vault/folders", new { name, description, parentId });
    public async Task<bool> CreatePolicyAsync(string name, string? description = null, string? policyType = null) => await PostBoolAsync("/api/v1/policies", new { name, description, policyType });
    public async Task<bool> CreatePolicyAsync(string name, string policyType, int scope, string policyJson, int priority) => await PostBoolAsync("/api/v1/policies", new { name, policyType, scope, policyJson, priority });
    public async Task<bool> CreateSoarConfigAsync(string name, string provider, string webhookUrl, string secret) => await PostBoolAsync("/api/v1/integrations/soar", new { name, provider, webhookUrl, secret });
    public async Task<bool> CreateItsmConfigAsync(string name, string provider, string baseUrl, string username, string apiKey, string password, bool requireTicket, bool validateTicket) => await PostBoolAsync("/api/v1/integrations/itsm", new { name, provider, baseUrl, username, apiKey, password, requireTicket, validateTicket });
    public async Task<bool> CreateSiemTargetAsync(string name, string host, int port, string protocol, string format, int facility) => await PostBoolAsync("/api/v1/integrations/siem", new { name, host, port, protocol, format, facility });
    public async Task<bool> CreateAlertRuleAsync(string name, string conditionJson, string actionJson, int cooldownMinutes) => await PostBoolAsync("/api/v1/threat-analytics/alert-rules", new { name, conditionJson, actionJson, cooldownMinutes });
    public async Task<bool> CreateAssignedCredentialAsync(string credentialId, string principalType, string principalId, string? deviceGroupId, string? notes = null) => await PostBoolAsync("/api/v1/vault/assigned-credentials", new { credentialId, principalType, principalId, deviceGroupId, notes });
    public async Task<bool> CreateAttestationAsync(string name, string scopeType, string? scopeFilter, DateTime startsAtUtc, DateTime deadlineUtc, bool autoRevokeOnMiss) => await PostBoolAsync("/api/v1/compliance/attestations", new { name, scopeType, startsAtUtc, deadlineUtc, autoRevokeOnMiss });
    public async Task<bool> CreateCloudAccountAsync(string name, string provider, string accountIdentifier, string region, string keyId, string secret) => await PostBoolAsync("/api/v1/cloud/accounts", new { name, provider, accountIdentifier, region, keyId, secret });
    public async Task<bool> CreateCloudJitRequestAsync(string resourceId, string permission, string justification, int durationMinutes, string? ticketNumber) => await PostBoolAsync("/api/v1/cloud/jit", new { resourceId, permission, justification, durationMinutes, ticketNumber });
    public async Task<bool> CreateCredentialTemplateAsync(string name, string? description, string? deviceType, string? defaultUsername, string? credentialKind, int rotationPeriodDays, int passwordMinLength, bool passwordRequireSpecial, bool sshKeyRotation, string? notes) => await PostBoolAsync("/api/v1/vault/credential-templates", new { name, description, deviceType, defaultUsername, credentialKind, rotationPeriodDays, passwordMinLength, passwordRequireSpecial, sshKeyRotation, notes });
    public async Task<bool> CreateDiscoveryJobAsync(string name, string type, string target, string? schedule) => await PostBoolAsync("/api/v1/discovery/jobs", new { name, type, target, schedule });
    public async Task<bool> CreateReportScheduleAsync(CreateReportScheduleDto dto) => await PostBoolAsync("/api/v1/reports/schedules", dto);
    public async Task<(bool Ok, string? Id)> CreateRotationScriptAsync(string name, string? description, string deviceType,
        string scriptType, string scriptContent, string? testScriptContent, bool isEnabled,
        string? connectorType = null, string? connectorConfig = null)
        => (await PostBoolAsync("/api/v1/vault/rotation-scripts", new { name, description, deviceType, scriptType, scriptContent, testScriptContent, isEnabled, connectorType, connectorConfig }), null);
    public async Task<bool> CreateLdapConfigAsync(string name, string host, int port, bool useSsl, string baseDn, string? bindDn, int syncInterval) => await PostBoolAsync("/api/v1/integrations/ldap", new { name, host, port, useSsl, baseDn, bindDn, syncInterval });
    public async Task<bool> CreateThreatFeedConfigAsync(string name, string url, string feedType, string? apiKey, int intervalMinutes, bool isEnabled) => await PostBoolAsync("/api/v1/threat-analytics/threat-intel/feeds", new { name, feedType, url, apiKey, intervalMinutes, isEnabled });
    public async Task<VendorAccessDto?> CreateVendorAccessAsync(
        string name, string company, string email, string phone,
        DateTime startAtUtc, DateTime endAtUtc,
        int? allowedHoursStart, int? allowedHoursEnd, int maxMinutes,
        List<Guid> deviceIds, string ipWhitelist, bool singleUse)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/vendors/access", new { name, company, email, phone, startAtUtc, endAtUtc, allowedHoursStart, allowedHoursEnd, maxMinutes, deviceIds, ipWhitelist, singleUse });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<VendorAccessDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    // ── POST methods returning bool (actions) ─────────────────────────────
    public async Task<bool> AcknowledgeAnomalyAsync(long id) => await PostBoolAsync($"/api/v1/threat-analytics/anomalies/{id}/acknowledge", new { });
    public async Task<bool> AcknowledgeBreakGlassAsync(string id, string? notes) => await PostBoolAsync($"/api/v1/break-glass/{id}/acknowledge", new { notes });
    public async Task<bool> ApproveJitRequestAsync(string id) => await PostBoolAsync($"/api/v1/jit/requests/{id}/approve", new { });
    public async Task<bool> DenyJitRequestAsync(string id, string? reason) => await PostBoolAsync($"/api/v1/jit/requests/{id}/deny", new { reason });
    public async Task<bool> RevokeJitRequestAsync(string id, string? reason) => await PostBoolAsync($"/api/v1/jit/requests/{id}/revoke", new { reason });
    public async Task<bool> ApproveJitExtensionAsync(string id) => await PostBoolAsync($"/api/v1/jit/requests/{id}/approve-extension", new { });
    public async Task<bool> RequestJitExtensionAsync(string id, int minutes = 60, string? reason = null) => await PostBoolAsync($"/api/v1/jit/requests/{id}/request-extension", new { minutes, reason });
    public async Task<bool> RevokeBreakGlassAsync(string id) => await PostBoolAsync($"/api/v1/break-glass/{id}/revoke", new { });
    public async Task<BreakGlassDto?> SubmitBreakGlassAsync(string resourceType, Guid? resourceId, string resourceName, string reason, string? ticketNumber, int durationMinutes) => await PostAsync<BreakGlassDto>("/api/v1/break-glass", new { resourceType, resourceId, resourceName, reason, ticketNumber, durationMinutes });
    public async Task<bool> SubmitJitRequestAsync(string resourceType, string? resourceName, string reason, int durationMinutes = 60, string? ticketNumber = null) => await PostBoolAsync("/api/v1/jit/requests", new { resourceType, resourceName, reason, durationMinutes, ticketNumber });
    public async Task<bool> DenyRequestAsync(string requestId, string? comment) => await PostBoolAsync($"/api/v1/approvals/{requestId}/deny", new { comment });
    public async Task<bool> ApproveCloudJitAsync(string id) => await PostBoolAsync($"/api/v1/cloud/jit/{id}/approve", new { });
    public async Task<bool> DenyCloudJitAsync(string id) => await PostBoolAsync($"/api/v1/cloud/jit/{id}/deny", new { });
    public async Task<bool> RevokeCloudJitAsync(string id) => await PostBoolAsync($"/api/v1/cloud/jit/{id}/revoke", new { });
    public async Task<CloudSyncResultDto?> SyncCloudAccountAsync(string id) { try { var c = await GetAuthClientAsync(); var r = await c.PostAsJsonAsync($"/api/v1/cloud/accounts/{id}/sync", new { }); if (!r.IsSuccessStatusCode) return null; return await r.Content.ReadFromJsonAsync<CloudSyncResultDto>(JsonOpts); } catch { return null; } }
    public async Task<bool> StartAttestationAsync(string id) => await PostBoolAsync($"/api/v1/compliance/attestations/{id}/start", new { });
    public async Task<bool> CompleteAttestationAsync(string id) => await PostBoolAsync($"/api/v1/compliance/attestations/{id}/complete", new { });
    public async Task<bool> DecideAttestationItemAsync(string campaignId, long decisionId, byte decision, string? comments) => await PostBoolAsync($"/api/v1/compliance/attestations/{campaignId}/decide", new { decisionId, decision, comments });
    public async Task<RemediationResultDto?> AutoRemediateReconciliationAsync() => await PostAsync<RemediationResultDto>("/api/v1/compliance/reconciliation/remediate", new { });
    public async Task<bool> EndMySessionAsync(string sessionId) => await PostBoolAsync($"/api/v1/sessions/{sessionId}/end", new { });
    public async Task<RestoreSessionResultDto?> RestoreSessionAsync(Guid tokenId) => await PostAsync<RestoreSessionResultDto>($"/api/v1/sessions/restore/{tokenId}", new { });
    public async Task<bool> CancelRestoreTokenAsync(Guid tokenId) => await PostBoolAsync($"/api/v1/sessions/restore/{tokenId}/cancel", new { });
    public async Task<(bool, string?)> ChangePasswordAsync(string currentPassword, string newPassword)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/change-password", new { currentPassword, newPassword });
            if (resp.IsSuccessStatusCode) return (true, null);
            var body = await resp.Content.ReadAsStringAsync();
            return (false, body);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }
    public async Task<bool> ForgotPasswordAsync(string username, string? email = null) => await PostBoolAsync("/api/v1/auth/forgot-password", new { username, email });
    public async Task<(bool Success, string? Message)> ResetPasswordAsync(string token, string newPassword)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password", new { token, newPassword });
            var body = await resp.Content.ReadAsStringAsync();
            return resp.IsSuccessStatusCode ? (true, body) : (false, body);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }
    public async Task<bool> RevokeMfaDeviceByTypeAsync(string type) => await PostBoolAsync($"/api/v1/mfa/revoke-by-type", new { type });
    public async Task<bool> RevokeMyTrustedDeviceAsync(Guid deviceId) => await PostBoolAsync($"/api/v1/auth/trusted-devices/{deviceId}/revoke", new { });
    public async Task<bool> RenameMyTrustedDeviceAsync(Guid deviceId, string name) => await PostBoolAsync($"/api/v1/auth/trusted-devices/{deviceId}/rename", new { name });
    public async Task<PushEnrollResultDto?> EnrollPushDeviceAsync(string name) => await PostAsync<PushEnrollResultDto>("/api/v1/mfa/push-devices/enroll", new { name });
    public async Task<bool> RemovePushDeviceAsync(string deviceId) => await DeleteBoolAsync($"/api/v1/mfa/push-devices/{deviceId}");
    public async Task<bool> RevokePushDeviceAsync(string deviceId) => await PostBoolAsync($"/api/v1/mfa/push-devices/{deviceId}/revoke", new { });
    public async Task<bool> ClearAlarmAsync(long id) => await PostBoolAsync($"/api/v1/system/alarms/{id}/clear", new { });
    public async Task<(bool Success, string? Message)> RotateEncryptionKeyAsync(string passphrase, string confirm)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/encryption/rotate", new { passphrase, confirm });
            var body = await resp.Content.ReadAsStringAsync();
            return resp.IsSuccessStatusCode ? (true, body) : (false, body);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }
    public async Task<string?> ExportKeyBackupAsync(string passphrase) { try { var c = await GetAuthClientAsync(); var r = await c.PostAsJsonAsync("/api/v1/encryption/backup", new { passphrase }); return r.IsSuccessStatusCode ? await r.Content.ReadAsStringAsync() : null; } catch { return null; } }
    public async Task<SshKeyPairDto?> GenerateSshKeyPairAsync() { try { var c = await GetAuthClientAsync(); var r = await c.PostAsJsonAsync("/api/v1/vault/ssh-keys/generate", new { }); if (!r.IsSuccessStatusCode) return null; return await r.Content.ReadFromJsonAsync<SshKeyPairDto>(JsonOpts); } catch { return null; } }
    public async Task<MfaSetupLinkDto?> GenerateMfaSetupLinkAsync(string userId) { try { var c = await GetAuthClientAsync(); var r = await c.PostAsJsonAsync($"/api/v1/users/{userId}/mfa-setup", new { }); if (!r.IsSuccessStatusCode) return null; return await r.Content.ReadFromJsonAsync<MfaSetupLinkDto>(JsonOpts); } catch { return null; } }
    public async Task<bool> ResetUserMfaAsync(string userId) => await PostBoolAsync($"/api/v1/users/{userId}/reset-mfa", new { });
    public async Task<MfaConfirmResult?> ConfirmMfaEnrollmentAsync(string token, string code)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/mfa/confirm", new { token, code });
            if (!resp.IsSuccessStatusCode) return new MfaConfirmResult(false, null);
            var data = await resp.Content.ReadFromJsonAsync<MfaConfirmDataDto>(JsonOpts);
            return new MfaConfirmResult(true, data);
        }
        catch { return new MfaConfirmResult(false, null); }
    }
    public async Task<ImportResultDto?> BulkImportUsersAsync(object file) => await PostAsync<ImportResultDto>("/api/v1/users/import", new { file });
    public async Task<BulkImportResultDto?> BulkImportDiscoveredAccountsAsync(List<string> ids, Guid folderId) => await PostAsync<BulkImportResultDto>("/api/v1/discovery/accounts/bulk-import", new { ids, folderId });
    public async Task<bool> IgnoreDiscoveredAccountAsync(string id) => await PostBoolAsync($"/api/v1/discovery/accounts/{id}/ignore", new { });
    public async Task<DiscoveryScanResultDto?> RunDiscoveryJobAsync(string id) => await PostAsync<DiscoveryScanResultDto>($"/api/v1/discovery/jobs/{id}/run", new { });
    public async Task<bool> TakeoverAccountAsync(string accountId, Guid folderId) => await PostBoolAsync($"/api/v1/discovery/accounts/{accountId}/takeover", new { folderId });
    public async Task<bool> ForceRefreshThreatFeedsAsync() => await PostBoolAsync("/api/v1/threat-analytics/threat-intel/refresh", new { });
    public async Task<LdapSyncResultDto?> SyncLdapNowAsync(string configId) => await PostAsync<LdapSyncResultDto>($"/api/v1/integrations/ldap/{configId}/sync", new { });
    public async Task<bool> RunReportScheduleNowAsync(string id) => await PostBoolAsync($"/api/v1/reports/schedules/{id}/run", new { });
    public async Task<CustomReportPreviewResultDto?> RunSavedCustomReportAsync(string id) => await PostAsync<CustomReportPreviewResultDto>($"/api/v1/reports/custom/{id}/run", new { });
    public async Task<bool> SaveCustomReportAsync(string name, string? id, string dataSource, string filtersJson, string columnsJson) => await PostBoolAsync("/api/v1/reports/custom", new { name, id, dataSource, filtersJson, columnsJson });
    public async Task<CustomReportPreviewResultDto?> PreviewCustomReportAsync(string dataSource, string filtersJson, string columnsJson, int limit = 50) => await PostAsync<CustomReportPreviewResultDto>("/api/v1/reports/custom/preview", new { dataSource, filtersJson, columnsJson, limit });
    public async Task<byte[]?> ExportCredentialsCsvAsync() { try { var c = await GetAuthClientAsync(); var r = await c.GetAsync("/api/v1/vault/credentials/export/csv"); return r.IsSuccessStatusCode ? await r.Content.ReadAsByteArrayAsync() : null; } catch { return null; } }
    public async Task<bool> ImportCertificateAsync(string pem, string? notes, string? source) => await PostBoolAsync("/api/v1/certificates/import", new { pem, notes, source });
    public async Task<bool> AddTrustedCaAsync(string name, string pem, string? ocspUrl, string? crlUrl, bool checkRevocation) => await PostBoolAsync("/api/v1/integrations/pki/cas", new { name, pem, ocspUrl, crlUrl, checkRevocation });
    public async Task<bool> MapUserCertAsync(string userId, string pem, bool requirePkiOnly) => await PostBoolAsync("/api/v1/integrations/pki/user-certs", new { userId, pem, requirePkiOnly });
    public async Task<bool> SavePasswordPolicyAsync(PasswordPolicySettingsDto dto) => await PostBoolAsync("/api/v1/policies/password", dto);
    public async Task<bool> SaveLockoutPolicyAsync(LockoutPolicySettingsDto dto) => await PostBoolAsync("/api/v1/policies/lockout", dto);
    public async Task<bool> SaveSessionPolicyAsync(SessionPolicySettingsDto dto) => await PostBoolAsync("/api/v1/policies/session", dto);
    public async Task<bool> SaveMfaPolicyAsync(MfaPolicySettingsDto dto) => await PostBoolAsync("/api/v1/policies/mfa-settings", dto);
    public async Task<bool> SaveWatermarkPolicyAsync(WatermarkPolicySettingsDto dto) => await PostBoolAsync("/api/v1/policies/watermark", dto);
    public async Task<bool> SaveAdaptiveMfaPolicyAsync(AdaptiveMfaPolicySettingsDto dto) => await PostBoolAsync("/api/v1/policies/adaptive-mfa", dto);
    public async Task<bool> SaveDeviceTrustPolicyAsync(DeviceTrustPolicySettingsDto dto) => await PostBoolAsync("/api/v1/policies/device-trust", dto);
    public async Task<bool> SaveGeolocationPolicyAsync(GeolocationPolicySettingsDto dto) => await PostBoolAsync("/api/v1/policies/geolocation", dto);
    public async Task<bool> SaveBackupScheduleAsync(bool enabled, int hourUtc, string scope, string? passphrase) => await PostBoolAsync("/api/v1/system/backup/schedule", new { enabled, hourUtc, scope, passphrase });
    public async Task<bool> SaveHealthAlarmConfigAsync(double cpuWarn, double memWarn, double diskFreeWarn, string recipients) => await PostBoolAsync("/api/v1/system/health/alarm-config", new { cpuWarn, memWarn, diskFreeWarn, recipients });
    public async Task<bool> SaveSmsGatewayConfigAsync(SmsGatewayConfigDto dto) => await PostBoolAsync("/api/v1/integrations/sms/config", dto);
    public async Task<bool> SaveWindowsAuthSettingsAsync(bool enabled, bool autoProvision, bool mfaBypass, string trustedDomains) => await PostBoolAsync("/api/v1/integrations/windows-auth", new { enabled, autoProvision, mfaBypass, trustedDomains });
    public async Task<bool> SaveTacacsCommandPolicyAsync(string username, string devicePattern, string mode, string? commands) => await PostBoolAsync("/api/v1/network-access/policies", new { username, devicePattern, mode, commands });
    public async Task<VendorUserDto?> OnboardVendorAsync(string name, string email, string? phone, string? company, DateTime expiresUtc, List<Guid> deviceIds)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/vendors/onboard", new { name, email, phone, company, expiresUtc, deviceIds });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<VendorUserDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }
    public async Task<string?> ResendVendorInviteAsync(string id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/vendors/access/{id}/resend", new { });
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadAsStringAsync();
        }
        catch { return null; }
    }
    public async Task<bool> RevokeVendorAccessAsync(string id, string? reason) => await PostBoolAsync($"/api/v1/vendors/access/{id}/revoke", new { reason });
    public async Task<bool> RevokeVendorUserAsync(Guid id, string? reason) => await PostBoolAsync($"/api/v1/vendors/{id}/revoke", new { reason });
    public async Task<bool> ExtendVendorAccessAsync(Guid id, DateTime newExpiry) => await PostBoolAsync($"/api/v1/vendors/access/{id}/extend", new { newExpiry });
    public async Task<bool> VerifyBackupAsync(string id) => await PostBoolAsync($"/api/v1/system/backup/{id}/verify", new { });
    public async Task<bool> TogglePolicyAsync(string id, bool? enable = null) => await PostBoolAsync($"/api/v1/policies/{id}/toggle", new { enable });
    public async Task<bool> ToggleAlertRuleAsync(string id) => await PostBoolAsync($"/api/v1/threat-analytics/alert-rules/{id}/toggle", new { });
    public async Task<bool> ToggleAlertRuleAsync(Guid id) => await ToggleAlertRuleAsync(id.ToString());
    public async Task<bool> ToggleAssignedCredentialAsync(string id) => await PostBoolAsync($"/api/v1/vault/assigned-credentials/{id}/toggle", new { });
    public async Task<bool> ToggleCloudAccountAsync(string id) => await PostBoolAsync($"/api/v1/cloud/accounts/{id}/toggle", new { });
    public async Task<bool> ToggleItsmConfigAsync(string id) => await PostBoolAsync($"/api/v1/integrations/itsm/{id}/toggle", new { });
    public async Task<bool> ToggleSiemTargetAsync(string id) => await PostBoolAsync($"/api/v1/integrations/siem/{id}/toggle", new { });
    public async Task<bool> ToggleSoarConfigAsync(string id) => await PostBoolAsync($"/api/v1/integrations/soar/{id}/toggle", new { });
    public async Task<bool> ToggleTrustedCaAsync(string id) => await PostBoolAsync($"/api/v1/integrations/pki/cas/{id}/toggle", new { });
    public async Task<bool> ToggleThreatFeedConfigAsync(string id) => await PostBoolAsync($"/api/v1/threat-analytics/threat-intel/feeds/{id}/toggle", new { });
    public async Task<ItsmTestResultDto?> TestItsmConfigAsync(string id) => await PostAsync<ItsmTestResultDto>($"/api/v1/integrations/itsm/{id}/test", new { });
    public async Task<(bool Success, string? Error, int LatencyMs)> TestSiemTargetAsync(string id)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/integrations/siem/{id}/test", new { });
            if (!resp.IsSuccessStatusCode) return (false, "HTTP " + (int)resp.StatusCode, 0);
            var wrapper = await resp.Content.ReadFromJsonAsync<SingleResult<SiemTestResultDto>>(JsonOpts);
            if (wrapper?.Data is { } d) return (d.Success, d.Error, d.LatencyMs);
            return (false, "Empty response", 0);
        }
        catch (Exception ex) { return (false, ex.Message, 0); }
    }
    public async Task<bool> TestSoarConfigAsync(string id) => await PostBoolAsync($"/api/v1/integrations/soar/{id}/test", new { });
    public async Task<ScriptTestResultDto?> TestRotationScriptAsync(string id) => await PostAsync<ScriptTestResultDto>($"/api/v1/vault/rotation-scripts/{id}/test", new { });
    public async Task<bool> RequestEmailOtpAsync(string username, string password) => await PostBoolAsync("/api/v1/auth/request-email-otp", new { username, password });
    public async Task<bool> RequestSmsOtpAsync(string username, string password) => await PostBoolAsync("/api/v1/auth/request-sms-otp", new { username, password });
    public async Task<LoginResult?> VerifyEmailOtpAsync(string username, string code) => await PostAsync<LoginResult>("/api/v1/auth/verify-email-otp", new { username, code });
    public async Task<LoginResult?> VerifySmsOtpAsync(string username, string code) => await PostAsync<LoginResult>("/api/v1/auth/verify-sms-otp", new { username, code });
    public async Task<object?> Fido2RegisterBeginAsync() => await PostAsync<object>("/api/v1/mfa/fido2/register/begin", new { });
    public async Task<bool> Fido2RegisterCompleteAsync(object attestation, string? keyName = null) => await PostBoolAsync("/api/v1/mfa/fido2/register/complete", new { attestation, keyName });
    public async Task<bool> Fido2RemoveCredentialAsync(string id) => await DeleteBoolAsync($"/api/v1/mfa/fido2/{id}");

    // ── PUT / PATCH methods ──────────────────────────────────────────────
    public async Task<bool> UpdateReportScheduleAsync(string id, UpdateReportScheduleDto dto) => await PutBoolAsync($"/api/v1/reports/schedules/{id}", dto);
    public async Task<bool> UpdateCredentialTemplateAsync(string id, string name, string? description, string? deviceType, string? defaultUsername, string? credentialKind, int rotationPeriodDays, int passwordMinLength, bool passwordRequireSpecial, bool sshKeyRotation, string? notes) => await PutBoolAsync($"/api/v1/vault/credential-templates/{id}", new { name, description, deviceType, defaultUsername, credentialKind, rotationPeriodDays, passwordMinLength, passwordRequireSpecial, sshKeyRotation, notes });
    public async Task<bool> UpdateRotationScriptAsync(string id, string name, string? description, string deviceType,
        string scriptType, string scriptContent, string? testScriptContent, bool isEnabled)
        => await PutBoolAsync($"/api/v1/vault/rotation-scripts/{id}", new { name, description, deviceType, scriptType, scriptContent, testScriptContent, isEnabled });

    // ── DELETE methods ───────────────────────────────────────────────────
    public async Task<bool> DeletePolicyAsync(string id) => await DeleteBoolAsync($"/api/v1/policies/{id}");
    public async Task<bool> DeleteAlertRuleAsync(string id) => await DeleteBoolAsync($"/api/v1/threat-analytics/alert-rules/{id}");
    public async Task<bool> DeleteAlertRuleAsync(Guid id) => await DeleteAlertRuleAsync(id.ToString());
    public async Task<bool> DeleteAssignedCredentialAsync(string id) => await DeleteBoolAsync($"/api/v1/vault/assigned-credentials/{id}");
    public async Task<bool> DeleteCloudAccountAsync(string id) => await DeleteBoolAsync($"/api/v1/cloud/accounts/{id}");
    public async Task<bool> DeleteCredentialTemplateAsync(string id) => await DeleteBoolAsync($"/api/v1/vault/credential-templates/{id}");
    public async Task<bool> DeleteCustomReportAsync(string id) => await DeleteBoolAsync($"/api/v1/reports/custom/{id}");
    public async Task<bool> DeleteItsmConfigAsync(string id) => await DeleteBoolAsync($"/api/v1/integrations/itsm/{id}");
    public async Task<bool> DeletePkiUserCertAsync(string id) => await DeleteBoolAsync($"/api/v1/integrations/pki/user-certs/{id}");
    public async Task<bool> DeleteReportScheduleAsync(string id) => await DeleteBoolAsync($"/api/v1/reports/schedules/{id}");
    public async Task<bool> DeleteRotationScriptAsync(string id) => await DeleteBoolAsync($"/api/v1/vault/rotation-scripts/{id}");
    public async Task<bool> DeleteSiemTargetAsync(string id) => await DeleteBoolAsync($"/api/v1/integrations/siem/{id}");
    public async Task<bool> DeleteSoarConfigAsync(string id) => await DeleteBoolAsync($"/api/v1/integrations/soar/{id}");
    public async Task<bool> DeleteTacacsCommandPolicyAsync(string id) => await DeleteBoolAsync($"/api/v1/network-access/policies/{id}");
    public async Task<bool> DeleteThreatFeedConfigAsync(string id) => await DeleteBoolAsync($"/api/v1/threat-analytics/threat-intel/feeds/{id}");
    public async Task<bool> DeleteTrustedCaAsync(string id) => await DeleteBoolAsync($"/api/v1/integrations/pki/cas/{id}");

    // ── Bool helpers ─────────────────────────────────────────────────────
    private async Task<bool> PostBoolAsync(string url, object payload)
    {
        try { var c = await GetAuthClientAsync(); return (await c.PostAsJsonAsync(url, payload)).IsSuccessStatusCode; }
        catch { return false; }
    }

    private async Task<bool> PutBoolAsync(string url, object payload)
    {
        try { var c = await GetAuthClientAsync(); return (await c.PutAsJsonAsync(url, payload)).IsSuccessStatusCode; }
        catch { return false; }
    }

    private async Task<bool> DeleteBoolAsync(string url)
    {
        try { var c = await GetAuthClientAsync(); return (await c.DeleteAsync(url)).IsSuccessStatusCode; }
        catch { return false; }
    }

}

public record LoginResult(bool Success, LoginData? Data);
public record LoginData(
    string   AccessToken,
    string?  TokenType,
    int      ExpiresIn,
    string   Username,
    string?  DisplayName,
    string?  Role,
    bool     MfaRequired,
    string   UserId,
    string?  MfaType                = null,
    bool     MfaEnrollmentRequired  = false,
    bool     MustChangePassword     = false,
    bool     PasswordExpired        = false,
    string?  PortalProfile          = null,
    string?  RiskLevel              = null,
    decimal  RiskScore              = 0);

public record PagedResult<T>(bool Success, List<T>? Data, PageMeta? Meta);
public record ListResult<T>(bool Success, List<T>? Data);
public record SingleResult<T>(bool Success, T? Data);
public record PageMeta(int Page, int PageSize, int TotalCount);
public record PagingMeta(int Page, int PageSize, int Total, int TotalPages);

public record UserDto(
    string    Id,
    string    Username,
    string?   DisplayName,
    string?   Email,
    string    Status,
    string    AuthSource,
    bool      MfaEnabled,
    bool      IsTemporary,
    DateTime? LastLoginAtUtc,
    string?   LastLoginIp,
    int       FailedLoginCount,
    bool      IsServiceAccount,
    string    UserType,
    string    PortalProfile,
    DateTime  CreatedAtUtc,
    bool      IsOrphaned = false,
    DateTime? OrphanedDetectedAtUtc = null);

public record GroupDto(
    string   Id,
    string   Name,
    string?  Description,
    int      MemberCount,
    DateTime CreatedAtUtc);

public record RoleDto(
    Guid     Id,
    string   Name,
    string?  Description,
    bool     IsSystem,
    DateTime CreatedAtUtc);

public record DeviceDto(
    string    Id,
    string    Hostname,
    string?   Fqdn,
    string?   IpAddress,
    string    Type,
    string    Protocol,
    int?      ConnectionPort,
    string?   OperatingSystem,
    string    Status,
    bool?     IsReachable,
    DateTime? LastReachableCheck,
    string?   Tags,
    bool      IsManaged,
    string?   SshHostKeyFingerprint,
    int       CredentialCount,
    string?   NetworkZoneName = null,
    Guid?     NetworkZoneId = null);

public record DeviceGroupDto(
    string    Id,
    string    Name,
    string?   Description,
    Guid?     ParentGroupId,
    string?   ParentGroupName,
    int       DeviceCount,
    DateTime  CreatedAtUtc);

public record CredentialDto(
    string    Id,
    string?   Name,
    string    Username,
    string    CredentialType,
    string?   Type,
    string?   Status,
    string?   Description,
    string?   DeviceId,
    string    DeviceName,
    Guid?     GroupId,
    string?   GroupName,
    bool      IsCheckedOut,
    Guid?     CheckedOutBy,
    string?   CheckedOutByUserId,
    DateTime? CheckedOutAt,
    DateTime? CheckedOutUntil,
    DateTime? CheckOutExpiresUtc,
    DateTime? LastRotatedAt,
    DateTime? NextRotationAt,
    DateTime? LastRotatedAtUtc = null,
    bool      RequiresApproval = false,
    string?   RiskLevel = null,
    int       RiskScore = 0,
    int       RotationFailureCount = 0,
    string?   LastRotationError = null,
    DateTime  CreatedAtUtc = default);

public record CredentialGroupDto(
    Guid      Id,
    string    Name,
    string?   Description,
    Guid?     ParentGroupId,
    string?   ParentGroupName,
    int       CredentialCount,
    DateTime  CreatedAtUtc);

public record CheckoutDto(string Password, DateTime ExpiresAt);

public record AccessAssignmentDto(
    Guid      Id,
    Guid      UserId,
    string    UserName,
    Guid?     GroupId,
    string?   GroupName,
    Guid?     DeviceId,
    string?   DeviceName,
    Guid?     DeviceGroupId,
    string?   DeviceGroupName,
    Guid?     CredentialId,
    string?   CredentialName,
    string    AccessLevel,
    DateTime? ExpiresAt,
    bool      RequiresApproval,
    DateTime  CreatedAtUtc);

public record DeviceRealmDto(
    string    Id,
    string    Name,
    string?   Description,
    List<Guid> UserGroupIds,
    List<string> UserGroupNames,
    List<Guid> DeviceGroupIds,
    List<string> DeviceGroupNames,
    string    PolicyKey,
    bool      RequiresApproval,
    DateTime  CreatedAtUtc,
    DateTime  UpdatedAtUtc,
    bool      IsEnabled = true,
    List<DeviceRealmGroupItemDto>? UserGroups = null,
    List<DeviceRealmGroupItemDto>? DeviceGroups = null);

public record DeviceRealmGroupItemDto(string Id, string Name, string? UserGroupId = null, string? DeviceGroupId = null);

public record SessionDto(
    string    Id,
    Guid      UserId,
    Guid      DeviceId,
    Guid      CredentialId,
    [property: JsonPropertyName("type")] string SessionType,
    string    Status,
    DateTime  StartedAtUtc,
    DateTime? EndedAtUtc,
    int?      DurationSeconds,
    string?   ClientIpAddress,
    string?   TargetIpAddress,
    int?      TargetPort,
    decimal   RiskScore,
    bool      HasKeystrokeLog,
    bool      HasOcrData,
    string?   Reason,
    string?   TicketNumber,
    string?   Tags);

public record SessionAnnotationDto(
    Guid     Id,
    Guid     SessionId,
    string?  Note,
    string?  AuthorUsername,
    DateTime CreatedAtUtc);

public record AuditLogDto(
    Guid      Id,
    string    Action,
    string?   ActorUsername,
    string?   TargetEntity,
    string?   TargetId,
    string?   Details,
    string?   IpAddress,
    DateTime  CreatedAtUtc,
    DateTime  Timestamp = default,
    string?   EventCategory = null,
    string?   EventType = null,
    string?   ActorIpAddress = null,
    string?   TargetType = null,
    string?   Outcome = null,
    bool      IsTampered = false);

public record SystemSettingsDto(
    string  CompanyName,
    string  SiteName,
    string  DefaultLanguage,
    string  DefaultTimezone,
    int     SessionTimeoutMinutes,
    int     MaxFailedLoginAttempts,
    int     LockoutDurationMinutes,
    bool    EmailNotificationsEnabled,
    string? SmtpHost,
    int     SmtpPort,
    string? SmtpUser,
    bool    SmtpUseSsl,
    string? SmtpFrom);

public record LdapConfigDto(
    string   Host,
    int      Port,
    bool     UseSsl,
    string   BaseDn,
    string   BindDn,
    bool     IsEnabled,
    DateTime? LastSyncAt,
    int      LastSyncCount,
    string?  Id = null,
    string?  Name = null,
    int      SyncIntervalMinutes = 60,
    DateTime? LastSyncAtUtc = null);

public record LdapSyncResultDto(int UsersAdded, int UsersUpdated, int UsersDisabled, int Total, DateTime SyncedAt);

public record RadiusConfigDto(
    string  Host,
    int     Port,
    bool    IsEnabled,
    int     TimeoutSeconds,
    int     RetryCount);

public record SiemConfigDto(
    string  Host,
    int     Port,
    string  Protocol,
    string  Format,
    bool    IsEnabled,
    DateTime? LastEventAt);

public record WebhookDto(
    Guid     Id,
    string   Name,
    string   Url,
    string[] Events,
    bool     IsActive,
    DateTime? LastTriggeredAt,
    int      FailureCount,
    DateTime CreatedAtUtc);

public record PasswordPolicyDto(
    Guid    Id,
    string  Name,
    int     MinLength,
    bool    RequireUppercase,
    bool    RequireLowercase,
    bool    RequireDigit,
    bool    RequireSpecial,
    int     PasswordHistoryCount,
    int     MaxAgeDays,
    int     MinAgeDays,
    bool    IsDefault,
    DateTime CreatedAtUtc);

public record SessionPolicyDto(
    Guid    Id,
    string  Name,
    int     MaxSessionDurationMinutes,
    int     IdleTimeoutMinutes,
    bool    RequireApproval,
    bool    RecordSessions,
    bool    AllowConcurrentSessions,
    int     MaxConcurrentSessions,
    DateTime CreatedAtUtc);

public record ApprovalRequestDto(
    Guid      Id,
    string    RequestType,
    Guid      RequestedBy,
    string    RequestedByName,
    string    Status,
    string?   TargetResource,
    string?   Reason,
    string?   ApproverComment,
    Guid?     ApprovedBy,
    string?   ApprovedByName,
    DateTime? ApprovedAt,
    DateTime  CreatedAtUtc,
    DateTime? ExpiresAt,
    string?   RequesterId = null,
    string?   ResourceType = null,
    DateTime? CompletedAtUtc = null);

public record DashboardStatsDto(
    int   TotalUsers,
    int   ActiveUsers,
    int   TotalDevices,
    int   OnlineDevices,
    int   TotalCredentials,
    int   CheckedOutCredentials,
    int   ActiveSessions,
    int   TodaysSessions,
    int   PendingApprovals,
    int   SecurityAlerts,
    int   AuditEventsToday);

public record ComplianceReportDto(
    int      TotalChecks,
    int      PassedChecks,
    int      FailedChecks,
    double   ComplianceScore,
    List<ComplianceItemDto> Items);

public record ComplianceItemDto(
    string  Category,
    string  Check,
    bool    Passed,
    string? Details);

public record ActivitySummaryDto(
    DateTime Date,
    int      LoginCount,
    int      SessionCount,
    int      CredentialCheckouts,
    int      FailedLogins,
    int      AuditEvents);

public record NotificationDto(
    Guid      Id,
    string    Title,
    string    Message,
    string    Type,
    bool      IsRead,
    DateTime  CreatedAtUtc);

public record MfaSetupDto(
    string  SecretKey,
    string  QrCodeUri,
    bool    IsEnabled);

public record RecoveryCodesDto(string[] Codes);

// Backup Codes (#289 — MFA #21)
public record BackupCodesGeneratedDto(string[] Codes);
public record BackupCodeStatusDto(bool MfaEnabled, int Remaining, DateTime? GeneratedAtUtc);

public record SshKeyDto(
    Guid      Id,
    string    Name,
    string?   Description,
    string    KeyType,
    int       KeySize,
    string    Fingerprint,
    DateTime  CreatedAtUtc);

public record SshPublicKeyDto(string PublicKey);

public record CertificateDto(
    Guid      Id,
    string    Name,
    string?   Description,
    string    Subject,
    string    Thumbprint,
    DateTime  NotBefore,
    DateTime  NotAfter,
    bool      IsExpired,
    DateTime  CreatedAtUtc);

public record LicenseDto(
    string    LicenseKey,
    string    Product,
    string    Edition,
    int       MaxUsers,
    int       MaxDevices,
    DateTime  ExpiresAt,
    bool      IsValid,
    string?   LicensedTo);

public record BackupDto(
    Guid      Id,
    string    FileName,
    long      FileSizeBytes,
    string?   Description,
    string    Status,
    DateTime  CreatedAtUtc);

public record HealthDto(
    string   Status,
    string   Version,
    DateTime Timestamp,
    Dictionary<string, string> Components);

public record PkiConfigDto(
    bool     IsEnabled,
    string?  CaThumbprint,
    string?  OcspUrl,
    bool     RequireClientCert);

public record EmergencyAccessDto(
    bool      IsEnabled,
    string?   EnabledBy,
    string?   Reason,
    DateTime? EnabledAt,
    DateTime? ExpiresAt);

public record RdpProxySettingsDto(
    string  ListenAddress,
    int     ListenPort,
    bool    IsEnabled,
    bool    RecordSessions,
    int     MaxConcurrentSessions,
    bool    AllowClipboard,
    bool    AllowFileTransfer,
    bool    AllowPrinterRedirection,
    bool    AllowUsbRedirection,
    bool    AllowAudioRedirection,
    bool    AllowSmartCardRedirection,
    Guid?   DeviceGroupId,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

public record SshProxySettingsDto(
    string   ListenAddress,
    int      ListenPort,
    bool     IsEnabled,
    bool     RecordSessions,
    int      MaxConcurrentSessions,
    bool     AllowPortForwarding,
    bool     AllowX11Forwarding,
    bool     AllowSftp,
    bool     AllowScp,
    string?  HostKeyFingerprint,
    Guid?    DeviceGroupId,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

public record MfaEnrollmentTokenDto(
    Guid     Token,
    DateTime ExpiresAt,
    string   EnrollmentUrl);

public record PasswordResetTokenDto(
    string   Token,
    DateTime ExpiresAt,
    string   ResetUrl);

public record RadiusUserDto(
    Guid     Id,
    string   Username,
    string?  Description,
    bool     IsEnabled,
    DateTime CreatedAtUtc);

public record VendorUserDto(
    Guid      Id,
    string    Username,
    string?   DisplayName,
    string?   Email,
    string?   Phone,
    Guid?     SponsorUserId,
    string?   SponsorName,
    string?   AllowedDeviceIds,
    DateTime? AccessExpiresAt,
    string    Status,
    DateTime  CreatedAtUtc,
    bool      MfaEnabled = false,
    DateTime? TemporaryExpiresUtc = null,
    string?   VendorSponsorUsername = null);

public record OrphanedAccountDto(
    Guid      Id,
    string    Username,
    string?   DisplayName,
    string    AuthSource,
    DateTime? OrphanedDetectedAtUtc,
    DateTime  CreatedAtUtc);

public record ApprovalPolicyDto(
    Guid     Id,
    string   Name,
    string?  Description,
    string[] TriggerEvents,
    int      RequiredApprovers,
    int      ApprovalTimeoutMinutes,
    bool     IsActive,
    DateTime CreatedAtUtc);

public record MfaPolicyDto(
    bool     RequireMfaForAll,
    bool     RequireMfaForAdmins,
    bool     AllowTotpMethod,
    bool     AllowSmsMethod,
    bool     AllowEmailMethod,
    bool     AllowHardwareKey,
    int      GracePeriodDays,
    bool     MfaRequired = false,
    bool     EmailOtpEnabled = false,
    bool     SmsOtpEnabled = false);

public record ThreatIndicatorDto(
    Guid     Id,
    string   IndicatorType,
    string   Value,
    string?  Description,
    int      Severity,
    bool     IsActive,
    DateTime CreatedAtUtc,
    string?  Source = null,
    DateTime? ExpiresAtUtc = null);

public record AnomalyAlertDto(
    Guid      Id,
    string    AlertType,
    string    Description,
    string    Severity,
    Guid?     UserId,
    string?   Username,
    bool      IsResolved,
    string?   ResolutionNote,
    DateTime  CreatedAtUtc,
    DateTime? ResolvedAtUtc);

public record RotationRuleDto(
    Guid     Id,
    string   Name,
    string?  Description,
    int      RotationIntervalDays,
    bool     AutoRotate,
    bool     NotifyBeforeExpiry,
    int      NotifyDaysBefore,
    bool     IsActive,
    DateTime CreatedAtUtc);

public record DiscoveredDeviceDto(
    string   IpAddress,
    string?  Hostname,
    string[] OpenPorts,
    string?  DetectedOs,
    string?  DeviceType);

public record JumpServerDto(
    Guid      Id,
    string    Name,
    string    Hostname,
    string    IpAddress,
    int       SshPort,
    bool      IsEnabled,
    string?   Description,
    DateTime  CreatedAtUtc);

public record RecordingDto(
    Guid      Id,
    Guid      SessionId,
    string    FilePath,
    long      FileSizeBytes,
    string    Format,
    int?      DurationSeconds,
    DateTime  CreatedAtUtc);

public record PlaybackUrlDto(string Url, DateTime ExpiresAt);

public record HsmConfigDto(
    bool     IsEnabled,
    string   Provider,
    string?  ConnectionString,
    string?  SlotId,
    bool     UseForEncryption,
    bool     UseForSigning);

public record AutomationTaskDto(
    Guid      Id,
    string    Name,
    string?   Description,
    string    TaskType,
    string?   Script,
    string    ScheduleType,
    string?   CronExpression,
    bool      IsEnabled,
    DateTime? LastRunAt,
    string?   LastRunStatus,
    DateTime  CreatedAtUtc);

// API Keys (#250)
public record ApiKeyDto(
    Guid      Id,
    string    Name,
    string?   Description,
    string    Prefix,
    Guid      ServiceAccountUserId,
    string    ServiceAccountName,
    string?   AllowedIpCidrs,
    DateTime? ExpiresAtUtc,
    DateTime? LastUsedAtUtc,
    long      UsageCount,
    bool      IsActive,
    DateTime  CreatedAtUtc);

public record ApiKeyCreatedDto(
    Guid      Id,
    string    Name,
    string    Prefix,
    string    RawKey,
    string    HmacSecret,
    DateTime? ExpiresAtUtc);

// Credential Orchestration DTOs (#251)
public record OrchestrationSetDto(
    Guid      Id,
    string    Name,
    string?   Description,
    string    ExecutionMode,
    bool      RollbackOnFailure,
    bool      NotifyOnComplete,
    string?   ScheduleCron,
    int       MemberCount,
    string?   LastRunStatus,
    DateTime? LastRunAt,
    DateTime  CreatedAtUtc);

public record OrchestrationMemberDto(
    Guid   Id,
    Guid   CredentialId,
    string CredentialName,
    string? CredentialUser,
    int    ExecutionOrder);

public record OrchestrationSetDetailDto(
    Guid      Id,
    string    Name,
    string?   Description,
    string    ExecutionMode,
    bool      RollbackOnFailure,
    bool      NotifyOnComplete,
    string?   ScheduleCron,
    List<OrchestrationMemberDto> Members,
    DateTime  CreatedAtUtc);

public record OrchestrationRunResultDto(
    Guid   RunId,
    string Status,
    int    SuccessCount,
    int    FailureCount,
    string? Log);

public record OrchestrationRunDto(
    Guid      Id,
    DateTime  StartedAtUtc,
    DateTime? CompletedAtUtc,
    string    Status,
    int       SuccessCount,
    int       FailureCount,
    string?   Log,
    string    TriggeredBy);

public record IdDto(Guid Id);

// MFA Trusted Sessions (#257)
public record MfaTrustPolicyDto(int MaxHours);
public record MfaTrustedSessionDto(
    Guid      Id,
    string?   DeviceLabel,
    DateTime  TrustExpiresAtUtc,
    string?   GrantedFromIp,
    DateTime  GrantedAtUtc,
    DateTime? LastUsedAtUtc);

public record ShadowStartDto(
    Guid     ShadowId,
    Guid     SessionId,
    string   StreamUrl,
    string   StatusUrl,
    string   TerminateUrl,
    DateTime StartedAtUtc);

public record LiveStreamDto(string Text, int NewOffset);

public record LiveSessionStatusDto(
    Guid     SessionId,
    string   Status,
    string   SessionType,
    DateTime StartedAtUtc,
    string?  TargetIp,
    decimal  RiskScore,
    int      ActiveObservers,
    List<LiveObserverDto> Observers);

public record LiveObserverDto(string? ObserverUsername, DateTime JoinedAtUtc);
// SessionCommandDto is now an alias for CommandLogDto (used by SessionShadow.razor)

// Session Handoff (#263)
public record HandoffCreatedDto(
    Guid     HandoffId,
    Guid     SessionId,
    string?  RequestedToUser,
    DateTime ExpiresAtUtc,
    string   Status);

public record PendingHandoffDto(
    Guid     Id,
    Guid     SessionId,
    string?  RequestedByUsername,
    DateTime RequestedAtUtc,
    DateTime ExpiresAtUtc,
    string?  TransferNotes);

// Session Delegation (#269 RA #42)
public record SessionDelegationDto(
    Guid      Id,
    string?   DelegatorUsername,
    string?   DelegateUsername,
    Guid?     DeviceId,
    Guid?     DeviceGroupId,
    Guid?     CredentialId,
    DateTime  GrantedAtUtc,
    DateTime  ExpiresAtUtc,
    DateTime? RevokedAtUtc,
    string    Status,
    int       MaxSessionCount,
    int       UsageCount,
    string?   DelegationNote);

public record ReceivedDelegationDto(
    Guid     Id,
    string?  DelegatorUsername,
    Guid?    DeviceId,
    Guid?    DeviceGroupId,
    Guid?    CredentialId,
    DateTime ExpiresAtUtc,
    int      MaxSessionCount,
    int      UsageCount,
    string?  DelegationNote);

public record GrantedDelegationDto(
    Guid     Id,
    string?  DelegateUsername,
    Guid?    DeviceId,
    Guid?    DeviceGroupId,
    Guid?    CredentialId,
    DateTime GrantedAtUtc,
    DateTime ExpiresAtUtc,
    string   Status,
    int      MaxSessionCount,
    int      UsageCount);

public record DelegationMyDto(
    List<ReceivedDelegationDto> Received,
    List<GrantedDelegationDto>  Granted);

// Session Compliance
public record SessionComplianceSummaryDto(
    int    PeriodDays,
    int    TotalSessions,
    int    ViolatedSessions,
    int    CleanSessions,
    double ComplianceRate,
    int    AdminTerminated,
    int    BlockedCommands,
    Dictionary<string, int>?              ViolationTypes,
    List<ComplianceViolatingUserDto>?     TopViolatingUsers,
    List<ComplianceViolatingDeviceDto>?   TopViolatingDevices);

public record ComplianceViolatingUserDto(Guid UserId, string Username, int ViolationCount);
public record ComplianceViolatingDeviceDto(Guid DeviceId, string Hostname, int ViolationCount);

// Hardware Tokens (#261)
public record HardwareTokenDto(
    Guid     Id,
    Guid     UserId,
    string   SerialNumber,
    string   TokenType,
    string   Algorithm,
    int      Digits,
    int      PeriodSeconds,
    string?  Label,
    bool     IsActive,
    DateTime ProvisionedAtUtc,
    long     CounterValue = 0);

// OIDC Federation (#271)
public record OidcProviderPublicDto(Guid Id, string Name, string DisplayName);

public record OidcProviderDto(
    Guid     Id,
    string   Name,
    string   DisplayName,
    string   Authority,
    string   ClientId,
    bool     ClientSecretSet,
    string   Scopes,
    string?  GroupClaimType,
    string?  GroupRoleMapping,
    bool     AutoProvisionUsers,
    string   DefaultRole,
    bool     IsEnabled,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

public record OidcTestResultDto(
    bool     Success,
    bool     Reachable,
    string?  AuthorizationEndpoint,
    string?  TokenEndpoint,
    string?  Issuer,
    string?  Error);

// Command Filter Policy (#231)
public record CommandFilterPolicyDto(
    string   Id,
    string   Name,
    string?  Description,
    bool     IsEnabled,
    string   Mode,
    Guid?    DeviceGroupId,
    int      RuleCount,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

public record CommandFilterPolicyDetailDto(
    string   Id,
    string   Name,
    string?  Description,
    bool     IsEnabled,
    string   Mode,
    Guid?    DeviceGroupId,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc,
    List<CommandFilterRuleDto>? Rules);

public record CommandFilterRuleDto(
    string   Id,
    string   Pattern,
    bool     IsRegex,
    string   Action,
    int      RiskScore,
    string?  Justification,
    int      SortOrder);

// Peripheral Redirection Policy (#249)
public record PeripheralRedirectionPolicyDto(
    Guid     Id,
    string   Name,
    string?  Description,
    bool     IsEnabled,
    bool     AllowClipboard,
    bool     AllowDriveRedirection,
    bool     AllowPrinterRedirection,
    bool     AllowUsbRedirection,
    bool     AllowAudioRedirection,
    bool     AllowSmartCardRedirection,
    Guid?    DeviceGroupId,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

// Device MFA Policy (#270 — MFA #22)
public record DeviceMfaPolicyDto(
    Guid     Id,
    string   Name,
    string?  Description,
    bool     IsEnabled,
    Guid?    DeviceGroupId,
    Guid?    DeviceId,
    string   RequiredMfaLevel,
    bool     EnforceAtSessionStart,
    DateTime CreatedAtUtc,
    DateTime UpdatedAtUtc);

// Hardware Token Drift Report (#277 — MFA #23)
public record TokenDriftReportItemDto(
    Guid      TokenId,
    string    SerialNumber,
    Guid      UserId,
    string    Username,
    long      CounterValue,
    string?   Label,
    DateTime? LastResyncAtUtc,
    int       ResyncCount,
    string?   LastEvent);

// Operational Reports (#278 — Reporting #39-41)
public record CapacityTrendPoint(string Week, int NewCount, int Total);

public record StorageTrendPoint(string Week, double NewGb);

public record CapacityProjection(int Devices, int Creds, int Users);

public record CapacityReportDto(
    int    Months,
    DateTime Since,
    List<JsonElement> DeviceTrend,
    List<JsonElement> CredentialTrend,
    List<JsonElement> UserTrend,
    List<JsonElement> StorageTrend,
    JsonElement?      Projection90Days);

public record ProxyUptimeItem(string Protocol, int ActiveDays, int TotalDays, double UptimePercent);

public record TopTerminatedDevice(Guid DeviceId, string Hostname, int FailedCount);

public record PerformanceReportDto(
    DateTime PeriodFrom,
    DateTime PeriodTo,
    int      TotalSessions,
    int      CompletedSessions,
    double   SessionSuccessRate,
    int      TotalCredentials,
    int      CredentialsRotated,
    double   RotationSuccessRate,
    int      TotalRotationFailures,
    List<JsonElement> ProxyUptimeByProtocol,
    List<JsonElement> TopTerminatedDevices);

public record SlaBreachItem(string Metric, double Actual, double Target, string? Unit = null);

public record SlaReportDto(
    DateTime PeriodFrom,
    DateTime PeriodTo,
    double   RotationOnTimePercent,
    double   RotationTarget,
    int      CredentialsWithPolicy,
    int      OnTimeRotations,
    double   RecordingCoveragePercent,
    double   RecordingTarget,
    int      TotalPeriodSessions,
    int      RecordedSessions,
    double   AvgApprovalHours,
    double   ApprovalMaxHoursTarget,
    int      TotalApprovals,
    double   CheckoutCompliancePercent,
    double   CheckoutTarget,
    int      TotalCheckouts,
    int      CompliantCheckouts,
    double   MfaEnrollmentPercent,
    double   MfaTarget,
    int      TotalActiveUsers,
    int      MfaEnrolledUsers,
    List<JsonElement> SlaBreaches);

public record Fido2CredentialDto(
    Guid      Id,
    string    FriendlyName,
    string    AuthenticatorType,
    DateTime  RegisteredAt,
    DateTime? LastUsed);

public record NetworkZoneDto(
    Guid      Id,
    string    Name,
    string?   Description,
    string?   IpRangesJson,
    string?   JumpHostAddress,
    Guid?     JumpHostCredentialId,
    string?   JumpHostFingerprint,
    string?   ProxyBindAddress,
    bool      IsDefault,
    string?   Notes,
    int       DeviceCount);

public record NetworkZoneTestResultDto(bool Reachable, int LatencyMs, string Message);

public record ExternalVaultDto(
    Guid      Id,
    string    Name,
    string    VaultType,
    string    Endpoint,
    string    AuthMethod,
    string?   KeyVaultName,
    string?   Namespace,
    string?   MountPath,
    string?   TenantId,
    string?   ClientId,
    bool      SyncEnabled,
    int       SyncIntervalMinutes,
    bool      IsEnabled,
    DateTime? LastSyncAtUtc,
    string?   LastSyncError,
    DateTime  CreatedAtUtc,
    int       MappingCount);

public record ExternalVaultMappingDto(
    Guid      Id,
    string    ExternalPath,
    string?   UsernameField,
    string?   PasswordField,
    Guid?     MappedCredentialId,
    string    SyncMode,
    string    SyncStatus,
    DateTime? LastFetchedAtUtc,
    DateTime? LastSyncedAtUtc,
    string?   LastError);

public record ExternalVaultTestResultDto(bool Success, string? Error, long LatencyMs);

// SCIM 2.0 Provisioning DTOs (#291)
public record ScimTokenDto(
    Guid      Id,
    string    Name,
    string    TokenPrefix,
    bool      IsActive,
    DateTime  CreatedAtUtc,
    DateTime? ExpiresAtUtc,
    DateTime? LastUsedAtUtc);

public record ScimTokenCreatedDto(
    Guid      Id,
    string    Name,
    string    TokenPrefix,
    DateTime? ExpiresAtUtc,
    string    RawToken);

public record ScimProvisioningLogDto(
    Guid      Id,
    string    EventType,
    Guid?     ActorId,
    string?   ActorUsername,
    string?   TargetId,
    DateTime  OccurredAtUtc,
    string?   IpAddress);

public record ExternalVaultSyncResultDto(int SyncedCount);

// ========== Missing DTO definitions for build fix ==========

// CertificateManager.razor
public record ManagedCertificateDto(
    Guid      Id,
    string    SubjectCN,
    string?   SubjectAltNames,
    string?   Issuer,
    string?   SerialNumber,
    string?   Thumbprint,
    DateTime  NotBefore,
    DateTime  NotAfter,
    string?   KeyAlgorithm,
    int       KeySizeBits,
    string?   KeyUsage,
    string?   Source,
    string?   Notes,
    bool      IsExpired,
    int       DaysUntilExpiry,
    DateTime  CreatedAtUtc);

// MyDevices.razor
public record TrustedDeviceDto(
    Guid      Id,
    string?   DeviceName,
    string?   UserAgent,
    string?   TrustLevel,
    bool      IsRevoked,
    DateTime  RegisteredAtUtc,
    DateTime  LastSeenAtUtc);

// JIT.razor, SelfService.razor
public record JitRequestDto(
    string    Id,
    string    Status,
    string?   ResourceType,
    string?   ResourceName,
    int       RequestedDurationMinutes,
    string?   Reason,
    string?   DenyReason,
    string?   RequesterUsername,
    string?   RequesterIpAddress,
    bool      ExtensionRequested,
    int?      ExtensionRequestedMinutes,
    DateTime  CreatedAtUtc,
    DateTime? ExpiresAtUtc);

// BreakGlass.razor
public record BreakGlassDto(
    string    Id,
    string    Status,
    string    RequesterUsername,
    string?   RequesterIpAddress,
    string    ResourceType,
    string    ResourceName,
    string    EmergencyReason,
    string?   TicketNumber,
    string?   AcknowledgedByUsername,
    DateTime  CreatedAtUtc,
    DateTime  ExpiresAtUtc);

// Policies.razor
public record PolicyDto(
    string    Id,
    string    Name,
    string?   Description,
    string?   PolicyType,
    string?   Scope,
    int       Priority,
    bool      IsEnabled,
    string?   Mode,
    int       RuleCount,
    string?   DeviceId,
    string?   DeviceGroupId,
    bool      AllowClipboard,
    bool      AllowDriveRedirection,
    bool      AllowPrinterRedirection,
    bool      AllowUsbRedirection,
    bool      AllowSmartCardRedirection,
    bool      AllowAudioRedirection,
    bool      EnforceAtSessionStart,
    string?   RequiredMfaLevel);

// Reports.razor
public record ReportDto(
    string    Id,
    string    Name,
    string?   Description,
    string?   Category);

public record ReportRunResult(
    JsonElement Data,
    string?   FilterSummary,
    List<string>? Columns,
    List<JsonElement>? Rows,
    JsonElement? Meta);

public record ReportScheduleDto(
    string    Id,
    string    Name,
    string?   ReportType,
    string    Frequency,
    int       DayOfWeek,
    int       DayOfMonth,
    int       RunAtHourUtc,
    string?   Recipients,
    bool      IsActive,
    string?   LastRunStatus,
    DateTime? LastRunAtUtc,
    DateTime? NextRunAtUtc);

public record AccessPatternSummaryDto(
    int       TotalSessions,
    int       UniqueUsers,
    int       LoginFailures,
    List<AccessPatternUserDto>?     TopUsers,
    List<AccessPatternTargetDto>?   TopTargets,
    List<AccessPatternWeekdayDto>?  WeekdayDistribution,
    List<AccessPatternProtocolDto>? ProtocolBreakdown);

public record AccessPatternUserDto(Guid UserId, int SessionCount);
public record AccessPatternTargetDto(string Target, int SessionCount);
public record AccessPatternWeekdayDto(string Day, int SessionCount);
public record AccessPatternProtocolDto(string Protocol, int Count);

public record AccessPatternTimeOfDayDto(
    List<AccessPatternHourlyDto>? Hourly);
public record AccessPatternHourlyDto(int Hour, int SessionCount);

public record ApiUsageSummaryDto(
    int       TotalCalls,
    int       Granted,
    int       Denied,
    double    ErrorRate,
    List<ApiClientDto>?       TopClients,
    List<ApiEventTypeDto>?    AuditTopEventTypes,
    List<ApiHourlyTrendDto>?  HourlyTrend);
public record ApiClientDto(string ClientName, int TotalCalls, int Denied, int RateLimited);
public record ApiEventTypeDto(string EventType, int Count);
public record ApiHourlyTrendDto(int Hour, int CallCount);

public record ApiUsageAnomaliesDto(
    List<ApiHighDenialDto>?    HighDenialRateClients,
    List<ApiRateLimitedDto>?   RateLimitedClients);
public record ApiHighDenialDto(string ClientName, int TotalCalls, int DeniedCalls, double DenialRate);
public record ApiRateLimitedDto(string ClientName, int RateLimitHits);

public record ComplianceReportResultDto(
    string    Framework,
    string    FrameworkName,
    DateTime  GeneratedAt,
    CompliancePeriodDto Period,
    ComplianceSummaryDto Summary,
    List<ComplianceControlDto> Controls);
public record CompliancePeriodDto(DateTime From, DateTime To);
public record ComplianceSummaryDto(int Passed, int Partial, int Failed, double Score, string OverallStatus);
public record ComplianceControlDto(string Code, string Name, string? Reference, string Status, string? Finding, Dictionary<string, string>? Evidence);

public record AuditVerifyResult(
    bool      IntegrityValid,
    string?   Message,
    int       EntriesChecked,
    int       TamperedCount);

public record CustomReportDefinitionDto(
    string    Id,
    string    Name,
    string    DataSource,
    string    ColumnsJson,
    string    FiltersJson,
    DateTime? LastRunAtUtc);

// Backup.razor
public record BackupRecordDto(
    string    Id,
    string?   FileName,
    string?   Scope,
    string?   Status,
    long      FileSizeBytes,
    string?   InitiatedBy,
    bool      IntegrityVerified,
    string?   ErrorMessage,
    DateTime  CreatedAtUtc);

public record BackupRestoreResultDto(
    int       RestoredCount,
    string?   Message);

public record BackupScheduleDto(
    bool      Enabled,
    int       HourUtc,
    string    Scope);

// CloudPam.razor
public record CloudDashboardDto(
    int       TotalAccounts,
    int       TotalResources,
    int       ActiveJitRequests,
    int       PendingJitRequests,
    List<CloudProviderSummaryDto>? ByProvider,
    List<CloudJitDto>?             RecentJit);
public record CloudProviderSummaryDto(string Provider, int AccountCount, int ResourceCount, int Accounts = 0, int Resources = 0, int ActiveJit = 0);

public record CloudAccountDto(
    string    Id,
    string    Name,
    string    Provider,
    string?   AccountIdentifier,
    string?   Region,
    bool      IsEnabled,
    int       ResourceCount,
    DateTime? LastSyncAtUtc);

public record CloudResourceDto(
    string    Id,
    string    Name,
    string    Provider,
    string?   NativeId,
    string?   ResourceType,
    string?   Region,
    string?   Status,
    string?   IpAddress,
    DateTime? LastSeenAtUtc);

public record CloudJitResourceDto(
    string    Provider,
    string    Name,
    string?   ResourceType,
    string?   Region);

public record CloudSyncResultDto(
    int       NewResources,
    int       TotalResources);

public record CloudJitDto(
    string    Id,
    string?   RequestedByUsername,
    CloudJitResourceDto? Resource,
    string?   Permission,
    string?   Status,
    string?   TicketNumber,
    DateTime  RequestedAtUtc,
    DateTime? ExpiresAtUtc);

// Compliance.razor
public record AttestationCampaignDto(
    string    Id,
    string    Name,
    byte      Status,
    DateTime  StartsAtUtc,
    DateTime  DeadlineUtc,
    bool      AutoRevokeOnMiss,
    DateTime? CompletedAtUtc);

public record AttestationDetailDto(
    string    Id,
    string    Name,
    int       TotalItems,
    int       DecidedItems,
    int       PendingItems,
    List<AttestationDecisionDto>? Decisions);
public record AttestationDecisionDto(
    long      Id,
    string?   SubjectUserId,
    string?   SubjectUsername,
    string?   ResourceType,
    string?   ResourceName,
    byte?     Decision,
    DateTime? DecisionAtUtc);

public record ReconciliationDriftDto(
    string    Username,
    string?   UserStatus,
    string    DriftType,
    string?   FolderName,
    string?   PermissionLevel);

public record ReconciliationHistoryDto(
    DateTime  Timestamp,
    string?   ActorUsername,
    string?   Details);

public record RemediationResultDto(
    int       RevokedPermissions);

// ThreatAnalytics.razor
public record SocDashboardDto(
    int       TotalAnomalies24h,
    int       Unacknowledged,
    int       CriticalUnacked,
    List<SocTypeBreakdownDto>?  TypeBreakdown,
    List<SocRiskyUserDto>?      TopRiskyUsers,
    List<AnomalyDto>?           RecentAnomalies);
public record SocTypeBreakdownDto(string Type, int Count);
public record SocRiskyUserDto(string UserId, int AnomalyCount, int MaxSeverity, decimal RiskScore);

public record AnomalyDto(
    long      Id,
    string    AnomalyType,
    int       Severity,
    string?   Details,
    Guid?     UserId,
    Guid?     SessionId,
    bool      IsAcknowledged,
    DateTime  DetectedAtUtc);

public record RiskMapDto(
    Guid      UserId,
    decimal   RiskScore,
    int       AnomalyCount,
    int       OffHours,
    int       UnusualIp,
    int       UnusualDevice,
    int       FrequencySpike,
    int       HighRiskCommand,
    DateTime  LastDetected);

public record AlertRuleDto(
    string    Id,
    string    Name,
    string?   ConditionJson,
    int       CooldownMinutes,
    bool      IsEnabled);

public record BehaviorBaselineDto(
    Guid      UserId,
    DateTime  BaselineDate,
    DateTime  UpdatedAtUtc,
    string?   TypicalHoursJson,
    string?   KnownIpsJson,
    string?   KnownDevicesJson);

public record ThreatIntelReportDto(
    int       TotalActive,
    List<AnomalyDto>    Hits24h,
    List<ThreatSourceDto>? BySource);
public record ThreatSourceDto(string Source, int Count);

public record ThreatFeedConfigDto(
    string    Id,
    string    Name,
    string    FeedType,
    bool      IsEnabled,
    DateTime? LastRefreshedAtUtc,
    int?      LastIndicatorCount,
    string?   LastError);

// SessionPlayback.razor
public record RecordingMetadataDto(
    DateTime  CreatedAtUtc,
    double    DurationSeconds,
    string?   FileHash,
    long      FileSizeBytes,
    string?   Format,
    bool      IntegrityValid,
    int?      TerminalWidth,
    int?      TerminalHeight,
    string?   WatermarkTitle);

public record RecordingStreamDto(
    string?   Format,
    List<RecordingEventDto>? Events,
    List<HttpEntryDto>? Entries);

public record RecordingEventDto(
    double    T,
    string    Type,
    string?   Data);

public record HttpEntryDto(
    double    T,
    string    Method,
    string    Url,
    int       StatusCode,
    double    DurationMs,
    Dictionary<string, string>? RequestHeaders,
    string?   RequestBody,
    Dictionary<string, string>? ResponseHeaders,
    string?   ResponseBody);

public record CommandLogDto(
    string?   Command,
    DateTime  Timestamp,
    bool      WasBlocked,
    string?   BlockReason,
    decimal   RiskScore,
    long      Id = 0,
    Guid      SessionId = default);

public record RecordingSearchHitDto(
    int       EventIndex,
    double    TimestampSeconds,
    string?   MatchedText);

public record ScreenCaptureFrameDto(
    int       FrameIndex,
    DateTime  CapturedAtUtc,
    int?      Width,
    int?      Height,
    string?   SessionType);

// Integrations.razor
public record SoarConfigDto(
    string?   Id,
    string?   Name,
    string?   Provider,
    string?   WebhookUrl,
    bool      IsEnabled);

public record ItsmConfigDto(
    string    Id,
    string    Name,
    string    Provider,
    string    BaseUrl,
    bool      RequireTicket,
    bool      ValidateTicket,
    bool      IsEnabled);

public record TrustedCaDto(
    string    Id,
    string    Name,
    string    Subject,
    string    Thumbprint,
    DateTime  NotAfter,
    bool      IsEnabled);

public record PkiUserCertDto(
    string    Id,
    string    Username,
    string    SubjectDn,
    string    CertThumbprint,
    DateTime  ExpiresAtUtc,
    bool      RequirePkiOnly,
    DateTime? LastUsedAtUtc);

public record SiemTargetDto(
    string    Id,
    string    Name,
    string    Host,
    int       Port,
    string    Protocol,
    string    Format,
    bool      IsEnabled,
    DateTime? LastSentAtUtc,
    int       TotalEventsSent,
    string?   LastError);


// Integrations.razor — Windows Auth settings DTO
public record WindowsAuthSettingsDto(
    bool      Enabled,
    bool      AutoProvision,
    bool      MfaBypass,
    string    TrustedDomains);

// Integrations.razor — ITSM test result DTO
public record ItsmTestResultDto(
    string    Provider,
    string    BaseUrl,
    int       ResponseTimeMs,
    string?   Message);

// Integrations.razor — SIEM test result DTO
public record SiemTestResultDto(
    bool      Success,
    string?   Error,
    int       LatencyMs);
// Home.razor
public record CredentialRiskSummaryDto(
    int       Critical,
    int       High,
    int       Medium,
    int       Low);

public record HighRiskCredentialDto(
    string    Name,
    string?   Username,
    string    RiskLevel,
    int       RiskScore,
    string?   FolderName,
    DateTime? LastRotatedAtUtc);

public record RotationFailuresResponseDto(
    List<RotationFailureItemDto> Items,
    int Count24h = 0);
public record RotationFailureItemDto(
    string    Name,
    string?   Username,
    int       RotationFailureCount,
    string?   LastRotationError,
    DateTime? LastRotationFailedAtUtc);

// Vault.razor
public record FolderDto(
    string    Id,
    string    Name,
    string?   ParentFolderId,
    int       CredentialCount);

public record CredentialTemplateDto(
    Guid      Id,
    string    Name,
    string?   Description,
    string?   DeviceType,
    string?   CredentialKind,
    int       RotationPeriodDays,
    string?   DefaultUsername,
    bool      IsBuiltIn,
    DateTime? CreatedAtUtc,
    string?   Notes = null,
    int       PasswordMinLength = 0,
    bool      PasswordRequireSpecial = false,
    bool      SshKeyRotation = false);

public record RotationScriptDto(
    string    Id,
    string    Name,
    string?   Description,
    string?   DeviceType,
    string?   ScriptType,
    bool      IsEnabled,
    DateTime  CreatedAtUtc,
    string?   ScriptContent = null,
    string?   TestScriptContent = null);

// Discovery.razor
public record DiscoveredAccountDto(
    Guid      Id,
    string    AccountName,
    string?   AccountType,
    string    Status,
    bool      InVault,
    Guid?     LinkedCredentialId,
    string?   HostName,
    bool      IsEnabled,
    DateTime  DiscoveredAtUtc);

public record DiscoveryJobDto(
    Guid      Id,
    string    Name,
    string    Type,
    string?   Schedule,
    DateTime? LastRunAtUtc);

public record DiscoveryScanResultDto(
    string    Result,
    int       AccountsFound,
    List<DiscoveryScanAccountDto>? Accounts);
public record DiscoveryScanAccountDto(
    string    AccountName,
    string?   AccountType,
    string?   HostName,
    bool      IsEnabled);

// SelfService.razor
public record CheckoutResultDto(
    string    Name,
    string?   Username,
    string?   Password,
    DateTime? ExpiresAt,
    string?   PrivateKey = null);

public record MySessionDto(
    string    Id,
    string?   TargetIpAddress,
    int?      TargetPort,
    string    Type,
    string    Status,
    DateTime  StartedAtUtc,
    int       DurationMinutes);

public record UserProfileDto(
    string    Username,
    string?   DisplayName,
    string?   Email,
    string    AuthSource,
    string    Status,
    List<string>? Roles,
    bool      MfaEnabled,
    string?   MfaType,
    DateTime? LastLoginAtUtc,
    DateTime? PasswordLastChanged,
    DateTime? PasswordExpiresAt,
    string?   Timezone,
    string?   Language,
    bool      MustChangePassword);

public record MfaDeviceDto(
    string    Type,
    string    Name,
    string    Status,
    string?   Detail,
    string?   DeviceId = null);

// Encryption.razor
public record KeyStatusDto(
    bool      IsInitialized,
    int       Version,
    DateTime? InitializedAtUtc,
    int       RotationCount,
    int       DekCacheTtlMinutes);

public record FipsStatusDto(
    bool      FipsEnabled,
    string?   Algorithm,
    string?   Standard);

// SystemHealth.razor
public record SystemHealthSnapshotDto(
    double    CpuPercent,
    double    MemoryMb,
    double    DiskPercent,
    List<ProxyServiceStatusDto>? Services);
public record ProxyServiceStatusDto(
    string    Name,
    bool      Healthy,
    int       LatencyMs);

public record SystemAlarmDto(
    long      Id,
    DateTime  OccurredAtUtc,
    string    MetricName,
    string    Severity,
    string?   Message,
    string    Status,
    bool      EmailSent);

// SystemLogs.razor
public record SystemLogEntryDto(
    string    Timestamp,
    string    Level,
    string    Message,
    string?   Username,
    string?   IpAddress,
    string?   Details,
    string?   Source = null);

// NetworkAccess.razor
public record TacacsCommandPolicyDto(
    string    Id,
    string    Username,
    string    DevicePattern,
    string    Mode,
    string?   Commands,
    DateTime  CreatedAtUtc);

// PushDevices.razor
public record PushDeviceDto(
    string?   Id,
    string?   Name,
    DateTime? RegisteredAt = null);

public record PushEnrollResultDto(
    string?   DeviceToken,
    string?   DeviceName,
    string?   DeviceId);

// SecurityKeys.razor
public record SecurityKeyDto(
    string    Id,
    DateTime  RegisteredAt,
    DateTime? LastUsed,
    string?   FriendlyName = null);

// RdpManagement.razor
public record RdpHaNodeDto(
    string    Host,
    bool      Healthy,
    int       LatencyMs,
    string?   Error = null);

public record RemoteAppDto(
    string    Name,
    string    AppPath,
    string?   Description = null,
    string?   Category = null);

// Approvals.razor
public record PendingApprovalDto(
    string    RequestId,
    string?   ResourceType,
    string?   ResourceId,
    string?   RequesterId,
    string?   Reason,
    int       StepOrder,
    DateTime  CreatedAtUtc,
    DateTime? ExpiresAtUtc);

// Vendors.razor
public record VendorAccessDto(
    string    Id,
    string    Username,
    string?   DisplayName,
    string?   Email,
    string    Status,
    bool      MfaEnabled,
    DateTime? TemporaryExpiresUtc,
    string?   VendorSponsorUsername,
    string?   Company = null,
    string?   VendorName = null,
    DateTime  StartAtUtc = default,
    DateTime  EndAtUtc = default,
    string?   CreatedByUsername = null,
    int?      AllowedHoursStart = null,
    int?      AllowedHoursEnd = null,
    string?   RevokeReason = null);

// CredentialAssignments.razor
public record AssignedCredentialDto(
    string    Id,
    string?   CredentialName,
    string    PrincipalType,
    string    PrincipalId,
    string?   DeviceGroupId,
    bool      IsEnabled);

// CredentialGovernance.razor
public record CredentialGovernanceSummaryDto(
    int       TotalCredentials,
    int       ExpiredCredentials,
    int       ExpiringIn7Days,
    int       CriticalRisk,
    int       TotalAssignments,
    int       NeverRotated,
    int       RotationFailures,
    int       OrphanedAssignments);

public record CredentialAccessMatrixItemDto(
    string    CredentialName,
    string?   CredentialUsername,
    string?   FolderName,
    string?   CredentialRiskLevel,
    string    PrincipalName,
    string    PrincipalType,
    string?   DeviceGroup,
    DateTime? LastUsed,
    bool      IsEnabled);

public record StaleCredentialAccessDto(
    string    Username,
    string    CredentialName,
    string?   CredentialUsername,
    bool      IsNeverUsed,
    DateTime? LastUsed,
    DateTime  AssignedAt = default,
    int       DaysInactive = 0);

// Sessions.razor
public record RestorableSessionDto(
    Guid      Id,
    string    Protocol,
    DateTime  CreatedAtUtc,
    DateTime  ExpiresAtUtc,
    Guid?     OriginalSessionId = null);

// Users.razor
public record ImportResultDto(
    int       Imported,
    int       Failed);

// ExecutiveDashboard.razor
public record ExecutiveDashboardDto(
    DateTime  GeneratedAtUtc,
    int       PeriodDays,
    ExecKpisDto                      Kpis,
    ExecComplianceDto                Compliance,
    List<ExecSessionTrendDto>?       SessionTrend,
    List<ExecProtocolDistDto>?       ProtocolDistribution,
    List<ExecSessionTrendDto>?       FailedLoginTrend,
    List<ExecTopDeviceDto>?          TopDevices,
    List<ExecTopUserDto>?            TopUsers);
public record ExecKpisDto(
    int       TotalPrivilegedUsers,
    int       UserWeeklyChange,
    int       ActiveSessions,
    int       OpenAlarms,
    int       PendingApprovals,
    int       FailedLoginsLast24h,
    int       ExpiringCredentials);
public record ExecComplianceDto(
    double    RotationCompliance,
    double    MfaEnrollmentRate,
    int       OrphanedAccountCount,
    bool      CertificationCompleted,
    double    CertCompletionRate);
public record ExecSessionTrendDto(string Date, int Count);
public record ExecProtocolDistDto(string Protocol, int Count);
public record ExecTopDeviceDto(string? Name, string? IpAddress, int SessionCount);
public record ExecTopUserDto(string Username, int SessionCount);

// Policies.razor — policy settings DTOs
public record PasswordPolicySettingsDto(
    int       MinLength,
    int       MaxLength,
    bool      RequireUppercase,
    bool      RequireLowercase,
    bool      RequireDigit,
    bool      RequireSpecial,
    int       ExpiryDays,
    int       PreventReuseCount,
    bool      ForceChangeOnFirstLogin);

public record LockoutPolicySettingsDto(
    int       MaxFailedAttempts,
    int       LockoutMinutes,
    int       FailedAttemptWindowMinutes);

public record SessionPolicySettingsDto(
    int       IdleTimeoutMinutes,
    int       MaxConcurrentSessions,
    byte      CommandFilterMode,
    string?   CommandFilterRulesJson,
    decimal   DoubleConfirmRiskThreshold,
    string?   DoubleConfirmCommandsJson);

public record MfaPolicySettingsDto(
    bool      MfaRequired,
    bool      EmailOtpEnabled,
    bool      SmsOtpEnabled);

public record WatermarkPolicySettingsDto(
    bool      Enabled,
    string?   Template,
    int       MarkerIntervalMin,
    bool      EnableSsh,
    bool      EnableRdp,
    bool      EnableVnc);

public record AdaptiveMfaPolicySettingsDto(
    bool      Enabled,
    int       LowRiskThreshold,
    int       MediumRiskThreshold,
    int       HighRiskThreshold,
    int       BlockThreshold);

public record DeviceTrustPolicySettingsDto(
    bool      Enabled,
    bool      RequireTrustedDevice,
    string?   UnknownDeviceAction,
    int       MaxTrustAgeDays,
    bool      AutoRegisterOnLogin);

public record GeolocationPolicySettingsDto(
    bool      Enabled,
    string[]  AllowedCountryCodes,
    string[]  BlockedCountryCodes,
    string?   ViolationAction,
    string?   UnknownLocationAction,
    bool      AllowPrivateIps);

// Reports.razor — schedule DTOs
public record CreateReportScheduleDto(
    string    Name,
    string    ReportType,
    string    Frequency,
    int       DayOfWeek,
    int       DayOfMonth,
    int       RunAtHourUtc,
    string    Format,
    string    Recipients);

public record UpdateReportScheduleDto(
    bool      IsActive);

// Integrations.razor — SMS gateway DTO
public record SmsGatewayConfigDto(
    string?   Provider,
    string?   AccountSid,
    string?   AuthToken,
    string?   FromNumber,
    string?   WebhookUrl,
    string?   WebhookSecret,
    string?   NetgsmUser,
    string?   NetgsmPassword,
    string?   NetgsmOriginator,
    bool      AuthTokenSet = false,
    bool      WebhookSecretSet = false,
    bool      NetgsmPasswordSet = false);

// Vault.razor — Current user DTO
public record CurrentUserDto(
    string?       UserId,
    string?       Username,
    List<string>  Roles);

// Vault.razor — Access request result
public record AccessRequestResultDto(
    bool      Success,
    string?   Message = null,
    string?   Status = null);

// Vault.razor — SSH key pair generation result
public record SshKeyPairDto(
    string    PrivateKey,
    string    PublicKey);

// Vault.razor — Script test result
public record ScriptTestResultDto(
    bool      Success,
    int       ExitCode,
    string?   Output = null,
    string?   Error = null);

// BreakGlass.razor — list wrapper
public record BreakGlassListResult(List<BreakGlassDto> Data);

// Policies.razor — list wrapper
public record PolicyListResult(List<PolicyDto> Data);

// MfaSetup.razor — enrollment DTO
public record MfaEnrollmentDto(
    string    Username,
    string    Secret,
    string    QrUri);

// MfaSetup.razor — confirm result
public record MfaConfirmResult(bool Success, MfaConfirmDataDto? Data);
public record MfaConfirmDataDto(string[]? RecoveryCodes);

// Users.razor — MFA setup link DTO
public record MfaSetupLinkDto(
    string    EnrollmentToken,
    DateTime? ExpiresAt);

// Connect.razor / RdpManagement.razor — RDP launch/shadow result
public record RdpLaunchResultDto(
    RdpFileDto? RdpFile,
    string? SessionId = null);

public record RdpFileDto(
    string Filename,
    string ContentBase64);

// Connect.razor — connection profile download
public record ConnectionProfileResultDto(
    string Filename,
    string Content,
    string MimeType);

// CredentialGovernance.razor — access matrix paged result
public record CredentialAccessMatrixResultDto(
    List<CredentialAccessMatrixItemDto>? Items,
    int Total);

// Discovery.razor — bulk import result
public record BulkImportResultDto(
    string? Message,
    int Imported = 0,
    int Skipped = 0);

// Sessions.razor — restore session result
public record RestoreSessionResultDto(
    Guid NewSessionId,
    string? Protocol,
    string? TargetIpAddress,
    int? TargetPort);

// HealthAlarmConfig DTO for SystemHealth.razor
public record HealthAlarmConfigDto(
    string? CpuWarningPct,
    string? MemoryWarningMb,
    string? DiskFreeWarningPct,
    string? AlarmRecipients);

// CustomReportPreviewResult DTO for Reports.razor custom report preview/run
public record CustomReportPreviewResultDto(
    List<string> Columns,
    List<Dictionary<string, string>> Rows,
    string? FilterSummary);
