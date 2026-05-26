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

    public async Task<PagedResult<GroupDto>?> GetGroupsAsync(int page = 1, int pageSize = 50)
        => await GetAsync<PagedResult<GroupDto>>($"/api/v1/users/groups?page={page}&pageSize={pageSize}");

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

    // ── Roles ──────────────────────────────────────────
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

    // ── Devices ──────────────────────────────────────────
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

    // ── Network Zones ─────────────────────────────────────
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

    // ── External Vault Federation (#284 — PV #12) ────────────────────────

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

    // ── SCIM 2.0 Token Management (#291) ──────────────────────────────────
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

    // ── Device Groups ──────────────────────────────────────────
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

    // ── Credentials / Vault ───────────────────────────────────────
    public async Task<PagedResult<CredentialDto>?> GetCredentialsAsync(
        string? search = null, string? type = null, Guid? deviceId = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/vault/credentials?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(search)) url += $"&search={Uri.EscapeDataString(search)}";
        if (!string.IsNullOrEmpty(type))   url += $"&type={type}";
        if (deviceId.HasValue)             url += $"&deviceId={deviceId.Value}";
        return await GetAsync<PagedResult<CredentialDto>>(url);
    }

    public async Task<CredentialDto?> GetCredentialAsync(string id)
        => await GetAsync<CredentialDto>($"/api/v1/vault/credentials/{id}");

    public async Task<CredentialDto?> CreateCredentialAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/vault/credentials", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<CredentialDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
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

    public async Task<string?> CheckoutCredentialAsync(string id, string? reason = null, int? durationMinutes = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync($"/api/v1/vault/credentials/{id}/checkout",
                new { reason, durationMinutes });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<CheckoutDto>>(JsonOpts);
            return result?.Data?.Password;
        }
        catch { return null; }
    }

    public async Task<bool> CheckinCredentialAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/vault/credentials/{id}/checkin", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> RotateCredentialAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/vault/credentials/{id}/rotate", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // ── Credential Groups ──────────────────────────────────────────
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

    // ── Access Assignments ─────────────────────────────────────────
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

    // ── Device Realms ──────────────────────────────────────────
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