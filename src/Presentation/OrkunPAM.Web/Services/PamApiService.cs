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

    public async Task<DeviceDto?> CreateDeviceAsync(object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/devices", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<DeviceDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<DeviceDto?> UpdateDeviceAsync(string id, object payload)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PutAsJsonAsync($"/api/v1/devices/{id}", payload);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<DeviceDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
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

    // ── Sessions ───────────────────────────────────────────────────────────────
    public async Task<PagedResult<SessionDto>?> GetSessionsAsync(
        string? status = null, Guid? userId = null, Guid? deviceId = null, int page = 1, int pageSize = 20)
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

    public async Task<PagedResult<SessionCommandDto>?> GetSessionCommandsAsync(
        string sessionId, int page = 1, int pageSize = 100)
        => await GetAsync<PagedResult<SessionCommandDto>>(
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

    // ── Audit Logs ─────────────────────────────────────────────────────────────
    public async Task<PagedResult<AuditLogDto>?> GetAuditLogsAsync(
        string? action = null, string? userId = null, DateTime? from = null, DateTime? to = null,
        int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/audit?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(action)) url += $"&action={Uri.EscapeDataString(action)}";
        if (!string.IsNullOrEmpty(userId)) url += $"&userId={userId}";
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
    public async Task<List<BackupDto>?> GetBackupsAsync()
    {
        var result = await GetAsync<ListResult<BackupDto>>("/api/v1/system/backups");
        return result?.Data;
    }

    public async Task<BackupDto?> CreateBackupAsync(string? description = null)
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp = await client.PostAsJsonAsync("/api/v1/system/backups", new { description });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<BackupDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> RestoreBackupAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/system/backups/{id}/restore", null)).IsSuccessStatusCode; }
        catch { return false; }
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
    public async Task<PagedResult<VendorUserDto>?> GetVendorUsersAsync(int page = 1, int pageSize = 20)
        => await GetAsync<PagedResult<VendorUserDto>>($"/api/v1/users/vendors?page={page}&pageSize={pageSize}");

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
    public async Task<List<ThreatIndicatorDto>?> GetThreatIndicatorsAsync()
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

    /// <summary>
    /// GET helper: tries to deserialize the `data` sub-field of the API envelope first.
    /// Falls back to reading the full root JSON for wrapper types (PagedResult/ListResult).
    /// </summary>
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
    Guid     UserId,
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
    Guid      Id,
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
    DateTime  CreatedAtUtc);

public record GroupDto(
    Guid     Id,
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
    Guid      Id,
    string    Name,
    string    Hostname,
    string    IpAddress,
    string    DeviceType,
    string    OperatingSystem,
    int       SshPort,
    int       RdpPort,
    string    Status,
    Guid?     GroupId,
    string?   GroupName,
    string?   Description,
    DateTime  CreatedAtUtc,
    DateTime  UpdatedAtUtc);

public record DeviceGroupDto(
    Guid      Id,
    string    Name,
    string?   Description,
    Guid?     ParentGroupId,
    string?   ParentGroupName,
    int       DeviceCount,
    DateTime  CreatedAtUtc);

public record CredentialDto(
    Guid      Id,
    string    Username,
    string    CredentialType,
    Guid      DeviceId,
    string    DeviceName,
    Guid?     GroupId,
    string?   GroupName,
    bool      IsCheckedOut,
    Guid?     CheckedOutBy,
    DateTime? CheckedOutAt,
    DateTime? CheckedOutUntil,
    DateTime? LastRotatedAt,
    DateTime? NextRotationAt,
    DateTime  CreatedAtUtc);

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
    Guid      Id,
    string    Name,
    string?   Description,
    List<Guid> UserGroupIds,
    List<string> UserGroupNames,
    List<Guid> DeviceGroupIds,
    List<string> DeviceGroupNames,
    string    PolicyKey,
    bool      RequiresApproval,
    DateTime  CreatedAtUtc,
    DateTime  UpdatedAtUtc);

public record SessionDto(
    Guid      Id,
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
    DateTime  CreatedAtUtc);

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
    int      LastSyncCount);

public record LdapSyncResultDto(int Added, int Updated, int Disabled, int Total, DateTime SyncedAt);

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
    DateTime? ExpiresAt);

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
    DateTime  CreatedAtUtc);

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
    int      GracePeriodDays);

public record ThreatIndicatorDto(
    Guid     Id,
    string   IndicatorType,
    string   Value,
    string?  Description,
    string   Severity,
    bool     IsActive,
    DateTime CreatedAtUtc);

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

public record SessionCommandDto(
    long     Id,
    Guid     SessionId,
    DateTime Timestamp,
    string?  Command,
    decimal  RiskScore,
    bool     WasBlocked,
    string?  BlockReason);

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
    DateTime ProvisionedAtUtc);