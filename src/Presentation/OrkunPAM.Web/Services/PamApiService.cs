using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

namespace OrkunPAM.Web.Services;

/// <summary>
/// Thin API client for PAM Web API. Injects Bearer token from AuthStateService.
/// All methods return null on HTTP error to let pages show friendly error state.
/// </summary>
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

    // -----------------------------------------------------------------------
    // Auth
    // -----------------------------------------------------------------------

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

    // -----------------------------------------------------------------------
    // Users
    // -----------------------------------------------------------------------

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
            var resp = await client.PatchAsJsonAsync($"/api/v1/users/{id}/status",
                new { status = newStatus });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> CreateUserAsync(string username, string? displayName, string? email, string password)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/users",
                new { username, displayName, email, password, authSource = "Local" });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdateUserAsync(string id, string? displayName, string? email)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PatchAsJsonAsync($"/api/v1/users/{id}",
                new { displayName, email });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // -----------------------------------------------------------------------
    // Devices
    // -----------------------------------------------------------------------

    public async Task<PagedResult<DeviceDto>?> GetDevicesAsync(
        string? search = null, string? type = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/devices?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(search)) url += $"&search={Uri.EscapeDataString(search)}";
        if (!string.IsNullOrEmpty(type))   url += $"&type={type}";
        return await GetAsync<PagedResult<DeviceDto>>(url);
    }

    public async Task<bool> CreateDeviceAsync(
        string hostname, string? fqdn, string? ipAddress,
        string type, string protocol, int connectionPort, string? operatingSystem)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/devices",
                new { hostname, fqdn, ipAddress, type, protocol, connectionPort, operatingSystem });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdateDeviceAsync(
        string id, string hostname, string? fqdn, string? ipAddress,
        string type, string protocol, int connectionPort, string? operatingSystem)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync($"/api/v1/devices/{id}",
                new { hostname, fqdn, ipAddress, type, protocol, connectionPort, operatingSystem });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // -----------------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------------

    public async Task<PagedResult<SessionDto>?> GetSessionsAsync(
        string? status = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/sessions?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(status)) url += $"&status={status}";
        return await GetAsync<PagedResult<SessionDto>>(url);
    }

    /// <summary>
    /// Creates an RDP session and returns token + .rdp file content for the browser to download.
    /// </summary>
    public async Task<RdpLaunchResult?> LaunchRdpSessionAsync(string deviceId, string credentialId,
        string? reason = null, string? ticketNumber = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/sessions/rdp/connect", new
            {
                deviceId     = Guid.Parse(deviceId),
                credentialId = Guid.Parse(credentialId),
                reason,
                ticketNumber
            });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<RdpLaunchResult>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    // -----------------------------------------------------------------------
    // Vault -- Folders
    // -----------------------------------------------------------------------

    public async Task<List<FolderDto>?> GetFoldersAsync()
    {
        var result = await GetAsync<ListResult<FolderDto>>("/api/v1/vault/folders");
        return result?.Data;
    }

    public async Task<List<CredentialDto>?> GetFolderCredentialsAsync(string folderId)
    {
        var result = await GetAsync<ListResult<CredentialDto>>(
            $"/api/v1/vault/folders/{folderId}/credentials");
        return result?.Data;
    }

    public async Task<bool> CreateFolderAsync(string name, string? description = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/vault/folders",
                new { name, description, parentFolderId = (string?)null });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // -----------------------------------------------------------------------
    // Vault -- Credentials
    // -----------------------------------------------------------------------

    public async Task<PagedResult<CredentialDto>?> GetCredentialsAsync(
        string? deviceId = null, string? search = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/vault/credentials?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(deviceId)) url += $"&deviceId={deviceId}";
        if (!string.IsNullOrEmpty(search))   url += $"&search={Uri.EscapeDataString(search)}";
        return await GetAsync<PagedResult<CredentialDto>>(url);
    }

    public async Task<bool> CreateCredentialAsync(
        string name, int type, string? username, string? password,
        string folderId, string? deviceId, string? description,
        int maxCheckoutMinutes, bool requiresApproval)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/vault/credentials",
                new { folderId, name, description, type, username, password,
                      deviceId, maxCheckoutMinutes, requiresApproval });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<CheckoutResultDto?> CheckoutCredentialAsync(
        string id, string? reason, string? ticketNumber, int? durationMinutes)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync(
                $"/api/v1/vault/credentials/{id}/checkout",
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
        try
        {
            return (await client.PostAsync(
                $"/api/v1/vault/credentials/{id}/checkin", null)).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // -----------------------------------------------------------------------
    // Policies
    // -----------------------------------------------------------------------

    public async Task<SimpleResult<PolicyDto>?> GetPoliciesAsync(string? type = null)
    {
        var url = "/api/v1/policies";
        if (!string.IsNullOrEmpty(type)) url += $"?type={type}";
        return await GetAsync<SimpleResult<PolicyDto>>(url);
    }

    public async Task<bool> CreatePolicyAsync(string name, string policyType, int scope, string policyJson, int priority)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/policies", new
            {
                name, policyType, scope,
                scopeId    = (Guid?)null,
                policyJson, priority
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> TogglePolicyAsync(string id, bool enabled)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync($"/api/v1/policies/{id}",
                new { isEnabled = enabled });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeletePolicyAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/policies/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<PasswordPolicySettingsDto?> GetPasswordPolicyAsync()
    {
        var result = await GetAsync<PolicySettingResult<PasswordPolicySettingsDto>>("/api/v1/policy/password");
        return result?.Data;
    }

    public async Task<bool> SavePasswordPolicyAsync(PasswordPolicySettingsDto s)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsJsonAsync("/api/v1/policy/password", s)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<LockoutPolicySettingsDto?> GetLockoutPolicyAsync()
    {
        var result = await GetAsync<PolicySettingResult<LockoutPolicySettingsDto>>("/api/v1/policy/lockout");
        return result?.Data;
    }

    public async Task<bool> SaveLockoutPolicyAsync(LockoutPolicySettingsDto s)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsJsonAsync("/api/v1/policy/lockout", s)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<SessionPolicySettingsDto?> GetSessionPolicyAsync()
    {
        var result = await GetAsync<PolicySettingResult<SessionPolicySettingsDto>>("/api/v1/policy/session");
        return result?.Data;
    }

    public async Task<bool> SaveSessionPolicyAsync(SessionPolicySettingsDto s)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsJsonAsync("/api/v1/policy/session", s)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // -----------------------------------------------------------------------
    // Approvals
    // -----------------------------------------------------------------------

    public async Task<int> GetPendingApprovalCountAsync()
    {
        var result = await GetAsync<PagedResult<object>>("/api/v1/approval-requests?status=Pending&pageSize=1");
        return result?.Meta?.TotalCount ?? 0;
    }

    // -----------------------------------------------------------------------
    // Current user
    // -----------------------------------------------------------------------

    public async Task<AuthUser?> GetCurrentUserAsync() => await _auth.GetUserAsync();

    // -----------------------------------------------------------------------
    // Dashboard stats helpers
    // -----------------------------------------------------------------------

    public async Task<int> GetTotalCountAsync(string path)
    {
        var result = await GetAsync<PagedResultMeta>($"{path}?pageSize=1");
        return result?.Meta?.TotalCount ?? 0;
    }

    // -----------------------------------------------------------------------
    // Private helpers
    // -----------------------------------------------------------------------

    private async Task<HttpClient> GetAuthClientAsync()
    {
        var client = _factory.CreateClient("PamApi");
        var token  = await _auth.GetTokenAsync();
        if (!string.IsNullOrEmpty(token))
            client.DefaultRequestHeaders.Authorization =
                new AuthenticationHeaderValue("Bearer", token);
        return client;
    }

    private async Task<T?> GetAsync<T>(string url) where T : class
    {
        try
        {
            var client = await GetAuthClientAsync();
            var resp   = await client.GetAsync(url);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<T>(JsonOpts);
        }
        catch { return null; }
    }
}

// ---------------------------------------------------------------------------
// DTOs matching PAM API response envelope
// ---------------------------------------------------------------------------

public record LoginResult(bool Success, LoginData? Data);
public record LoginData(
    string   AccessToken,
    string   RefreshToken,
    DateTime ExpiresAt,
    string   UserId,
    string   Username,
    string   DisplayName,
    bool     MfaRequired,
    bool     MustChangePassword,
    bool     PasswordExpired);

public record PagedResult<T>(bool Success, List<T>? Data, PageMeta? Meta);
public record PagedResultMeta(bool Success, PageMeta? Meta);
public record PageMeta(int Page, int PageSize, int TotalCount);
public record SingleResult<T>(bool Success, T? Data) where T : class;
public record ListResult<T>(bool Success, List<T>? Data);
public record SimpleResult<T>(bool Success, List<T>? Data);

public record UserDto(
    string    Id,
    string    Username,
    string?   DisplayName,
    string?   Email,
    string    AuthSource,
    string    Status,
    bool      MfaEnabled,
    bool      IsTemporary,
    DateTime? LastLoginAtUtc,
    DateTime  CreatedAtUtc);

public record DeviceDto(
    string  Id,
    string  Hostname,
    string? Fqdn,
    string? IpAddress,
    string  Type,
    string  Protocol,
    int?    ConnectionPort,
    string? OperatingSystem,
    string  Status,
    bool    IsReachable,
    bool    IsManaged,
    int     CredentialCount);

public record SessionDto(
    string    Id,
    string    SessionType,
    string    Status,
    string?   ClientIpAddress,
    string?   TargetIpAddress,
    int?      TargetPort,
    DateTime  StartedAtUtc,
    DateTime? EndedAtUtc);

public record CredentialDto(
    string    Id,
    string    Name,
    string?   Username,
    string    Type,
    string    Status,
    string?   Description,
    string?   DeviceId,
    string?   FolderId,
    bool      IsCheckedOut,
    string?   CheckedOutByUserId,
    DateTime? CheckOutExpiresUtc,
    DateTime? LastRotatedAtUtc,
    bool      RequiresApproval);

public record FolderDto(
    string  Id,
    string  Name,
    string? Description,
    string? ParentFolderId,
    int     CredentialCount,
    int     ChildCount);

public record CheckoutResultDto(
    string    Id,
    string    Name,
    string?   Username,
    string?   Password,
    DateTime? ExpiresAt);

public record PolicyDto(
    string  Id,
    string  Name,
    string  PolicyType,
    string  Scope,
    string? ScopeId,
    int     Priority,
    bool    IsEnabled);

public record PolicySettingResult<T>(bool Success, T? Data) where T : class;

public record PasswordPolicySettingsDto(
    int  MinLength,
    int  MaxLength,
    bool RequireUppercase,
    bool RequireLowercase,
    bool RequireDigit,
    bool RequireSpecial,
    int  ExpiryDays,
    int  PreventReuseCount,
    bool ForceChangeOnFirstLogin);

public record LockoutPolicySettingsDto(
    int MaxFailedAttempts,
    int LockoutMinutes,
    int FailedAttemptWindowMinutes);

public record SessionPolicySettingsDto(
    int IdleTimeoutMinutes,
    int MaxConcurrentSessions);

public record RdpLaunchResult(
    string       SessionId,
    string       SessionToken,
    string       ProxyHost,
    int          ProxyPort,
    RdpFileInfo  RdpFile);

public record RdpFileInfo(string Filename, string ContentBase64);
