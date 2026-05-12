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

    public async Task<LoginResult?> LoginAsync(string username, string password)
    {
        var client = _factory.CreateClient("PamApi");
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/login",
                new { username, password, mfaCode = (string?)null });
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

    // -----------------------------------------------------------------------
    // Vault
    // -----------------------------------------------------------------------

    public async Task<PagedResult<CredentialDto>?> GetCredentialsAsync(
        string? deviceId = null, string? search = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/vault/credentials?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(deviceId)) url += $"&deviceId={deviceId}";
        if (!string.IsNullOrEmpty(search))   url += $"&search={Uri.EscapeDataString(search)}";
        return await GetAsync<PagedResult<CredentialDto>>(url);
    }

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
    string  Id,
    string? Username,
    string  CredentialType,
    string? Description,
    string  DeviceId,
    string? FolderId,
    bool    IsActive);
