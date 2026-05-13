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

    public async Task<List<PendingApprovalDto>?> GetPendingApprovalsAsync(string approverId)
    {
        var result = await GetAsync<SimpleResult<PendingApprovalDto>>(
            "/api/v1/approval-requests/pending?approverId=" + Uri.EscapeDataString(approverId));
        return result?.Data;
    }

    public async Task<PagedResult<ApprovalRequestDto>?> GetApprovalsAsync(
        string? status = null, int page = 1, int pageSize = 20)
    {
        var url = "/api/v1/approval-requests?page=" + page + "&pageSize=" + pageSize;
        if (!string.IsNullOrEmpty(status)) url += "&status=" + Uri.EscapeDataString(status);
        return await GetAsync<PagedResult<ApprovalRequestDto>>(url);
    }

    public async Task<bool> ApproveRequestAsync(string id, string? comments)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync(
                "/api/v1/approval-requests/" + id + "/approve",
                new { comments });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DenyRequestAsync(string id, string? comments)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync(
                "/api/v1/approval-requests/" + id + "/deny",
                new { comments });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> RotateCredentialAsync(
        string credentialId, string connector,
        string? host = null, int? port = null, string? domain = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync(
                "/api/v1/vault/credentials/" + credentialId + "/rotate",
                new { connector, host, port, domain });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // -----------------------------------------------------------------------
    // Reports & Audit Logs
    // -----------------------------------------------------------------------

    public async Task<ListResult<ReportDto>?> GetReportsListAsync()
        => await GetAsync<ListResult<ReportDto>>("/api/v1/reports/");

    public async Task<ReportRunResult?> RunReportAsync(string reportId, DateTime from, DateTime to)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/reports/" + reportId + "/run",
                new { from, to });
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<ReportRunResult>(JsonOpts);
        }
        catch { return null; }
    }

    public async Task<PagedResult<AuditLogDto>?> GetAuditLogsAsync(
        string? category = null, string? eventType = null,
        DateTime? from = null, DateTime? to = null,
        int page = 1, int pageSize = 50)
    {
        var url = "/api/v1/audit-logs?page=" + page + "&pageSize=" + pageSize;
        if (!string.IsNullOrEmpty(category)) url += "&category=" + Uri.EscapeDataString(category);
        if (!string.IsNullOrEmpty(eventType)) url += "&eventType=" + Uri.EscapeDataString(eventType);
        if (from.HasValue) url += "&from=" + Uri.EscapeDataString(from.Value.ToString("O"));
        if (to.HasValue) url += "&to=" + Uri.EscapeDataString(to.Value.ToString("O"));
        return await GetAsync<PagedResult<AuditLogDto>>(url);
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
    // Break-Glass (#46)
    // -----------------------------------------------------------------------

    public async Task<BreakGlassSubmitResult?> SubmitBreakGlassAsync(
        string resourceType, Guid? resourceId, string? resourceName,
        string emergencyReason, string? ticketNumber, int expiresInMinutes = 60)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/break-glass", new
            {
                resourceType, resourceId, resourceName,
                emergencyReason, ticketNumber, expiresInMinutes
            });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<BreakGlassSubmitResult>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<PagedResult<BreakGlassDto>?> GetBreakGlassEventsAsync(
        string? status = null, int page = 1, int pageSize = 50)
    {
        var url = $"/api/v1/break-glass?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(status)) url += $"&status={status}";
        return await GetAsync<PagedResult<BreakGlassDto>>(url);
    }

    public async Task<ListResult<BreakGlassDto>?> GetMyBreakGlassEventsAsync()
        => await GetAsync<ListResult<BreakGlassDto>>("/api/v1/break-glass/my");

    public async Task<bool> AcknowledgeBreakGlassAsync(string id, string? notes)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/break-glass/{id}/acknowledge",
                new { notes });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> RevokeBreakGlassAsync(string id, string? notes = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/break-glass/{id}/revoke",
                new { notes });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // -----------------------------------------------------------------------
    // SMTP (#54)
    // -----------------------------------------------------------------------

    public async Task<bool> SaveSmtpConfigAsync(string host, int port, string from,
        string? fromName, string? username, string? password, bool useTls)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/system/email/config",
                new { host, port, from, fromName, username, password, useTls });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<Dictionary<string, string>?> GetSmtpConfigAsync()
    {
        var result = await GetAsync<SingleResult<Dictionary<string, string>>>("/api/v1/system/email/config");
        return result?.Data;
    }

    public async Task<(bool Success, string Message)> TestSmtpAsync(string to)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/email/test", new { to });
            if (!resp.IsSuccessStatusCode) return (false, "HTTP error");
            var result = await resp.Content.ReadFromJsonAsync<SmtpTestResult>(JsonOpts);
            return (result?.Success ?? false, result?.Message ?? "No response");
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    // -----------------------------------------------------------------------
    // Encryption / BYOK (#53)
    // -----------------------------------------------------------------------

    public async Task<KeyStatusDto?> GetEncryptionStatusAsync()
    {
        var result = await GetAsync<SingleResult<KeyStatusDto>>("/api/v1/system/encryption/status");
        return result?.Data;
    }

    public async Task<(bool Ok, string? Message)> RotateEncryptionKeyAsync(
        string newPassphrase, string confirmPassphrase)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/encryption/rotate",
                new { newPassphrase, confirmPassphrase });
            if (!resp.IsSuccessStatusCode) return (false, "HTTP error " + (int)resp.StatusCode);
            var r = await resp.Content.ReadFromJsonAsync<SimpleMessageResult>(JsonOpts);
            return (r?.Success ?? false, r?.Message);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    public async Task<string?> ExportKeyBackupAsync(string backupPassphrase)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/encryption/backup",
                new { backupPassphrase });
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadAsStringAsync();
        }
        catch { return null; }
    }

    // -----------------------------------------------------------------------
    // MFA Enrollment (#83)
    // -----------------------------------------------------------------------

    public async Task<MfaEnrollmentDto?> GetMfaEnrollmentAsync(string token)
    {
        var result = await GetAsync<SingleResult<MfaEnrollmentDto>>(
            "/api/v1/auth/mfa/enrollment?token=" + Uri.EscapeDataString(token));
        return result?.Data;
    }

    public async Task<bool> ConfirmMfaEnrollmentAsync(string token, string code)
    {
        var client = _factory.CreateClient("PamApi");
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/mfa/enrollment/confirm",
                new { token, code });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> ResetUserMfaAsync(string userId)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/users/{userId}/mfa/reset", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<MfaSetupLinkDto?> GenerateMfaSetupLinkAsync(string userId)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync($"/api/v1/users/{userId}/mfa/send-setup", null);
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<MfaSetupLinkDto>>(JsonOpts);
            return r?.Data;
        }
        catch { return null; }
    }

    // -----------------------------------------------------------------------
    // JIT Access (#38)
    // -----------------------------------------------------------------------

    public async Task<List<JitRequestDto>?> GetJitRequestsAsync(string? status = null)
    {
        var url = "/api/v1/jit/requests";
        if (!string.IsNullOrEmpty(status)) url += "?status=" + Uri.EscapeDataString(status);
        var result = await GetAsync<JitListResult>(url);
        return result?.Data;
    }

    public async Task<List<JitRequestDto>?> GetMyJitRequestsAsync()
    {
        var result = await GetAsync<JitListResult>("/api/v1/jit/requests/my");
        return result?.Data;
    }

    public async Task<bool> SubmitJitRequestAsync(
        string resourceType, string? resourceName, string reason, int durationMinutes)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/jit/requests", new
            {
                resourceType,
                resourceId = (Guid?)null,
                resourceName,
                reason,
                durationMinutes
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> ApproveJitRequestAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/jit/requests/" + id + "/approve", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> DenyJitRequestAsync(string id, string? reason)
    {
        var client = await GetAuthClientAsync();
        try
        {
            return (await client.PostAsJsonAsync("/api/v1/jit/requests/" + id + "/deny",
                new { reason })).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> RevokeJitRequestAsync(string id, string? reason)
    {
        var client = await GetAuthClientAsync();
        try
        {
            return (await client.PostAsJsonAsync("/api/v1/jit/requests/" + id + "/revoke",
                new { reason })).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> RequestJitExtensionAsync(string id, int additionalMinutes, string? reason)
    {
        var client = await GetAuthClientAsync();
        try
        {
            return (await client.PostAsJsonAsync("/api/v1/jit/requests/" + id + "/extend",
                new { additionalMinutes, reason })).IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> ApproveJitExtensionAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            return (await client.PostAsync(
                "/api/v1/jit/requests/" + id + "/approve-extension", null)).IsSuccessStatusCode;
        }
        catch { return false; }
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

    // -----------------------------------------------------------------------
    // Bulk User Import (#85)
    // -----------------------------------------------------------------------

    public async Task<ImportResultDto?> BulkImportUsersAsync(
        Microsoft.AspNetCore.Components.Forms.IBrowserFile file)
    {
        try
        {
            var client = await GetAuthClientAsync();
            using var content = new MultipartFormDataContent();
            var stream = file.OpenReadStream(maxAllowedSize: 5 * 1024 * 1024);
            using var sc = new StreamContent(stream);
            sc.Headers.ContentType = new MediaTypeHeaderValue("text/csv");
            content.Add(sc, "file", file.Name);

            var resp = await client.PostAsync("/api/v1/users/import", content);
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<ImportResultDto>>(JsonOpts);
            return r?.Data;
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

public record ReportDto(string Id, string Name, string Category, string Description);
public record ReportRunResult(bool Success, System.Text.Json.JsonElement Data, ReportRunMeta? Meta);
public record ReportRunMeta(string ReportId, DateTime From, DateTime To, DateTime GeneratedAt);
public record AuditLogDto(
    long      Id,
    DateTime  Timestamp,
    string    EventCategory,
    string    EventType,
    string?   ActorUsername,
    string?   ActorIpAddress,
    string?   TargetType,
    string?   TargetId,
    string?   Details,
    string    Outcome);

public record ApprovalRequestDto(
    string    Id,
    string?   WorkflowId,
    string?   RequesterId,
    string    ResourceType,
    string?   ResourceId,
    int       CurrentStep,
    string    Status,
    string?   Reason,
    string?   TicketNumber,
    DateTime? ExpiresAtUtc,
    DateTime  CreatedAtUtc,
    DateTime? CompletedAtUtc);

public record PendingApprovalDto(
    long      StepId,
    string    RequestId,
    string    ResourceType,
    string?   ResourceId,
    string?   Reason,
    string?   RequesterId,
    int       StepOrder,
    DateTime  CreatedAtUtc,
    DateTime? ExpiresAtUtc);

public record BreakGlassDto(
    string    Id,
    string    RequesterUsername,
    string?   RequesterIpAddress,
    string    ResourceType,
    string?   ResourceId,
    string?   ResourceName,
    string    EmergencyReason,
    string?   TicketNumber,
    string    Status,
    DateTime  CreatedAtUtc,
    DateTime  ExpiresAtUtc,
    DateTime? AcknowledgedAtUtc,
    string?   AcknowledgedByUsername,
    string?   AcknowledgementNotes);

public record BreakGlassSubmitResult(string Id, string Status, DateTime ExpiresAtUtc);
public record SmtpTestResult(bool Success, string? Message);

// Encryption / BYOK DTOs
public record KeyStatusDto(
    int       Version,
    DateTime? InitializedAtUtc,
    int       RotationCount,
    bool      IsInitialized,
    int       DekCacheTtlMinutes);

public record SimpleMessageResult(bool Success, string? Message);

// JIT Access DTOs (#38)
public record JitRequestDto(
    string    Id,
    string    RequesterUsername,
    string?   RequesterIpAddress,
    string    ResourceType,
    string?   ResourceId,
    string?   ResourceName,
    string    Reason,
    int       RequestedDurationMinutes,
    string    Status,
    DateTime  CreatedAtUtc,
    DateTime? ApprovedAtUtc,
    string?   ApprovedByUsername,
    DateTime? ActivatedAtUtc,
    DateTime? ExpiresAtUtc,
    string?   DenyReason,
    string?   RevokeReason,
    string?   RevokedByUsername,
    bool      ExtensionRequested,
    int?      ExtensionRequestedMinutes,
    string?   ExtensionReason);

public record JitListResult(bool Success, List<JitRequestDto>? Data);

// MFA Enrollment DTOs (#83)
public record MfaEnrollmentDto(string Username, string Secret, string QrUri);
public record MfaSetupLinkDto(string EnrollmentToken, DateTime? ExpiresAt);

// Bulk Import DTOs (#85)
public record ImportResultDto(int Imported, int Failed, List<ImportRowError> Errors);
public record ImportRowError(int Row, string Username, string Reason);
