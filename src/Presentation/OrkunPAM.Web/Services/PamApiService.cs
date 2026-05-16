using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json;

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
            var resp = await client.PatchAsJsonAsync($"/api/v1/users/{id}/status",
                new { status = newStatus });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> CreateUserAsync(string username, string? displayName, string? email,
        string password, DateTime? expiresAt = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/users",
                new { username, displayName, email, password, authSource = "Local", expiresAt });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> UpdateUserAsync(string id, string? displayName, string? email,
        DateTime? expiresAt = null, bool clearExpiry = false)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync($"/api/v1/users/{id}",
                new { displayName, email, expiresAt, clearExpiry = clearExpiry ? (bool?)true : null });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<AccountPolicyDto?> GetAccountPolicyAsync()
    {
        var result = await GetAsync<SingleResult<AccountPolicyDto>>("/api/v1/system/account-policy");
        return result?.Data;
    }

    public async Task<bool> SaveAccountPolicyAsync(int maxPasswordAgeDays, int maxInactivityDays, int warnDaysBefore)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/system/account-policy",
                new { maxPasswordAgeDays, maxInactivityDays, warnDaysBefore });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

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

    public async Task<PagedResult<SessionDto>?> GetSessionsAsync(
        string? status = null, int page = 1, int pageSize = 20)
    {
        var url = $"/api/v1/sessions?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(status)) url += $"&status={status}";
        return await GetAsync<PagedResult<SessionDto>>(url);
    }

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

    public async Task<List<RdpHaNodeDto>?> GetRdpHaNodesAsync()
    {
        var result = await GetAsync<ListResult<RdpHaNodeDto>>("/api/v1/rdp/ha-nodes");
        return result?.Data;
    }

    public async Task<List<RemoteAppDto>?> GetRemoteAppsAsync()
    {
        var result = await GetAsync<ListResult<RemoteAppDto>>("/api/v1/rdp/remoteapps");
        return result?.Data;
    }

    public async Task<RdpLaunchResult?> LaunchRemoteAppAsync(
        string deviceId, string credentialId, string appName, string? reason = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/rdp/remoteapp/connect", new
            {
                deviceId     = Guid.Parse(deviceId),
                credentialId = Guid.Parse(credentialId),
                appName,
                reason
            });
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<RdpLaunchResult>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<RdpShadowResult?> ShadowSessionAsync(string sessionId)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync("/api/v1/rdp/sessions/" + sessionId + "/shadow", null);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<RdpShadowResult>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<List<SessionDto>?> GetActiveSessionsAsync()
    {
        var result = await GetAsync<ListResult<SessionDto>>("/api/v1/sessions/active");
        return result?.Data;
    }

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
        int maxCheckoutMinutes, bool requiresApproval, string? privateKey = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/vault/credentials",
                new { folderId, name, description, type, username, password, privateKey,
                      deviceId, maxCheckoutMinutes, requiresApproval });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<SshKeyPairDto?> GenerateSshKeyPairAsync()
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync("/api/v1/vault/credentials/generate-ssh-key", null);
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<SshKeyPairDto>>(JsonOpts);
            return r?.Data;
        }
        catch { return null; }
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

    // --- Report Schedules (#159) ---

    // --- Executive Dashboard (#168) ---

    // --- FIDO2/WebAuthn Security Keys (#158) ---

    public async Task<List<SecurityKeyDto>?> GetFido2CredentialsAsync()
    {
        var result = await GetAsync<ListResult<SecurityKeyDto>>("/api/v1/auth/fido2/credentials");
        return result?.Data;
    }

    public async Task<object?> Fido2RegisterBeginAsync()
    {
        var result = await GetAsync<SingleResult<System.Text.Json.JsonElement>>("/api/v1/auth/fido2/register/begin");
        if (result == null || !result.Success) return null;
        return result.Data;
    }

    public async Task<bool> Fido2RegisterCompleteAsync(string credentialJson, string? friendlyName)
    {
        var client = await GetAuthClientAsync();
        try
        {
            using var doc = System.Text.Json.JsonDocument.Parse(credentialJson);
            var root = doc.RootElement;
            var resp = await client.PostAsJsonAsync("/api/v1/auth/fido2/register/complete", new
            {
                clientDataJSON    = root.GetProperty("response").GetProperty("clientDataJSON").GetString(),
                attestationObject = root.GetProperty("response").GetProperty("attestationObject").GetString(),
                friendlyName
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> Fido2RemoveCredentialAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync($"/api/v1/auth/fido2/credentials/{id}")).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<Fido2AuthOptionsDto?> Fido2AuthBeginAsync(string username)
    {
        var httpClient = _factory.CreateClient("PamApi");
        try
        {
            var resp = await httpClient.PostAsJsonAsync("/api/v1/auth/fido2/authenticate/begin",
                new { username });
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<Fido2AuthOptionsDto>>(JsonOpts);
            return r?.Data;
        }
        catch { return null; }
    }

    public async Task<LoginResult?> Fido2AuthCompleteAsync(
        string userId, string credentialId, string assertionJson)
    {
        var httpClient = _factory.CreateClient("PamApi");
        try
        {
            using var doc  = System.Text.Json.JsonDocument.Parse(assertionJson);
            var root = doc.RootElement;
            var resp = await httpClient.PostAsJsonAsync("/api/v1/auth/fido2/authenticate/complete", new
            {
                userId,
                credentialId,
                clientDataJSON    = root.GetProperty("response").GetProperty("clientDataJSON").GetString(),
                authenticatorData = root.GetProperty("response").GetProperty("authenticatorData").GetString(),
                signature         = root.GetProperty("response").GetProperty("signature").GetString()
            });
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<LoginResult>(JsonOpts);
        }
        catch { return null; }
    }

    // --- Native CLI Connection Profiles (#150) ---

    public async Task<ConnectionProfileDto?> GetConnectionProfileAsync(string deviceId, string credentialId, string client)
    {
        var url = $"/api/v1/sessions/connection-profile?deviceId={Uri.EscapeDataString(deviceId)}&credentialId={Uri.EscapeDataString(credentialId)}&client={Uri.EscapeDataString(client)}";
        var result = await GetAsync<SingleResult<ConnectionProfileDto>>(url);
        return result?.Data;
    }

    public async Task<ExecutiveDashboardDto?> GetExecutiveDashboardAsync(int days = 30, string? username = null)
    {
        var url = $"/api/v1/dashboard/executive?days={days}";
        if (!string.IsNullOrEmpty(username))
            url += "&actorUsername=" + Uri.EscapeDataString(username);
        var result = await GetAsync<SingleResult<ExecutiveDashboardDto>>(url);
        return result?.Data;
    }

    // --- Report Schedules (#159) ---

    public async Task<ListResult<ReportScheduleDto>?> GetReportSchedulesAsync()
        => await GetAsync<ListResult<ReportScheduleDto>>("/api/v1/reports/schedules/");

    public async Task<bool> CreateReportScheduleAsync(CreateReportScheduleDto dto)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsJsonAsync("/api/v1/reports/schedules/", dto)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> UpdateReportScheduleAsync(string id, UpdateReportScheduleDto dto)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PutAsJsonAsync("/api/v1/reports/schedules/" + id, dto)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> DeleteReportScheduleAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync("/api/v1/reports/schedules/" + id)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> RunReportScheduleNowAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/reports/schedules/" + id + "/run-now", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // --- Custom Report Builder (#169) ---

    public async Task<List<CustomReportDefinitionDto>?> GetCustomReportsAsync()
    {
        var result = await GetAsync<ListResult<CustomReportDefinitionDto>>("/api/v1/reports/custom/");
        return result?.Data;
    }

    public async Task<bool> SaveCustomReportAsync(
        string name, string? description, string dataSource,
        string filtersJson, string columnsJson)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsJsonAsync("/api/v1/reports/custom/",
            new { name, description, dataSource, filtersJson, columnsJson })).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> DeleteCustomReportAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync("/api/v1/reports/custom/" + id)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<CustomReportResultDto?> PreviewCustomReportAsync(
        string dataSource, string filtersJson, string columnsJson, int maxRows = 50)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/reports/custom/preview",
                new { dataSource, filtersJson, columnsJson, maxRows });
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<CustomReportResultDto>>(JsonOpts);
            return r?.Data;
        }
        catch { return null; }
    }

    public async Task<CustomReportResultDto?> RunSavedCustomReportAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync("/api/v1/reports/custom/" + id + "/run", null);
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<CustomReportResultDto>>(JsonOpts);
            return r?.Data;
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

    public async Task<AuditVerifyResult?> VerifyAuditIntegrityAsync()
    {
        var result = await GetAsync<SingleResult<AuditVerifyResult>>("/api/v1/audit-logs/verify");
        return result?.Data;
    }

    public async Task<List<LdapConfigDto>?> GetLdapConfigsAsync()
    {
        var result = await GetAsync<ListResult<LdapConfigDto>>("/api/v1/ldap-configs");
        return result?.Data;
    }

    public async Task<bool> CreateLdapConfigAsync(string name, string host, int port, bool useSsl,
        string baseDn, string? bindDn, int syncIntervalMinutes)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/ldap-configs",
                new { name, host, port, useSsl, baseDn, bindDn, syncIntervalMinutes });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<List<SiemTargetDto>?> GetSiemTargetsAsync()
    {
        var result = await GetAsync<ListResult<SiemTargetDto>>("/api/v1/integrations/siem");
        return result?.Data;
    }

    public async Task<bool> CreateSiemTargetAsync(string name, string host, int port,
        string protocol, string format, int facility)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/integrations/siem",
                new { name, host, port, protocol, format, facility, eventFilterJson = "[]" });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteSiemTargetAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.DeleteAsync("/api/v1/integrations/siem/" + id);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> ToggleSiemTargetAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync("/api/v1/integrations/siem/" + id + "/toggle", null);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<(bool Success, string? Error, long Ms)> TestSiemTargetAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync("/api/v1/integrations/siem/" + id + "/test", null);
            if (!resp.IsSuccessStatusCode) return (false, "HTTP " + (int)resp.StatusCode, 0);
            var r = await resp.Content.ReadFromJsonAsync<SiemTestResult>(JsonOpts);
            return (r?.Success ?? false, r?.Data?.Error, r?.Data?.ResponseTimeMs ?? 0);
        }
        catch (Exception ex) { return (false, ex.Message, 0); }
    }

    // === ITSM Integration (#114) ===
    public async Task<List<ItsmConfigDto>?> GetItsmConfigsAsync()
    {
        var result = await GetAsync<ListResult<ItsmConfigDto>>("/api/v1/integrations/itsm");
        return result?.Data;
    }

    public async Task<bool> CreateItsmConfigAsync(string name, string provider, string baseUrl,
        string? username, string? apiKey, string? password, bool requireTicket, bool validateTicket)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/integrations/itsm",
                new { name, provider, baseUrl, username, apiKey, password, requireTicket, validateTicket });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteItsmConfigAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync("/api/v1/integrations/itsm/" + id)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> ToggleItsmConfigAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PutAsync("/api/v1/integrations/itsm/" + id + "/toggle", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<ItsmTestResultDto?> TestItsmConfigAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync("/api/v1/integrations/itsm/" + id + "/test", null);
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<ItsmTestResultDto>>(JsonOpts);
            return r?.Data;
        }
        catch { return null; }
    }

    // === Native Desktop Client SSO (#170) ===
    public async Task<LaunchTokenResultDto?> GenerateLaunchTokenAsync(
        string deviceId, string credentialId, string? protocol = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/sessions/launch-token",
                new { deviceId = Guid.Parse(deviceId), credentialId = Guid.Parse(credentialId), protocol });
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<LaunchTokenResultDto>>(JsonOpts);
            return r?.Data;
        }
        catch { return null; }
    }

    // === PKI / Smart Card (#115) ===
    public async Task<List<TrustedCaDto>?> GetTrustedCasAsync()
    {
        var result = await GetAsync<ListResult<TrustedCaDto>>("/api/v1/auth/pki/trusted-cas");
        return result?.Data;
    }

    public async Task<bool> AddTrustedCaAsync(string name, string pemCertificate, string? ocspUrl, string? crlUrl, bool checkRevocation)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/pki/trusted-cas",
                new { name, pemCertificate, ocspUrl, crlUrl, checkRevocation });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeleteTrustedCaAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync("/api/v1/auth/pki/trusted-cas/" + id)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> ToggleTrustedCaAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PutAsync("/api/v1/auth/pki/trusted-cas/" + id + "/toggle", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<List<PkiUserCertDto>?> GetPkiUserCertsAsync()
    {
        var result = await GetAsync<ListResult<PkiUserCertDto>>("/api/v1/auth/pki/user-certs");
        return result?.Data;
    }

    public async Task<bool> MapUserCertAsync(string userId, string pemCertificate, bool requirePkiOnly)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/pki/user-certs",
                new { userId, pemCertificate, requirePkiOnly });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> DeletePkiUserCertAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.DeleteAsync("/api/v1/auth/pki/user-certs/" + id)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // === Vendor Access (#127) ===
    public async Task<List<VendorAccessDto>?> GetVendorAccessListAsync(string? status = null)
    {
        var url = "/api/v1/vendor-access";
        if (!string.IsNullOrEmpty(status)) url += $"?status={status}";
        var result = await GetAsync<PagedResult<VendorAccessDto>>(url);
        return result?.Data;
    }

    public async Task<VendorCreateResult?> CreateVendorAccessAsync(
        string vendorName, string? company, string email, string? phone,
        DateTime startAtUtc, DateTime endAtUtc,
        int? allowedHoursStart, int? allowedHoursEnd,
        int maxSessionMinutesPerDay,
        List<Guid> authorizedDeviceIds,
        string? ipWhitelist, bool singleUseInvite = false)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/vendor-access", new
            {
                vendorName, company, email, phone,
                startAtUtc, endAtUtc,
                allowedHoursStart, allowedHoursEnd,
                maxSessionMinutesPerDay, authorizedDeviceIds,
                ipWhitelist, singleUseInvite
            });
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<VendorCreateResult>(JsonOpts);
        }
        catch { return null; }
    }

    public async Task<bool> RevokeVendorAccessAsync(string id, string? reason)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync($"/api/v1/vendor-access/{id}/revoke",
                new { reason });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<string?> ResendVendorInviteAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync($"/api/v1/vendor-access/{id}/resend", null);
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<VendorResendResult>(JsonOpts);
            return r?.PortalUrl;
        }
        catch { return null; }
    }

    // === Windows Auth Settings (#126) ===
    public async Task<WindowsAuthSettingsDto?> GetWindowsAuthSettingsAsync()
    {
        var result = await GetAsync<SingleResult<WindowsAuthSettingsDto>>("/api/v1/system/windows-auth");
        return result?.Data;
    }

    public async Task<bool> SaveWindowsAuthSettingsAsync(bool enabled, bool autoProvision, bool mfaBypass, string trustedDomains)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/system/windows-auth",
                new { enabled, autoProvision, mfaBypass, trustedDomains });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // === Backup (#55) ===
    public async Task<List<BackupRecordDto>?> GetBackupsAsync()
    {
        var result = await GetAsync<ListResult<BackupRecordDto>>("/api/v1/system/backup");
        return result?.Data;
    }

    public async Task<BackupRecordDto?> CreateBackupAsync(string scope, string passphrase)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/system/backup",
                new { scope, passphrase, initiatedBy = "admin" });
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<BackupRecordDto>>(JsonOpts);
            return r?.Data;
        }
        catch { return null; }
    }

    public async Task<bool> DeleteBackupAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.DeleteAsync($"/api/v1/system/backup/{id}");
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> VerifyBackupAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync($"/api/v1/system/backup/{id}/verify", null);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public string GetBackupDownloadUrl(string id) => $"/api/v1/system/backup/{id}/download";

    public async Task<BackupScheduleDto?> GetBackupScheduleAsync()
    {
        var result = await GetAsync<SingleResult<BackupScheduleDto>>("/api/v1/system/backup/schedule");
        return result?.Data;
    }

    public async Task<bool> SaveBackupScheduleAsync(bool enabled, int hourUtc, string scope, string? passphrase)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/system/backup/schedule",
                new { enabled, hourUtc, scope, passphrase });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<(bool Success, string? Error, int RestoredCount)> RestoreBackupAsync(
        byte[] fileBytes, string fileName, string passphrase, string conflictStrategy)
    {
        var client = await GetAuthClientAsync();
        try
        {
            using var form = new MultipartFormDataContent();
            form.Add(new ByteArrayContent(fileBytes), "file", fileName);
            form.Add(new StringContent(passphrase), "passphrase");
            form.Add(new StringContent(conflictStrategy), "conflictStrategy");
            var resp = await client.PostAsync("/api/v1/system/backup/restore", form);
            if (!resp.IsSuccessStatusCode) return (false, "HTTP " + (int)resp.StatusCode, 0);
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<BackupRestoreResultDto>>(JsonOpts);
            return (true, null, r?.Data?.RestoredCount ?? 0);
        }
        catch (Exception ex) { return (false, ex.Message, 0); }
    }

    public async Task<LdapSyncApplyDto?> SyncLdapNowAsync(string configId)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync($"/api/v1/ldap-configs/{configId}/sync", null);
            if (!resp.IsSuccessStatusCode) return null;
            var r = await resp.Content.ReadFromJsonAsync<SingleResult<LdapSyncApplyDto>>(JsonOpts);
            return r?.Data;
        }
        catch { return null; }
    }

    public async Task<string?> GetSessionsExportCsvAsync(DateTime? from = null, DateTime? to = null)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var url = "/api/v1/reports/sessions/export?format=csv";
            if (from.HasValue) url += "&from=" + Uri.EscapeDataString(from.Value.ToString("O"));
            if (to.HasValue)   url += "&to="   + Uri.EscapeDataString(to.Value.ToString("O"));
            var resp = await client.GetAsync(url);
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadAsStringAsync();
        }
        catch { return null; }
    }

    public async Task<AuthUser?> GetCurrentUserAsync() => await _auth.GetUserAsync();

    public async Task<int> GetTotalCountAsync(string path)
    {
        var result = await GetAsync<PagedResultMeta>($"{path}?pageSize=1");
        return result?.Meta?.TotalCount ?? 0;
    }

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

    // === System Log Viewer (#160) ===

    public async Task<PagedResult<SystemLogEntryDto>?> GetSystemLogsAsync(
        string source = "api",
        string? level = null,
        DateTime? from = null,
        DateTime? to = null,
        string? search = null,
        int page = 1,
        int pageSize = 100)
    {
        var url = $"/api/v1/system/logs?source={source}&page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(level))  url += "&level=" + level;
        if (from.HasValue)                 url += "&from=" + Uri.EscapeDataString(from.Value.ToString("o"));
        if (to.HasValue)                   url += "&to="   + Uri.EscapeDataString(to.Value.ToString("o"));
        if (!string.IsNullOrEmpty(search)) url += "&search=" + Uri.EscapeDataString(search);
        return await GetAsync<PagedResult<SystemLogEntryDto>>(url);
    }

    // === System Health (#138) ===

    public async Task<SystemHealthSnapshotDto?> GetSystemHealthAsync()
    {
        var result = await GetAsync<SingleResult<SystemHealthSnapshotDto>>("/api/v1/system/health");
        return result?.Data;
    }

    public async Task<PagedResult<SystemAlarmDto>?> GetSystemAlarmsAsync(
        string? status = null, string? severity = null, int page = 1, int pageSize = 50)
    {
        var url = $"/api/v1/system/health/alarms?page={page}&pageSize={pageSize}";
        if (!string.IsNullOrEmpty(status))   url += $"&status={status}";
        if (!string.IsNullOrEmpty(severity))  url += $"&severity={severity}";
        return await GetAsync<PagedResult<SystemAlarmDto>>(url);
    }

    public async Task<HealthAlarmConfigDto?> GetHealthAlarmConfigAsync()
    {
        var result = await GetAsync<SingleResult<HealthAlarmConfigDto>>("/api/v1/system/health/config");
        return result?.Data;
    }

    public async Task<bool> SaveHealthAlarmConfigAsync(double cpuPct, double memMb,
        double diskFreePct, string? recipients)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PutAsJsonAsync("/api/v1/system/health/config",
                new { cpuWarningPct = cpuPct, memoryWarningMb = memMb,
                      diskFreeWarningPct = diskFreePct, alarmRecipients = recipients });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> ClearAlarmAsync(long id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync($"/api/v1/system/health/alarms/{id}/clear", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

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

    public async Task<MfaEnrollmentDto?> GetMfaEnrollmentAsync(string token)
    {
        var result = await GetAsync<SingleResult<MfaEnrollmentDto>>(
            "/api/v1/auth/mfa/enrollment?token=" + Uri.EscapeDataString(token));
        return result?.Data;
    }

    public async Task<MfaConfirmResult?> ConfirmMfaEnrollmentAsync(string token, string code)
    {
        var client = _factory.CreateClient("PamApi");
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/mfa/enrollment/confirm",
                new { token, code });
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadFromJsonAsync<MfaConfirmResult>(JsonOpts);
        }
        catch { return null; }
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

    public async Task<List<DiscoveryJobDto>?> GetDiscoveryJobsAsync()
    {
        var result = await GetAsync<ListResult<DiscoveryJobDto>>("/api/v1/vault/discovery-jobs");
        return result?.Data;
    }

    public async Task<bool> CreateDiscoveryJobAsync(string name, string discoveryType, string? targetScope, string? schedule)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/vault/discovery-jobs", new
            {
                name, discoveryType, targetScope, schedule,
                createdBy = (Guid?)null
            });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<DiscoveryScanResultDto?> RunDiscoveryJobAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync("/api/v1/vault/discovery-jobs/" + id + "/run", null);
            if (!resp.IsSuccessStatusCode) return null;
            var result = await resp.Content.ReadFromJsonAsync<SingleResult<DiscoveryScanResultDto>>(JsonOpts);
            return result?.Data;
        }
        catch { return null; }
    }

    public async Task<List<DiscoveredAccountDto>?> GetDiscoveredAccountsAsync(string? status = null)
    {
        var url = "/api/v1/vault/discovered-accounts";
        if (!string.IsNullOrEmpty(status)) url += "?status=" + Uri.EscapeDataString(status);
        var result = await GetAsync<ListResult<DiscoveredAccountDto>>(url);
        return result?.Data;
    }

    public async Task<bool> TakeoverAccountAsync(string id, Guid folderId)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/vault/discovered-accounts/" + id + "/takeover",
                new { folderId });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> IgnoreDiscoveredAccountAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/vault/discovered-accounts/" + id + "/ignore", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<List<OrphanedUserDto>?> GetOrphanedUsersAsync()
    {
        var client = await GetAuthClientAsync();
        try
        {
            var r = await client.GetFromJsonAsync<PagedResult<OrphanedUserDto>>("/api/v1/users/orphaned", JsonOpts);
            return r?.Data;
        }
        catch { return null; }
    }

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

    // ── Session Recording Playback ──────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    public async Task<RecordingMetadataDto?> GetRecordingMetadataAsync(string sessionId)
    {
        var result = await GetAsync<SingleResult<RecordingMetadataDto>>(
            $"/api/v1/sessions/{sessionId}/recording");
        return result?.Data;
    }

    public async Task<RecordingStreamDto?> GetRecordingStreamAsync(string sessionId)
    {
        var result = await GetAsync<SingleResult<RecordingStreamDto>>(
            $"/api/v1/sessions/{sessionId}/recording/stream");
        return result?.Data;
    }

    public async Task<RecordingSearchResultsDto?> SearchRecordingAsync(string sessionId, string query)
    {
        var url = $"/api/v1/sessions/{sessionId}/recording/search?q={Uri.EscapeDataString(query)}";
        return await GetAsync<RecordingSearchResultsDto>(url);
    }

    public async Task<PagedResult<CommandLogDto>?> GetSessionCommandsAsync(
        string sessionId, int page = 1, int pageSize = 100)
    {
        return await GetAsync<PagedResult<CommandLogDto>>(
            $"/api/v1/sessions/{sessionId}/commands?page={page}&pageSize={pageSize}");
    }

    public async Task<byte[]?> DownloadRecordingAsync(string sessionId)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.GetAsync($"/api/v1/sessions/{sessionId}/recording/stream");
            if (!resp.IsSuccessStatusCode) return null;
            return await resp.Content.ReadAsByteArrayAsync();
        }
        catch { return null; }
    }

    // MFA Policy
    public async Task<MfaPolicySettingsDto?> GetMfaPolicyAsync()
    {
        var result = await GetAsync<PolicySettingResult<MfaPolicySettingsDto>>("/api/v1/policy/mfa");
        return result?.Data;
    }

    public async Task<bool> SaveMfaPolicyAsync(MfaPolicySettingsDto s)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsJsonAsync("/api/v1/policy/mfa", s)).IsSuccessStatusCode; }
        catch { return false; }
    }

    // Self-Service Password Reset
    public async Task<bool> ForgotPasswordAsync(string username, string email)
    {
        var client = _factory.CreateClient("PamApi");
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/forgot-password",
                new { username, email });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<(bool Success, string? Message)> ResetPasswordAsync(string token, string newPassword)
    {
        var client = _factory.CreateClient("PamApi");
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/auth/reset-password",
                new { token, newPassword });
            var result = await resp.Content.ReadFromJsonAsync<SimpleMessageResult>(JsonOpts);
            return (result?.Success ?? false, result?.Message);
        }
        catch (Exception ex) { return (false, ex.Message); }
    }

    // My Active Sessions
    public async Task<List<MySessionDto>?> GetMySessionsAsync()
    {
        var result = await GetAsync<ListResult<MySessionDto>>("/api/v1/auth/my-sessions");
        return result?.Data;
    }

    public async Task<bool> EndMySessionAsync(string sessionId)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsync($"/api/v1/auth/my-sessions/{sessionId}/end", null);
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    // ── TACACS+ Command Policies (deferred — v2+ stubs) ─────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────
    public Task<List<TacacsCommandPolicyDto>?> GetTacacsCommandPoliciesAsync()
        => Task.FromResult<List<TacacsCommandPolicyDto>?>(new List<TacacsCommandPolicyDto>());

    public Task<bool> SaveTacacsCommandPolicyAsync(string username, string devicePattern, string mode, string? commands)
        => Task.FromResult(false);

    public Task<bool> DeleteTacacsCommandPolicyAsync(string id)
        => Task.FromResult(false);

    // === Access Certification Campaigns (#154) ===
    public async Task<List<AttestationCampaignDto>?> GetAttestationsAsync()
    {
        var result = await GetAsync<ListResult<AttestationCampaignDto>>("/api/v1/compliance/attestations");
        return result?.Data;
    }

    public async Task<bool> CreateAttestationAsync(string name, string? scopeJson, Guid? reviewerUserId,
        DateTime startsAtUtc, DateTime deadlineUtc, bool autoRevokeOnMiss)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync("/api/v1/compliance/attestations",
                new { name, scopeJson, reviewerUserId, startsAtUtc, deadlineUtc, autoRevokeOnMiss });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<AttestationDetailDto?> GetAttestationDetailAsync(string id)
    {
        var result = await GetAsync<SingleResult<AttestationDetailDto>>("/api/v1/compliance/attestations/" + id);
        return result?.Data;
    }

    public async Task<bool> StartAttestationAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/compliance/attestations/" + id + "/start", null)).IsSuccessStatusCode; }
        catch { return false; }
    }

    public async Task<bool> DecideAttestationItemAsync(string campaignId, long decisionId, byte decision, string? comments)
    {
        var client = await GetAuthClientAsync();
        try
        {
            var resp = await client.PostAsJsonAsync(
                "/api/v1/compliance/attestations/" + campaignId + "/decisions/" + decisionId + "/decide",
                new { decision, comments });
            return resp.IsSuccessStatusCode;
        }
        catch { return false; }
    }

    public async Task<bool> CompleteAttestationAsync(string id)
    {
        var client = await GetAuthClientAsync();
        try { return (await client.PostAsync("/api/v1/compliance/attestations/" + id + "/complete", null)).IsSuccessStatusCode; }
        catch { return false; }
    }
}

public record LoginResult(bool Success, LoginData? Data);
public record LoginData(
    string   AccessToken,
    string   RefreshToken,
    DateTime ExpiresAt,
    string   UserId,
    string   Username,
    string   DisplayName,
    bool     MfaRequired,
    bool     MfaEnrollmentRequired,
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
    DateTime? TemporaryExpiresUtc,
    DateTime? LastLoginAtUtc,
    DateTime  CreatedAtUtc,
    bool      IsOrphaned = false,
    DateTime? OrphanedDetectedAtUtc = null);

public record OrphanedUserDto(
    string    Id,
    string    Username,
    string?   DisplayName,
    string?   Email,
    string    AuthSource,
    string    Status,
    DateTime? LastLoginAtUtc,
    DateTime? OrphanedDetectedAtUtc);

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
    bool?   IsReachable,
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
    string?   PrivateKey,
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
    int MaxConcurrentSessions,
    byte CommandFilterMode = 0,
    string? CommandFilterRulesJson = null,
    decimal DoubleConfirmRiskThreshold = 0,
    string? DoubleConfirmCommandsJson = null);

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
    string    Outcome,
    bool      IsTampered = false);

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

public record KeyStatusDto(
    int       Version,
    DateTime? InitializedAtUtc,
    int       RotationCount,
    bool      IsInitialized,
    int       DekCacheTtlMinutes);

public record SimpleMessageResult(bool Success, string? Message);

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

public record MfaEnrollmentDto(string Username, string Secret, string QrUri);
public record MfaSetupLinkDto(string EnrollmentToken, DateTime? ExpiresAt);
public record MfaConfirmResult(bool Success, string? Message, MfaConfirmData? Data);
public record MfaConfirmData(string[]? RecoveryCodes);

public record ImportResultDto(int Imported, int Failed, List<ImportRowError> Errors);
public record ImportRowError(int Row, string Username, string Reason);

public record SshKeyPairDto(string PrivateKey, string PublicKey);

public record AuditVerifyResult(bool IntegrityValid, int EntriesChecked, int TamperedCount, long? FirstTamperedId, string Message);

public record LdapConfigDto(string Id, string Name, string Host, int Port, bool UseSsl, string BaseDn, int SyncIntervalMinutes, DateTime? LastSyncAtUtc, bool IsEnabled);

public record DiscoveryJobDto(Guid Id, string Name, string Type, string? Schedule, DateTime? LastRunAtUtc, bool IsEnabled);
public record DiscoveredAccountDto(Guid Id, Guid DiscoveryJobId, Guid? DeviceId, string AccountName, string? AccountType, DateTime DiscoveredAtUtc, string Status, Guid? LinkedCredentialId);
public record DiscoveryScanResultDto(DateTime LastRunAtUtc, int AccountsFound, string Result, List<DiscoveredAccountInfoDto> Accounts);
public record DiscoveredAccountInfoDto(string AccountName, string AccountType, string? HostName, string? Dn, bool IsEnabled, string Source);

public record LdapSyncApplyDto(int UsersAdded, int UsersUpdated, int UsersDisabled, string Message);

public record SiemTargetDto(
    string Id, string Name, string Host, int Port,
    string Protocol, string Format, int Facility,
    bool IsEnabled, DateTime? LastSentAtUtc, int TotalEventsSent, string? LastError);
public record SiemTestResultData(bool Success, string? Error, long ResponseTimeMs);
public record SiemTestResult(bool Success, SiemTestResultData? Data);

public record BackupRecordDto(
    string Id, string FileName, string Scope, long FileSizeBytes,
    string? IntegrityHash, bool IntegrityVerified,
    string Status, string? ErrorMessage,
    DateTime? CompletedAtUtc, DateTime CreatedAtUtc, string InitiatedBy);
public record BackupScheduleDto(bool Enabled, int HourUtc, string Scope);
public record BackupRestoreResultDto(int RestoredCount, string Message);

// Session Recording Playback DTOs
public record RecordingMetadataDto(
    string SessionId, string Format, long FileSizeBytes, double DurationSeconds,
    int? TerminalWidth, int? TerminalHeight, DateTime CreatedAtUtc,
    bool IntegrityValid, string? IntegrityMessage, string? FileHash);

public class RecordingStreamDto
{
    public string Format { get; set; } = "";
    public RecordingHeaderDto? Header { get; set; }
    public List<RecordingEventDto>? Events { get; set; }
    public List<HttpEntryDto>? Entries { get; set; }
    public string? ContentBase64 { get; set; }
    public int? SizeBytes { get; set; }
}

public record RecordingHeaderDto(int Version, int Width, int Height, double Duration, string? Title, string? Command);

public record RecordingEventDto(double T, string Type, string Data);

public record HttpEntryDto(
    double T, string Method, string Url, int StatusCode,
    Dictionary<string, string>? RequestHeaders, string? RequestBody,
    Dictionary<string, string>? ResponseHeaders, string? ResponseBody,
    double DurationMs);

public record RecordingSearchResultsDto(
    bool Success,
    List<RecordingSearchHitDto>? Data,
    RecordingSearchMeta? Meta);

public record RecordingSearchHitDto(double TimestampSeconds, string MatchedText, int EventIndex);
public record RecordingSearchMeta(string Query, int MatchCount);

public record CommandLogDto(
    long Id, DateTime Timestamp, string? Command, decimal RiskScore, bool WasBlocked, string? BlockReason);

// TACACS+ (deferred -- v2+, stub DTO for compilation)
public record TacacsCommandPolicyDto(
    string Id, string Username, string DevicePattern, string Mode, string? Commands, bool IsEnabled, DateTime CreatedAtUtc);

// MFA Policy DTO
public record MfaPolicySettingsDto(bool MfaRequired);

public record AccountPolicyDto(int MaxPasswordAgeDays, int MaxInactivityDays, int WarnDaysBefore);

// My Sessions DTO
public record MySessionDto(
    string    Id,
    string    Type,
    string?   TargetIpAddress,
    int?      TargetPort,
    DateTime  StartedAtUtc,
    int       DurationMinutes,
    string    Status);

// Windows Auth DTOs (#126)
public record WindowsAuthSettingsDto(bool Enabled, bool AutoProvision, bool MfaBypass, string TrustedDomains);

// Vendor Access DTOs (#127)
public record VendorAccessDto(
    string    Id,
    string    VendorName,
    string?   Company,
    string    Email,
    string?   Phone,
    DateTime  StartAtUtc,
    DateTime  EndAtUtc,
    int?      AllowedHoursStart,
    int?      AllowedHoursEnd,
    int       MaxSessionMinutesPerDay,
    string    AuthorizedDeviceIdsJson,
    string?   IpWhitelist,
    string    InviteToken,
    DateTime  InviteExpiresAtUtc,
    DateTime? InviteUsedAtUtc,
    bool      SingleUseInvite,
    string    Status,
    string    CreatedByUsername,
    DateTime  CreatedAtUtc,
    string?   RevokeReason,
    string?   RevokedByUsername,
    DateTime? RevokedAtUtc);

public record VendorCreateResult(bool Success, VendorAccessDto? Data, string? PortalUrl);

// RDP Gateway DTOs (#110)
public record RdpHaNodeDto(string Host, bool Healthy, int LatencyMs, string Error);

public record RemoteAppDto(
    string Name,
    string AppPath,
    string? Description,
    string? AppArgs,
    string? Category,
    string? DefaultDeviceId);

public record RdpShadowResult(
    string ShadowSessionId,
    string OriginalSessionId,
    RdpFileInfo RdpFile);
public record VendorResendResult(bool Success, string? PortalUrl);

// System Health DTOs (#138)
public record SystemHealthSnapshotDto(
    double CpuPercent,
    double MemoryMb,
    double DiskPercent,
    List<ProxyServiceStatusDto> Services,
    List<SystemAlarmDto> RecentAlarms);

public record ProxyServiceStatusDto(string Name, bool Healthy, int LatencyMs);

public record SystemAlarmDto(
    long Id, DateTime OccurredAtUtc, string MetricName,
    string Severity, double MetricValue, double Threshold,
    string Message, string Status, bool EmailSent);

public record HealthAlarmConfigDto(
    string CpuWarningPct,
    string MemoryWarningMb,
    string DiskFreeWarningPct,
    string AlarmRecipients);

// System Log Viewer DTOs (#160)
public record SystemLogEntryDto(
    string Timestamp,
    string Level,
    string Source,
    string Message,
    string? Username,
    string? IpAddress,
    string? Details);

// Access Certification DTOs (#154)
public record AttestationCampaignDto(
    string    Id,
    string    Name,
    byte      Status,
    DateTime  StartsAtUtc,
    DateTime  DeadlineUtc,
    bool      AutoRevokeOnMiss,
    string?   ReviewerUserId,
    DateTime? CompletedAtUtc);

public record AttestationDecisionItemDto(
    long      Id,
    string    SubjectUserId,
    string?   SubjectUsername,
    string?   ResourceType,
    string?   ResourceId,
    string?   ResourceName,
    byte?     Decision,
    DateTime? DecisionAtUtc,
    string?   Comments);

public record AttestationDetailDto(
    string    Id,
    string    Name,
    byte      Status,
    DateTime  StartsAtUtc,
    DateTime  DeadlineUtc,
    bool      AutoRevokeOnMiss,
    string?   ReviewerUserId,
    DateTime? CompletedAtUtc,
    int       TotalItems,
    int       DecidedItems,
    int       PendingItems,
    List<AttestationDecisionItemDto>? Decisions);

// Scheduled Report Delivery DTOs (#159)
public record ReportScheduleDto(
    string    Id,
    string    Name,
    string    ReportType,
    string    Frequency,
    int       DayOfWeek,
    int       DayOfMonth,
    int       RunAtHourUtc,
    string    OutputFormat,
    string    Recipients,
    bool      IsActive,
    DateTime? LastRunAtUtc,
    DateTime? NextRunAtUtc,
    string?   LastRunStatus,
    DateTime  CreatedAtUtc);

public record CreateReportScheduleDto(
    string  Name,
    string  ReportType,
    string  Frequency,
    int     DayOfWeek,
    int     DayOfMonth,
    int     RunAtHourUtc,
    string  OutputFormat,
    string  Recipients);

public record UpdateReportScheduleDto(
    string? Name        = null,
    string? Recipients  = null,
    bool?   IsActive    = null,
    string? Frequency   = null,
    int?    DayOfWeek   = null,
    int?    DayOfMonth  = null,
    int?    RunAtHourUtc = null);

// Executive Dashboard DTOs (#168)
public record ExecutiveDashboardDto(
    DateTime                         GeneratedAtUtc,
    int                              PeriodDays,
    ExecKpisDto                      Kpis,
    List<ExecTrendPointDto>          SessionTrend,
    List<ExecProtocolDto>            ProtocolDistribution,
    List<ExecTrendPointDto>          FailedLoginTrend,
    List<ExecDeviceDto>              TopDevices,
    List<ExecUserDto>                TopUsers,
    ExecComplianceDto                Compliance);

public record ExecKpisDto(
    int TotalPrivilegedUsers,
    int UserWeeklyChange,
    int ActiveSessions,
    int OpenAlarms,
    int PendingApprovals,
    int FailedLoginsLast24h,
    int ExpiringCredentials);

public record ExecTrendPointDto(string Date, int Count);

public record ExecProtocolDto(string Protocol, int Count);

public record ExecDeviceDto(string Id, string? Name, string? IpAddress, int SessionCount);

public record ExecUserDto(string Id, string Username, string? DisplayName, int SessionCount);

public record ExecComplianceDto(
    double RotationCompliance,
    double MfaEnrollmentRate,
    int    OrphanedAccountCount,
    bool   CertificationCompleted,
    double CertCompletionRate);

// FIDO2/WebAuthn DTOs (#158)
public record SecurityKeyDto(string Id, string FriendlyName, DateTime RegisteredAt, DateTime? LastUsed);

public record Fido2AuthOptionsDto(
    string   Challenge,
    int      Timeout,
    string   RpId,
    string   UserId,
    System.Text.Json.JsonElement[]? AllowCredentials);

// Native CLI Connection Profiles (#150)
public record ConnectionProfileDto(
    string Filename,
    string Content,
    string MimeType,
    string SshCommand);

// Custom Report Builder DTOs (#169)
public record CustomReportDefinitionDto(
    string    Id,
    string    Name,
    string?   Description,
    string    DataSource,
    string    FiltersJson,
    string    ColumnsJson,
    DateTime  CreatedAtUtc,
    DateTime? LastRunAtUtc);

public record CustomReportResultDto(
    List<string>                    Columns,
    List<Dictionary<string, string>> Rows,
    int                             TotalRows,
    string                          FilterSummary);

// ITSM Integration DTOs (#114)
public record ItsmConfigDto(
    string  Id,
    string  Name,
    string  Provider,
    string  BaseUrl,
    bool    RequireTicket,
    bool    ValidateTicket,
    bool    IsEnabled);

public record ItsmTestResultDto(
    string  Provider,
    string  BaseUrl,
    long    ResponseTimeMs,
    string? ServerVersion,
    string? Message);

// Native Desktop Client SSO DTOs (#170)
public record LaunchTokenResultDto(string Token, string LaunchUri, DateTime ExpiresAt);

// PKI / Smart Card Authentication DTOs (#115)
public record TrustedCaDto(
    string   Id,
    string   Name,
    string   Subject,
    string?  Issuer,
    string   Thumbprint,
    DateTime NotBefore,
    DateTime NotAfter,
    bool     IsEnabled,
    bool     CheckRevocation,
    string?  OcspUrl,
    string?  CrlUrl);

public record PkiUserCertDto(
    string    Id,
    string    UserId,
    string    Username,
    string    CertThumbprint,
    string    SubjectDn,
    string    IssuingCaThumbprint,
    DateTime  ExpiresAtUtc,
    bool      RequirePkiOnly,
    bool      IsEnabled,
    DateTime? LastUsedAtUtc);
