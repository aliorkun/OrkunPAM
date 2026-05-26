using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Entities.Integration;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

public interface IExternalVaultService
{
    Task<ExternalVaultTestResult> TestConnectionAsync(ExternalVaultConnection conn, string? plainAuthSecret);
    Task<List<string>> ListSecretsAsync(ExternalVaultConnection conn, string? path);
    Task<ExternalSecretValue?> FetchSecretAsync(ExternalVaultConnection conn, string secretPath,
        string? usernameField, string? passwordField);
    Task<SyncResult> SyncMappingAsync(ExternalVaultConnection conn, ExternalCredentialMapping mapping,
        OrkunPamDbContext db);
}

public record ExternalVaultTestResult(bool Success, string? Error, long LatencyMs);
public record ExternalSecretValue(string? Username, string? Password);
public record SyncResult(bool Success, string? Error);

public class ExternalVaultService : IExternalVaultService
{
    private readonly IHttpClientFactory _httpFactory;
    private readonly OrkunPAM.Cryptography.IVaultEncryptionService _vault;
    private readonly ILogger<ExternalVaultService> _log;

    public ExternalVaultService(IHttpClientFactory httpFactory, OrkunPAM.Cryptography.IVaultEncryptionService vault,
        ILogger<ExternalVaultService> log)
    {
        _httpFactory = httpFactory;
        _vault = vault;
        _log = log;
    }

    public async Task<ExternalVaultTestResult> TestConnectionAsync(ExternalVaultConnection conn, string? plainAuthSecret)
    {
        var sw = System.Diagnostics.Stopwatch.StartNew();
        try
        {
            var token = await GetAccessTokenAsync(conn, plainAuthSecret);
            if (token == null)
                return new ExternalVaultTestResult(false, "Authentication failed", sw.ElapsedMilliseconds);

            // Verify we can list secrets
            var secrets = await ListSecretsInternalAsync(conn, token, null);
            sw.Stop();
            return new ExternalVaultTestResult(true, null, sw.ElapsedMilliseconds);
        }
        catch (Exception ex)
        {
            sw.Stop();
            _log.LogWarning(ex, "External vault test failed for {Name}", conn.Name);
            return new ExternalVaultTestResult(false, ex.Message, sw.ElapsedMilliseconds);
        }
    }

    public async Task<List<string>> ListSecretsAsync(ExternalVaultConnection conn, string? path)
    {
        var authSecret = conn.AuthSecretEnc != null
            ? _vault.DecryptString(conn.AuthSecretEnc).Value
            : null;
        var token = await GetAccessTokenAsync(conn, authSecret);
        if (token == null) return new List<string>();
        return await ListSecretsInternalAsync(conn, token, path);
    }

    public async Task<ExternalSecretValue?> FetchSecretAsync(ExternalVaultConnection conn, string secretPath,
        string? usernameField, string? passwordField)
    {
        var authSecret = conn.AuthSecretEnc != null
            ? _vault.DecryptString(conn.AuthSecretEnc).Value
            : null;
        var token = await GetAccessTokenAsync(conn, authSecret);
        if (token == null) return null;

        return conn.VaultType switch
        {
            ExternalVaultType.HashiCorpVault =>
                await FetchHcvSecretAsync(conn, token, secretPath, usernameField ?? "username", passwordField ?? "password"),
            ExternalVaultType.AzureKeyVault =>
                await FetchAzureKvSecretAsync(conn, token, secretPath, usernameField, passwordField),
            _ => null
        };
    }

    public async Task<SyncResult> SyncMappingAsync(ExternalVaultConnection conn, ExternalCredentialMapping mapping,
        OrkunPamDbContext db)
    {
        try
        {
            var secret = await FetchSecretAsync(conn, mapping.ExternalPath,
                mapping.UsernameField, mapping.PasswordField);
            if (secret == null)
                return new SyncResult(false, "Could not fetch secret from external vault");

            if (mapping.MappedCredentialId != null)
            {
                var credential = await db.Credentials.FindAsync(mapping.MappedCredentialId);
                if (credential != null && secret.Password != null)
                {
                    var encrypted = _vault.EncryptString(secret.Password);
                    if (encrypted.IsSuccess)
                    {
                        credential.PasswordEnc = encrypted.Value;
                        credential.LastRotatedAtUtc = DateTime.UtcNow;
                    }
                }
            }

            mapping.LastSyncedAtUtc = DateTime.UtcNow;
            mapping.LastFetchedAtUtc = DateTime.UtcNow;
            mapping.SyncStatus = ExternalSyncStatus.Ok;
            mapping.LastError = null;
            await db.SaveChangesAsync();
            return new SyncResult(true, null);
        }
        catch (Exception ex)
        {
            mapping.SyncStatus = ExternalSyncStatus.Error;
            mapping.LastError = ex.Message;
            await db.SaveChangesAsync();
            return new SyncResult(false, ex.Message);
        }
    }

    // ── HashiCorp Vault ───────────────────────────────────────────────────────

    private async Task<string?> GetHcvTokenAsync(ExternalVaultConnection conn, string? authSecret)
    {
        if (conn.AuthMethod == ExternalVaultAuthMethod.Token)
            return authSecret;

        if (conn.AuthMethod == ExternalVaultAuthMethod.AppRole)
        {
            // authSecret format: "role_id:secret_id"
            if (string.IsNullOrEmpty(authSecret)) return null;
            var parts = authSecret.Split(':', 2);
            if (parts.Length != 2) return null;

            var http = _httpFactory.CreateClient();
            http.BaseAddress = new Uri(conn.Endpoint.TrimEnd('/'));
            if (!string.IsNullOrEmpty(conn.Namespace))
                http.DefaultRequestHeaders.Add("X-Vault-Namespace", conn.Namespace);

            var body = JsonSerializer.Serialize(new { role_id = parts[0], secret_id = parts[1] });
            var resp = await http.PostAsync("/v1/auth/approle/login",
                new StringContent(body, Encoding.UTF8, "application/json"));
            if (!resp.IsSuccessStatusCode) return null;

            var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            return json.RootElement.GetProperty("auth").GetProperty("client_token").GetString();
        }

        return null;
    }

    private async Task<ExternalSecretValue?> FetchHcvSecretAsync(ExternalVaultConnection conn,
        string token, string path, string usernameField, string passwordField)
    {
        var mount = (conn.MountPath ?? "secret").TrimEnd('/');
        var http = _httpFactory.CreateClient();
        http.BaseAddress = new Uri(conn.Endpoint.TrimEnd('/'));
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);
        if (!string.IsNullOrEmpty(conn.Namespace))
            http.DefaultRequestHeaders.Add("X-Vault-Namespace", conn.Namespace);

        var resp = await http.GetAsync($"/v1/{mount}/data/{path.TrimStart('/')}");
        if (!resp.IsSuccessStatusCode) return null;

        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var data = json.RootElement.GetProperty("data").GetProperty("data");
        var username = data.TryGetProperty(usernameField, out var u) ? u.GetString() : null;
        var password = data.TryGetProperty(passwordField, out var p) ? p.GetString() : null;
        return new ExternalSecretValue(username, password);
    }

    private async Task<List<string>> ListHcvSecretsAsync(ExternalVaultConnection conn, string token, string? path)
    {
        var mount = (conn.MountPath ?? "secret").TrimEnd('/');
        var http = _httpFactory.CreateClient();
        http.BaseAddress = new Uri(conn.Endpoint.TrimEnd('/'));
        http.DefaultRequestHeaders.Add("X-Vault-Token", token);
        if (!string.IsNullOrEmpty(conn.Namespace))
            http.DefaultRequestHeaders.Add("X-Vault-Namespace", conn.Namespace);

        var listPath = string.IsNullOrEmpty(path) ? "" : "/" + path.Trim('/');
        var req = new HttpRequestMessage(HttpMethod.Get,
            $"/v1/{mount}/metadata{listPath}?list=true");
        var resp = await http.SendAsync(req);
        if (!resp.IsSuccessStatusCode) return new List<string>();

        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var keys = json.RootElement.GetProperty("data").GetProperty("keys");
        return keys.EnumerateArray().Select(k => k.GetString() ?? "").Where(s => s.Length > 0).ToList();
    }

    // ── Azure Key Vault ───────────────────────────────────────────────────────

    private async Task<string?> GetAzureTokenAsync(ExternalVaultConnection conn, string? authSecret)
    {
        if (conn.AuthMethod == ExternalVaultAuthMethod.ManagedIdentity)
        {
            // IMDS endpoint
            var http = _httpFactory.CreateClient();
            var resp = await http.GetAsync(
                "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https://vault.azure.net");
            if (!resp.IsSuccessStatusCode) return null;
            var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            return json.RootElement.GetProperty("access_token").GetString();
        }

        if (conn.AuthMethod == ExternalVaultAuthMethod.ServicePrincipal)
        {
            if (string.IsNullOrEmpty(conn.TenantId) || string.IsNullOrEmpty(conn.ClientId) ||
                string.IsNullOrEmpty(authSecret))
                return null;

            var http = _httpFactory.CreateClient();
            var form = new Dictionary<string, string>
            {
                ["grant_type"]    = "client_credentials",
                ["client_id"]     = conn.ClientId,
                ["client_secret"] = authSecret,
                ["scope"]         = "https://vault.azure.net/.default"
            };
            var resp = await http.PostAsync(
                $"https://login.microsoftonline.com/{conn.TenantId}/oauth2/v2.0/token",
                new FormUrlEncodedContent(form));
            if (!resp.IsSuccessStatusCode) return null;
            var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            return json.RootElement.GetProperty("access_token").GetString();
        }

        return authSecret; // Token-based
    }

    private async Task<ExternalSecretValue?> FetchAzureKvSecretAsync(ExternalVaultConnection conn,
        string token, string secretName, string? usernameField, string? passwordField)
    {
        var vaultName = conn.KeyVaultName ?? conn.Name;
        var http = _httpFactory.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        // For Azure KV, if usernameField is set, the secret path encodes "secretName"
        // and username comes from a separate secret named "{secretName}-username"
        string? username = null;
        if (!string.IsNullOrEmpty(usernameField))
        {
            var uResp = await http.GetAsync(
                $"https://{vaultName}.vault.azure.net/secrets/{secretName}-{usernameField}?api-version=7.4");
            if (uResp.IsSuccessStatusCode)
            {
                var uJson = JsonDocument.Parse(await uResp.Content.ReadAsStringAsync());
                username = uJson.RootElement.GetProperty("value").GetString();
            }
        }

        var resp = await http.GetAsync(
            $"https://{vaultName}.vault.azure.net/secrets/{secretName}?api-version=7.4");
        if (!resp.IsSuccessStatusCode) return null;
        var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
        var password = json.RootElement.GetProperty("value").GetString();
        return new ExternalSecretValue(username, password);
    }

    private async Task<List<string>> ListAzureKvSecretsAsync(ExternalVaultConnection conn, string token)
    {
        var vaultName = conn.KeyVaultName ?? conn.Name;
        var http = _httpFactory.CreateClient();
        http.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var secrets = new List<string>();
        var url = $"https://{vaultName}.vault.azure.net/secrets?api-version=7.4&maxresults=25";
        while (url != null)
        {
            var resp = await http.GetAsync(url);
            if (!resp.IsSuccessStatusCode) break;
            var json = JsonDocument.Parse(await resp.Content.ReadAsStringAsync());
            var items = json.RootElement.GetProperty("value");
            foreach (var item in items.EnumerateArray())
            {
                var id = item.GetProperty("id").GetString() ?? "";
                var name = id.Split('/').LastOrDefault() ?? id;
                secrets.Add(name);
            }
            url = json.RootElement.TryGetProperty("nextLink", out var next) ? next.GetString() : null;
        }
        return secrets;
    }

    // ── Shared helpers ────────────────────────────────────────────────────────

    private async Task<string?> GetAccessTokenAsync(ExternalVaultConnection conn, string? authSecret)
    {
        return conn.VaultType switch
        {
            ExternalVaultType.HashiCorpVault    => await GetHcvTokenAsync(conn, authSecret),
            ExternalVaultType.AzureKeyVault     => await GetAzureTokenAsync(conn, authSecret),
            _ => authSecret
        };
    }

    private async Task<List<string>> ListSecretsInternalAsync(ExternalVaultConnection conn,
        string token, string? path)
    {
        return conn.VaultType switch
        {
            ExternalVaultType.HashiCorpVault => await ListHcvSecretsAsync(conn, token, path),
            ExternalVaultType.AzureKeyVault  => await ListAzureKvSecretsAsync(conn, token),
            _ => new List<string>()
        };
    }
}
