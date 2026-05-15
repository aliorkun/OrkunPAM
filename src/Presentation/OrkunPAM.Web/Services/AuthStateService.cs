using System.Text.Json;
using Microsoft.JSInterop;

namespace OrkunPAM.Web.Services;

/// <summary>
/// Manages JWT auth state backed by browser localStorage.
/// In-memory cache avoids repeated JS interop calls within a circuit.
/// </summary>
public sealed class AuthStateService
{
    private const string TokenKey  = "orkunpam_token";
    private const string UserKey   = "orkunpam_user";

    private readonly IJSRuntime _js;

    private string?   _token;
    private AuthUser? _user;

    public AuthStateService(IJSRuntime js) => _js = js;

    public async Task<string?> GetTokenAsync()
    {
        if (_token != null) return _token;
        try
        {
            _token = await _js.InvokeAsync<string?>("localStorage.getItem", TokenKey);
        }
        catch (InvalidOperationException)
        {
            // Prerender — JS not available yet
        }
        return _token;
    }

    public async Task<AuthUser?> GetUserAsync()
    {
        if (_user != null) return _user;
        try
        {
            var json = await _js.InvokeAsync<string?>("localStorage.getItem", UserKey);
            if (json == null) return null;
            _user = JsonSerializer.Deserialize<AuthUser>(json, JsonOpts);
        }
        catch (InvalidOperationException)
        {
            // Prerender — JS not available yet
        }
        catch
        {
            // stale/corrupt data — treat as logged out
        }
        return _user;
    }

    public async Task<bool> IsAuthenticatedAsync()
        => !string.IsNullOrEmpty(await GetTokenAsync());

    public async Task SetSessionAsync(string token, AuthUser user)
    {
        _token = token;
        _user  = user;
        await _js.InvokeVoidAsync("localStorage.setItem", TokenKey, token);
        await _js.InvokeVoidAsync("localStorage.setItem", UserKey,
            JsonSerializer.Serialize(user, JsonOpts));
    }

    public async Task ClearAsync()
    {
        _token = null;
        _user  = null;
        await _js.InvokeVoidAsync("localStorage.removeItem", TokenKey);
        await _js.InvokeVoidAsync("localStorage.removeItem", UserKey);
    }

    private static readonly JsonSerializerOptions JsonOpts =
        new() { PropertyNameCaseInsensitive = true };
}

public record AuthUser(
    string   UserId,
    string   Username,
    string   DisplayName,
    string[] Roles);
