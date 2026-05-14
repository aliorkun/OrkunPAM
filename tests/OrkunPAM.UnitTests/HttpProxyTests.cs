using System.Text;
using OrkunPAM.HttpProxy;

namespace OrkunPAM.UnitTests;

/// <summary>
/// Tests credential injector strategies: BasicAuth header generation,
/// HeaderInjector placeholder replacement.
/// </summary>
public class HttpProxyTests
{
    private static HttpSessionInfo CreateSession(
        Dictionary<string, string>? customHeaders = null,
        string? formLoginUrl = null) => new()
    {
        SessionId = Guid.NewGuid().ToString(),
        TargetUrl = "https://target.example.com",
        Username = "admin",
        CredentialId = Guid.NewGuid().ToString(),
        AuthStrategy = AuthStrategy.BasicAuth,
        CustomHeaders = customHeaders,
        FormLoginUrl = formLoginUrl,
    };

    [Fact]
    public async Task BasicAuth_InjectsCorrectHeader()
    {
        var injector = new BasicAuthInjector();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://target.example.com");
        var session = CreateSession();
        var password = Encoding.UTF8.GetBytes("s3cret!");

        var result = await injector.InjectAsync(request, session, "admin", password, CancellationToken.None);

        Assert.True(result);
        Assert.NotNull(request.Headers.Authorization);
        Assert.Equal("Basic", request.Headers.Authorization.Scheme);

        // Verify the encoded value
        var decoded = Encoding.UTF8.GetString(
            Convert.FromBase64String(request.Headers.Authorization.Parameter!));
        Assert.Equal("admin:s3cret!", decoded);
    }

    [Fact]
    public async Task BasicAuth_HandlesSpecialCharacters()
    {
        var injector = new BasicAuthInjector();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://target.example.com");
        var session = CreateSession();
        var password = Encoding.UTF8.GetBytes("p@ss:w0rd/with=special&chars");

        var result = await injector.InjectAsync(request, session, "user@domain", password, CancellationToken.None);

        Assert.True(result);
        var decoded = Encoding.UTF8.GetString(
            Convert.FromBase64String(request.Headers.Authorization!.Parameter!));
        Assert.Equal("user@domain:p@ss:w0rd/with=special&chars", decoded);
    }

    [Fact]
    public async Task BasicAuth_HandlesUnicodePassword()
    {
        var injector = new BasicAuthInjector();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://target.example.com");
        var session = CreateSession();
        var password = Encoding.UTF8.GetBytes("Parola_Guclue_2026!");

        var result = await injector.InjectAsync(request, session, "admin", password, CancellationToken.None);

        Assert.True(result);
        var decoded = Encoding.UTF8.GetString(
            Convert.FromBase64String(request.Headers.Authorization!.Parameter!));
        Assert.Equal("admin:Parola_Guclue_2026!", decoded);
    }

    [Fact]
    public async Task HeaderInjector_ReplacesUsernamePlaceholder()
    {
        var headers = new Dictionary<string, string>
        {
            ["X-Auth-User"] = "{username}",
            ["X-Custom"] = "static-value"
        };
        var injector = new HeaderInjector();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://target.example.com");
        var session = CreateSession(customHeaders: headers);
        var password = Encoding.UTF8.GetBytes("pass123");

        var result = await injector.InjectAsync(request, session, "admin", password, CancellationToken.None);

        Assert.True(result);
        Assert.Equal("admin", request.Headers.GetValues("X-Auth-User").First());
        Assert.Equal("static-value", request.Headers.GetValues("X-Custom").First());
    }

    [Fact]
    public async Task HeaderInjector_ReplacesPasswordPlaceholder()
    {
        var headers = new Dictionary<string, string>
        {
            ["Authorization"] = "Bearer {password}"
        };
        var injector = new HeaderInjector();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://target.example.com");
        var session = CreateSession(customHeaders: headers);
        var password = Encoding.UTF8.GetBytes("my-api-token-123");

        await injector.InjectAsync(request, session, "admin", password, CancellationToken.None);

        Assert.Equal("Bearer my-api-token-123",
            request.Headers.GetValues("Authorization").First());
    }

    [Fact]
    public async Task HeaderInjector_ReplacesBothPlaceholders()
    {
        var headers = new Dictionary<string, string>
        {
            ["X-Auth"] = "{username}:{password}"
        };
        var injector = new HeaderInjector();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://target.example.com");
        var session = CreateSession(customHeaders: headers);
        var password = Encoding.UTF8.GetBytes("secret");

        await injector.InjectAsync(request, session, "admin", password, CancellationToken.None);

        Assert.Equal("admin:secret",
            request.Headers.GetValues("X-Auth").First());
    }

    [Fact]
    public async Task HeaderInjector_NullCustomHeaders_NoOp()
    {
        var injector = new HeaderInjector();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://target.example.com");
        var session = CreateSession(customHeaders: null);
        var password = Encoding.UTF8.GetBytes("pass");

        var result = await injector.InjectAsync(request, session, "admin", password, CancellationToken.None);

        Assert.True(result);
        // No headers should have been added (beyond defaults)
        Assert.False(request.Headers.Contains("X-Auth-User"));
    }

    [Fact]
    public async Task BasicAuth_ProcessResponse_IsNoOp()
    {
        var injector = new BasicAuthInjector();
        var response = new HttpResponseMessage(System.Net.HttpStatusCode.OK);
        var session = CreateSession();

        // Should complete without error
        await injector.ProcessResponseAsync(response, session, CancellationToken.None);
    }

    [Fact]
    public async Task HeaderInjector_PlaceholderReplacementIsCaseInsensitive()
    {
        var headers = new Dictionary<string, string>
        {
            ["X-User"] = "{USERNAME}",
            ["X-Pass"] = "{PASSWORD}"
        };
        var injector = new HeaderInjector();
        var request = new HttpRequestMessage(HttpMethod.Get, "https://target.example.com");
        var session = CreateSession(customHeaders: headers);
        var password = Encoding.UTF8.GetBytes("secret");

        await injector.InjectAsync(request, session, "admin", password, CancellationToken.None);

        Assert.Equal("admin", request.Headers.GetValues("X-User").First());
        Assert.Equal("secret", request.Headers.GetValues("X-Pass").First());
    }
}
