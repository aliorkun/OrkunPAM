using System.Net;
using System.Net.Http.Json;
using System.Text.Json;

namespace OrkunPAM.IntegrationTests;

public class SessionFlowTests : IClassFixture<WebApiFactory>
{
    private readonly WebApiFactory _factory;
    private readonly HttpClient _authedClient;

    public SessionFlowTests(WebApiFactory factory)
    {
        _factory = factory;
        _authedClient = factory.CreateAuthenticatedClient();
    }

    [Fact]
    public async Task CreateSshSession_ReturnsSessionToken()
    {
        var response = await _authedClient.PostAsJsonAsync("/api/v1/sessions/ssh/connect",
            new
            {
                deviceId = WebApiFactory.TestDeviceId,
                credentialId = WebApiFactory.TestCredentialId,
                reason = "Integration test SSH session",
                clientIp = "10.0.0.1"
            });
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());

        var data = body.GetProperty("data");
        Assert.False(string.IsNullOrEmpty(data.GetProperty("sessionId").GetString()));
        Assert.False(string.IsNullOrEmpty(data.GetProperty("sessionToken").GetString()));
        Assert.Equal("Ssh", data.GetProperty("type").GetString());
    }

    [Fact]
    public async Task GetSession_ReturnsSessionInfo()
    {
        // Create a session first
        var createResp = await _authedClient.PostAsJsonAsync("/api/v1/sessions/ssh/connect",
            new
            {
                deviceId = WebApiFactory.TestDeviceId,
                credentialId = WebApiFactory.TestCredentialId,
                reason = "Get session test",
                clientIp = "10.0.0.2"
            });
        createResp.EnsureSuccessStatusCode();
        var createBody = await createResp.Content.ReadFromJsonAsync<JsonElement>();
        var sessionId = createBody.GetProperty("data").GetProperty("sessionId").GetString();

        // Retrieve session details
        var getResp = await _authedClient.GetAsync($"/api/v1/sessions/{sessionId}");
        getResp.EnsureSuccessStatusCode();

        var body = await getResp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());

        var data = body.GetProperty("data");
        Assert.Equal("Ssh", data.GetProperty("type").GetString());
        Assert.Equal("Active", data.GetProperty("status").GetString());
        Assert.Equal("192.168.1.100", data.GetProperty("targetIpAddress").GetString());
    }

    [Fact]
    public async Task EndSession_ViaProxySecret_Succeeds()
    {
        // Create a session
        var createResp = await _authedClient.PostAsJsonAsync("/api/v1/sessions/ssh/connect",
            new
            {
                deviceId = WebApiFactory.TestDeviceId,
                credentialId = WebApiFactory.TestCredentialId,
                reason = "End session test",
                clientIp = "10.0.0.3"
            });
        createResp.EnsureSuccessStatusCode();
        var sessionId = (await createResp.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("data").GetProperty("sessionId").GetString();

        // End session (simulating proxy calling back with proxy secret)
        var endClient = _factory.CreateClient();
        endClient.DefaultRequestHeaders.Add("X-Proxy-Secret", WebApiFactory.ProxySecret);
        // The end endpoint also requires a JWT for general auth, but it's AllowAnonymous
        var endResp = await endClient.PostAsJsonAsync(
            $"/api/v1/sessions/{sessionId}/end",
            new { durationSeconds = 120, recordingPath = "/recordings/test-session.cast" });
        endResp.EnsureSuccessStatusCode();

        // Verify session is completed
        var getResp = await _authedClient.GetAsync($"/api/v1/sessions/{sessionId}");
        getResp.EnsureSuccessStatusCode();
        var data = (await getResp.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("data");
        Assert.Equal("Completed", data.GetProperty("status").GetString());
    }

    [Fact]
    public async Task ListSessions_WithPagination_Succeeds()
    {
        var response = await _authedClient.GetAsync("/api/v1/sessions?page=1&pageSize=10");
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());
        Assert.True(body.TryGetProperty("meta", out var meta));
        Assert.True(meta.GetProperty("totalCount").GetInt32() >= 0);
    }

    [Fact]
    public async Task ListActiveSessions_Succeeds()
    {
        var response = await _authedClient.GetAsync("/api/v1/sessions/active");
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());
        Assert.True(body.TryGetProperty("meta", out var meta));
    }

    [Fact]
    public async Task TerminateSession_ByAdmin_Succeeds()
    {
        // Create a session
        var createResp = await _authedClient.PostAsJsonAsync("/api/v1/sessions/ssh/connect",
            new
            {
                deviceId = WebApiFactory.TestDeviceId,
                credentialId = WebApiFactory.TestCredentialId,
                reason = "Terminate test",
                clientIp = "10.0.0.4"
            });
        createResp.EnsureSuccessStatusCode();
        var sessionId = (await createResp.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("data").GetProperty("sessionId").GetString();

        // Terminate
        var termResp = await _authedClient.PostAsJsonAsync(
            $"/api/v1/sessions/{sessionId}/terminate",
            new { reason = "Admin terminated in test" });
        termResp.EnsureSuccessStatusCode();

        // Verify terminated
        var getResp = await _authedClient.GetAsync($"/api/v1/sessions/{sessionId}");
        getResp.EnsureSuccessStatusCode();
        var data = (await getResp.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("data");
        Assert.Equal("Terminated", data.GetProperty("status").GetString());
    }

    [Fact]
    public async Task SessionPolicies_CrudFlow()
    {
        // Create policy
        var createResp = await _authedClient.PostAsJsonAsync("/api/v1/session-policies",
            new
            {
                name = "Test Integration Policy",
                maxDurationMinutes = 120,
                idleTimeoutMinutes = 15,
                allowClipboard = false,
                allowFileTransfer = false,
                allowDriveMapping = false,
                allowPrinting = false,
                recordingEnabled = true,
                keystrokeLogging = true,
                requireReason = true,
                requireTicket = false,
                twoPersonRule = false,
                enableWatermark = true
            });
        Assert.Equal(HttpStatusCode.Created, createResp.StatusCode);

        var createBody = await createResp.Content.ReadFromJsonAsync<JsonElement>();
        var policyId = createBody.GetProperty("data").GetProperty("id").GetString();

        // List policies
        var listResp = await _authedClient.GetAsync("/api/v1/session-policies");
        listResp.EnsureSuccessStatusCode();
        var listBody = await listResp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(listBody.GetProperty("data").GetArrayLength() >= 1);

        // Get by ID
        var getResp = await _authedClient.GetAsync($"/api/v1/session-policies/{policyId}");
        getResp.EnsureSuccessStatusCode();
    }

    [Fact]
    public async Task CreateSession_WithoutAuth_Returns401()
    {
        var unauthClient = _factory.CreateClient();
        var response = await unauthClient.PostAsJsonAsync("/api/v1/sessions/ssh/connect",
            new
            {
                deviceId = WebApiFactory.TestDeviceId,
                credentialId = WebApiFactory.TestCredentialId,
                reason = "Should fail"
            });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}
