using System.Net;
using System.Net.Http.Json;
using System.Text.Json;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.IntegrationTests;

public class VaultFlowTests : IClassFixture<WebApiFactory>
{
    private readonly WebApiFactory _factory;
    private readonly HttpClient _authedClient;

    public VaultFlowTests(WebApiFactory factory)
    {
        _factory = factory;
        _authedClient = factory.CreateAuthenticatedClient();
    }

    [Fact]
    public async Task CreateCredential_EncryptAndStore_Succeeds()
    {
        var response = await _authedClient.PostAsJsonAsync("/api/v1/vault/credentials",
            new
            {
                folderId = WebApiFactory.TestFolderId,
                name = "New Test Credential",
                description = "Created in integration test",
                type = "UserPassword",
                username = "testcreduser",
                password = "SecretPassword123!",
                tags = "integration,test",
                maxCheckoutMinutes = 30,
                requiresApproval = false
            });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());
        Assert.Equal("New Test Credential", body.GetProperty("data").GetProperty("name").GetString());

        var credId = body.GetProperty("data").GetProperty("id").GetString();
        Assert.NotNull(credId);

        // Verify we can retrieve the credential metadata (no password)
        var getResponse = await _authedClient.GetAsync($"/api/v1/vault/credentials/{credId}");
        getResponse.EnsureSuccessStatusCode();
        var getBody = await getResponse.Content.ReadFromJsonAsync<JsonElement>();
        Assert.Equal("Active", getBody.GetProperty("data").GetProperty("status").GetString());
    }

    [Fact]
    public async Task Checkout_GetDecryptedCredential_Succeeds()
    {
        // Create a new credential specifically for checkout testing
        var createResp = await _authedClient.PostAsJsonAsync("/api/v1/vault/credentials",
            new
            {
                folderId = WebApiFactory.TestFolderId,
                name = "Checkout Test Cred",
                type = "UserPassword",
                username = "checkoutuser",
                password = "CheckoutSecret!123",
                requiresApproval = false
            });
        createResp.EnsureSuccessStatusCode();
        var createBody = await createResp.Content.ReadFromJsonAsync<JsonElement>();
        var credId = createBody.GetProperty("data").GetProperty("id").GetString();

        // Checkout the credential
        var checkoutResp = await _authedClient.PostAsJsonAsync(
            $"/api/v1/vault/credentials/{credId}/checkout",
            new { reason = "Integration test", durationMinutes = 30 });
        checkoutResp.EnsureSuccessStatusCode();

        var checkoutBody = await checkoutResp.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(checkoutBody.GetProperty("success").GetBoolean());
        Assert.Equal("CheckoutSecret!123",
            checkoutBody.GetProperty("data").GetProperty("password").GetString());
        Assert.Equal("checkoutuser",
            checkoutBody.GetProperty("data").GetProperty("username").GetString());
    }

    [Fact]
    public async Task Checkin_ChangesStatusBackToActive()
    {
        // Create and checkout
        var createResp = await _authedClient.PostAsJsonAsync("/api/v1/vault/credentials",
            new
            {
                folderId = WebApiFactory.TestFolderId,
                name = "Checkin Test Cred",
                type = "UserPassword",
                username = "checkinuser",
                password = "CheckinSecret!123",
                requiresApproval = false
            });
        createResp.EnsureSuccessStatusCode();
        var credId = (await createResp.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("data").GetProperty("id").GetString();

        // Checkout
        var checkoutResp = await _authedClient.PostAsJsonAsync(
            $"/api/v1/vault/credentials/{credId}/checkout",
            new { reason = "Test" });
        checkoutResp.EnsureSuccessStatusCode();

        // Verify it's checked out
        var getResp1 = await _authedClient.GetAsync($"/api/v1/vault/credentials/{credId}");
        getResp1.EnsureSuccessStatusCode();
        var data1 = (await getResp1.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("data");
        Assert.Equal("CheckedOut", data1.GetProperty("status").GetString());

        // Checkin
        var checkinResp = await _authedClient.PostAsync(
            $"/api/v1/vault/credentials/{credId}/checkin", null);
        checkinResp.EnsureSuccessStatusCode();

        // Verify it's active again
        var getResp2 = await _authedClient.GetAsync($"/api/v1/vault/credentials/{credId}");
        getResp2.EnsureSuccessStatusCode();
        var data2 = (await getResp2.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("data");
        Assert.Equal("Active", data2.GetProperty("status").GetString());
    }

    [Fact]
    public async Task DoubleCheckout_ShouldFail()
    {
        // Create credential
        var createResp = await _authedClient.PostAsJsonAsync("/api/v1/vault/credentials",
            new
            {
                folderId = WebApiFactory.TestFolderId,
                name = "Double Checkout Cred",
                type = "UserPassword",
                username = "doubleuser",
                password = "DoubleSecret!123",
                requiresApproval = false
            });
        createResp.EnsureSuccessStatusCode();
        var credId = (await createResp.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("data").GetProperty("id").GetString();

        // First checkout - should succeed
        var checkout1 = await _authedClient.PostAsJsonAsync(
            $"/api/v1/vault/credentials/{credId}/checkout",
            new { reason = "First checkout" });
        checkout1.EnsureSuccessStatusCode();

        // Second checkout - should fail with conflict
        var checkout2 = await _authedClient.PostAsJsonAsync(
            $"/api/v1/vault/credentials/{credId}/checkout",
            new { reason = "Second checkout" });
        Assert.Equal(HttpStatusCode.Conflict, checkout2.StatusCode);
    }

    [Fact]
    public async Task ListCredentials_WithPagination_Succeeds()
    {
        var response = await _authedClient.GetAsync("/api/v1/vault/credentials?page=1&pageSize=10");
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());
        Assert.True(body.TryGetProperty("meta", out var meta));
        Assert.True(meta.GetProperty("totalCount").GetInt32() >= 0);
    }

    [Fact]
    public async Task CreateFolder_Succeeds()
    {
        var response = await _authedClient.PostAsJsonAsync("/api/v1/vault/folders",
            new { name = "Integration Test Folder", description = "Created by test" });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());
    }

    [Fact]
    public async Task GetFolderCredentials_ReturnsCredentialsInFolder()
    {
        var response = await _authedClient.GetAsync(
            $"/api/v1/vault/folders/{WebApiFactory.TestFolderId}/credentials");
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());
        // Seed data has at least one credential in the test folder
        Assert.True(body.GetProperty("data").GetArrayLength() >= 1);
    }

    [Fact]
    public async Task CheckoutHistory_ReturnsHistory()
    {
        // Create and checkout to generate history
        var createResp = await _authedClient.PostAsJsonAsync("/api/v1/vault/credentials",
            new
            {
                folderId = WebApiFactory.TestFolderId,
                name = "History Test Cred",
                type = "UserPassword",
                username = "histuser",
                password = "HistSecret!123",
                requiresApproval = false
            });
        createResp.EnsureSuccessStatusCode();
        var credId = (await createResp.Content.ReadFromJsonAsync<JsonElement>())
            .GetProperty("data").GetProperty("id").GetString();

        await _authedClient.PostAsJsonAsync(
            $"/api/v1/vault/credentials/{credId}/checkout",
            new { reason = "History test", ticketNumber = "INC-001" });

        var response = await _authedClient.GetAsync($"/api/v1/vault/credentials/{credId}/history");
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());
        Assert.True(body.GetProperty("data").GetArrayLength() >= 1);
    }

    [Fact]
    public async Task PersonalVault_CreatesAndReturns()
    {
        var response = await _authedClient.GetAsync("/api/v1/vault/credentials/personal");
        response.EnsureSuccessStatusCode();

        var body = await response.Content.ReadFromJsonAsync<JsonElement>();
        Assert.True(body.GetProperty("success").GetBoolean());
        Assert.Equal("Personal Vault",
            body.GetProperty("data").GetProperty("name").GetString());
    }
}
