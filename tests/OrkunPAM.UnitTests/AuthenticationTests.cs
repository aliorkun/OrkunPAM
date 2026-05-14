using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;
using System.Security.Cryptography;

namespace OrkunPAM.UnitTests;

public class AuthenticationTests : IDisposable
{
    private readonly OrkunPamDbContext _db;
    private readonly AuthenticationService _authService;
    private readonly JwtTokenService _jwtService;
    private readonly Argon2PasswordHasher _hasher = new();
    private readonly RsaSecurityKey _rsaKey;

    public AuthenticationTests()
    {
        var options = new DbContextOptionsBuilder<OrkunPamDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        _db = new OrkunPamDbContext(options);
        _db.Database.OpenConnection();
        _db.Database.EnsureCreated();

        var rsa = RSA.Create(2048);
        _rsaKey = new RsaSecurityKey(rsa);

        var config = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["Jwt:Issuer"] = "OrkunPAM-Test",
                ["Jwt:Audience"] = "OrkunPAM-Test",
                ["Jwt:AccessTokenMinutes"] = "15",
                ["Jwt:RefreshTokenHours"] = "8",
                ["Jwt:KeyDirectory"] = Path.Combine(Path.GetTempPath(), "orkunpam-auth-test-keys"),
            })
            .Build();

        _jwtService = new JwtTokenService(_rsaKey, config);
        var policyService = new PasswordPolicyService(_db, _hasher);

        _authService = new AuthenticationService(
            _db, _hasher, _jwtService, policyService,
            NullLogger<AuthenticationService>.Instance);
    }

    private User CreateTestUser(string username = "testuser", string password = "Str0ng!P@ssword",
        UserStatus status = UserStatus.Active)
    {
        var hash = _hasher.Hash(password);
        var user = new User
        {
            Username = username,
            NormalizedUsername = username.ToUpperInvariant(),
            DisplayName = "Test User",
            PasswordHash = hash,
            AuthSource = AuthSource.Local,
            Status = status,
            PasswordLastChanged = DateTime.UtcNow,
        };
        _db.Users.Add(user);
        _db.SaveChanges();
        return user;
    }

    [Fact]
    public async Task LoginLocal_ValidCredentials_ReturnsSuccess()
    {
        CreateTestUser();
        var result = await _authService.LoginLocalAsync("testuser", "Str0ng!P@ssword", "10.0.0.1");

        Assert.True(result.IsSuccess);
        Assert.NotNull(result.Value.Tokens.AccessToken);
        Assert.NotNull(result.Value.Tokens.RefreshToken);
        Assert.Equal("testuser", result.Value.Username);
    }

    [Fact]
    public async Task LoginLocal_WrongPassword_ReturnsFailure()
    {
        CreateTestUser();
        var result = await _authService.LoginLocalAsync("testuser", "WrongPassword!", "10.0.0.1");

        Assert.True(result.IsFailure);
        Assert.Equal("Unauthorized", result.Error.Code);
    }

    [Fact]
    public async Task LoginLocal_NonExistentUser_ReturnsFailure()
    {
        var result = await _authService.LoginLocalAsync("noexist", "AnyPassword1!", "10.0.0.1");

        Assert.True(result.IsFailure);
        Assert.Contains("Invalid username or password", result.Error.Message);
    }

    [Fact]
    public async Task LoginLocal_LockoutAfter5Failures()
    {
        CreateTestUser();

        // Fail 5 times
        for (int i = 0; i < 5; i++)
        {
            await _authService.LoginLocalAsync("testuser", "Wrong!", "10.0.0.1");
        }

        // 6th attempt should be locked
        var result = await _authService.LoginLocalAsync("testuser", "Str0ng!P@ssword", "10.0.0.1");
        Assert.True(result.IsFailure);
        Assert.Contains("locked", result.Error.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task LoginLocal_DisabledUser_ReturnsFailure()
    {
        CreateTestUser(status: UserStatus.Disabled);
        var result = await _authService.LoginLocalAsync("testuser", "Str0ng!P@ssword", "10.0.0.1");

        Assert.True(result.IsFailure);
        Assert.Contains("Disabled", result.Error.Message);
    }

    [Fact]
    public async Task LoginLocal_SuccessResetsFailedCount()
    {
        CreateTestUser();

        // Fail 3 times
        for (int i = 0; i < 3; i++)
            await _authService.LoginLocalAsync("testuser", "Wrong!", "10.0.0.1");

        // Successful login
        var result = await _authService.LoginLocalAsync("testuser", "Str0ng!P@ssword", "10.0.0.1");
        Assert.True(result.IsSuccess);

        var user = await _db.Users.FirstAsync(u => u.Username == "testuser");
        Assert.Equal(0, user.FailedLoginCount);
    }

    [Fact]
    public async Task LoginLocal_ExpiredPassword_SetsFlagButSucceeds()
    {
        var user = CreateTestUser();
        user.PasswordExpiresAt = DateTime.UtcNow.AddDays(-1);
        await _db.SaveChangesAsync();

        var result = await _authService.LoginLocalAsync("testuser", "Str0ng!P@ssword", "10.0.0.1");
        Assert.True(result.IsSuccess);
        Assert.True(result.Value.PasswordExpired);
        Assert.True(result.Value.MustChangePassword);
    }

    [Fact]
    public void JwtToken_GenerateAndValidate_Roundtrip()
    {
        var userId = Guid.NewGuid();
        var generateResult = _jwtService.GenerateTokens(
            userId, "admin", "Admin User", "Local",
            new[] { "GlobalAdmin" }, new[] { "vault.credential.checkout" }, mfaVerified: true);

        Assert.True(generateResult.IsSuccess);
        Assert.NotEmpty(generateResult.Value.AccessToken);

        var validateResult = _jwtService.ValidateToken(generateResult.Value.AccessToken);
        Assert.True(validateResult.IsSuccess);

        var claims = validateResult.Value;
        Assert.Contains(claims.Claims, c => c.Type == "username" && c.Value == "admin");
        Assert.Contains(claims.Claims, c => c.Type == "mfa_verified" && c.Value == "true");
    }

    [Fact]
    public void JwtToken_InvalidToken_ReturnsFailure()
    {
        var result = _jwtService.ValidateToken("totally.invalid.token");
        Assert.True(result.IsFailure);
        Assert.Equal("Unauthorized", result.Error.Code);
    }

    [Fact]
    public async Task CreateLocalUser_DuplicateUsername_ReturnsConflict()
    {
        CreateTestUser("existing");
        var result = await _authService.CreateLocalUserAsync("existing", "Str0ng!P@ssword2#",
            "Duplicate User", null);

        Assert.True(result.IsFailure);
        Assert.Equal("Conflict", result.Error.Code);
    }

    public void Dispose() => _db.Dispose();
}
