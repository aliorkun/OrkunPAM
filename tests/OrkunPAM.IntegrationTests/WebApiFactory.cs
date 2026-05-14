using System.Data.Common;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.IdentityModel.Tokens;
using OrkunPAM.Cryptography;
using OrkunPAM.Domain.Entities.Device;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;

namespace OrkunPAM.IntegrationTests;

/// <summary>
/// Custom WebApplicationFactory for integration testing.
/// Uses SQLite in-memory, seeds test data, configures test JWT, disables background services.
/// </summary>
public class WebApiFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    // Shared RSA key for test JWT signing/validation
    private static readonly RSA TestRsa = RSA.Create(2048);
    public static readonly RsaSecurityKey TestSigningKey = new(TestRsa);
    public static readonly string TestIssuer = "OrkunPAM";
    public static readonly string TestAudience = "OrkunPAM";

    // Well-known test IDs
    public static readonly Guid AdminUserId = Guid.Parse("aaaaaaaa-aaaa-aaaa-aaaa-aaaaaaaaaaaa");
    public static readonly Guid RegularUserId = Guid.Parse("bbbbbbbb-bbbb-bbbb-bbbb-bbbbbbbbbbbb");
    public static readonly Guid TestDeviceId = Guid.Parse("cccccccc-cccc-cccc-cccc-cccccccccccc");
    public static readonly Guid TestFolderId = Guid.Parse("dddddddd-dddd-dddd-dddd-dddddddddddd");
    public static readonly Guid TestCredentialId = Guid.Parse("eeeeeeee-eeee-eeee-eeee-eeeeeeeeeeee");

    public const string AdminUsername = "admin";
    public const string AdminPassword = "Admin123!@#Secure";
    public const string RegularUsername = "testuser";
    public const string RegularPassword = "Test123!@#Secure";
    public const string ProxySecret = "ThisIsATestProxySecretThatIsLongEnoughForValidation!!";

    // Keep the SQLite connection alive for the lifetime of the factory
    private SqliteConnection? _connection;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.UseEnvironment("Development");

        builder.ConfigureServices(services =>
        {
            // Remove all hosted services (background jobs) to avoid interference
            services.RemoveAll<IHostedService>();

            // Replace the DbContext registration with SQLite in-memory
            services.RemoveAll<DbContextOptions<OrkunPamDbContext>>();
            services.RemoveAll<OrkunPamDbContext>();

            _connection = new SqliteConnection("DataSource=:memory:");
            _connection.Open();

            services.AddDbContext<OrkunPamDbContext>(options =>
            {
                options.UseSqlite(_connection);
            });

            // Replace the RSA signing key with our test key
            services.RemoveAll<RsaSecurityKey>();
            services.AddSingleton(TestSigningKey);

            // Replace JWT token service with test-configured one
            services.RemoveAll<IJwtTokenService>();
            services.AddSingleton<IJwtTokenService>(sp =>
            {
                var config = sp.GetRequiredService<Microsoft.Extensions.Configuration.IConfiguration>();
                return new JwtTokenService(TestSigningKey, config);
            });

            // Replace TokenValidationParameters singleton
            services.RemoveAll<TokenValidationParameters>();
            services.AddSingleton(new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = TestIssuer,
                ValidateAudience = true,
                ValidAudience = TestAudience,
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = TestSigningKey,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            });

            // Override JwtBearer options AFTER Program.cs configures them
            // so the test signing key is used for token validation
            services.PostConfigure<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>(
                Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme,
                options =>
                {
                    options.TokenValidationParameters = new TokenValidationParameters
                    {
                        ValidateIssuer = true,
                        ValidIssuer = TestIssuer,
                        ValidateAudience = true,
                        ValidAudience = TestAudience,
                        ValidateIssuerSigningKey = true,
                        IssuerSigningKey = TestSigningKey,
                        ValidateLifetime = true,
                        ClockSkew = TimeSpan.FromSeconds(30)
                    };
                });

            // The IKeyStore and IVaultEncryptionService will be created by the host's DI.
            // We just need to ensure the vault passphrase is configured (done below via UseSetting).
        });

        // Set required configuration values
        builder.UseSetting("Vault:MasterPassphrase", "IntegrationTestVaultPassphrase123!");
        builder.UseSetting("ProxyService:Secret", ProxySecret);
        builder.UseSetting("Jwt:Issuer", TestIssuer);
        builder.UseSetting("Jwt:Audience", TestAudience);
    }

    public async Task InitializeAsync()
    {
        // Force the host to start and create/seed the database
        using var scope = Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        await db.Database.EnsureCreatedAsync();

        await SeedTestDataAsync(db, scope.ServiceProvider);
    }

    async Task IAsyncLifetime.DisposeAsync()
    {
        if (_connection != null)
        {
            await _connection.CloseAsync();
            await _connection.DisposeAsync();
        }
    }

    private static async Task SeedTestDataAsync(OrkunPamDbContext db, IServiceProvider sp)
    {
        var hasher = sp.GetRequiredService<IPasswordHasher>();

        // Admin user with GlobalAdmin role
        var adminUser = new User
        {
            Id = AdminUserId,
            Username = AdminUsername,
            NormalizedUsername = AdminUsername.ToUpperInvariant(),
            DisplayName = "Test Admin",
            Email = "admin@test.local",
            PasswordHash = hasher.Hash(AdminPassword),
            AuthSource = AuthSource.Local,
            Status = UserStatus.Active,
            PasswordLastChanged = DateTime.UtcNow,
            PasswordExpiresAt = DateTime.UtcNow.AddDays(90)
        };
        db.Users.Add(adminUser);

        // Regular user
        var regularUser = new User
        {
            Id = RegularUserId,
            Username = RegularUsername,
            NormalizedUsername = RegularUsername.ToUpperInvariant(),
            DisplayName = "Test User",
            Email = "user@test.local",
            PasswordHash = hasher.Hash(RegularPassword),
            AuthSource = AuthSource.Local,
            Status = UserStatus.Active,
            PasswordLastChanged = DateTime.UtcNow,
            PasswordExpiresAt = DateTime.UtcNow.AddDays(90)
        };
        db.Users.Add(regularUser);

        // Assign GlobalAdmin role to admin user
        db.UserRoles.Add(new UserRole
        {
            UserId = AdminUserId,
            RoleId = SeedData.AdminRoleId
        });

        // Test device
        var device = new Device
        {
            Id = TestDeviceId,
            Hostname = "test-server",
            IpAddress = "192.168.1.100",
            DeviceType = DeviceType.LinuxServer,
            ConnectionProtocol = ConnectionProtocol.Ssh,
            ConnectionPort = 22,
            Status = DeviceStatus.Active,
            IsManaged = true
        };
        db.Devices.Add(device);

        // Vault folder
        var folder = new VaultFolder
        {
            Id = TestFolderId,
            Name = "Test Folder",
            Description = "Integration test credentials"
        };
        db.VaultFolders.Add(folder);

        // Encrypt a test password via vault
        var vault = sp.GetRequiredService<IVaultEncryptionService>();
        var encResult = vault.EncryptString("TestTargetPassword123!");

        var credential = new Credential
        {
            Id = TestCredentialId,
            FolderId = TestFolderId,
            Name = "Test SSH Credential",
            Description = "Integration test credential",
            CredentialType = CredentialType.UserPassword,
            Username = "sshuser",
            PasswordEnc = encResult.IsSuccess ? encResult.Value : null,
            DeviceId = TestDeviceId,
            Status = CredentialStatus.Active,
            KeyVersion = 1,
            MaxCheckoutMinutes = 60
        };
        db.Credentials.Add(credential);

        // Give admin access to the credential folder
        db.CredentialPermissions.Add(new CredentialPermission
        {
            FolderId = TestFolderId,
            PrincipalType = PrincipalType.User,
            PrincipalId = AdminUserId,
            PermissionLevel = PermissionLevel.Owner,
            CanShare = true
        });

        await db.SaveChangesAsync();
    }

    /// <summary>
    /// Generate a valid JWT for the given user/roles.
    /// </summary>
    public static string GenerateTestJwt(Guid userId, string username, string[] roles, TimeSpan? lifetime = null)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Name, username),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        foreach (var role in roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        var creds = new SigningCredentials(TestSigningKey, SecurityAlgorithms.RsaSha256);
        var token = new JwtSecurityToken(
            issuer: TestIssuer,
            audience: TestAudience,
            claims: claims,
            expires: DateTime.UtcNow.Add(lifetime ?? TimeSpan.FromHours(1)),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Generate an expired JWT for testing token expiry.
    /// </summary>
    public static string GenerateExpiredJwt(Guid userId, string username, string[] roles)
    {
        var claims = new List<Claim>
        {
            new(ClaimTypes.NameIdentifier, userId.ToString()),
            new(ClaimTypes.Name, username),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        foreach (var role in roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        var creds = new SigningCredentials(TestSigningKey, SecurityAlgorithms.RsaSha256);
        var token = new JwtSecurityToken(
            issuer: TestIssuer,
            audience: TestAudience,
            claims: claims,
            notBefore: DateTime.UtcNow.AddHours(-2),
            expires: DateTime.UtcNow.AddHours(-1),
            signingCredentials: creds);

        return new JwtSecurityTokenHandler().WriteToken(token);
    }

    /// <summary>
    /// Create an HttpClient with a valid admin JWT already set.
    /// </summary>
    public HttpClient CreateAuthenticatedClient(Guid? userId = null, string? username = null, string[]? roles = null)
    {
        var client = CreateClient();
        var jwt = GenerateTestJwt(
            userId ?? AdminUserId,
            username ?? AdminUsername,
            roles ?? new[] { "GlobalAdmin" });
        client.DefaultRequestHeaders.Authorization =
            new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", jwt);
        return client;
    }
}
