using System.Security.Cryptography;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OrkunPAM.Cryptography;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;
using OrkunPAM.WebAPI.Endpoints;
using OrkunPAM.WebAPI.Middleware;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] {Message:lj} {Properties:j}{NewLine}{Exception}")
    .WriteTo.File("logs/orkunpam-.log", rollingInterval: RollingInterval.Day)
    .Enrich.FromLogContext()
    .Enrich.WithProperty("Application", "OrkunPAM")
    .CreateLogger();

try
{
    Log.Information("Starting Orkun PAM...");

    var builder = WebApplication.CreateBuilder(args);
    builder.Host.UseSerilog();

    // === Database (SQLite for dev, SQL Server for prod) ===
    var connectionString = builder.Configuration.GetConnectionString("Default")
        ?? "Data Source=orkunpam.db";

    builder.Services.AddDbContext<OrkunPamDbContext>(options =>
    {
        if (connectionString.Contains(".db") || connectionString.Contains("Data Source="))
            options.UseSqlite(connectionString);
        else
            options.UseSqlServer(connectionString);
    });

    // === Cryptography ===
    builder.Services.AddSingleton<IKeyStore, InMemoryKeyStore>();
    builder.Services.AddSingleton<IVaultEncryptionService, AesGcmEncryptionService>();

    // === Repository ===
    builder.Services.AddScoped(typeof(IRepository<>), typeof(Repository<>));
    builder.Services.AddScoped<IUnitOfWork>(sp => sp.GetRequiredService<OrkunPamDbContext>());

    // === Identity ===
    builder.Services.AddSingleton<IPasswordHasher, Argon2PasswordHasher>();
    builder.Services.AddSingleton<IJwtTokenService>(sp =>
        new JwtTokenService(sp.GetRequiredService<RsaSecurityKey>(),
            sp.GetRequiredService<IConfiguration>()));
    builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();
    builder.Services.AddScoped<IPermissionService, PermissionService>();
    builder.Services.AddSingleton<ITotpService, TotpService>();
    builder.Services.AddScoped<OrkunPAM.Persistence.Services.IAuditService, OrkunPAM.Persistence.Services.AuditService>();

    // === Integration Services ===
    builder.Services.AddSingleton<OrkunPAM.Identity.Services.ILdapService, OrkunPAM.Identity.Services.LdapService>();
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.IWebhookDeliveryService, OrkunPAM.Persistence.Services.WebhookDeliveryService>();
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.IItsmService, OrkunPAM.Persistence.Services.ItsmService>();
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.IDiscoveryService, OrkunPAM.Persistence.Services.DiscoveryService>();
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.IRotationService, OrkunPAM.Persistence.Services.RotationService>();

    // === Swagger ===
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new() { Title = "Orkun PAM API", Version = "v1",
            Description = "Enterprise Privileged Access Management - REST API" });
    });

    // === Rate Limiting (fixes #8) ===
    builder.Services.AddRateLimiter(options =>
    {
        options.AddFixedWindowLimiter("auth", opt =>
        {
            opt.PermitLimit = 5;
            opt.Window = TimeSpan.FromMinutes(1);
            opt.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
            opt.QueueLimit = 0;
        });
        options.AddFixedWindowLimiter("api", opt =>
        {
            opt.PermitLimit = 100;
            opt.Window = TimeSpan.FromMinutes(1);
            opt.QueueProcessingOrder = System.Threading.RateLimiting.QueueProcessingOrder.OldestFirst;
            opt.QueueLimit = 0;
        });
        options.RejectionStatusCode = StatusCodes.Status429TooManyRequests;
    });

    // === CORS (fixes #7) ===
    var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>()
        ?? ["https://localhost:5001"];
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy =>
            policy.WithOrigins(allowedOrigins)
                .AllowAnyMethod()
                .AllowAnyHeader()
                .AllowCredentials());
    });

    // === JWT Authentication (fixes #1) ===
    var rsaKey = RSA.Create(2048);
    var signingKey = new RsaSecurityKey(rsaKey);
    builder.Services.AddSingleton(signingKey);

    builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
        .AddJwtBearer(options =>
        {
            options.TokenValidationParameters = new TokenValidationParameters
            {
                ValidateIssuer = true,
                ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? "OrkunPAM",
                ValidateAudience = true,
                ValidAudience = builder.Configuration["Jwt:Audience"] ?? "OrkunPAM",
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = signingKey,
                ValidateLifetime = true,
                ClockSkew = TimeSpan.FromSeconds(30)
            };
        });

    builder.Services.AddAuthorizationBuilder()
        .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build());

    var app = builder.Build();

    // === Initialize DB ===
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        await db.Database.EnsureCreatedAsync();
        Log.Information("Database initialized");
    }

    // === Initialize Key Store (fixes #2) ===
    var keyStore = app.Services.GetRequiredService<IKeyStore>();
    var passphrase = Environment.GetEnvironmentVariable("ORKUNPAM_VAULT_PASSPHRASE")
        ?? builder.Configuration["Vault:MasterPassphrase"];
    if (string.IsNullOrEmpty(passphrase))
    {
        Log.Fatal("Vault passphrase not configured. Set ORKUNPAM_VAULT_PASSPHRASE env var or Vault:MasterPassphrase in config.");
        return;
    }
    var initResult = keyStore.Initialize(passphrase);
    if (initResult.IsFailure)
    {
        Log.Fatal("Failed to initialize vault key store: {Error}", initResult.Error.Message);
        return;
    }
    Log.Information("Vault encryption engine initialized");

    // === Middleware ===
    app.UseGlobalExceptionHandler();
    app.UseSerilogRequestLogging();
    app.UseCors();
    app.UseRateLimiter();
    app.UseAuthentication();
    app.UseAuthorization();

    if (app.Environment.IsDevelopment())
    {
        app.UseSwagger();
        app.UseSwaggerUI();
    }

    app.UseHttpsRedirection();

    // === Health Check ===
    app.MapGet("/api/v1/system/health", () => Results.Ok(new
    {
        status = "healthy",
        version = "0.1.0",
        timestamp = DateTime.UtcNow,
        vault = keyStore.IsInitialized ? "initialized" : "not_initialized"
    })).WithTags("System").AllowAnonymous();

    // === Vault Encryption Test Endpoint (dev only) ===
    app.MapPost("/api/v1/vault/test-encrypt", (string plaintext, IVaultEncryptionService vault) =>
    {
        var encResult = vault.EncryptString(plaintext);
        if (encResult.IsFailure) return Results.BadRequest(encResult.Error);

        var decResult = vault.DecryptString(encResult.Value);
        if (decResult.IsFailure) return Results.BadRequest(decResult.Error);

        return Results.Ok(new
        {
            originalLength = plaintext.Length,
            encryptedLength = encResult.Value.Length,
            decrypted = decResult.Value,
            match = plaintext == decResult.Value
        });
    }).WithTags("Vault").AllowAnonymous();

    // === Map Module Endpoints ===
    app.MapAuthEndpoints();
    app.MapUserEndpoints();
    app.MapGroupEndpoints();
    app.MapRoleEndpoints();
    app.MapVaultEndpoints();
    app.MapDeviceEndpoints();
    app.MapPolicyEndpoints();
    app.MapWorkflowEndpoints();
    app.MapLdapSamlEndpoints();
    app.MapAapmEndpoints();
    app.MapSessionEndpoints();
    app.MapDiscoveryEndpoints();
    app.MapReportEndpoints();
    app.MapComplianceEndpoints();
    app.MapAnalyticsEndpoints();
    app.MapIntegrationEndpoints();
    app.MapImportEndpoints();
    app.MapSystemEndpoints();

    Log.Information("Orkun PAM started on {Urls}", string.Join(", ", app.Urls));
    app.Run();
}
catch (Exception ex)
{
    Log.Fatal(ex, "Orkun PAM terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}

// Request records moved to Endpoints/ files
