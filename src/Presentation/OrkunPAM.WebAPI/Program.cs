using System.Security.Cryptography;
using FluentValidation;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using OrkunPAM.Cryptography;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;
using OrkunPAM.WebAPI.Endpoints;
using OrkunPAM.WebAPI.Middleware;
using OrkunPAM.WebAPI.Validation;
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
    builder.Services.AddScoped<IPasswordPolicyService, PasswordPolicyService>();
    builder.Services.AddScoped<IPermissionService, PermissionService>();
    builder.Services.AddSingleton<ITotpService, TotpService>();
    builder.Services.AddScoped<OrkunPAM.Persistence.Services.IAuditService, OrkunPAM.Persistence.Services.AuditService>();

    // === Input Validation (fixes #19) ===
    builder.Services.AddValidatorsFromAssemblyContaining<Program>(ServiceLifetime.Singleton);

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

    // === JWT Authentication (fixes #1, #10) ===
    var keyDir = builder.Configuration["Jwt:KeyDirectory"]
        ?? Path.Combine(AppContext.BaseDirectory, "keys");
    Directory.CreateDirectory(keyDir);
    var keyPath = Path.Combine(keyDir, "jwt-signing-key.xml");
    RSA rsaKey;
    if (File.Exists(keyPath))
    {
        rsaKey = RSA.Create();
        try
        {
            rsaKey.FromXmlString(File.ReadAllText(keyPath));
            Log.Information("JWT signing key loaded from persistent store");
        }
        catch (Exception loadEx)
        {
            Log.Warning(loadEx, "Failed to load JWT key from {Path}, regenerating", keyPath);
            rsaKey.Dispose();
            rsaKey = RSA.Create(4096);
            File.WriteAllText(keyPath, rsaKey.ToXmlString(includePrivateParameters: true));
            if (!OperatingSystem.IsWindows())
                File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        }
    }
    else
    {
        rsaKey = RSA.Create(4096);
        File.WriteAllText(keyPath, rsaKey.ToXmlString(includePrivateParameters: true));
        if (!OperatingSystem.IsWindows())
            File.SetUnixFileMode(keyPath, UnixFileMode.UserRead | UnixFileMode.UserWrite);
        Log.Information("JWT signing key generated and persisted to {Path}", keyPath);
    }
    var signingKey = new RsaSecurityKey(rsaKey);
    builder.Services.AddSingleton(signingKey);

    // Register TokenValidationParameters as singleton for WebSocket JWT validation
    // (browser WebSocket API cannot set custom headers, so JWT is passed as query param)
    builder.Services.AddSingleton(_ => new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidIssuer = builder.Configuration["Jwt:Issuer"] ?? "OrkunPAM",
        ValidateAudience = true,
        ValidAudience = builder.Configuration["Jwt:Audience"] ?? "OrkunPAM",
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = signingKey,
        ValidateLifetime = true,
        ClockSkew = TimeSpan.FromSeconds(30)
    });

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
    app.UseWebSockets(new WebSocketOptions { KeepAliveInterval = TimeSpan.FromSeconds(30) });
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
    if (app.Environment.IsDevelopment())
    {
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
        }).WithTags("Vault").RequireAuthorization();
    }

    // === Map Module Endpoints (all routed through validation filter) ===
    // ValidationEndpointFilter validates request bodies against registered FluentValidation validators.
    var api = app.MapGroup("").AddEndpointFilter<ValidationEndpointFilter>();
    api.MapAuthEndpoints();
    api.MapUserEndpoints();
    api.MapGroupEndpoints();
    api.MapRoleEndpoints();
    api.MapVaultEndpoints();
    api.MapDeviceEndpoints();
    api.MapPolicyEndpoints();
    api.MapWorkflowEndpoints();
    api.MapLdapSamlEndpoints();
    api.MapAapmEndpoints();
    api.MapSessionEndpoints();
    api.MapWebSshEndpoints();
    api.MapDiscoveryEndpoints();
    api.MapReportEndpoints();
    api.MapComplianceEndpoints();
    api.MapAnalyticsEndpoints();
    api.MapIntegrationEndpoints();
    api.MapImportEndpoints();
    api.MapSystemEndpoints();

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
