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
using Microsoft.AspNetCore.Authentication.Certificate;
using Microsoft.AspNetCore.RateLimiting;
using OrkunPAM.Grpc.Services;
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

    // Background services should not crash the host
    builder.Services.Configure<Microsoft.Extensions.Hosting.HostOptions>(opts =>
        opts.BackgroundServiceExceptionBehavior = Microsoft.Extensions.Hosting.BackgroundServiceExceptionBehavior.Ignore);

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
    var hsmMode = (builder.Configuration["Security:HsmMode"] ?? "none").ToLowerInvariant();
    var hsmEnabled = hsmMode is "softhsm" or "pkcs11" or "azure-keyvault" or "aws-kms";
    switch (hsmMode)
    {
        case "softhsm":
            builder.Services.AddSingleton<IHsmProvider, SoftHsmProvider>();
            builder.Services.AddSingleton<IKeyStore, HsmKeyStore>();
            break;
        case "pkcs11":
            builder.Services.AddSingleton<IHsmProvider, Pkcs11HsmProvider>();
            builder.Services.AddSingleton<IKeyStore, HsmKeyStore>();
            break;
        case "azure-keyvault":
            builder.Services.AddSingleton<IHsmProvider, AzureKeyVaultHsmProvider>();
            builder.Services.AddSingleton<IKeyStore, HsmKeyStore>();
            break;
        case "aws-kms":
            builder.Services.AddSingleton<IHsmProvider, AwsCloudHsmProvider>();
            builder.Services.AddSingleton<IKeyStore, HsmKeyStore>();
            break;
        default:
            if (hsmMode != "none")
                Log.Warning("Unknown Security:HsmMode '{Mode}' — falling back to software key store", hsmMode);
            builder.Services.AddSingleton<IKeyStore, InMemoryKeyStore>();
            break;
    }
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
    builder.Services.AddScoped<OrkunPAM.Application.Contracts.IAuditService, OrkunPAM.Persistence.Services.AuditService>();
    builder.Services.AddScoped<OrkunPAM.Application.Contracts.IPamAuthorizationService, OrkunPAM.Persistence.Services.PamAuthorizationService>();

    // === Input Validation (fixes #19) ===
    builder.Services.AddValidatorsFromAssemblyContaining<Program>(ServiceLifetime.Singleton);

    // === Integration Services ===
    builder.Services.AddSingleton<OrkunPAM.Application.Contracts.ILdapService, OrkunPAM.Identity.Services.LdapService>();
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.IWebhookDeliveryService, OrkunPAM.Persistence.Services.WebhookDeliveryService>();
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.IItsmService, OrkunPAM.Persistence.Services.ItsmService>();
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.IDiscoveryService, OrkunPAM.Persistence.Services.DiscoveryService>();
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.IRotationService, OrkunPAM.Persistence.Services.RotationService>();

    // === Email / SMTP (#54) ===
    builder.Services.AddScoped<IEmailService, OrkunPAM.Persistence.Services.SmtpEmailService>();

    // === JIT Expiry Background Service (#38) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.JitExpiryService>();

    // === LDAP Scheduled Sync (#90) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.LdapPamSyncService>();

    // === HttpClient (required by ThreatFeedService) ===
    builder.Services.AddHttpClient();

    // === Audit Integrity Daily Job (#91) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.AuditIntegrityJob>();

    // === Account Lifecycle Policy (#135 #137) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.AccountLifecycleJob>();

    // === Backup / DR (#55) ===
    builder.Services.AddScoped<OrkunPAM.Persistence.Services.IBackupService, OrkunPAM.Persistence.Services.BackupService>();
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.BackupSchedulerService>();

    // === System Health Monitoring (#138) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.SystemHealthMonitorService>();

    // === Connection Scheduling (#142) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.SessionSchedulerService>();

    // === Scheduled Report Delivery (#159) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.ReportSchedulerService>();

    // === Certificate Expiry Monitor (#191) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.CertificateExpiryMonitorJob>();

    // === Threat Analytics — Anomaly Detection + Behavior Baseline (#35) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.AnomalyDetectionService>();
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.BehaviorBaselineService>();

    // === Threat Intelligence Feed (#206) ===
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.ThreatFeedService>();

    // === Session Recording Playback ===
    builder.Services.AddScoped<OrkunPAM.Persistence.Services.IRecordingPlaybackService, OrkunPAM.Persistence.Services.RecordingPlaybackService>();

    // === Event Bus (shared singleton for pub/sub) ===
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.InProcessEventBus>();
    builder.Services.AddSingleton<IEventBus>(sp => sp.GetRequiredService<OrkunPAM.Persistence.Services.InProcessEventBus>());

    // === SIEM Syslog/CEF Forwarder (#63) ===
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.SiemForwarderService>();
    builder.Services.AddSingleton<OrkunPAM.Persistence.Services.ISiemForwarderService>(
        sp => sp.GetRequiredService<OrkunPAM.Persistence.Services.SiemForwarderService>());
    builder.Services.AddHostedService(
        sp => sp.GetRequiredService<OrkunPAM.Persistence.Services.SiemForwarderService>());
    builder.Services.AddHostedService<OrkunPAM.Persistence.Services.SyslogForwarderService>();

    // === Memory Cache (used by RDP token store) ===
    builder.Services.AddMemoryCache();

    // === Live Session Monitor — in-memory chunk store (#214) ===
    builder.Services.AddSingleton<OrkunPAM.WebAPI.Services.SessionChunkStore>();

    // === gRPC Services (proxy↔core internal communication) ===
    builder.Services.AddGrpc(options =>
    {
        options.MaxReceiveMessageSize = 4 * 1024 * 1024; // 4 MB
        options.MaxSendMessageSize = 4 * 1024 * 1024;
        options.EnableDetailedErrors = builder.Environment.IsDevelopment();
    });

    // === Certificate Authentication for mTLS (gRPC proxy clients) ===
    builder.Services.AddAuthentication()
        .AddCertificate("MutualTls", options =>
        {
            options.AllowedCertificateTypes = CertificateTypes.All;
            options.RevocationMode = System.Security.Cryptography.X509Certificates.X509RevocationMode.NoCheck;
            options.ValidateValidityPeriod = true;
            options.Events = new CertificateAuthenticationEvents
            {
                OnCertificateValidated = ctx =>
                {
                    // Accept certificates with CN matching configured proxy service names
                    var cn = ctx.ClientCertificate.GetNameInfo(
                        System.Security.Cryptography.X509Certificates.X509NameType.SimpleName, false);
                    var allowedCns = ctx.HttpContext.RequestServices
                        .GetRequiredService<IConfiguration>()
                        .GetSection("Grpc:AllowedClientCNs").Get<string[]>()
                        ?? ["OrkunPAM-SshProxy", "OrkunPAM-RdpProxy", "OrkunPAM-VncProxy",
                            "OrkunPAM-HttpProxy", "OrkunPAM-SqlProxy"];

                    if (cn != null && allowedCns.Contains(cn, StringComparer.OrdinalIgnoreCase))
                    {
                        var claims = new[] { new System.Security.Claims.Claim("proxy-cn", cn) };
                        ctx.Principal = new System.Security.Claims.ClaimsPrincipal(
                            new System.Security.Claims.ClaimsIdentity(claims, "Certificate"));
                        ctx.Success();
                    }
                    else
                    {
                        ctx.Fail($"Client certificate CN '{cn}' is not in the allowed list");
                    }

                    return Task.CompletedTask;
                },
                OnAuthenticationFailed = ctx =>
                {
                    Log.Warning("mTLS authentication failed: {Error}", ctx.Exception?.Message);
                    return Task.CompletedTask;
                }
            };
        });

    // === JSON: serialize enums as strings globally ===
    builder.Services.ConfigureHttpJsonOptions(opts =>
        opts.SerializerOptions.Converters.Add(new System.Text.Json.Serialization.JsonStringEnumConverter()));

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
            opt.PermitLimit = 20;
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
        })
        .AddNegotiate(); // Windows/Kerberos/NTLM SSO (#126)

    builder.Services.AddAuthorizationBuilder()
        .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
            .RequireAuthenticatedUser()
            .Build())
        .AddPolicy("AdminPolicy", p => p.RequireRole("Admin", "SecurityAdmin"))
        .AddPolicy("GrpcProxy", p => p
            .AddAuthenticationSchemes("MutualTls")
            .RequireAuthenticatedUser())
        .AddPolicy("WindowsAuth", p => p
            .AddAuthenticationSchemes("Negotiate")
            .RequireAuthenticatedUser());

    var app = builder.Build();

    // === Initialize DB ===
    using (var scope = app.Services.CreateScope())
    {
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        await db.Database.EnsureCreatedAsync();
        Log.Information("Database initialized");
    }

    // === Initialize Key Store ===
    var keyStore = app.Services.GetRequiredService<IKeyStore>();
    if (!hsmEnabled)
    {
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
        Log.Information("Vault encryption engine initialized (software key store)");
    }
    else
    {
        // HSM mode — validate HSM availability before proceeding (fail-fast)
        var hsm = app.Services.GetRequiredService<IHsmProvider>();
        var hsmAvailable = await hsm.IsAvailableAsync();
        if (!hsmAvailable)
        {
            Log.Fatal("HSM not reachable at startup. Mode: {Mode}, Provider: {Provider}. Check HSM configuration.",
                hsmMode, hsm.ProviderName);
            return;
        }
        var hsmInitResult = keyStore.Initialize(string.Empty); // passphrase ignored — MEK lives in HSM
        if (hsmInitResult.IsFailure)
        {
            Log.Fatal("Failed to initialize HSM key store via {Provider}: {Error}",
                hsm.ProviderName, hsmInitResult.Error.Message);
            return;
        }
        Log.Information("Vault encryption engine initialized via HSM: {Provider}", hsm.ProviderName);
    }

    // === Proxy Secret Validation (fixes #92) ===
    var proxySecret = builder.Configuration["ProxyService:Secret"] ?? "";
    if (proxySecret.Length < 32)
    {
        Log.Fatal("ProxyService:Secret is not configured or too short (min 32 chars). " +
                  "Set PAM_PROXYSERVICE__SECRET env var or ProxyService:Secret in config.");
        return;
    }
    Log.Information("Proxy service secret validated");

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

    // === Liveness Probe (renamed to /status to avoid conflict with rich /health endpoint) ===
    app.MapGet("/api/v1/status", () => Results.Ok(new
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
    api.MapSamlAuthEndpoints();
    api.MapAapmEndpoints();
    api.MapSessionEndpoints();
    api.MapWebSshEndpoints();
    api.MapWebRdpEndpoints();
    api.MapDiscoveryEndpoints();
    api.MapReportEndpoints();
    api.MapReportScheduleEndpoints();
    api.MapCustomReportEndpoints();
    api.MapExecutiveDashboardEndpoints();
    api.MapConnectionProfileEndpoints();
    api.MapFido2Endpoints();
    api.MapComplianceEndpoints();
    api.MapComplianceReportEndpoints();
    api.MapAnalyticsEndpoints();
    api.MapIntegrationEndpoints();
    api.MapImportEndpoints();
    api.MapBreakGlassEndpoints();
    api.MapJitEndpoints();
    api.MapEncryptionEndpoints();
    api.MapBackupEndpoints();
    api.MapAccessAssignmentEndpoints();
    api.MapSetupEndpoints();
    api.MapSystemEndpoints();
    api.MapVendorAccessEndpoints();
    api.MapVendorEndpoints();
    api.MapRdpGatewayEndpoints();
    api.MapPkiEndpoints();
    api.MapLaunchTokenEndpoints();
    api.MapCloudPamEndpoints();
    api.MapCertificateEndpoints();
    api.MapPushMfaEndpoints();
    api.MapSoarEndpoints();
    api.MapSocDashboardEndpoints();
    api.MapDeviceTrustEndpoints();
    api.MapAccessPatternEndpoints();
    api.MapTelnetEndpoints();
    api.MapLiveSessionEndpoints();

    // === gRPC Endpoints (proxy↔core internal, mTLS authenticated) ===
    app.MapGrpcService<SessionGrpcService>().RequireAuthorization("GrpcProxy");
    app.MapGrpcService<VaultGrpcService>().RequireAuthorization("GrpcProxy");
    app.MapGrpcService<AuditGrpcService>().RequireAuthorization("GrpcProxy");
    Log.Information("gRPC services mapped (Session, Vault, Audit) — mTLS required for proxy clients");

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

// Make Program accessible for integration tests (WebApplicationFactory<Program>)
public partial class Program { }
