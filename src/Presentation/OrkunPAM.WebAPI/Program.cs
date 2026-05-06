using Microsoft.EntityFrameworkCore;
using OrkunPAM.Cryptography;
using OrkunPAM.Identity.Services;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;
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
    builder.Services.AddSingleton<IJwtTokenService, JwtTokenService>();
    builder.Services.AddScoped<IAuthenticationService, AuthenticationService>();

    // === Swagger ===
    builder.Services.AddEndpointsApiExplorer();
    builder.Services.AddSwaggerGen(c =>
    {
        c.SwaggerDoc("v1", new() { Title = "Orkun PAM API", Version = "v1" });
    });

    // === CORS ===
    builder.Services.AddCors(options =>
    {
        options.AddDefaultPolicy(policy =>
            policy.AllowAnyOrigin().AllowAnyMethod().AllowAnyHeader());
    });

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
    var passphrase = builder.Configuration["Vault:MasterPassphrase"] ?? "OrkunPAM-Dev-2026!";
    var initResult = keyStore.Initialize(passphrase);
    if (initResult.IsFailure)
    {
        Log.Fatal("Failed to initialize vault key store: {Error}", initResult.Error.Message);
        return;
    }
    Log.Information("Vault encryption engine initialized");

    // === Middleware ===
    app.UseSerilogRequestLogging();
    app.UseCors();

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
    })).WithTags("System");

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
    }).WithTags("Vault");

    // === Auth Endpoints ===
    app.MapPost("/api/v1/auth/login", async (LoginRequest req, IAuthenticationService auth, HttpContext ctx) =>
    {
        var ip = ctx.Connection.RemoteIpAddress?.ToString() ?? "unknown";
        var result = await auth.LoginLocalAsync(req.Username, req.Password, ip);

        if (result.IsFailure)
            return Results.Unauthorized();

        var data = result.Value;
        return Results.Ok(new
        {
            success = true,
            data = new
            {
                accessToken = data.Tokens.AccessToken,
                refreshToken = data.Tokens.RefreshToken,
                expiresAt = data.Tokens.AccessTokenExpiry,
                userId = data.UserId,
                username = data.Username,
                displayName = data.DisplayName,
                mfaRequired = data.MfaRequired
            }
        });
    }).WithTags("Auth");

    app.MapPost("/api/v1/auth/register", async (RegisterRequest req, IAuthenticationService auth) =>
    {
        var result = await auth.CreateLocalUserAsync(req.Username, req.Password, req.DisplayName, req.Email);
        if (result.IsFailure)
            return Results.Conflict(new { success = false, errors = new[] { result.Error.Message } });

        return Results.Created($"/api/v1/users/{result.Value.Id}", new
        {
            success = true,
            data = new { result.Value.Id, result.Value.Username, result.Value.DisplayName }
        });
    }).WithTags("Auth");

    // === User Endpoints ===
    app.MapGet("/api/v1/users", async (OrkunPamDbContext db) =>
    {
        var users = await db.Users.Select(u => new
        {
            u.Id, u.Username, u.DisplayName, u.Email,
            u.AuthSource, u.Status, u.MfaEnabled,
            u.LastLoginAtUtc, u.CreatedAtUtc
        }).ToListAsync();
        return Results.Ok(new { success = true, data = users, meta = new { totalCount = users.Count } });
    }).WithTags("Users");

    app.MapPost("/api/v1/users", async (CreateUserRequest req, OrkunPamDbContext db) =>
    {
        if (await db.Users.AnyAsync(u => u.NormalizedUsername == req.Username.ToUpperInvariant()))
            return Results.Conflict(new { success = false, errors = new[] { $"Username '{req.Username}' already exists" } });

        var user = new OrkunPAM.Domain.Entities.Identity.User
        {
            Username = req.Username,
            NormalizedUsername = req.Username.ToUpperInvariant(),
            DisplayName = req.DisplayName,
            Email = req.Email,
            AuthSource = OrkunPAM.Domain.Enums.AuthSource.Local,
            Status = OrkunPAM.Domain.Enums.UserStatus.Active,
            PasswordHash = "PLACEHOLDER" // Will be Argon2id in Phase 1
        };

        db.Users.Add(user);
        await db.SaveChangesAsync();

        return Results.Created($"/api/v1/users/{user.Id}", new { success = true, data = new { user.Id, user.Username } });
    }).WithTags("Users");

    app.MapGet("/api/v1/users/{id:guid}", async (Guid id, OrkunPamDbContext db) =>
    {
        var user = await db.Users.FindAsync(id);
        if (user == null) return Results.NotFound(new { success = false, errors = new[] { "User not found" } });
        return Results.Ok(new { success = true, data = user });
    }).WithTags("Users");

    // === Role Endpoints ===
    app.MapGet("/api/v1/roles", async (OrkunPamDbContext db) =>
    {
        var roles = await db.Roles.Select(r => new { r.Id, r.Name, r.Description, r.IsSystemRole }).ToListAsync();
        return Results.Ok(new { success = true, data = roles });
    }).WithTags("Roles");

    // === Audit Log ===
    app.MapGet("/api/v1/audit-logs", async (OrkunPamDbContext db, int page = 1, int pageSize = 50) =>
    {
        var total = await db.AuditLogs.CountAsync();
        var logs = await db.AuditLogs
            .OrderByDescending(a => a.Timestamp)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();
        return Results.Ok(new { success = true, data = logs, meta = new { page, pageSize, totalCount = total } });
    }).WithTags("Audit");

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

record CreateUserRequest(string Username, string? DisplayName, string? Email);
record LoginRequest(string Username, string Password);
record RegisterRequest(string Username, string Password, string? DisplayName, string? Email);
