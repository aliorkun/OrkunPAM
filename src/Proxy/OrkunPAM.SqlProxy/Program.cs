using OrkunPAM.SqlProxy;
using OrkunPAM.SqlProxy.Session;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [SQL] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File("logs/sqlproxy-.log", rollingInterval: RollingInterval.Day)
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddWindowsService(opts => opts.ServiceName = "OrkunPAM SQL Proxy");
    builder.Services.AddSerilog();

    builder.Services.Configure<SqlProxyOptions>(builder.Configuration.GetSection("SqlProxy"));

    builder.Services.AddHttpClient("PamApi", client =>
    {
        client.BaseAddress = new Uri(
            builder.Configuration["PamApi:BaseUrl"] ?? "https://localhost:5001");
        client.Timeout = TimeSpan.FromSeconds(10);
    })
    .ConfigurePrimaryHttpMessageHandler(() =>
    {
        var handler = new HttpClientHandler();
        // In development, accept self-signed Core API certificates.
        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return handler;
    });

    builder.Services.AddSingleton<PamApiClient>();
    builder.Services.AddHostedService<QueryLogRetentionService>();
    builder.Services.AddHostedService<SqlProxyService>();

    await builder.Build().RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "OrkunPAM SQL Proxy terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
