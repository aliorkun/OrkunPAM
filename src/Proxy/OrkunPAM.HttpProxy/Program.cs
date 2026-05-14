using OrkunPAM.HttpProxy;
using OrkunPAM.HttpProxy.Session;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [HTTP] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File("logs/httpproxy-.log", rollingInterval: RollingInterval.Day)
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddWindowsService(opts => opts.ServiceName = "OrkunPAM HTTP Proxy");
    builder.Services.AddSerilog();

    builder.Services.Configure<HttpProxyOptions>(builder.Configuration.GetSection("HttpProxy"));

    builder.Services.AddHttpClient("PamApi", client =>
    {
        client.BaseAddress = new Uri(
            builder.Configuration["PamApi:BaseUrl"] ?? "https://localhost:5001");
        client.Timeout = TimeSpan.FromSeconds(10);
    })
    .ConfigurePrimaryHttpMessageHandler(() =>
    {
        var handler = new HttpClientHandler();
        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return handler;
    });

    builder.Services.AddSingleton<PamApiClient>();
    builder.Services.AddHostedService<LogRetentionService>();
    builder.Services.AddHostedService<HttpProxyService>();

    await builder.Build().RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "OrkunPAM HTTP Proxy terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
