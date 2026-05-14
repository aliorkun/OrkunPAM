using OrkunPAM.TacacsProxy;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [TACACS+] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File("logs/tacacsproxy-.log", rollingInterval: RollingInterval.Day)
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddWindowsService(opts => opts.ServiceName = "OrkunPAM TACACS+ Proxy");
    builder.Services.AddSerilog();

    builder.Services.Configure<TacacsProxyOptions>(builder.Configuration.GetSection("TacacsProxy"));

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
    builder.Services.AddHostedService<TacacsProxyService>();
    builder.Services.AddHostedService<RadiusProxyService>();

    await builder.Build().RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "OrkunPAM TACACS+ Proxy terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
