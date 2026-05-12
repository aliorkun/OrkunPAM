using Microsoft.Extensions.Options;
using OrkunPAM.SshProxy;
using OrkunPAM.SshProxy.Crypto;
using OrkunPAM.SshProxy.Session;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [SSH] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File("logs/sshproxy-.log", rollingInterval: RollingInterval.Day)
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.AddWindowsService(opts => opts.ServiceName = "OrkunPAM SSH Proxy");
    builder.Services.AddSerilog();

    builder.Services.Configure<SshProxyOptions>(builder.Configuration.GetSection("SshProxy"));

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
        // In production, use a trusted CA or pin the Core API certificate fingerprint.
        if (Environment.GetEnvironmentVariable("ASPNETCORE_ENVIRONMENT") == "Development")
            handler.ServerCertificateCustomValidationCallback =
                HttpClientHandler.DangerousAcceptAnyServerCertificateValidator;
        return handler;
    });

    builder.Services.AddSingleton<SshHostKey>();
    builder.Services.AddSingleton<PamApiClient>();
    builder.Services.AddSingleton(sp =>
    {
        var opts = sp.GetRequiredService<IOptions<SshProxyOptions>>().Value;
        var log  = sp.GetRequiredService<ILogger<HashChainStore>>();
        return new HashChainStore(opts.RecordingDirectory, log);
    });
    builder.Services.AddHostedService<RecordingRetentionService>();
    builder.Services.AddHostedService<SshProxyService>();

    await builder.Build().RunAsync();
}
catch (Exception ex)
{
    Log.Fatal(ex, "OrkunPAM SSH Proxy terminated unexpectedly");
}
finally
{
    Log.CloseAndFlush();
}
