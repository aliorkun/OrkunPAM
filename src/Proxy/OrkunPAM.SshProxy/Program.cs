using OrkunPAM.SshProxy;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level:u3}] [SSH] {Message:lj}{NewLine}{Exception}")
    .WriteTo.File("logs/sshproxy-.log", rollingInterval: RollingInterval.Day)
    .CreateLogger();

try
{
    var builder = Host.CreateApplicationBuilder(args);
    builder.Services.UseWindowsService(opts => opts.ServiceName = "OrkunPAM SSH Proxy");
    builder.Host.UseSerilog();

    builder.Services.Configure<SshProxyOptions>(builder.Configuration.GetSection("SshProxy"));

    builder.Services.AddHttpClient("PamApi", client =>
    {
        client.BaseAddress = new Uri(
            builder.Configuration["PamApi:BaseUrl"] ?? "http://localhost:5000");
        client.Timeout = TimeSpan.FromSeconds(10);
    });

    builder.Services.AddSingleton<SshHostKey>();
    builder.Services.AddSingleton<PamApiClient>();
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
