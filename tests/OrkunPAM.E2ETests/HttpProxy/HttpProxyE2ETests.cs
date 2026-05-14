using System.Net;
using System.Net.Sockets;
using System.Text;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.E2ETests.Helpers;
using OrkunPAM.HttpProxy;
using OrkunPAM.HttpProxy.Session;

namespace OrkunPAM.E2ETests.HttpProxy;

/// <summary>
/// Full integration tests for the HTTP proxy service.
/// Each test starts a real HttpProxyService host pointing at a MockPamApiServer,
/// then connects via TCP to exercise the full request-dispatch path.
/// </summary>
public sealed class HttpProxyE2ETests : IAsyncDisposable
{
    private readonly MockPamApiServer _pam;
    private readonly int _proxyPort;
    private readonly IHost _host;

    public HttpProxyE2ETests()
    {
        _pam       = new MockPamApiServer();
        _proxyPort = NetHelpers.GetFreePort();
        _host      = BuildHost(_proxyPort, _pam.BaseUrl);
        _host.StartAsync().GetAwaiter().GetResult();
        NetHelpers.WaitForPortAsync(_proxyPort, TimeSpan.FromSeconds(5)).GetAwaiter().GetResult();
    }

    public async ValueTask DisposeAsync()
    {
        await _host.StopAsync(TimeSpan.FromSeconds(3));
        _host.Dispose();
        _pam.Dispose();
    }

    // ── Tests ─────────────────────────────────────────────────────

    [Fact]
    [Trait("Category", "E2E")]
    public async Task HttpProxy_NoProxyAuthorization_Returns407()
    {
        var line = await SendAndReadFirstLineAsync(
            "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 407", line, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task HttpProxy_InvalidCredentials_Returns407()
    {
        var b64  = Convert.ToBase64String(Encoding.UTF8.GetBytes("wronguser:wrongpass"));
        var line = await SendAndReadFirstLineAsync(
            $"CONNECT example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {b64}\r\n\r\n");

        Assert.StartsWith("HTTP/1.1 407", line, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task HttpProxy_ValidAuth_ConnectBlockedUrl_Returns403()
    {
        int port = NetHelpers.GetFreePort();
        using var pam = new MockPamApiServer();
        var host = BuildHost(port, pam.BaseUrl, urlBlacklist: ["*blocked-host*"]);
        await host.StartAsync();
        await NetHelpers.WaitForPortAsync(port, TimeSpan.FromSeconds(5));
        try
        {
            var b64  = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{pam.ValidUsername}:{pam.ValidPassword}"));
            var line = await SendAndReadFirstLineAsync(
                $"CONNECT blocked-host.example.com:443 HTTP/1.1\r\nProxy-Authorization: Basic {b64}\r\n\r\n",
                port);

            Assert.StartsWith("HTTP/1.1 403", line, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            await host.StopAsync(TimeSpan.FromSeconds(3));
            host.Dispose();
        }
    }

    [Fact]
    [Trait("Category", "E2E")]
    public async Task HttpProxy_ValidAuth_ConnectToMockTarget_Returns200()
    {
        var targetListener = new TcpListener(IPAddress.Loopback, 0);
        targetListener.Start();
        int targetPort = ((IPEndPoint)targetListener.LocalEndpoint).Port;

        using var targetCts = new CancellationTokenSource(TimeSpan.FromSeconds(10));
        _ = Task.Run(async () =>
        {
            try
            {
                var t = await targetListener.AcceptTcpClientAsync(targetCts.Token);
                t.Dispose();
            }
            catch { }
        }, targetCts.Token);

        try
        {
            var b64  = Convert.ToBase64String(Encoding.UTF8.GetBytes($"{_pam.ValidUsername}:{_pam.ValidPassword}"));
            var line = await SendAndReadFirstLineAsync(
                $"CONNECT localhost:{targetPort} HTTP/1.1\r\nProxy-Authorization: Basic {b64}\r\n\r\n");

            Assert.StartsWith("HTTP/1.1 200", line, StringComparison.OrdinalIgnoreCase);
        }
        finally
        {
            targetCts.Cancel();
            targetListener.Stop();
        }
    }

    // ── Helpers ───────────────────────────────────────────────────

    private async Task<string> SendAndReadFirstLineAsync(string request, int? port = null)
    {
        using var tcp = new TcpClient();
        await tcp.ConnectAsync(IPAddress.Loopback, port ?? _proxyPort);

        var stream = tcp.GetStream();
        await stream.WriteAsync(Encoding.ASCII.GetBytes(request));

        using var cts = new CancellationTokenSource(TimeSpan.FromSeconds(8));
        return await NetHelpers.ReadResponseLineAsync(stream, cts.Token);
    }

    private static IHost BuildHost(int proxyPort, string pamBaseUrl,
        List<string>? urlBlacklist = null)
    {
        return new HostBuilder()
            .ConfigureLogging(l => l.SetMinimumLevel(LogLevel.Warning))
            .ConfigureAppConfiguration(b => b.AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["PamApi:BaseUrl"]           = pamBaseUrl,
                ["PamApi:ProxySecret"]       = E2EConstants.TestProxySecret,
                ["HttpProxy:ListenPort"]     = proxyPort.ToString(),
                ["HttpProxy:MaxConcurrentSessions"] = "5",
                ["HttpProxy:LogDirectory"]   = Path.Combine(Path.GetTempPath(), "e2e-http-logs"),
            }))
            .ConfigureServices((ctx, services) =>
            {
                services.Configure<HttpProxyOptions>(o =>
                {
                    o.ListenPort           = proxyPort;
                    o.MaxConcurrentSessions = 5;
                    o.LogDirectory         = Path.Combine(Path.GetTempPath(), "e2e-http-logs");
                    if (urlBlacklist != null)
                        o.UrlBlacklist = urlBlacklist;
                });
                services.AddHttpClient("PamApi", c =>
                {
                    c.BaseAddress = new Uri(pamBaseUrl);
                    c.Timeout     = TimeSpan.FromSeconds(5);
                });
                services.AddSingleton<PamApiClient>();
                services.AddHostedService<LogRetentionService>();
                services.AddHostedService<HttpProxyService>();
            })
            .Build();
    }
}
