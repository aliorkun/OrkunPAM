using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using OrkunPAM.SshProxy.Crypto;
using OrkunPAM.SshProxy.Server;

namespace OrkunPAM.SshProxy;

/// <summary>
/// Windows Service / IHostedService that listens on TCP :2222 and dispatches
/// each accepted connection to an SshServerSession running on the thread pool.
/// </summary>
internal sealed class SshProxyService : BackgroundService
{
    private readonly ILogger<SshProxyService> _log;
    private readonly SshProxyOptions _opts;
    private readonly SshHostKey _hostKey;
    private readonly PamApiClient _api;

    public SshProxyService(
        ILogger<SshProxyService> log,
        IOptions<SshProxyOptions> opts,
        SshHostKey hostKey,
        PamApiClient api)
    {
        _log = log;
        _opts = opts.Value;
        _hostKey = hostKey;
        _api = api;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var address = string.IsNullOrEmpty(_opts.ListenAddress)
            ? IPAddress.Any
            : IPAddress.Parse(_opts.ListenAddress);

        var listener = new TcpListener(address, _opts.ListenPort);
        listener.Start();
        _log.LogInformation("SSH proxy listening on {Address}:{Port}", address, _opts.ListenPort);

        using var semaphore = new SemaphoreSlim(_opts.MaxConcurrentSessions);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(stoppingToken); }
                catch (OperationCanceledException) { break; }

                var remote = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
                _log.LogInformation("SSH connection from {Remote}", remote);

                await semaphore.WaitAsync(stoppingToken);

                _ = Task.Run(async () =>
                {
                    try
                    {
                        client.NoDelay = true;
                        var session = new SshServerSession(client, _hostKey, _api, _log, stoppingToken);
                        await session.RunAsync();
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "Session error from {Remote}", remote);
                    }
                    finally
                    {
                        client.Dispose();
                        semaphore.Release();
                    }
                }, stoppingToken);
            }
        }
        finally
        {
            listener.Stop();
            _log.LogInformation("SSH proxy stopped");
        }
    }
}
