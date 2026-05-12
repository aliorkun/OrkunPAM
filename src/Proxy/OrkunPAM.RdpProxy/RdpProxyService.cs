using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using OrkunPAM.RdpProxy.Server;

namespace OrkunPAM.RdpProxy;

/// <summary>
/// Windows Service / IHostedService that listens on TCP (default :3389) and dispatches
/// each accepted connection to an RdpServerSession running on the thread pool.
/// Enforces per-IP connection rate limiting to mitigate connection floods.
/// </summary>
internal sealed class RdpProxyService : BackgroundService
{
    private readonly ILogger<RdpProxyService> _log;
    private readonly RdpProxyOptions _opts;
    private readonly PamApiClient _api;

    // Per-IP rate limiter: max 5 connections per 30-second window
    private readonly ConcurrentDictionary<string, (int count, DateTimeOffset windowStart)> _connTracker = new();
    private const int MaxConnectionsPerWindow = 5;
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromSeconds(30);

    public RdpProxyService(
        ILogger<RdpProxyService> log,
        IOptions<RdpProxyOptions> opts,
        PamApiClient api)
    {
        _log  = log;
        _opts = opts.Value;
        _api  = api;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var address = string.IsNullOrEmpty(_opts.ListenAddress)
            ? IPAddress.Any
            : IPAddress.Parse(_opts.ListenAddress);

        var listener = new TcpListener(address, _opts.ListenPort);
        listener.Start();
        _log.LogInformation("RDP proxy listening on {Address}:{Port}", address, _opts.ListenPort);

        using var semaphore = new SemaphoreSlim(_opts.MaxConcurrentSessions);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(stoppingToken); }
                catch (OperationCanceledException) { break; }

                var clientIp = ((IPEndPoint?)client.Client.RemoteEndPoint)?.Address.ToString() ?? "unknown";

                if (IsRateLimited(clientIp))
                {
                    _log.LogWarning("RDP connection from {ClientIp} dropped — rate limit exceeded", clientIp);
                    client.Dispose();
                    continue;
                }

                _log.LogDebug("Accepted RDP connection from {ClientIp}", clientIp);

                await semaphore.WaitAsync(stoppingToken);
                client.NoDelay = true;

                _ = Task.Run(async () =>
                {
                    try
                    {
                        var session = new RdpServerSession(client, _api, _opts, _log, stoppingToken);
                        await session.RunAsync();
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "Unhandled error in RDP session from {ClientIp}", clientIp);
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
            _log.LogInformation("RDP proxy stopped");
        }
    }

    private bool IsRateLimited(string ip)
    {
        var now = DateTimeOffset.UtcNow;
        var entry = _connTracker.AddOrUpdate(ip,
            _ => (1, now),
            (_, old) => now - old.windowStart > RateLimitWindow
                ? (1, now)
                : (old.count + 1, old.windowStart));
        return entry.count > MaxConnectionsPerWindow;
    }
}
