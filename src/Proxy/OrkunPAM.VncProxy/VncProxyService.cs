using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using OrkunPAM.VncProxy.Session;

namespace OrkunPAM.VncProxy;

/// <summary>
/// Windows Service / IHostedService that listens on TCP :5900 and dispatches
/// each accepted connection to a VncSession running on the thread pool.
/// Enforces per-IP connection rate limiting to mitigate connection floods.
/// </summary>
internal sealed class VncProxyService : BackgroundService
{
    private readonly ILogger<VncProxyService> _log;
    private readonly VncProxyOptions _opts;
    private readonly PamApiClient _api;

    // Per-IP rate limiter: max 10 connections per 60-second window
    private readonly ConcurrentDictionary<string, (int count, DateTimeOffset windowStart)> _connTracker = new();
    private const int MaxConnectionsPerWindow = 10;
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromSeconds(60);

    public VncProxyService(ILogger<VncProxyService> log, IOptions<VncProxyOptions> opts, PamApiClient api)
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
        _log.LogInformation("VNC proxy listening on {Address}:{Port}", address, _opts.ListenPort);

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
                    _log.LogWarning("VNC connection from {ClientIp} dropped — rate limit exceeded", clientIp);
                    client.Dispose();
                    continue;
                }

                await semaphore.WaitAsync(stoppingToken);
                client.NoDelay = true;

                _ = Task.Run(async () =>
                {
                    try
                    {
                        var session = new VncSession(client, _api, _opts, _log, stoppingToken);
                        await session.RunAsync();
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "Unhandled error in VNC session from {ClientIp}", clientIp);
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
            _log.LogInformation("VNC proxy stopped");
        }
    }

    private bool IsRateLimited(string ip)
    {
        var now = DateTimeOffset.UtcNow;

        if (_connTracker.TryGetValue(ip, out var existing) &&
            now - existing.windowStart > RateLimitWindow)
        {
            _connTracker.TryRemove(ip, out _);
        }

        var entry = _connTracker.AddOrUpdate(ip,
            _ => (1, now),
            (_, old) => now - old.windowStart > RateLimitWindow
                ? (1, now)
                : (old.count + 1, old.windowStart));
        return entry.count > MaxConnectionsPerWindow;
    }
}
