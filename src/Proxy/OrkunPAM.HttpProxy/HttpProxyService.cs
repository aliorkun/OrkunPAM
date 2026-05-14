using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using OrkunPAM.HttpProxy.Session;

namespace OrkunPAM.HttpProxy;

/// <summary>
/// Windows Service / IHostedService that listens on TCP :8080 and dispatches
/// each accepted connection to an HttpSession running on the thread pool.
/// Enforces per-IP connection rate limiting to mitigate connection floods.
/// </summary>
internal sealed class HttpProxyService : BackgroundService
{
    private readonly ILogger<HttpProxyService> _log;
    private readonly HttpProxyOptions _opts;
    private readonly PamApiClient _api;

    // Per-IP rate limiter: max 20 connections per 60-second window
    private readonly ConcurrentDictionary<string, (int count, DateTimeOffset windowStart)> _connTracker = new();
    private const int MaxConnectionsPerWindow = 20;
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromSeconds(60);

    public HttpProxyService(
        ILogger<HttpProxyService> log, IOptions<HttpProxyOptions> opts, PamApiClient api)
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
        _log.LogInformation("HTTP proxy listening on {Address}:{Port}", address, _opts.ListenPort);

        using var semaphore = new SemaphoreSlim(_opts.MaxConcurrentSessions);

        // Periodically evict expired rate-limit entries to prevent unbounded growth (#109)
        _ = Task.Run(async () =>
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                try { await Task.Delay(TimeSpan.FromMinutes(5), stoppingToken); }
                catch (OperationCanceledException) { return; }
                var cutoff = DateTimeOffset.UtcNow - RateLimitWindow;
                foreach (var key in _connTracker.Keys)
                {
                    if (_connTracker.TryGetValue(key, out var e) && e.windowStart < cutoff)
                        _connTracker.TryRemove(key, out _);
                }
            }
        }, stoppingToken);

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
                    _log.LogWarning("HTTP connection from {ClientIp} dropped — rate limit exceeded", clientIp);
                    client.Dispose();
                    continue;
                }

                await semaphore.WaitAsync(stoppingToken);
                client.NoDelay = true;

                _ = Task.Run(async () =>
                {
                    try
                    {
                        var session = new HttpSession(client, _api, _opts, _log, stoppingToken);
                        await session.RunAsync();
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "Unhandled error in HTTP session from {ClientIp}", clientIp);
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
            _log.LogInformation("HTTP proxy stopped");
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
