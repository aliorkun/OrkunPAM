using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using OrkunPAM.TacacsProxy.Session;

namespace OrkunPAM.TacacsProxy;

/// <summary>
/// Windows Service / IHostedService that listens on TCP :49 (TACACS+ standard port)
/// and dispatches each accepted connection to a TacacsSession on the thread pool.
/// </summary>
internal sealed class TacacsProxyService : BackgroundService
{
    private readonly ILogger<TacacsProxyService> _log;
    private readonly TacacsProxyOptions _opts;
    private readonly PamApiClient _api;

    // Per-IP connection rate limiter: max 20 conn per 60-second window
    private readonly ConcurrentDictionary<string, (int count, DateTimeOffset windowStart)> _connTracker = new();
    private const int MaxConnectionsPerWindow = 20;
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromSeconds(60);

    public TacacsProxyService(
        ILogger<TacacsProxyService> log,
        IOptions<TacacsProxyOptions> opts,
        PamApiClient api)
    {
        _log  = log;
        _opts = opts.Value;
        _api  = api;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (string.IsNullOrEmpty(_opts.DefaultSharedSecret))
        {
            _log.LogError("DefaultSharedSecret is not configured. TACACS+ proxy cannot start securely.");
            return;
        }

        var address = string.IsNullOrEmpty(_opts.ListenAddress)
            ? IPAddress.Any
            : IPAddress.Parse(_opts.ListenAddress);

        var listener = new TcpListener(address, _opts.ListenPort);
        listener.Start();
        _log.LogInformation("TACACS+ proxy listening on {Address}:{Port}", address, _opts.ListenPort);

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
                    _log.LogWarning("TACACS+ connection from {ClientIp} dropped — rate limit exceeded", clientIp);
                    client.Dispose();
                    continue;
                }

                _log.LogDebug("Accepted TACACS+ connection from {ClientIp}", clientIp);

                await semaphore.WaitAsync(stoppingToken);
                client.NoDelay = true;

                _ = Task.Run(async () =>
                {
                    try
                    {
                        var session = new TacacsSession(client, _api, _opts, _log, stoppingToken);
                        await session.RunAsync();
                    }
                    catch (Exception ex)
                    {
                        _log.LogError(ex, "Unhandled error in TACACS+ session from {ClientIp}", clientIp);
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
            _log.LogInformation("TACACS+ proxy stopped");
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
