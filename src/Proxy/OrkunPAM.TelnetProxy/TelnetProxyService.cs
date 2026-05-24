using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;

namespace OrkunPAM.TelnetProxy;

/// <summary>
/// Windows Service / IHostedService that listens on TCP port 2323
/// and dispatches each accepted connection to a TelnetSession on the thread pool.
/// </summary>
internal sealed class TelnetProxyService : BackgroundService
{
    private readonly ILogger<TelnetProxyService> _log;
    private readonly TelnetProxyOptions _opts;
    private readonly PamApiClient _api;

    // Per-IP connection rate limiter: max 10 new connections per 60-second window
    private readonly ConcurrentDictionary<string, (int count, DateTimeOffset windowStart)> _connTracker = new();
    private const int MaxConnectionsPerWindow = 10;
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromSeconds(60);

    public TelnetProxyService(
        ILogger<TelnetProxyService> log,
        IOptions<TelnetProxyOptions> opts,
        PamApiClient api)
    {
        _log  = log;
        _opts = opts.Value;
        _api  = api;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var address = string.IsNullOrEmpty(_opts.ListenAddress)
            ? IPAddress.IPv6Any  // dual-stack (#262)
            : IPAddress.Parse(_opts.ListenAddress);

        var listener = new TcpListener(address, _opts.ListenPort);
        if (address.Equals(IPAddress.IPv6Any)) listener.Server.DualMode = true;
        listener.Start();
        _log.LogInformation("Telnet proxy listening on {Address}:{Port}", address, _opts.ListenPort);

        using var semaphore = new SemaphoreSlim(_opts.MaxConcurrentSessions);

        try
        {
            while (!stoppingToken.IsCancellationRequested)
            {
                TcpClient client;
                try { client = await listener.AcceptTcpClientAsync(stoppingToken); }
                catch (OperationCanceledException) { break; }

                var clientIp = ((IPEndPoint?)client.Client.RemoteEndPoint)?.Address.ToString() ?? "unknown";

                // Per-IP rate limiting
                if (!IsConnectionAllowed(clientIp))
                {
                    _log.LogWarning("Telnet rate limit exceeded from {Ip} — dropping connection", clientIp);
                    client.Dispose();
                    continue;
                }

                // Max concurrent sessions
                if (!await semaphore.WaitAsync(0, stoppingToken))
                {
                    _log.LogWarning("Telnet max concurrent sessions ({Max}) reached — dropping {Ip}",
                        _opts.MaxConcurrentSessions, clientIp);
                    try
                    {
                        var ns = client.GetStream();
                        await ns.WriteAsync(
                            "\r\nPAM Telnet Gateway: max sessions reached, try again later.\r\n"u8.ToArray(),
                            stoppingToken);
                    }
                    catch { /* ignore */ }
                    client.Dispose();
                    continue;
                }

                // Dispatch to thread pool
                _ = Task.Run(async () =>
                {
                    try
                    {
                        var session = new TelnetSession(client, _api, _opts, _log, clientIp);
                        await session.RunAsync(stoppingToken);
                    }
                    finally
                    {
                        semaphore.Release();
                    }
                }, stoppingToken);
            }
        }
        finally
        {
            listener.Stop();
            _log.LogInformation("Telnet proxy stopped");
        }
    }

    private bool IsConnectionAllowed(string clientIp)
    {
        var now = DateTimeOffset.UtcNow;
        var entry = _connTracker.AddOrUpdate(clientIp,
            _ => (1, now),
            (_, existing) =>
            {
                if (now - existing.windowStart > RateLimitWindow)
                    return (1, now);
                return (existing.count + 1, existing.windowStart);
            });

        return entry.count <= MaxConnectionsPerWindow;
    }
}
