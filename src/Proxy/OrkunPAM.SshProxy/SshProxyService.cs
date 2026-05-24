using System.Collections.Concurrent;
using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using OrkunPAM.SshProxy.Crypto;
using OrkunPAM.SshProxy.Server;
using OrkunPAM.SshProxy.Session;

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
    private readonly HashChainStore _hashChain;

    // Per-IP connection rate limiter: max 10 connections per 60-second window
    private readonly ConcurrentDictionary<string, (int count, DateTimeOffset windowStart)> _connTracker = new();
    private const int MaxConnectionsPerWindow = 10;
    private static readonly TimeSpan RateLimitWindow = TimeSpan.FromSeconds(60);

    private bool IsConnectionRateLimited(string ip)
    {
        var now = DateTimeOffset.UtcNow;
        var entry = _connTracker.AddOrUpdate(ip,
            _ => (1, now),
            (_, old) => now - old.windowStart > RateLimitWindow
                ? (1, now)
                : (old.count + 1, old.windowStart));
        return entry.count > MaxConnectionsPerWindow;
    }

    public SshProxyService(
        ILogger<SshProxyService> log,
        IOptions<SshProxyOptions> opts,
        SshHostKey hostKey,
        PamApiClient api,
        HashChainStore hashChain)
    {
        _log       = log;
        _opts      = opts.Value;
        _hostKey   = hostKey;
        _api       = api;
        _hashChain = hashChain;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        var address = string.IsNullOrEmpty(_opts.ListenAddress)
            ? IPAddress.IPv6Any  // dual-stack: accepts IPv4-mapped and native IPv6 (#262)
            : IPAddress.Parse(_opts.ListenAddress);

        var listener = new TcpListener(address, _opts.ListenPort);
        if (address.Equals(IPAddress.IPv6Any)) listener.Server.DualMode = true;
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

                var remote    = client.Client.RemoteEndPoint?.ToString() ?? "unknown";
                var clientIp  = ((IPEndPoint?)client.Client.RemoteEndPoint)?.Address.ToString() ?? "unknown";

                if (IsConnectionRateLimited(clientIp))
                {
                    _log.LogWarning("Connection from {ClientIp} dropped — rate limit exceeded", clientIp);
                    client.Dispose();
                    continue;
                }

                _log.LogInformation("SSH connection from {Remote}", remote);

                await semaphore.WaitAsync(stoppingToken);

                _ = Task.Run(async () =>
                {
                    try
                    {
                        client.NoDelay = true;
                        var session = new SshServerSession(client, _hostKey, _api, _opts, _log, stoppingToken, _hashChain);
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
