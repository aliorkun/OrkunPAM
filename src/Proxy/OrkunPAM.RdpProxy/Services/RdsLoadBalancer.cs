using Microsoft.Extensions.Options;

namespace OrkunPAM.RdpProxy.Services;

public sealed class RdsNodeStatus
{
    public string Host { get; }
    public bool IsHealthy { get; set; } = true;
    public int ActiveConnections { get; set; }
    public int LastLatencyMs { get; set; }
    public DateTime LastCheckUtc { get; set; } = DateTime.UtcNow;
    public string LastError { get; set; } = "";

    public RdsNodeStatus(string host) => Host = host;
}

// Background service that health-checks RDS/RDSH nodes and provides least-connections routing.
public sealed class RdsLoadBalancer : BackgroundService
{
    private readonly ILogger<RdsLoadBalancer> _log;
    private readonly RdpProxyOptions _opts;
    private readonly Dictionary<string, RdsNodeStatus> _nodes;
    private readonly object _lock = new();

    public RdsLoadBalancer(ILogger<RdsLoadBalancer> log, IOptions<RdpProxyOptions> opts)
    {
        _log = log;
        _opts = opts.Value;
        _nodes = new Dictionary<string, RdsNodeStatus>(StringComparer.OrdinalIgnoreCase);
        foreach (var host in _opts.RdsHosts)
            _nodes[host] = new RdsNodeStatus(host);

        if (_nodes.Count > 0)
            _log.LogInformation("RDS load balancer initialized with {Count} nodes: {Hosts}",
                _nodes.Count, string.Join(", ", _opts.RdsHosts));
    }

    protected override async Task ExecuteAsync(CancellationToken ct)
    {
        if (_nodes.Count == 0) return;
        using var timer = new PeriodicTimer(TimeSpan.FromSeconds(30));
        while (!ct.IsCancellationRequested && await timer.WaitForNextTickAsync(ct))
            await HealthCheckAllAsync(ct);
    }

    // Least-connections pick; returns null when no nodes configured or all unhealthy.
    public string? PickBestNode()
    {
        lock (_lock)
        {
            return _nodes.Values
                .Where(n => n.IsHealthy)
                .OrderBy(n => n.ActiveConnections)
                .ThenBy(n => n.LastLatencyMs)
                .FirstOrDefault()?.Host;
        }
    }

    public void RecordConnectionStart(string host)
    {
        lock (_lock)
        {
            if (_nodes.TryGetValue(host, out var n))
                n.ActiveConnections++;
        }
    }

    public void RecordConnectionEnd(string host)
    {
        lock (_lock)
        {
            if (_nodes.TryGetValue(host, out var n))
                n.ActiveConnections = Math.Max(0, n.ActiveConnections - 1);
        }
    }

    public IReadOnlyList<RdsNodeStatus> GetAllNodes()
    {
        lock (_lock)
            return _nodes.Values.ToList();
    }

    public int NodeCount => _nodes.Count;

    private async Task HealthCheckAllAsync(CancellationToken ct)
    {
        foreach (var (host, node) in _nodes.ToList())
        {
            try
            {
                var sw = System.Diagnostics.Stopwatch.StartNew();
                using var tcp = new System.Net.Sockets.TcpClient();
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(3000);
                await tcp.ConnectAsync(host, _opts.ListenPort, cts.Token);
                sw.Stop();

                lock (_lock)
                {
                    node.IsHealthy = true;
                    node.LastLatencyMs = (int)sw.ElapsedMilliseconds;
                    node.LastCheckUtc = DateTime.UtcNow;
                    node.LastError = "";
                }
            }
            catch (Exception ex)
            {
                lock (_lock)
                {
                    node.IsHealthy = false;
                    node.LastCheckUtc = DateTime.UtcNow;
                    node.LastError = ex.Message;
                }
                _log.LogWarning("RDS node {Host} health check failed: {Error}", host, ex.Message);
            }
        }
    }
}
