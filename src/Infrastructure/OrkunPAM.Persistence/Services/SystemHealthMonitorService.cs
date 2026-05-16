using System.Diagnostics;
using System.Net.Sockets;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

public sealed class SystemHealthMonitorService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<SystemHealthMonitorService> _logger;

    private static readonly TimeSpan Interval = TimeSpan.FromSeconds(60);

    // Proxy service ports to check (TCP)
    private static readonly (string Name, string Host, int Port)[] ProxyServices =
    [
        ("SSH Proxy",    "127.0.0.1", 2222),
        ("RDP Proxy",    "127.0.0.1", 3389),
        ("TACACS+",      "127.0.0.1", 49),
        ("HTTP Proxy",   "127.0.0.1", 8080),
        ("SQL Proxy",    "127.0.0.1", 1433),
        ("VNC Proxy",    "127.0.0.1", 5900),
    ];

    // Guard: don't send duplicate alarms within this window
    private readonly Dictionary<string, DateTime> _lastAlarmAt = new();
    private static readonly TimeSpan AlarmCooldown = TimeSpan.FromMinutes(5);

    // CPU measurement state
    private TimeSpan _previousCpuTime = TimeSpan.Zero;
    private DateTime _previousMeasureAt = DateTime.MinValue;

    public SystemHealthMonitorService(IServiceScopeFactory scopeFactory,
        ILogger<SystemHealthMonitorService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        _logger.LogInformation("System health monitor started");

        using var timer = new PeriodicTimer(Interval);
        while (await timer.WaitForNextTickAsync(stoppingToken))
        {
            try { await RunHealthCheckAsync(stoppingToken); }
            catch (Exception ex) { _logger.LogError(ex, "Health check sweep failed"); }
        }
    }

    private async Task RunHealthCheckAsync(CancellationToken ct)
    {
        await using var scope = _scopeFactory.CreateAsyncScope();
        var db    = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();
        var email = scope.ServiceProvider.GetRequiredService<IEmailService>();

        var thresholds = await LoadThresholdsAsync(db, ct);

        var cpuPct    = MeasureCpuPercent();
        var memMb     = MeasureMemoryMb();
        var diskPct   = MeasureDiskPercent();
        var services  = await CheckProxyServicesAsync(ct);

        // Evaluate thresholds and fire alarms
        await EvaluateMetricAsync(db, email, "cpu",    cpuPct,  thresholds.CpuWarningPct,
            $"CPU usage {cpuPct:F1}% exceeds threshold {thresholds.CpuWarningPct}%", ct);

        await EvaluateMetricAsync(db, email, "memory", memMb,   thresholds.MemoryWarningMb,
            $"Memory usage {memMb:F0} MB exceeds threshold {thresholds.MemoryWarningMb} MB", ct);

        var diskFreePct = 100 - diskPct;
        if (thresholds.DiskFreeWarningPct > 0 && diskFreePct < thresholds.DiskFreeWarningPct)
        {
            await EvaluateMetricAsync(db, email, "disk", diskFreePct, thresholds.DiskFreeWarningPct,
                $"Disk free space {diskFreePct:F1}% below threshold {thresholds.DiskFreeWarningPct}%", ct);
        }

        // Alarm on service down
        foreach (var (name, healthy, _) in services)
        {
            if (!healthy)
            {
                var key = "service_" + name.Replace(" ", "_").ToLower();
                await EvaluateMetricAsync(db, email, key, 0, 1,
                    $"Proxy service '{name}' is unreachable", ct);
            }
        }

        await db.SaveChangesAsync(ct);
    }

    private async Task EvaluateMetricAsync(OrkunPamDbContext db, IEmailService email,
        string metricName, double value, double threshold, string message, CancellationToken ct)
    {
        if (value <= threshold) return;
        if (_lastAlarmAt.TryGetValue(metricName, out var last) && DateTime.UtcNow - last < AlarmCooldown)
            return;

        _lastAlarmAt[metricName] = DateTime.UtcNow;

        var alarm = new SystemAlarmLog
        {
            MetricName   = metricName,
            MetricValue  = value,
            Threshold    = threshold,
            Message      = message,
            Severity     = value > threshold * 1.5 ? "Critical" : "Warning",
            Status       = "Active"
        };
        db.SystemAlarmLogs.Add(alarm);

        // Send email notification
        var adminEmails = await db.SystemConfigs
            .Where(c => c.Key == "health.alarm.recipients")
            .Select(c => c.Value)
            .FirstOrDefaultAsync(ct);

        if (!string.IsNullOrEmpty(adminEmails))
        {
            foreach (var recipient in adminEmails.Split(';', StringSplitOptions.RemoveEmptyEntries))
            {
                alarm.EmailSent = await email.SendAsync(
                    recipient.Trim(),
                    $"[OrkunPAM ALARM] {alarm.Severity}: {metricName}",
                    $"<h3>OrkunPAM System Alarm</h3><p><b>Severity:</b> {alarm.Severity}</p>" +
                    $"<p><b>Metric:</b> {metricName}</p>" +
                    $"<p><b>Message:</b> {message}</p>" +
                    $"<p><b>Time:</b> {DateTime.UtcNow:yyyy-MM-dd HH:mm:ss} UTC</p>",
                    ct);
            }
        }

        _logger.LogWarning("Health alarm [{Severity}] {Metric}: {Message}", alarm.Severity, metricName, message);
    }

    private double MeasureCpuPercent()
    {
        try
        {
            var proc     = Process.GetCurrentProcess();
            var now      = DateTime.UtcNow;
            var cpuNow   = proc.TotalProcessorTime;

            if (_previousMeasureAt == DateTime.MinValue)
            {
                _previousCpuTime   = cpuNow;
                _previousMeasureAt = now;
                return 0;
            }

            var elapsed  = (now - _previousMeasureAt).TotalSeconds;
            var cpuUsed  = (cpuNow - _previousCpuTime).TotalSeconds;
            _previousCpuTime   = cpuNow;
            _previousMeasureAt = now;

            if (elapsed <= 0) return 0;
            var pct = cpuUsed / (elapsed * Environment.ProcessorCount) * 100.0;
            return Math.Min(100, Math.Round(pct, 1));
        }
        catch { return 0; }
    }

    private static double MeasureMemoryMb()
    {
        try
        {
            var info = GC.GetGCMemoryInfo();
            var usedBytes = info.HeapSizeBytes;
            var ws = Process.GetCurrentProcess().WorkingSet64;
            return Math.Round(Math.Max(usedBytes, ws) / (1024.0 * 1024.0), 1);
        }
        catch { return 0; }
    }

    private static double MeasureDiskPercent()
    {
        try
        {
            var appDir = AppContext.BaseDirectory;
            var drive  = new DriveInfo(Path.GetPathRoot(appDir) ?? "/");
            if (drive.TotalSize == 0) return 0;
            return Math.Round((1.0 - (double)drive.AvailableFreeSpace / drive.TotalSize) * 100, 1);
        }
        catch { return 0; }
    }

    private static async Task<List<(string Name, bool Healthy, int LatencyMs)>> CheckProxyServicesAsync(CancellationToken ct)
    {
        var results = new List<(string, bool, int)>();
        foreach (var (name, host, port) in ProxyServices)
        {
            var sw = Stopwatch.StartNew();
            bool healthy;
            try
            {
                using var tcp = new TcpClient();
                var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(2));
                await tcp.ConnectAsync(host, port, cts.Token);
                healthy = tcp.Connected;
            }
            catch { healthy = false; }
            sw.Stop();
            results.Add((name, healthy, (int)sw.ElapsedMilliseconds));
        }
        return results;
    }

    private static async Task<(double CpuWarningPct, double MemoryWarningMb, double DiskFreeWarningPct)>
        LoadThresholdsAsync(OrkunPamDbContext db, CancellationToken ct)
    {
        var keys = new[] { "health.cpu.warn_pct", "health.mem.warn_mb", "health.disk.free_warn_pct" };
        var configs = await db.SystemConfigs
            .Where(c => keys.Contains(c.Key))
            .ToDictionaryAsync(c => c.Key, c => c.Value ?? string.Empty, ct);

        double cpuPct  = double.TryParse(configs.GetValueOrDefault("health.cpu.warn_pct"),  out var c) ? c : 80;
        double memMb   = double.TryParse(configs.GetValueOrDefault("health.mem.warn_mb"),   out var m) ? m : 2048;
        double diskPct = double.TryParse(configs.GetValueOrDefault("health.disk.free_warn_pct"), out var d) ? d : 10;
        return (cpuPct, memMb, diskPct);
    }

    // Public helper so the API endpoint can collect current metrics on demand
    public static async Task<SystemHealthSnapshot> CollectSnapshotAsync(
        OrkunPamDbContext db, CancellationToken ct = default)
    {
        var services = await CheckProxyServicesAsync(ct);
        var memMb    = MeasureMemoryMb();
        var diskPct  = MeasureDiskPercent();

        var recentAlarms = await db.SystemAlarmLogs
            .OrderByDescending(a => a.OccurredAtUtc)
            .Take(50)
            .Select(a => new SystemAlarmDto(a.Id, a.OccurredAtUtc, a.MetricName,
                a.Severity, a.MetricValue, a.Threshold, a.Message, a.Status, a.EmailSent))
            .ToListAsync(ct);

        return new SystemHealthSnapshot(
            CpuPercent:   0,
            MemoryMb:     memMb,
            DiskPercent:  diskPct,
            Services:     services.Select(s => new ProxyServiceStatus(s.Name, s.Healthy, s.LatencyMs)).ToList(),
            RecentAlarms: recentAlarms
        );
    }
}

public record SystemHealthSnapshot(
    double CpuPercent,
    double MemoryMb,
    double DiskPercent,
    List<ProxyServiceStatus> Services,
    List<SystemAlarmDto> RecentAlarms);

public record ProxyServiceStatus(string Name, bool Healthy, int LatencyMs);

public record SystemAlarmDto(
    long Id, DateTime OccurredAtUtc, string MetricName,
    string Severity, double MetricValue, double Threshold,
    string Message, string Status, bool EmailSent);
