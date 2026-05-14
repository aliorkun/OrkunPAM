using System.Net;
using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Text;
using System.Threading.Channels;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Persistence.Services;

/// <summary>
/// Background service that subscribes to domain events via IEventBus and forwards them
/// to one or more SIEM targets using Syslog (RFC 5424) with optional CEF payload.
/// Supports UDP, TCP, and TLS transport. Includes internal buffering via Channel&lt;T&gt;
/// and automatic reconnection for TCP/TLS connections.
/// </summary>
public sealed class SyslogForwarderService : BackgroundService
{
    private readonly InProcessEventBus _eventBus;
    private readonly ILogger<SyslogForwarderService> _logger;
    private readonly List<SiemTarget> _targets;
    private readonly Channel<IDomainEvent> _buffer;
    private readonly bool _useCef;

    public SyslogForwarderService(
        InProcessEventBus eventBus,
        IConfiguration configuration,
        ILogger<SyslogForwarderService> logger)
    {
        _eventBus = eventBus;
        _logger = logger;

        // Parse configuration
        var section = configuration.GetSection("Siem");
        var useCefStr = section["UseCef"];
        _useCef = string.IsNullOrEmpty(useCefStr) || !bool.TryParse(useCefStr, out var parsed) || parsed;

        _targets = section.GetSection("Targets").GetChildren()
            .Select(t => new SiemTarget
            {
                Host = t["Host"] ?? "127.0.0.1",
                Port = int.TryParse(t["Port"], out var p) ? p : 514,
                Protocol = Enum.TryParse<SyslogProtocol>(t["Protocol"], true, out var proto) ? proto : SyslogProtocol.Udp,
                TlsServerName = t["TlsServerName"]
            })
            .ToList();

        // Internal buffer for reliability — events are queued here before forwarding
        _buffer = Channel.CreateBounded<IDomainEvent>(new BoundedChannelOptions(50_000)
        {
            FullMode = BoundedChannelFullMode.DropOldest,
            SingleReader = true,
            SingleWriter = true
        });
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (_targets.Count == 0)
        {
            _logger.LogWarning("SyslogForwarder: No SIEM targets configured. Service will not start. " +
                               "Configure targets in Siem:Targets section.");
            return;
        }

        _logger.LogInformation("SyslogForwarder starting with {TargetCount} target(s), CEF={UseCef}",
            _targets.Count, _useCef);

        // Subscribe to the event bus — push events into our internal buffer
        _eventBus.Subscribe(async (evt, ct) =>
        {
            if (!_buffer.Writer.TryWrite(evt))
            {
                _logger.LogWarning("SyslogForwarder buffer full, dropping oldest event. EventType={EventType}",
                    evt.EventType);
            }
            await Task.CompletedTask;
        });

        // Initialize transport connections for each target
        var transports = new List<SiemTransport>();
        foreach (var target in _targets)
        {
            transports.Add(new SiemTransport(target, _logger));
        }

        try
        {
            await foreach (var domainEvent in _buffer.Reader.ReadAllAsync(stoppingToken))
            {
                var message = FormatMessage(domainEvent);
                var messageBytes = Encoding.UTF8.GetBytes(message);

                foreach (var transport in transports)
                {
                    try
                    {
                        await transport.SendAsync(messageBytes, stoppingToken);
                    }
                    catch (Exception ex) when (ex is not OperationCanceledException)
                    {
                        _logger.LogError(ex, "SyslogForwarder: Failed to send to {Host}:{Port} via {Protocol}",
                            transport.Target.Host, transport.Target.Port, transport.Target.Protocol);
                    }
                }
            }
        }
        finally
        {
            foreach (var transport in transports)
            {
                transport.Dispose();
            }
            _logger.LogInformation("SyslogForwarder stopped");
        }
    }

    private string FormatMessage(IDomainEvent domainEvent)
    {
        if (_useCef)
        {
            // Syslog header wrapping a CEF payload
            var cef = CefFormatter.Format(domainEvent);
            return SyslogFormatter.Format(domainEvent, cef);
        }

        // Plain syslog with structured data
        return SyslogFormatter.Format(domainEvent);
    }
}

/// <summary>
/// Syslog transport protocol.
/// </summary>
public enum SyslogProtocol
{
    Udp,
    Tcp,
    Tls
}

/// <summary>
/// Configuration for a single SIEM target.
/// </summary>
public sealed class SiemTarget
{
    public string Host { get; init; } = "127.0.0.1";
    public int Port { get; init; } = 514;
    public SyslogProtocol Protocol { get; init; } = SyslogProtocol.Udp;
    /// <summary>
    /// TLS server name for certificate validation. If null, Host is used.
    /// </summary>
    public string? TlsServerName { get; init; }
}

/// <summary>
/// Manages a single transport connection to a SIEM target.
/// Handles UDP (stateless), TCP (persistent with reconnect), and TLS (persistent with reconnect).
/// </summary>
internal sealed class SiemTransport : IDisposable
{
    public SiemTarget Target { get; }
    private readonly ILogger _logger;

    // UDP
    private UdpClient? _udpClient;
    private IPEndPoint? _udpEndpoint;

    // TCP / TLS
    private TcpClient? _tcpClient;
    private Stream? _stream;
    private readonly SemaphoreSlim _connectLock = new(1, 1);

    private static readonly TimeSpan ReconnectDelay = TimeSpan.FromSeconds(5);
    private const int MaxReconnectAttempts = 3;
    private static readonly byte[] OctetFramingNewline = "\n"u8.ToArray();

    public SiemTransport(SiemTarget target, ILogger logger)
    {
        Target = target;
        _logger = logger;
    }

    public async Task SendAsync(byte[] message, CancellationToken ct)
    {
        switch (Target.Protocol)
        {
            case SyslogProtocol.Udp:
                await SendUdpAsync(message, ct);
                break;
            case SyslogProtocol.Tcp:
            case SyslogProtocol.Tls:
                await SendTcpAsync(message, ct);
                break;
        }
    }

    private async Task SendUdpAsync(byte[] message, CancellationToken ct)
    {
        if (_udpClient == null)
        {
            _udpClient = new UdpClient();
            var addresses = await Dns.GetHostAddressesAsync(Target.Host, ct);
            _udpEndpoint = new IPEndPoint(addresses[0], Target.Port);
            _logger.LogInformation("SyslogForwarder: UDP endpoint resolved for {Host}:{Port}", Target.Host, Target.Port);
        }

        await _udpClient.SendAsync(message, _udpEndpoint!, ct);
    }

    private async Task SendTcpAsync(byte[] message, CancellationToken ct)
    {
        // Ensure connection is established
        await EnsureConnectedAsync(ct);

        if (_stream == null)
        {
            _logger.LogWarning("SyslogForwarder: No active stream for {Host}:{Port}, message dropped", Target.Host, Target.Port);
            return;
        }

        try
        {
            // RFC 5425 octet-counting: prepend message length for TLS,
            // or use newline-delimited framing for plain TCP (more common for syslog)
            if (Target.Protocol == SyslogProtocol.Tls)
            {
                // Octet counting: "LEN SP MSG"
                var header = Encoding.ASCII.GetBytes($"{message.Length} ");
                await _stream.WriteAsync(header, ct);
                await _stream.WriteAsync(message, ct);
            }
            else
            {
                // Newline-delimited (non-transparent framing)
                await _stream.WriteAsync(message, ct);
                await _stream.WriteAsync(OctetFramingNewline, ct);
            }

            await _stream.FlushAsync(ct);
        }
        catch (Exception ex) when (ex is IOException or SocketException or ObjectDisposedException)
        {
            _logger.LogWarning(ex, "SyslogForwarder: Connection lost to {Host}:{Port}, will reconnect on next send",
                Target.Host, Target.Port);
            DisconnectTcp();
        }
    }

    private async Task EnsureConnectedAsync(CancellationToken ct)
    {
        if (_tcpClient?.Connected == true && _stream != null)
            return;

        await _connectLock.WaitAsync(ct);
        try
        {
            // Double-check after acquiring lock
            if (_tcpClient?.Connected == true && _stream != null)
                return;

            DisconnectTcp();

            for (var attempt = 1; attempt <= MaxReconnectAttempts; attempt++)
            {
                try
                {
                    _tcpClient = new TcpClient();
                    _tcpClient.SendTimeout = 10_000;
                    _tcpClient.ReceiveTimeout = 10_000;

                    await _tcpClient.ConnectAsync(Target.Host, Target.Port, ct);

                    if (Target.Protocol == SyslogProtocol.Tls)
                    {
                        var sslStream = new SslStream(_tcpClient.GetStream(), leaveInnerStreamOpen: false);
                        var sslOptions = new SslClientAuthenticationOptions
                        {
                            TargetHost = Target.TlsServerName ?? Target.Host,
                            EnabledSslProtocols = SslProtocols.Tls12 | SslProtocols.Tls13
                        };
                        await sslStream.AuthenticateAsClientAsync(sslOptions, ct);
                        _stream = sslStream;

                        _logger.LogInformation("SyslogForwarder: TLS connection established to {Host}:{Port} (protocol: {SslProtocol})",
                            Target.Host, Target.Port, sslStream.SslProtocol);
                    }
                    else
                    {
                        _stream = _tcpClient.GetStream();
                        _logger.LogInformation("SyslogForwarder: TCP connection established to {Host}:{Port}",
                            Target.Host, Target.Port);
                    }

                    return; // Connected successfully
                }
                catch (Exception ex) when (ex is not OperationCanceledException)
                {
                    _logger.LogWarning(ex, "SyslogForwarder: Connection attempt {Attempt}/{Max} to {Host}:{Port} failed",
                        attempt, MaxReconnectAttempts, Target.Host, Target.Port);

                    DisconnectTcp();

                    if (attempt < MaxReconnectAttempts)
                        await Task.Delay(ReconnectDelay * attempt, ct);
                }
            }

            _logger.LogError("SyslogForwarder: All {Max} connection attempts to {Host}:{Port} failed",
                MaxReconnectAttempts, Target.Host, Target.Port);
        }
        finally
        {
            _connectLock.Release();
        }
    }

    private void DisconnectTcp()
    {
        try { _stream?.Dispose(); } catch { /* best effort */ }
        try { _tcpClient?.Dispose(); } catch { /* best effort */ }
        _stream = null;
        _tcpClient = null;
    }

    public void Dispose()
    {
        _udpClient?.Dispose();
        DisconnectTcp();
        _connectLock.Dispose();
    }
}
