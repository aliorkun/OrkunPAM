using System.Net;
using System.Net.Sockets;
using Microsoft.Extensions.Options;
using OrkunPAM.TacacsProxy.Protocol;

namespace OrkunPAM.TacacsProxy;

/// <summary>
/// UDP RADIUS server per RFC 2865 (authentication) and RFC 2866 (accounting).
/// Listens on :1812 (auth) and :1813 (accounting), delegating to PamApiClient.
/// </summary>
internal sealed class RadiusProxyService : BackgroundService
{
    private readonly ILogger<RadiusProxyService> _log;
    private readonly TacacsProxyOptions          _opts;
    private readonly PamApiClient                _api;

    public RadiusProxyService(
        ILogger<RadiusProxyService> log,
        IOptions<TacacsProxyOptions> opts,
        PamApiClient api)
    {
        _log  = log;
        _opts = opts.Value;
        _api  = api;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        if (!_opts.RadiusEnabled)
        {
            _log.LogInformation("RADIUS proxy disabled — set TacacsProxy:RadiusEnabled=true to enable");
            return;
        }

        if (string.IsNullOrEmpty(_opts.DefaultSharedSecret))
        {
            _log.LogError("DefaultSharedSecret not configured. RADIUS proxy cannot start securely.");
            return;
        }

        _log.LogInformation("RADIUS proxy starting — auth UDP:{AuthPort}, acct UDP:{AcctPort}",
            _opts.RadiusAuthPort, _opts.RadiusAcctPort);

        using var authSocket = new UdpClient(new IPEndPoint(IPAddress.Any, _opts.RadiusAuthPort));
        using var acctSocket = new UdpClient(new IPEndPoint(IPAddress.Any, _opts.RadiusAcctPort));

        try
        {
            await Task.WhenAll(
                UdpLoopAsync(authSocket, isAccounting: false, stoppingToken),
                UdpLoopAsync(acctSocket, isAccounting: true,  stoppingToken));
        }
        finally
        {
            _log.LogInformation("RADIUS proxy stopped");
        }
    }

    private async Task UdpLoopAsync(UdpClient socket, bool isAccounting, CancellationToken ct)
    {
        while (!ct.IsCancellationRequested)
        {
            UdpReceiveResult result;
            try
            {
                result = await socket.ReceiveAsync(ct);
            }
            catch (OperationCanceledException) { break; }
            catch (Exception ex)
            {
                _log.LogWarning(ex, "RADIUS receive error on {Port}",
                    isAccounting ? _opts.RadiusAcctPort : _opts.RadiusAuthPort);
                continue;
            }

            // Fire-and-forget per packet (UDP is connectionless)
            _ = Task.Run(() => HandlePacketAsync(socket, result, isAccounting, ct), ct);
        }
    }

    private async Task HandlePacketAsync(
        UdpClient socket, UdpReceiveResult result, bool isAccounting, CancellationToken ct)
    {
        var remote   = result.RemoteEndPoint;
        var clientIp = remote.Address.ToString();

        var pkt = RadiusPacket.TryParse(result.Buffer);
        if (pkt == null)
        {
            _log.LogWarning("[RADIUS] Malformed packet from {Ip}", clientIp);
            return;
        }

        var secret = CidrMatcher.Resolve(clientIp, _opts.SharedSecrets) ?? _opts.DefaultSharedSecret;

        if (isAccounting)
        {
            await HandleAccountingAsync(socket, pkt, remote, clientIp, secret, ct);
            return;
        }

        await HandleAuthAsync(socket, pkt, remote, clientIp, secret, ct);
    }

    private async Task HandleAuthAsync(
        UdpClient socket, RadiusPacket pkt, IPEndPoint remote,
        string clientIp, string secret, CancellationToken ct)
    {
        if (pkt.Code != RadiusCode.AccessRequest)
        {
            _log.LogWarning("[RADIUS] Unexpected code {Code} from {Ip}", pkt.Code, clientIp);
            return;
        }

        var username = pkt.GetString(RadiusAttr.UserName);
        var password = pkt.DecryptPassword(secret, pkt.Authenticator);

        if (string.IsNullOrEmpty(username) || password == null)
        {
            _log.LogWarning("[RADIUS] Missing credentials in Access-Request from {Ip}", clientIp);
            var reject = pkt.BuildResponse(RadiusCode.AccessReject, secret, "Missing credentials");
            await SendAsync(socket, reject, remote, ct);
            return;
        }

        var ok = await _api.ValidateCredentialAsync(username, password, clientIp, ct);
        password = string.Empty;

        _log.LogInformation("[RADIUS] Auth {Result} user={User} nas={Ip}",
            ok ? "ACCEPT" : "REJECT", username, clientIp);

        var resp = pkt.BuildResponse(
            ok ? RadiusCode.AccessAccept : RadiusCode.AccessReject,
            secret,
            ok ? null : "Authentication failed");

        await SendAsync(socket, resp, remote, ct);
    }

    private async Task HandleAccountingAsync(
        UdpClient socket, RadiusPacket pkt, IPEndPoint remote,
        string clientIp, string secret, CancellationToken ct)
    {
        if (pkt.Code != RadiusCode.AccountingRequest) return;

        var username = pkt.GetString(RadiusAttr.UserName) ?? "";
        _log.LogInformation("[RADIUS] Accounting from {Ip} user={User}", clientIp, username);

        await _api.SendAccountingAsync(username, clientIp, "", "RADIUS-ACCT", "", ct);

        var resp = pkt.BuildAccountingResponse(secret);
        await SendAsync(socket, resp, remote, ct);
    }

    private static async Task SendAsync(
        UdpClient socket, byte[] data, IPEndPoint remote, CancellationToken ct)
    {
        try { await socket.SendAsync(data, remote, ct); }
        catch (Exception ex) when (ex is not OperationCanceledException)
        {
            // UDP send failures are non-fatal
        }
    }
}
