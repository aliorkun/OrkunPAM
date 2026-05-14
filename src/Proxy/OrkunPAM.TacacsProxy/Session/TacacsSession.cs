using System.Net.Sockets;
using OrkunPAM.TacacsProxy.Protocol;

namespace OrkunPAM.TacacsProxy.Session;

/// <summary>
/// Handles a single TACACS+ client connection.
/// Supports Authentication (ASCII/PAP), Authorization (cmd), and Accounting.
/// </summary>
internal sealed class TacacsSession
{
    private readonly TcpClient _client;
    private readonly PamApiClient _api;
    private readonly TacacsProxyOptions _opts;
    private readonly ILogger _log;
    private readonly CancellationToken _ct;
    private readonly string _deviceIp;
    private readonly string _sharedSecret;

    private static readonly TimeSpan ReadTimeout = TimeSpan.FromSeconds(30);

    public TacacsSession(
        TcpClient client,
        PamApiClient api,
        TacacsProxyOptions opts,
        ILogger log,
        CancellationToken ct)
    {
        _client = client;
        _api    = api;
        _opts   = opts;
        _log    = log;
        _ct     = ct;

        _deviceIp     = ((System.Net.IPEndPoint?)client.Client.RemoteEndPoint)?.Address.ToString() ?? "unknown";
        _sharedSecret = ResolveSecret(_deviceIp);
    }

    public async Task RunAsync()
    {
        using var stream = _client.GetStream();
        try
        {
            while (!_ct.IsCancellationRequested && _client.Connected)
            {
                var header = await ReadHeaderAsync(stream);
                if (header is null) break;

                var body = await ReadBodyAsync(stream, header.Length);

                if (header.IsEncrypted && !string.IsNullOrEmpty(_sharedSecret))
                    body = TacacsCrypto.Crypt(body, header.SessionId, _sharedSecret, header.Version, header.SeqNo);

                switch (header.Type)
                {
                    case TacacsHeader.TypeAuthentication:
                        await HandleAuthenticationAsync(stream, header, body);
                        break;
                    case TacacsHeader.TypeAuthorization:
                        await HandleAuthorizationAsync(stream, header, body);
                        break;
                    case TacacsHeader.TypeAccounting:
                        await HandleAccountingAsync(stream, header, body);
                        break;
                    default:
                        _log.LogWarning("[{DeviceIp}] Unknown TACACS+ packet type {Type}", _deviceIp, header.Type);
                        break;
                }
            }
        }
        catch (OperationCanceledException) { }
        catch (TacacsProtocolException ex)
        {
            _log.LogWarning("[{DeviceIp}] Protocol error: {Msg}", _deviceIp, ex.Message);
        }
        catch (IOException ex) when (ex.InnerException is SocketException)
        {
            // Client disconnected — normal
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "[{DeviceIp}] Unexpected error in TACACS+ session", _deviceIp);
        }
    }

    private async Task HandleAuthenticationAsync(
        NetworkStream stream, TacacsHeader reqHeader, byte[] body)
    {
        var start = AuthenStartPacket.Parse(body);
        _log.LogInformation("[{DeviceIp}] AUTHEN START user={User} type={Type} service={Svc}",
            _deviceIp, start.User, start.AuthenType, start.AuthenService);

        string username = start.User;
        string password;

        if (start.AuthenType == AuthenType.Pap)
        {
            password = System.Text.Encoding.UTF8.GetString(start.Data);
            var ok = await _api.ValidateCredentialAsync(username, password, _deviceIp, _ct);
            password = string.Empty;
            await SendAuthReplyAsync(stream, reqHeader,
                ok ? AuthenStatus.Pass : AuthenStatus.Fail,
                ok ? "Authentication successful" : "Authentication failed");
            _log.LogInformation("[{DeviceIp}] AUTHEN PAP result={Result} user={User}",
                _deviceIp, ok ? "PASS" : "FAIL", username);
        }
        else
        {
            if (string.IsNullOrEmpty(username))
            {
                var getUser = new AuthenReplyPacket
                {
                    Status    = AuthenStatus.Getuser,
                    ServerMsg = "Username: "
                };
                await SendRawReplyAsync(stream, reqHeader, getUser.Serialize());

                var contHeader = await ReadHeaderAsync(stream);
                if (contHeader is null) return;
                var contBody = await ReadBodyAsync(stream, contHeader.Length);
                if (contHeader.IsEncrypted && !string.IsNullOrEmpty(_sharedSecret))
                    contBody = TacacsCrypto.Crypt(contBody, contHeader.SessionId, _sharedSecret, contHeader.Version, contHeader.SeqNo);

                var cont = AuthenContinuePacket.Parse(contBody);
                if (cont.IsAbort) return;
                username = cont.UserMsg;
                reqHeader = contHeader;
            }

            var getPass = new AuthenReplyPacket
            {
                Status    = AuthenStatus.Getpass,
                Flags     = AuthenReplyFlag.Noecho,
                ServerMsg = "Password: "
            };
            await SendRawReplyAsync(stream, reqHeader, getPass.Serialize());

            var passHeader = await ReadHeaderAsync(stream);
            if (passHeader is null) return;
            var passBody = await ReadBodyAsync(stream, passHeader.Length);
            if (passHeader.IsEncrypted && !string.IsNullOrEmpty(_sharedSecret))
                passBody = TacacsCrypto.Crypt(passBody, passHeader.SessionId, _sharedSecret, passHeader.Version, passHeader.SeqNo);

            var passCont = AuthenContinuePacket.Parse(passBody);
            if (passCont.IsAbort) return;
            password = passCont.UserMsg;

            var authenticated = await _api.ValidateCredentialAsync(username, password, _deviceIp, _ct);
            password = string.Empty;

            // Optional MFA TOTP second factor
            if (authenticated && _opts.EnableMfaTotp)
            {
                var otpPrompt = new AuthenReplyPacket
                {
                    Status    = AuthenStatus.Getdata,
                    ServerMsg = "OTP Code: "
                };
                await SendRawReplyAsync(stream, passHeader, otpPrompt.Serialize());

                var otpHeader = await ReadHeaderAsync(stream);
                if (otpHeader is null) return;
                var otpBody = await ReadBodyAsync(stream, otpHeader.Length);
                if (otpHeader.IsEncrypted && !string.IsNullOrEmpty(_sharedSecret))
                    otpBody = TacacsCrypto.Crypt(otpBody, otpHeader.SessionId, _sharedSecret, otpHeader.Version, otpHeader.SeqNo);

                var otpCont = AuthenContinuePacket.Parse(otpBody);
                if (otpCont.IsAbort) return;

                authenticated = await _api.VerifyTotpAsync(username, otpCont.UserMsg, _ct);
                passHeader    = otpHeader;
            }

            await SendAuthReplyAsync(stream, passHeader,
                authenticated ? AuthenStatus.Pass : AuthenStatus.Fail,
                authenticated ? "Authentication successful" : "Authentication failed");

            _log.LogInformation("[{DeviceIp}] AUTHEN ASCII result={Result} user={User}",
                _deviceIp, authenticated ? "PASS" : "FAIL", username);
        }
    }

    private Task SendAuthReplyAsync(
        NetworkStream stream, TacacsHeader req, byte status, string msg)
    {
        var reply = new AuthenReplyPacket { Status = status, ServerMsg = msg };
        return SendRawReplyAsync(stream, req, reply.Serialize());
    }

    private async Task HandleAuthorizationAsync(
        NetworkStream stream, TacacsHeader reqHeader, byte[] body)
    {
        var req = AuthorRequestPacket.Parse(body);
        var cmd = req.GetArgValue("cmd") ?? string.Empty;

        _log.LogInformation("[{DeviceIp}] AUTHOR REQUEST user={User} cmd={Cmd} priv={Priv}",
            _deviceIp, req.User, cmd, req.PrivLvl);

        bool permitted = _opts.CommandAuthorizationMode switch
        {
            "PermitAll" => true,
            "DenyAll"   => false,
            "Policy"    => await _api.AuthorizeCommandAsync(req.User, cmd, _deviceIp, _ct),
            _           => true
        };

        var reply = new AuthorResponsePacket
        {
            Status    = permitted ? AuthorStatus.PassAdd : AuthorStatus.Fail,
            ServerMsg = permitted ? string.Empty : "Command not permitted by policy"
        };

        await SendRawReplyAsync(stream, reqHeader, reply.Serialize(), TacacsHeader.TypeAuthorization);
        _log.LogInformation("[{DeviceIp}] AUTHOR result={Result} user={User} cmd={Cmd}",
            _deviceIp, permitted ? "PERMIT" : "DENY", req.User, cmd);
    }

    private async Task HandleAccountingAsync(
        NetworkStream stream, TacacsHeader reqHeader, byte[] body)
    {
        var req = AcctRequestPacket.Parse(body);
        var cmd = req.GetArgValue("cmd") ?? string.Empty;
        var eventType = req.IsStart ? "START" : req.IsStop ? "STOP" : "WATCHDOG";

        _log.LogInformation("[{DeviceIp}] ACCT {Event} user={User} cmd={Cmd}",
            _deviceIp, eventType, req.User, cmd);

        await _api.SendAccountingAsync(req.User, _deviceIp, cmd, eventType, req.Port, _ct);

        var reply = new AcctReplyPacket { Status = AcctStatus.Success };
        await SendRawReplyAsync(stream, reqHeader, reply.Serialize(), TacacsHeader.TypeAccounting);
    }

    private async Task<TacacsHeader?> ReadHeaderAsync(NetworkStream stream)
    {
        var buf = new byte[TacacsHeader.Size];
        int read = await ReadExactAsync(stream, buf, 0, TacacsHeader.Size);
        if (read == 0) return null;
        return TacacsHeader.Parse(buf);
    }

    private async Task<byte[]> ReadBodyAsync(NetworkStream stream, int length)
    {
        if (length == 0) return Array.Empty<byte>();
        var buf = new byte[length];
        await ReadExactAsync(stream, buf, 0, length);
        return buf;
    }

    private async Task<int> ReadExactAsync(NetworkStream stream, byte[] buf, int offset, int count)
    {
        int total = 0;
        using var cts = CancellationTokenSource.CreateLinkedTokenSource(_ct);
        cts.CancelAfter(ReadTimeout);

        while (total < count)
        {
            int n = await stream.ReadAsync(buf.AsMemory(offset + total, count - total), cts.Token);
            if (n == 0) return total;
            total += n;
        }
        return total;
    }

    private async Task SendRawReplyAsync(
        NetworkStream stream, TacacsHeader reqHeader, byte[] bodyPlain,
        byte? overrideType = null)
    {
        byte replySeq = (byte)(reqHeader.SeqNo + 1);
        var replyHeader = new TacacsHeader
        {
            Version   = reqHeader.Version,
            Type      = overrideType ?? reqHeader.Type,
            SeqNo     = replySeq,
            Flags     = reqHeader.Flags,
            SessionId = reqHeader.SessionId,
            Length    = bodyPlain.Length
        };

        byte[] encBody = bodyPlain;
        if (replyHeader.IsEncrypted && !string.IsNullOrEmpty(_sharedSecret))
            encBody = TacacsCrypto.Crypt(bodyPlain, reqHeader.SessionId, _sharedSecret, reqHeader.Version, replySeq);

        var packet = new byte[TacacsHeader.Size + encBody.Length];
        replyHeader.WriteTo(packet);
        encBody.CopyTo(packet, TacacsHeader.Size);

        await stream.WriteAsync(packet.AsMemory(), _ct);
        await stream.FlushAsync(_ct);
    }

    private string ResolveSecret(string deviceIp)
        => CidrMatcher.Resolve(deviceIp, _opts.SharedSecrets) ?? _opts.DefaultSharedSecret;
}
