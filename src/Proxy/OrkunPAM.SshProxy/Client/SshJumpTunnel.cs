using System.IO.Pipelines;
using System.Net.Sockets;
using System.Security.Cryptography;
using OrkunPAM.SshProxy.Protocol;

namespace OrkunPAM.SshProxy.Client;

/// <summary>
/// Opens an SSH direct-tcpip channel through a jump host to reach a target
/// in a segmented network zone. Used for SSH ProxyJump routing (RA #8).
/// </summary>
internal sealed class SshJumpTunnel : IDisposable
{
    private readonly string _jumpHost;
    private readonly int _jumpPort;
    private readonly string _jumpUser;
    private readonly byte[] _jumpPassword;
    private readonly string? _jumpHostFingerprint;
    private readonly ILogger _log;
    private SshTargetClient? _jumpClient;
    private SshChannelStream? _channelStream;

    internal string? ObservedFingerprint => _jumpClient?.ObservedFingerprint;

    internal SshJumpTunnel(string jumpAddress, string jumpUser, byte[] jumpPassword,
        string? jumpHostFingerprint, ILogger log)
    {
        var parts = jumpAddress.Split(':');
        _jumpHost = parts[0];
        _jumpPort = parts.Length > 1 && int.TryParse(parts[1], out var p) ? p : 22;
        _jumpUser = jumpUser;
        _jumpPassword = jumpPassword;
        _jumpHostFingerprint = jumpHostFingerprint;
        _log = log;
    }

    /// <summary>Connects to jump host and opens a direct-tcpip channel to target. Returns the tunnel stream.</summary>
    internal async Task<Stream> OpenAsync(string targetHost, int targetPort, CancellationToken ct)
    {
        _log.LogInformation("Opening SSH jump tunnel: {JumpHost}:{JumpPort} → {TargetHost}:{TargetPort}",
            _jumpHost, _jumpPort, targetHost, targetPort);

        _jumpClient = new SshTargetClient(_jumpHost, _jumpPort, _jumpUser, _jumpPassword, null, _log,
            expectedFingerprint: _jumpHostFingerprint);
        await _jumpClient.ConnectAsync(ct);

        _channelStream = await _jumpClient.OpenDirectTcpipChannelAsync(targetHost, targetPort, ct);
        _log.LogInformation("Jump tunnel established to {TargetHost}:{TargetPort} via {JumpHost}", targetHost, targetPort, _jumpHost);
        return _channelStream;
    }

    public void Dispose()
    {
        _channelStream?.Dispose();
        _jumpClient?.Dispose();
    }
}

/// <summary>
/// Stream wrapper for an SSH direct-tcpip channel. Reads SSH_MSG_CHANNEL_DATA
/// packets and writes data back as SSH_MSG_CHANNEL_DATA via the jump SSH connection.
/// </summary>
internal sealed class SshChannelStream : Stream
{
    private readonly SshConnection _conn;
    private readonly uint _srvChan;
    private readonly uint _cliChan;
    private readonly Pipe _pipe = new(new PipeOptions(pauseWriterThreshold: 4 * 1024 * 1024));
    private readonly CancellationTokenSource _cts = new();
    private int _localWindow = 2 * 1024 * 1024;

    internal SshChannelStream(SshConnection conn, uint srvChan, uint cliChan)
    {
        _conn = conn;
        _srvChan = srvChan;
        _cliChan = cliChan;
        _ = Task.Run(ReadLoopAsync);
    }

    private async Task ReadLoopAsync()
    {
        try
        {
            while (!_cts.IsCancellationRequested)
            {
                var pkt = await _conn.ReadPacketAsync(_cts.Token);

                if (pkt[0] == Msg.ChannelData)
                {
                    int pos = 1;
                    _ = SshEncoding.ReadUInt32(pkt, ref pos); // recipient channel
                    var data = SshEncoding.ReadByteString(pkt, ref pos);
                    await _pipe.Writer.WriteAsync(data.AsMemory(), _cts.Token);
                    await _pipe.Writer.FlushAsync(_cts.Token);

                    _localWindow -= data.Length;
                    if (_localWindow < 512 * 1024)
                    {
                        uint inc = (uint)(2 * 1024 * 1024 - _localWindow);
                        _localWindow += (int)inc;
                        using var adj = new MemoryStream();
                        SshEncoding.WriteByte(adj, Msg.ChannelWinAdj);
                        SshEncoding.WriteUInt32(adj, _srvChan);
                        SshEncoding.WriteUInt32(adj, inc);
                        await _conn.SendAsync(adj, _cts.Token);
                    }
                }
                else if (pkt[0] == Msg.ChannelWinAdj)
                {
                    // remote window adjust — no-op for now (single-channel, no flow control needed)
                }
                else if (pkt[0] is Msg.ChannelEof or Msg.ChannelClose)
                {
                    break;
                }
                // Ignore Msg.GlobalRequest, Msg.Debug, etc.
            }
        }
        catch (OperationCanceledException) { }
        catch (Exception ex) when (ex is not OutOfMemoryException)
        {
            // Channel closed or SSH error — signal EOF to reader
        }
        finally
        {
            await _pipe.Writer.CompleteAsync();
        }
    }

    public override bool CanRead  => true;
    public override bool CanWrite => true;
    public override bool CanSeek  => false;
    public override long Length   => throw new NotSupportedException();
    public override long Position { get => throw new NotSupportedException(); set => throw new NotSupportedException(); }
    public override long Seek(long offset, SeekOrigin origin) => throw new NotSupportedException();
    public override void SetLength(long value) => throw new NotSupportedException();

    public override Task<int> ReadAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        => ReadAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override async ValueTask<int> ReadAsync(Memory<byte> buffer, CancellationToken ct = default)
    {
        var result = await _pipe.Reader.ReadAsync(ct);
        if (result.IsCompleted && result.Buffer.IsEmpty) return 0;
        var len = Math.Min((int)result.Buffer.Length, buffer.Length);
        result.Buffer.Slice(0, len).CopyTo(buffer.Span);
        _pipe.Reader.AdvanceTo(result.Buffer.GetPosition(len));
        return len;
    }

    public override int Read(byte[] buffer, int offset, int count)
        => ReadAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

    public override Task WriteAsync(byte[] buffer, int offset, int count, CancellationToken ct)
        => WriteAsync(buffer.AsMemory(offset, count), ct).AsTask();

    public override async ValueTask WriteAsync(ReadOnlyMemory<byte> buffer, CancellationToken ct = default)
    {
        using var ms = new MemoryStream();
        SshEncoding.WriteByte(ms, Msg.ChannelData);
        SshEncoding.WriteUInt32(ms, _srvChan);
        SshEncoding.WriteByteString(ms, buffer.ToArray());
        await _conn.SendAsync(ms, ct);
    }

    public override void Write(byte[] buffer, int offset, int count)
        => WriteAsync(buffer, offset, count, CancellationToken.None).GetAwaiter().GetResult();

    public override void Flush() { }

    protected override void Dispose(bool disposing)
    {
        if (disposing)
        {
            _cts.Cancel();
            _cts.Dispose();
            _pipe.Writer.Complete();
            _pipe.Reader.Complete();
        }
        base.Dispose(disposing);
    }
}
