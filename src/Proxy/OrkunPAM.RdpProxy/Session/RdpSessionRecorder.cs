using System.Security.Cryptography;

namespace OrkunPAM.RdpProxy.Session;

/// <summary>
/// Records raw RDP traffic to disk as a time-stamped binary stream.
/// Each record: [direction:1][timestamp_ms:8][length:4][data:length]
/// Direction: 0 = client→target, 1 = target→client.
/// A SHA-256 hash-chain footer is appended on close for tamper detection.
/// </summary>
internal sealed class RdpSessionRecorder : IAsyncDisposable
{
    private readonly FileStream _file;
    private readonly IncrementalHash _hash;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private bool _disposed;

    private RdpSessionRecorder(FileStream file)
    {
        _file = file;
        _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    }

    public static async Task<RdpSessionRecorder> CreateAsync(string directory, string sessionId)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{sessionId}.rdp.rec");
        var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            bufferSize: 65536, useAsync: true);

        // Write a fixed 32-byte header
        var header = new byte[32];
        "ORKUNRDP1"u8.CopyTo(header);           // magic
        var now = BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
        now.CopyTo(header, 16);
        await file.WriteAsync(header);

        return new RdpSessionRecorder(file);
    }

    public string FilePath => _file.Name;

    public async Task WriteAsync(bool fromTarget, ReadOnlyMemory<byte> data)
    {
        if (_disposed || data.IsEmpty) return;
        await _lock.WaitAsync();
        try
        {
            var ts = BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds());
            var frame = new byte[1 + 8 + 4 + data.Length];
            frame[0] = fromTarget ? (byte)1 : (byte)0;
            ts.CopyTo(frame, 1);
            BitConverter.GetBytes(data.Length).CopyTo(frame, 9);
            data.Span.CopyTo(frame.AsSpan(13));
            _hash.AppendData(frame);
            await _file.WriteAsync(frame);
        }
        finally
        {
            _lock.Release();
        }
    }

    public async ValueTask DisposeAsync()
    {
        if (_disposed) return;
        _disposed = true;

        await _lock.WaitAsync();
        try
        {
            // Append SHA-256 chain hash footer
            var hash = _hash.GetCurrentHash();
            var footer = new byte[4 + 32];
            "HASH"u8.CopyTo(footer);
            hash.CopyTo(footer, 4);
            await _file.WriteAsync(footer);
            await _file.FlushAsync();
        }
        finally
        {
            _lock.Release();
            _hash.Dispose();
            await _file.DisposeAsync();
            _lock.Dispose();
        }
    }
}
