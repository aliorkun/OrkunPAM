using System.Security.Cryptography;

namespace OrkunPAM.RdpProxy.Session;

/// <summary>
/// Records raw RDP traffic to disk as an AES-256-GCM encrypted binary stream.
///
/// File format v2:
///   Header (96 bytes):
///     [0..9]   magic "ORKUNRDP2\0"
///     [10..11] version 0x0002
///     [12..15] reserved
///     [16..23] creation timestamp (Unix ms, little-endian)
///     [24..31] reserved
///     [32..63] content key (32 bytes, AES-256-GCM wrapped if master key provided)
///     [64..75] key-wrap nonce (12 bytes, zeros if no master key)
///     [76..91] key-wrap GCM tag (16 bytes, zeros if no master key)
///     [92..95] reserved
///
///   Each frame:
///     [0]      direction: 0 = client→target, 1 = target→client
///     [1..8]   timestamp_ms (Unix ms, little-endian)
///     [9..12]  payload_size = 12 + data_length + 16
///     [13..24] AES-GCM nonce (12 bytes, random per frame)
///     [25..25+data_length-1] ciphertext
///     [25+data_length..25+data_length+15] GCM authentication tag (16 bytes)
///
///   Footer: "HASH" + SHA-256 of all preceding bytes (including header)
/// </summary>
internal sealed class RdpSessionRecorder : IAsyncDisposable
{
    private readonly FileStream _file;
    private readonly byte[] _contentKey;
    private readonly AesGcm _aes;
    private readonly IncrementalHash _hash;
    private readonly SemaphoreSlim _lock = new(1, 1);
    private bool _disposed;

    private RdpSessionRecorder(FileStream file, byte[] contentKey)
    {
        _file = file;
        _contentKey = contentKey;
        _aes = new AesGcm(contentKey, tagSizeInBytes: 16);
        _hash = IncrementalHash.CreateHash(HashAlgorithmName.SHA256);
    }

    public static async Task<RdpSessionRecorder> CreateAsync(
        string directory, string sessionId, byte[]? masterKey = null)
    {
        Directory.CreateDirectory(directory);
        var path = Path.Combine(directory, $"{sessionId}.rdp.rec");
        var file = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None,
            bufferSize: 65536, useAsync: true);

        var contentKey = new byte[32];
        RandomNumberGenerator.Fill(contentKey);

        var header = new byte[96];
        "ORKUNRDP2\0"u8.CopyTo(header.AsSpan(0, 10));
        header[10] = 0x00; header[11] = 0x02;
        BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).CopyTo(header.AsSpan(16));

        if (masterKey is { Length: 32 })
        {
            // Wrap content key so it is protected even if the file is exfiltrated
            var wrapNonce = new byte[12];
            RandomNumberGenerator.Fill(wrapNonce);
            var wrappedKey = new byte[32];
            var wrapTag = new byte[16];
            using var wrapAes = new AesGcm(masterKey, tagSizeInBytes: 16);
            wrapAes.Encrypt(wrapNonce, contentKey, wrappedKey, wrapTag);
            wrappedKey.CopyTo(header.AsSpan(32));
            wrapNonce.CopyTo(header.AsSpan(64));
            wrapTag.CopyTo(header.AsSpan(76));
        }
        else
        {
            // No master key configured — content key stored unprotected in header;
            // frames are still AES-256-GCM encrypted at rest.
            contentKey.CopyTo(header.AsSpan(32));
        }

        await file.WriteAsync(header);
        return new RdpSessionRecorder(file, contentKey);
    }

    public string FilePath => _file.Name;

    public async Task WriteAsync(bool fromTarget, ReadOnlyMemory<byte> data)
    {
        if (_disposed || data.IsEmpty) return;
        await _lock.WaitAsync();
        try
        {
            // Frame layout: [direction:1][ts:8][payload_size:4][nonce:12][ciphertext:n][tag:16]
            int payloadSize = 12 + data.Length + 16;
            var frame = new byte[1 + 8 + 4 + payloadSize];
            frame[0] = fromTarget ? (byte)1 : (byte)0;
            BitConverter.GetBytes(DateTimeOffset.UtcNow.ToUnixTimeMilliseconds()).CopyTo(frame, 1);
            BitConverter.GetBytes(payloadSize).CopyTo(frame, 9);
            RandomNumberGenerator.Fill(frame.AsSpan(13, 12));
            _aes.Encrypt(
                nonce: frame.AsSpan(13, 12),
                plaintext: data.Span,
                ciphertext: frame.AsSpan(25, data.Length),
                tag: frame.AsSpan(25 + data.Length, 16));
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
            CryptographicOperations.ZeroMemory(_contentKey);
            _aes.Dispose();
            _hash.Dispose();
            await _file.DisposeAsync();
            _lock.Dispose();
        }
    }
}
