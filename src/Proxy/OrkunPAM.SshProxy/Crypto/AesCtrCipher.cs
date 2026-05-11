using System.Security.Cryptography;

namespace OrkunPAM.SshProxy.Crypto;

/// <summary>
/// AES-256-CTR stream cipher — stateful, maintains counter across packet boundaries.
/// SSH uses the IV as the initial counter block (128-bit big-endian integer).
/// </summary>
internal sealed class AesCtrCipher : IDisposable
{
    private readonly Aes _aes;
    private readonly byte[] _counter = new byte[16];
    private readonly byte[] _keystream = new byte[16];
    private int _keystreamPos = 16; // force generation on first use
    private bool _disposed;

    internal AesCtrCipher(byte[] key, byte[] iv)
    {
        _aes = Aes.Create();
        _aes.Key = key;
        _aes.Mode = CipherMode.ECB;
        _aes.Padding = PaddingMode.None;
        iv.CopyTo(_counter, 0);
    }

    // Encrypt or decrypt in-place (CTR is its own inverse)
    internal void Transform(byte[] buf, int offset, int count)
    {
        for (int i = 0; i < count; i++)
        {
            if (_keystreamPos == 16) RefillKeystream();
            buf[offset + i] ^= _keystream[_keystreamPos++];
        }
    }

    internal byte[] Transform(ReadOnlySpan<byte> data)
    {
        var output = data.ToArray();
        Transform(output, 0, output.Length);
        return output;
    }

    private void RefillKeystream()
    {
        using var enc = _aes.CreateEncryptor();
        enc.TransformBlock(_counter, 0, 16, _keystream, 0);
        // increment counter as 128-bit big-endian integer
        for (int i = 15; i >= 0; i--)
            if (++_counter[i] != 0) break;
        _keystreamPos = 0;
    }

    public void Dispose()
    {
        if (_disposed) return;
        _aes.Dispose();
        CryptographicOperations.ZeroMemory(_counter);
        CryptographicOperations.ZeroMemory(_keystream);
        _disposed = true;
    }
}
