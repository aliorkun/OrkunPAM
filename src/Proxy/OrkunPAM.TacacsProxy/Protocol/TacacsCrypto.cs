using System.Security.Cryptography;
using System.Text;

namespace OrkunPAM.TacacsProxy.Protocol;

/// <summary>
/// TACACS+ body encryption/decryption using the MD5-based pseudo-pad method
/// defined in draft-grant-tacacs (section 5.2).
///
/// pseudo_pad = MD5(session_id || key || version || seq_no)
///            | MD5(... || prev_md5_block)
///            | ... (until body_len bytes generated)
///
/// Decryption is identical to encryption (XOR is symmetric).
/// </summary>
internal static class TacacsCrypto
{
    public static byte[] Crypt(ReadOnlySpan<byte> body, uint sessionId, string key, byte version, byte seqNo)
    {
        var keyBytes = Encoding.ASCII.GetBytes(key);
        var result = new byte[body.Length];
        var pad = BuildPseudoPad(body.Length, sessionId, keyBytes, version, seqNo);
        for (int i = 0; i < body.Length; i++)
            result[i] = (byte)(body[i] ^ pad[i]);
        return result;
    }

    private static byte[] BuildPseudoPad(int needed, uint sessionId, byte[] key, byte version, byte seqNo)
    {
        Span<byte> sidBytes = stackalloc byte[4];
        System.Buffers.Binary.BinaryPrimitives.WriteUInt32BigEndian(sidBytes, sessionId);

        // Seed: session_id(4) || key(var) || version(1) || seq_no(1)
        int seedLen = 4 + key.Length + 2;
        var seed = new byte[seedLen];
        sidBytes.CopyTo(seed);
        key.CopyTo(seed, 4);
        seed[4 + key.Length]     = version;
        seed[4 + key.Length + 1] = seqNo;

        var pad = new byte[((needed / 16) + 1) * 16];
        byte[] prevMd5 = Array.Empty<byte>();
        int offset = 0;

        while (offset < needed)
        {
            byte[] block;
            if (prevMd5.Length == 0)
            {
                block = MD5.HashData(seed);
            }
            else
            {
                // Extend seed with previous MD5 block
                var extended = new byte[seedLen + 16];
                seed.CopyTo(extended, 0);
                prevMd5.CopyTo(extended, seedLen);
                block = MD5.HashData(extended);
                seed = extended; // grow for next iteration
                seedLen = extended.Length;
            }

            int copy = Math.Min(16, needed - offset);
            block.AsSpan(0, copy).CopyTo(pad.AsSpan(offset));
            prevMd5 = block;
            offset += copy;
        }

        return pad[..needed];
    }
}
