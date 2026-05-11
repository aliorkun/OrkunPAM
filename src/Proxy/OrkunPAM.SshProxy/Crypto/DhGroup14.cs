using System.Numerics;
using System.Security.Cryptography;
using OrkunPAM.SshProxy.Protocol;

namespace OrkunPAM.SshProxy.Crypto;

/// <summary>
/// Diffie-Hellman Group 14 (2048-bit MODP) with SHA-256, per RFC 3526 + RFC 4253.
/// Used for SSH key exchange (diffie-hellman-group14-sha256).
/// </summary>
internal sealed class DhGroup14
{
    // RFC 3526 §3 — 2048-bit MODP Group (Group 14)
    private static readonly BigInteger P = new BigInteger(
        Convert.FromHexString(
            "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
            "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
            "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
            "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
            "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
            "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
            "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
            "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
            "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
            "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
            "15728E5A8AACAA68FFFFFFFFFFFFFFFF"),
        isUnsigned: true, isBigEndian: true);

    private static readonly BigInteger G = 2;

    private readonly BigInteger _privateKey;
    internal readonly BigInteger PublicKey;

    internal DhGroup14()
    {
        var privBytes = new byte[32];
        RandomNumberGenerator.Fill(privBytes);
        // ensure private key is in [1, P-1]
        _privateKey = new BigInteger(privBytes, isUnsigned: true, isBigEndian: true) % (P - 1) + 1;
        PublicKey = BigInteger.ModPow(G, _privateKey, P);
    }

    internal BigInteger ComputeSharedSecret(BigInteger peerPublicKey) =>
        BigInteger.ModPow(peerPublicKey, _privateKey, P);

    /// <summary>
    /// RFC 4253 §7.2 — derive IV, encryption key, and MAC key from K and H.
    /// Returns (ivC2S[16], ivS2C[16], ekC2S[32], ekS2C[32], mkC2S[32], mkS2C[32]).
    /// </summary>
    internal static SessionKeys DeriveKeys(BigInteger K, byte[] H, byte[] sessionId)
    {
        // K must be encoded as SSH mpint for hashing
        using var ms = new MemoryStream();
        SshEncoding.WriteMpInt(ms, K);
        var kMpint = ms.ToArray();

        byte[] Derive(char letter, int length)
        {
            var result = new List<byte>(64);
            byte[]? prev = null;
            while (result.Count < length)
            {
                using var sha = SHA256.Create();
                sha.TransformBlock(kMpint, 0, kMpint.Length, null, 0);
                sha.TransformBlock(H, 0, H.Length, null, 0);
                if (prev == null)
                {
                    sha.TransformBlock(new[] { (byte)letter }, 0, 1, null, 0);
                    sha.TransformFinalBlock(sessionId, 0, sessionId.Length);
                }
                else
                {
                    sha.TransformFinalBlock(prev, 0, prev.Length);
                }
                prev = sha.Hash!;
                result.AddRange(prev);
            }
            return result.Take(length).ToArray();
        }

        return new SessionKeys(
            IvC2S: Derive('A', 16),
            IvS2C: Derive('B', 16),
            EkC2S: Derive('C', 32),
            EkS2C: Derive('D', 32),
            MkC2S: Derive('E', 32),
            MkS2C: Derive('F', 32));
    }
}

internal record SessionKeys(
    byte[] IvC2S, byte[] IvS2C,
    byte[] EkC2S, byte[] EkS2C,
    byte[] MkC2S, byte[] MkS2C);
