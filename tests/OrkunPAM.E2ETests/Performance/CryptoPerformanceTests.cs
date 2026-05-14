using System.Diagnostics;
using Microsoft.Extensions.Logging.Abstractions;
using OrkunPAM.Cryptography;

namespace OrkunPAM.E2ETests.Performance;

/// <summary>
/// Performance benchmark tests for the AES-256-GCM vault encryption engine.
///
/// Targets (from RFP and docs/perf-baseline.md):
///   - Encrypt: &lt; 5 ms per credential on average
///   - Decrypt: &lt; 5 ms per credential on average
///   - Round-trip correctness at scale: 1 000 samples, 0 failures
/// </summary>
public sealed class CryptoPerformanceTests
{
    private const int Iterations   = 1_000;
    private const int MaxTotalMs   = 5_000;
    private const string Passphrase = "PerfTest-Passphrase-OrkunPAM-2026!";

    private static (InMemoryKeyStore ks, AesGcmEncryptionService svc) CreateService()
    {
        var ks = new InMemoryKeyStore(NullLogger<InMemoryKeyStore>.Instance);
        ks.Initialize(Passphrase);
        var svc = new AesGcmEncryptionService(ks, NullLogger<AesGcmEncryptionService>.Instance);
        return (ks, svc);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void AesGcm_Encrypt_1000ops_Under5msPerOp()
    {
        var (_, svc) = CreateService();
        var plaintext = "SuperSecret-P@ssw0rd-2026!"u8.ToArray();

        for (int i = 0; i < 20; i++) svc.Encrypt(plaintext);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < Iterations; i++)
        {
            var result = svc.Encrypt(plaintext);
            Assert.True(result.IsSuccess, $"Encrypt failed on iteration {i}");
        }
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < MaxTotalMs,
            $"AES-256-GCM encrypt avg {(double)sw.ElapsedMilliseconds / Iterations:F3} ms/op " +
            $"— exceeded 5 ms target (total {sw.ElapsedMilliseconds} ms for {Iterations} ops)");
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void AesGcm_Decrypt_1000ops_Under5msPerOp()
    {
        var (_, svc) = CreateService();
        var plaintext = "SuperSecret-P@ssw0rd-2026!"u8.ToArray();

        var ciphertexts = Enumerable.Range(0, Iterations)
            .Select(_ => svc.Encrypt(plaintext).Value)
            .ToArray();

        for (int i = 0; i < 20; i++) svc.Decrypt(ciphertexts[i % ciphertexts.Length]);

        var sw = Stopwatch.StartNew();
        for (int i = 0; i < Iterations; i++)
        {
            var result = svc.Decrypt(ciphertexts[i]);
            Assert.True(result.IsSuccess, $"Decrypt failed on iteration {i}");
        }
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < MaxTotalMs,
            $"AES-256-GCM decrypt avg {(double)sw.ElapsedMilliseconds / Iterations:F3} ms/op " +
            $"— exceeded 5 ms target (total {sw.ElapsedMilliseconds} ms for {Iterations} ops)");
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void AesGcm_EncryptDecrypt_1000Roundtrips_AllCorrect()
    {
        var (_, svc) = CreateService();

        int failures = 0;
        for (int i = 0; i < Iterations; i++)
        {
            var plaintext = $"credential-{i:D6}-P@ss!"u8.ToArray();
            var enc = svc.Encrypt(plaintext);
            if (enc.IsFailure) { failures++; continue; }

            var dec = svc.Decrypt(enc.Value);
            if (dec.IsFailure || !dec.Value.SequenceEqual(plaintext))
                failures++;
        }

        Assert.Equal(0, failures);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void AesGcm_UniqueIVPerCall_NoDuplicateCiphertexts()
    {
        var (_, svc) = CreateService();
        const string plaintext = "SamePlaintextEveryTime";
        const int samples = 100;

        var ciphertexts = Enumerable.Range(0, samples)
            .Select(_ => Convert.ToHexString(svc.EncryptString(plaintext).Value))
            .ToHashSet();

        Assert.Equal(samples, ciphertexts.Count);
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void AesGcm_StringEncryptDecrypt_1000ops_Correct()
    {
        var (_, svc) = CreateService();
        var sw = Stopwatch.StartNew();

        for (int i = 0; i < Iterations; i++)
        {
            var original = $"password-{i:D6}";
            var enc = svc.EncryptString(original);
            Assert.True(enc.IsSuccess);

            var dec = svc.DecryptString(enc.Value);
            Assert.True(dec.IsSuccess);
            Assert.Equal(original, dec.Value);
        }
        sw.Stop();

        Assert.True(sw.ElapsedMilliseconds < MaxTotalMs * 2,
            $"String enc+dec avg {(double)sw.ElapsedMilliseconds / Iterations:F3} ms/op " +
            $"(total {sw.ElapsedMilliseconds} ms)");
    }

    [Fact]
    [Trait("Category", "E2E")]
    public void KeyStore_MasterKeyRotation_ExistingDataStillDecryptable()
    {
        var (ks, svc) = CreateService();
        const string secret = "pre-rotation-credential";

        var encrypted = svc.EncryptString(secret);
        Assert.True(encrypted.IsSuccess);

        var rotate = ks.RotateMasterKey();
        Assert.True(rotate.IsSuccess);

        var decrypted = svc.DecryptString(encrypted.Value);
        Assert.True(decrypted.IsSuccess);
        Assert.Equal(secret, decrypted.Value);
    }
}
