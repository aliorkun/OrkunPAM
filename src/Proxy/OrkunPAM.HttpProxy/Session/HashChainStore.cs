using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace OrkunPAM.HttpProxy.Session;

/// <summary>
/// Append-only tamper-proof hash chain for HTTP session recording files (RFP §68).
/// Same pattern as the SSH proxy's HashChainStore.
///
/// File: {recDir}/chain.jsonl — one JSON entry per line.
/// Integrity invariant:
///   entry[0].prevHash  = SHA-256("") (genesis sentinel)
///   entry[n].prevHash  = entry[n-1].contentHash
///   entry[n].contentHash = SHA-256(raw bytes of the .httprec file)
/// </summary>
internal sealed class HashChainStore
{
    private static readonly string GenesisHash =
        Convert.ToHexString(SHA256.HashData([])).ToLowerInvariant();

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        PropertyNamingPolicy = JsonNamingPolicy.CamelCase,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    private readonly string _chainPath;
    private readonly ILogger _log;
    private readonly SemaphoreSlim _appendLock = new(1, 1);

    internal HashChainStore(string recDir, ILogger log)
    {
        Directory.CreateDirectory(recDir);
        _chainPath = Path.Combine(recDir, "chain.jsonl");
        _log = log;
    }

    internal async Task AppendAsync(string recId, string filePath, CancellationToken ct = default)
    {
        await _appendLock.WaitAsync(ct);
        try
        {
            var contentHash = await ComputeFileHashHexAsync(filePath, ct);
            var prevHash    = await GetLastContentHashAsync(ct);

            var entry = new ChainEntry(
                recId,
                Path.GetFileName(filePath),
                contentHash,
                prevHash,
                DateTimeOffset.UtcNow.ToString("O"));

            var line = JsonSerializer.Serialize(entry, JsonOpts);
            await File.AppendAllTextAsync(_chainPath, line + "\n", Encoding.UTF8, ct);

            _log.LogDebug("HashChain: appended {RecId} hash={Hash}...", recId, contentHash[..16]);
        }
        catch (Exception ex)
        {
            _log.LogError(ex, "HashChain: failed to append entry for {RecId}", recId);
        }
        finally
        {
            _appendLock.Release();
        }
    }

    internal async Task<IReadOnlyList<string>> VerifyAsync(CancellationToken ct = default)
    {
        var violations = new List<string>();
        if (!File.Exists(_chainPath)) return violations;

        string? expectedPrev = GenesisHash;
        int lineNo = 0;
        await foreach (var line in ReadLinesAsync(_chainPath, ct))
        {
            lineNo++;
            if (string.IsNullOrWhiteSpace(line)) continue;

            ChainEntry? entry;
            try { entry = JsonSerializer.Deserialize<ChainEntry>(line, JsonOpts); }
            catch { violations.Add($"Line {lineNo}: JSON parse error"); continue; }

            if (entry == null) { violations.Add($"Line {lineNo}: null entry"); continue; }

            if (!string.Equals(entry.PrevHash, expectedPrev, StringComparison.OrdinalIgnoreCase))
                violations.Add($"Entry {entry.Id}: prevHash mismatch (expected {expectedPrev![..8]}... got {entry.PrevHash[..Math.Min(8, entry.PrevHash.Length)]}...)");

            var dir = Path.GetDirectoryName(_chainPath)!;
            var filePath = Path.Combine(dir, entry.File);
            if (File.Exists(filePath))
            {
                var actual = await ComputeFileHashHexAsync(filePath, ct);
                if (!string.Equals(actual, entry.ContentHash, StringComparison.OrdinalIgnoreCase))
                    violations.Add($"Entry {entry.Id}: file hash mismatch — recording may have been tampered with");
            }

            expectedPrev = entry.ContentHash;
        }

        return violations;
    }

    private async Task<string> GetLastContentHashAsync(CancellationToken ct)
    {
        if (!File.Exists(_chainPath)) return GenesisHash;

        string? lastLine = null;
        await foreach (var line in ReadLinesAsync(_chainPath, ct))
            if (!string.IsNullOrWhiteSpace(line)) lastLine = line;

        if (lastLine == null) return GenesisHash;

        try
        {
            var entry = JsonSerializer.Deserialize<ChainEntry>(lastLine, JsonOpts);
            return entry?.ContentHash ?? GenesisHash;
        }
        catch { return GenesisHash; }
    }

    private static async Task<string> ComputeFileHashHexAsync(string path, CancellationToken ct)
    {
        await using var fs = File.OpenRead(path);
        var hash = await SHA256.HashDataAsync(fs, ct);
        return Convert.ToHexString(hash).ToLowerInvariant();
    }

    private static async IAsyncEnumerable<string> ReadLinesAsync(string path,
        [EnumeratorCancellation] CancellationToken ct)
    {
        using var reader = new StreamReader(path, Encoding.UTF8);
        while (!reader.EndOfStream)
        {
            ct.ThrowIfCancellationRequested();
            var line = await reader.ReadLineAsync(ct);
            if (line != null) yield return line;
        }
    }

    private record ChainEntry(
        string Id, string File, string ContentHash, string PrevHash, string Timestamp);
}
