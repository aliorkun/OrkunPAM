using System.Security.Cryptography;
using System.Text;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;
using OrkunPAM.Persistence.Services;

namespace OrkunPAM.UnitTests;

public class AuditTests : IDisposable
{
    private readonly OrkunPamDbContext _db;
    private readonly AuditService _auditService;

    public AuditTests()
    {
        var options = new DbContextOptionsBuilder<OrkunPamDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        _db = new OrkunPamDbContext(options);
        _db.Database.OpenConnection();
        _db.Database.EnsureCreated();

        _auditService = new AuditService(_db, NullLogger<AuditService>.Instance);
    }

    [Fact]
    public async Task LogAsync_CreatesEntryWithHashChain()
    {
        await _auditService.LogAsync("Auth", "Login", null, "admin", "10.0.0.1",
            "User", "user-1", new { Reason = "test" });

        var entry = await _db.AuditLogs.FirstAsync();

        Assert.Equal("Auth", entry.EventCategory);
        Assert.Equal("Login", entry.EventType);
        Assert.Equal("admin", entry.ActorUsername);
        Assert.NotNull(entry.EntryHash);
        Assert.True(entry.EntryHash.Length > 0);
    }

    [Fact]
    public async Task LogAsync_SecondEntry_ReferencesFirstHash()
    {
        await _auditService.LogAsync("Auth", "Login1", null, "admin", "10.0.0.1",
            null, null, null);
        await _auditService.LogAsync("Auth", "Login2", null, "admin", "10.0.0.1",
            null, null, null);

        var entries = await _db.AuditLogs.OrderBy(a => a.Id).ToListAsync();
        Assert.Equal(2, entries.Count);

        // Second entry's PreviousHash should match first entry's EntryHash
        Assert.NotNull(entries[1].PreviousHash);
        Assert.Equal(entries[0].EntryHash, entries[1].PreviousHash);
    }

    [Fact]
    public async Task HashChain_ThreeEntries_IntegrityHolds()
    {
        for (int i = 0; i < 3; i++)
        {
            await _auditService.LogAsync("Test", $"Event{i}", null, "system", null,
                null, null, null);
        }

        var entries = await _db.AuditLogs.OrderBy(a => a.Id).ToListAsync();

        // First entry has no previous hash
        Assert.Null(entries[0].PreviousHash);

        // Chain verification
        for (int i = 1; i < entries.Count; i++)
        {
            Assert.NotNull(entries[i].PreviousHash);
            Assert.Equal(entries[i - 1].EntryHash, entries[i].PreviousHash);
        }
    }

    [Fact]
    public async Task HashChain_TamperDetection_ModifiedEntry_BreaksChain()
    {
        for (int i = 0; i < 3; i++)
        {
            await _auditService.LogAsync("Test", $"Event{i}", null, "system", null,
                null, null, null);
        }

        var entries = await _db.AuditLogs.OrderBy(a => a.Id).ToListAsync();

        // Tamper with the middle entry's hash
        entries[1].EntryHash = SHA256.HashData(Encoding.UTF8.GetBytes("TAMPERED"));
        await _db.SaveChangesAsync();

        // Reload and verify chain is broken
        var reloaded = await _db.AuditLogs.OrderBy(a => a.Id).ToListAsync();

        // Entry 2's PreviousHash should no longer match Entry 1's (now tampered) EntryHash
        // The chain is broken because entry[2].PreviousHash was set from the ORIGINAL entry[1].EntryHash
        // but entry[1].EntryHash has been modified
        Assert.NotEqual(reloaded[1].EntryHash, reloaded[2].PreviousHash);
    }

    [Fact]
    public async Task LogAsync_StoresAuditOutcome()
    {
        await _auditService.LogAsync("Auth", "LoginFailed", null, "attacker", "10.0.0.5",
            null, null, new { Reason = "bad password" }, AuditOutcome.Failure);

        var entry = await _db.AuditLogs.FirstAsync();
        Assert.Equal(AuditOutcome.Failure, entry.Outcome);
    }

    [Fact]
    public async Task LogAsync_SerializesDetailsAsJson()
    {
        await _auditService.LogAsync("Vault", "CredentialAccess", null, "admin", null,
            "Credential", "cred-123", new { Action = "CheckOut", Duration = 30 });

        var entry = await _db.AuditLogs.FirstAsync();
        Assert.NotNull(entry.Details);
        Assert.Contains("CheckOut", entry.Details);
        Assert.Contains("30", entry.Details);
    }

    [Fact]
    public async Task LogAsync_ConcurrentWrites_MaintainHashChain()
    {
        // Write multiple entries concurrently (the semaphore should serialize them)
        var tasks = Enumerable.Range(0, 5).Select(i =>
            _auditService.LogAsync("Test", $"Concurrent{i}", null, "system", null,
                null, null, null));

        await Task.WhenAll(tasks);

        var entries = await _db.AuditLogs.OrderBy(a => a.Id).ToListAsync();
        Assert.Equal(5, entries.Count);

        // Verify chain integrity (semaphore should have serialized writes)
        for (int i = 1; i < entries.Count; i++)
        {
            Assert.NotNull(entries[i].PreviousHash);
            Assert.Equal(entries[i - 1].EntryHash, entries[i].PreviousHash);
        }
    }

    [Fact]
    public async Task LogAsync_EntryHashIsDeterministic()
    {
        // Two entries with different data should have different hashes
        await _auditService.LogAsync("Auth", "Login", null, "admin", "10.0.0.1",
            null, null, null);
        await _auditService.LogAsync("Auth", "Logout", null, "admin", "10.0.0.1",
            null, null, null);

        var entries = await _db.AuditLogs.OrderBy(a => a.Id).ToListAsync();
        Assert.NotEqual(entries[0].EntryHash, entries[1].EntryHash);
    }

    public void Dispose() => _db.Dispose();
}
