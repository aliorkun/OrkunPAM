using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.UnitTests;

/// <summary>
/// Tests report endpoint logic: credential expiry calculations,
/// policy compliance percentages, group membership counts.
/// These test the domain query logic that backs the reporting endpoints.
/// </summary>
public class ReportTests : IDisposable
{
    private readonly OrkunPamDbContext _db;

    public ReportTests()
    {
        var options = new DbContextOptionsBuilder<OrkunPamDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        _db = new OrkunPamDbContext(options);
        _db.Database.OpenConnection();
        _db.Database.EnsureCreated();
    }

    [Fact]
    public async Task CredentialExpiry_ExpiringWithinDays_ReturnsCorrectCount()
    {
        var folder = new VaultFolder { Name = "TestFolder" };
        _db.VaultFolders.Add(folder);
        await _db.SaveChangesAsync();

        // Credential expiring in 5 days
        _db.Credentials.Add(new Credential
        {
            FolderId = folder.Id, Name = "Expiring", CredentialType = CredentialType.UserPassword,
            Username = "svc1", PasswordEnc = new byte[] { 1 }, KeyVersion = 1,
            Status = CredentialStatus.Active,
            NextRotationAtUtc = DateTime.UtcNow.AddDays(5)
        });

        // Credential expiring in 60 days
        _db.Credentials.Add(new Credential
        {
            FolderId = folder.Id, Name = "NotExpiring", CredentialType = CredentialType.UserPassword,
            Username = "svc2", PasswordEnc = new byte[] { 1 }, KeyVersion = 1,
            Status = CredentialStatus.Active,
            NextRotationAtUtc = DateTime.UtcNow.AddDays(60)
        });

        // Already expired
        _db.Credentials.Add(new Credential
        {
            FolderId = folder.Id, Name = "Expired", CredentialType = CredentialType.UserPassword,
            Username = "svc3", PasswordEnc = new byte[] { 1 }, KeyVersion = 1,
            Status = CredentialStatus.Active,
            NextRotationAtUtc = DateTime.UtcNow.AddDays(-1)
        });

        await _db.SaveChangesAsync();

        var expiringWithin30Days = await _db.Credentials
            .Where(c => c.NextRotationAtUtc.HasValue && c.NextRotationAtUtc < DateTime.UtcNow.AddDays(30))
            .CountAsync();

        Assert.Equal(2, expiringWithin30Days); // Expiring + Expired
    }

    [Fact]
    public async Task PolicyCompliance_ActiveUsersWithMfa_CalculatesPercentage()
    {
        // 3 active users: 2 with MFA enabled, 1 without
        _db.Users.Add(new User { Username = "u1", NormalizedUsername = "U1", Status = UserStatus.Active, MfaEnabled = true });
        _db.Users.Add(new User { Username = "u2", NormalizedUsername = "U2", Status = UserStatus.Active, MfaEnabled = true });
        _db.Users.Add(new User { Username = "u3", NormalizedUsername = "U3", Status = UserStatus.Active, MfaEnabled = false });
        await _db.SaveChangesAsync();

        var totalActive = await _db.Users.Where(u => u.Status == UserStatus.Active).CountAsync();
        var mfaEnabled = await _db.Users.Where(u => u.Status == UserStatus.Active && u.MfaEnabled).CountAsync();

        double compliancePercent = totalActive > 0 ? (double)mfaEnabled / totalActive * 100 : 0;

        Assert.Equal(3, totalActive);
        Assert.Equal(2, mfaEnabled);
        Assert.Equal(66.67, Math.Round(compliancePercent, 2));
    }

    [Fact]
    public async Task PolicyCompliance_PasswordAge_ExpiredPasswordCount()
    {
        _db.Users.Add(new User
        {
            Username = "old1", NormalizedUsername = "OLD1",
            Status = UserStatus.Active,
            PasswordExpiresAt = DateTime.UtcNow.AddDays(-10)
        });
        _db.Users.Add(new User
        {
            Username = "fresh", NormalizedUsername = "FRESH",
            Status = UserStatus.Active,
            PasswordExpiresAt = DateTime.UtcNow.AddDays(80)
        });
        _db.Users.Add(new User
        {
            Username = "old2", NormalizedUsername = "OLD2",
            Status = UserStatus.Active,
            PasswordExpiresAt = DateTime.UtcNow.AddDays(-5)
        });
        await _db.SaveChangesAsync();

        var expiredPasswordCount = await _db.Users
            .Where(u => u.Status == UserStatus.Active &&
                        u.PasswordExpiresAt.HasValue &&
                        u.PasswordExpiresAt < DateTime.UtcNow)
            .CountAsync();

        Assert.Equal(2, expiredPasswordCount);
    }

    [Fact]
    public async Task GroupMembership_CountsPerGroup()
    {
        var user1 = new User { Username = "m1", NormalizedUsername = "M1" };
        var user2 = new User { Username = "m2", NormalizedUsername = "M2" };
        var user3 = new User { Username = "m3", NormalizedUsername = "M3" };
        var group1 = new Group { Name = "Admins", GroupSource = GroupSource.Local };
        var group2 = new Group { Name = "Viewers", GroupSource = GroupSource.Local };

        _db.Users.AddRange(user1, user2, user3);
        _db.Groups.AddRange(group1, group2);
        await _db.SaveChangesAsync();

        _db.UserGroups.AddRange(
            new UserGroup { UserId = user1.Id, GroupId = group1.Id },
            new UserGroup { UserId = user2.Id, GroupId = group1.Id },
            new UserGroup { UserId = user3.Id, GroupId = group2.Id }
        );
        await _db.SaveChangesAsync();

        var groupCounts = await _db.Groups
            .Include(g => g.UserGroups)
            .Select(g => new { g.Name, MemberCount = g.UserGroups.Count })
            .OrderByDescending(g => g.MemberCount)
            .ToListAsync();

        Assert.Equal(2, groupCounts.Count);
        Assert.Equal("Admins", groupCounts[0].Name);
        Assert.Equal(2, groupCounts[0].MemberCount);
        Assert.Equal("Viewers", groupCounts[1].Name);
        Assert.Equal(1, groupCounts[1].MemberCount);
    }

    [Fact]
    public async Task CredentialReport_StatusDistribution()
    {
        var folder = new VaultFolder { Name = "Report" };
        _db.VaultFolders.Add(folder);
        await _db.SaveChangesAsync();

        _db.Credentials.AddRange(
            new Credential { FolderId = folder.Id, Name = "C1", CredentialType = CredentialType.UserPassword, Username = "u1", PasswordEnc = new byte[] { 1 }, KeyVersion = 1, Status = CredentialStatus.Active },
            new Credential { FolderId = folder.Id, Name = "C2", CredentialType = CredentialType.UserPassword, Username = "u2", PasswordEnc = new byte[] { 1 }, KeyVersion = 1, Status = CredentialStatus.Active },
            new Credential { FolderId = folder.Id, Name = "C3", CredentialType = CredentialType.SshKey, Username = "u3", PasswordEnc = new byte[] { 1 }, KeyVersion = 1, Status = CredentialStatus.CheckedOut },
            new Credential { FolderId = folder.Id, Name = "C4", CredentialType = CredentialType.UserPassword, Username = "u4", PasswordEnc = new byte[] { 1 }, KeyVersion = 1, Status = CredentialStatus.Disabled }
        );
        await _db.SaveChangesAsync();

        var statusCounts = await _db.Credentials
            .GroupBy(c => c.Status)
            .Select(g => new { Status = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Status, x => x.Count);

        Assert.Equal(2, statusCounts[CredentialStatus.Active]);
        Assert.Equal(1, statusCounts[CredentialStatus.CheckedOut]);
        Assert.Equal(1, statusCounts[CredentialStatus.Disabled]);
    }

    [Fact]
    public async Task UserReport_AuthSourceDistribution()
    {
        _db.Users.AddRange(
            new User { Username = "local1", NormalizedUsername = "LOCAL1", AuthSource = AuthSource.Local },
            new User { Username = "local2", NormalizedUsername = "LOCAL2", AuthSource = AuthSource.Local },
            new User { Username = "ad1", NormalizedUsername = "AD1", AuthSource = AuthSource.ActiveDirectory }
        );
        await _db.SaveChangesAsync();

        var sourceCounts = await _db.Users
            .GroupBy(u => u.AuthSource)
            .Select(g => new { Source = g.Key, Count = g.Count() })
            .ToDictionaryAsync(x => x.Source, x => x.Count);

        Assert.Equal(2, sourceCounts[AuthSource.Local]);
        Assert.Equal(1, sourceCounts[AuthSource.ActiveDirectory]);
    }

    public void Dispose() => _db.Dispose();
}
