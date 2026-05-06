using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;
using OrkunPAM.Persistence;

namespace OrkunPAM.UnitTests;

public class PersistenceTests : IDisposable
{
    private readonly OrkunPamDbContext _db;

    public PersistenceTests()
    {
        var options = new DbContextOptionsBuilder<OrkunPamDbContext>()
            .UseSqlite("Data Source=:memory:")
            .Options;

        _db = new OrkunPamDbContext(options);
        _db.Database.OpenConnection();
        _db.Database.EnsureCreated();
    }

    [Fact]
    public async Task User_CreateAndRetrieve()
    {
        var user = new User
        {
            Username = "testuser",
            NormalizedUsername = "TESTUSER",
            DisplayName = "Test User",
            AuthSource = AuthSource.Local,
            Status = UserStatus.Active
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        var retrieved = await _db.Users.FirstAsync(u => u.Username == "testuser");
        Assert.Equal("Test User", retrieved.DisplayName);
        Assert.NotEqual(Guid.Empty, retrieved.Id);
    }

    [Fact]
    public async Task User_SoftDelete_FilteredByDefault()
    {
        var user = new User
        {
            Username = "deleted",
            NormalizedUsername = "DELETED",
            IsDeleted = true,
            DeletedAtUtc = DateTime.UtcNow
        };

        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        // Global query filter should exclude deleted users
        var found = await _db.Users.AnyAsync(u => u.Username == "deleted");
        Assert.False(found);

        // IgnoreQueryFilters to find deleted users
        var foundWithDeleted = await _db.Users.IgnoreQueryFilters().AnyAsync(u => u.Username == "deleted");
        Assert.True(foundWithDeleted);
    }

    [Fact]
    public async Task Role_SeedData_Exists()
    {
        var roles = await _db.Roles.ToListAsync();
        Assert.True(roles.Count >= 7);
        Assert.Contains(roles, r => r.Name == "GlobalAdmin");
        Assert.Contains(roles, r => r.Name == "VaultAdmin");
        Assert.Contains(roles, r => r.Name == "Auditor");
    }

    [Fact]
    public async Task Permission_SeedData_Exists()
    {
        var perms = await _db.Permissions.ToListAsync();
        Assert.True(perms.Count >= 50);
        Assert.Contains(perms, p => p.Code == "vault.credential.checkout");
        Assert.Contains(perms, p => p.Code == "session.ssh.connect");
    }

    [Fact]
    public async Task RolePermission_SeedData_GlobalAdminHasAll()
    {
        var adminPerms = await _db.RolePermissions
            .Where(rp => rp.RoleId == SeedData.AdminRoleId)
            .CountAsync();

        var totalPerms = await _db.Permissions.CountAsync();
        Assert.Equal(totalPerms, adminPerms);
    }

    [Fact]
    public async Task Group_WithMembers()
    {
        var user = new User { Username = "member1", NormalizedUsername = "MEMBER1" };
        var group = new Group { Name = "TestGroup", GroupSource = GroupSource.Local };
        _db.Users.Add(user);
        _db.Groups.Add(group);
        await _db.SaveChangesAsync();

        _db.UserGroups.Add(new UserGroup { UserId = user.Id, GroupId = group.Id });
        await _db.SaveChangesAsync();

        var loaded = await _db.Groups.Include(g => g.UserGroups).FirstAsync(g => g.Name == "TestGroup");
        Assert.Single(loaded.UserGroups);
    }

    [Fact]
    public async Task Credential_CreateWithFolder()
    {
        var folder = new VaultFolder { Name = "TestFolder" };
        _db.VaultFolders.Add(folder);
        await _db.SaveChangesAsync();

        var cred = new Credential
        {
            FolderId = folder.Id,
            Name = "TestCred",
            CredentialType = CredentialType.UserPassword,
            Username = "admin",
            PasswordEnc = new byte[] { 1, 2, 3 },
            KeyVersion = 1
        };
        _db.Credentials.Add(cred);
        await _db.SaveChangesAsync();

        var loaded = await _db.VaultFolders.Include(f => f.Credentials).FirstAsync();
        Assert.Single(loaded.Credentials);
        Assert.Equal("TestCred", loaded.Credentials.First().Name);
    }

    [Fact]
    public async Task AuditableEntity_SetsUpdatedAtOnModify()
    {
        var user = new User { Username = "auditme", NormalizedUsername = "AUDITME" };
        _db.Users.Add(user);
        await _db.SaveChangesAsync();

        var originalUpdated = user.UpdatedAtUtc;
        await Task.Delay(10); // Tiny delay to ensure different timestamp

        user.DisplayName = "Updated";
        await _db.SaveChangesAsync();

        Assert.True(user.UpdatedAtUtc >= originalUpdated);
    }

    public void Dispose() => _db.Dispose();
}
