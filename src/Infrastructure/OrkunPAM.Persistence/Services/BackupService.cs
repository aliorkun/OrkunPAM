using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Domain.Entities.System;
using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Persistence.Services;

public interface IBackupService
{
    Task<BackupRecord> CreateBackupAsync(string scope, string passphrase, string initiatedBy, CancellationToken ct = default);
    Task<(bool Success, string? Error, int RestoredCount)> RestoreBackupAsync(byte[] fileBytes, string passphrase, string conflictStrategy, CancellationToken ct = default);
    Task<bool> VerifyIntegrityAsync(Guid backupId, CancellationToken ct = default);
    string GetBackupDirectory();
}

public sealed class BackupService : IBackupService
{
    private readonly OrkunPamDbContext _db;
    private readonly IConfiguration _configuration;
    private readonly ILogger<BackupService> _logger;
    private const string Magic = "PAMB";
    private const byte FormatVersion = 1;

    private static readonly JsonSerializerOptions JsonOpts = new()
    {
        ReferenceHandler = ReferenceHandler.IgnoreCycles,
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull
    };

    public BackupService(OrkunPamDbContext db, IConfiguration configuration, ILogger<BackupService> logger)
    {
        _db = db;
        _configuration = configuration;
        _logger = logger;
    }

    public string GetBackupDirectory()
    {
        var dir = _configuration["Backup:Directory"]
            ?? Path.Combine(AppContext.BaseDirectory, "backups");
        Directory.CreateDirectory(dir);
        return dir;
    }

    public async Task<BackupRecord> CreateBackupAsync(string scope, string passphrase, string initiatedBy, CancellationToken ct = default)
    {
        var record = new BackupRecord
        {
            Scope = scope,
            Status = "InProgress",
            InitiatedBy = initiatedBy,
            FileName = $"orkunpam-{scope.ToLower()}-{DateTime.UtcNow:yyyyMMdd-HHmmss}.pambackup"
        };
        _db.BackupRecords.Add(record);
        await _db.SaveChangesAsync(ct);

        try
        {
            var payload = await BuildPayloadAsync(scope, ct);
            var json = JsonSerializer.SerializeToUtf8Bytes(payload, JsonOpts);
            var encrypted = EncryptWithPassphrase(json, passphrase);

            var dir = GetBackupDirectory();
            var path = Path.Combine(dir, record.FileName);
            await File.WriteAllBytesAsync(path, encrypted, ct);

            record.FilePath = path;
            record.FileSizeBytes = encrypted.Length;
            record.IntegrityHash = Convert.ToHexString(SHA256.HashData(encrypted));
            record.IntegrityVerified = true;
            record.Status = "Completed";
            record.CompletedAtUtc = DateTime.UtcNow;

            await _db.SaveChangesAsync(ct);
            _logger.LogInformation("Backup created: {File} ({Size} bytes)", record.FileName, record.FileSizeBytes);
            return record;
        }
        catch (Exception ex)
        {
            record.Status = "Failed";
            record.ErrorMessage = ex.Message.Length > 500 ? ex.Message[..500] : ex.Message;
            await _db.SaveChangesAsync(ct);
            _logger.LogError(ex, "Backup failed for scope {Scope}", scope);
            throw;
        }
    }

    public async Task<(bool Success, string? Error, int RestoredCount)> RestoreBackupAsync(
        byte[] fileBytes, string passphrase, string conflictStrategy, CancellationToken ct = default)
    {
        byte[] json;
        try { json = DecryptWithPassphrase(fileBytes, passphrase); }
        catch { return (false, "Decryption failed — wrong passphrase or corrupted file", 0); }

        BackupPayload? payload;
        try { payload = JsonSerializer.Deserialize<BackupPayload>(json, JsonOpts); }
        catch { return (false, "Backup file is invalid or corrupted", 0); }

        if (payload == null) return (false, "Empty backup payload", 0);

        int restoredCount = 0;
        var overwrite = conflictStrategy == "Overwrite";

        if (payload.Credentials != null)
        {
            foreach (var dto in payload.Credentials)
            {
                var existing = await _db.Credentials.IgnoreQueryFilters().FirstOrDefaultAsync(c => c.Id == dto.Id, ct);
                if (existing == null)
                {
                    _db.Credentials.Add(new Credential
                    {
                        Id = dto.Id, Name = dto.Name, Username = dto.Username,
                        PasswordEnc = dto.PasswordEnc, PrivateKeyEnc = dto.PrivateKeyEnc,
                        CredentialType = Enum.TryParse<CredentialType>(dto.CredentialType, out var ct2) ? ct2 : CredentialType.Password,
                        FolderId = dto.FolderId, KeyVersion = dto.KeyVersion, Tags = dto.Tags
                    });
                    restoredCount++;
                }
                else if (overwrite)
                {
                    existing.Name = dto.Name; existing.Username = dto.Username;
                    existing.PasswordEnc = dto.PasswordEnc; existing.PrivateKeyEnc = dto.PrivateKeyEnc;
                    existing.Tags = dto.Tags;
                    restoredCount++;
                }
            }
        }

        if (payload.VaultFolders != null)
        {
            foreach (var dto in payload.VaultFolders)
            {
                var existing = await _db.VaultFolders.FirstOrDefaultAsync(f => f.Id == dto.Id, ct);
                if (existing == null)
                {
                    _db.VaultFolders.Add(new VaultFolder
                    {
                        Id = dto.Id, Name = dto.Name, Description = dto.Description,
                        ParentFolderId = dto.ParentFolderId, OwnerUserId = dto.OwnerUserId
                    });
                    restoredCount++;
                }
                else if (overwrite)
                {
                    existing.Name = dto.Name; existing.Description = dto.Description;
                    restoredCount++;
                }
            }
        }

        if (payload.Users != null)
        {
            foreach (var dto in payload.Users)
            {
                var existing = await _db.Users.IgnoreQueryFilters().FirstOrDefaultAsync(u => u.Id == dto.Id, ct);
                if (existing == null)
                {
                    _db.Users.Add(new User
                    {
                        Id = dto.Id, Username = dto.Username,
                        NormalizedUsername = dto.Username.ToUpperInvariant(),
                        DisplayName = dto.DisplayName, Email = dto.Email,
                        PasswordHash = dto.PasswordHash
                    });
                    restoredCount++;
                }
                else if (overwrite)
                {
                    existing.DisplayName = dto.DisplayName; existing.Email = dto.Email;
                    existing.PasswordHash = dto.PasswordHash;
                    restoredCount++;
                }
            }
        }

        if (payload.Policies != null)
        {
            foreach (var dto in payload.Policies)
            {
                var existing = await _db.Policies.FirstOrDefaultAsync(p => p.Id == dto.Id, ct);
                if (existing == null)
                {
                    _db.Policies.Add(new Policy
                    {
                        Id = dto.Id, Name = dto.Name,
                        PolicyType = dto.PolicyType, PolicyJson = dto.PolicyJson ?? "{}"
                    });
                    restoredCount++;
                }
                else if (overwrite)
                {
                    existing.Name = dto.Name; existing.PolicyJson = dto.PolicyJson ?? "{}";
                    restoredCount++;
                }
            }
        }

        await _db.SaveChangesAsync(ct);
        _logger.LogInformation("Restore completed: {Count} objects restored (strategy: {Strategy})", restoredCount, conflictStrategy);
        return (true, null, restoredCount);
    }

    public async Task<bool> VerifyIntegrityAsync(Guid backupId, CancellationToken ct = default)
    {
        var record = await _db.BackupRecords.FindAsync(new object[] { backupId }, ct);
        if (record == null || !File.Exists(record.FilePath)) return false;

        var fileBytes = await File.ReadAllBytesAsync(record.FilePath, ct);
        var hash = Convert.ToHexString(SHA256.HashData(fileBytes));
        record.IntegrityVerified = hash == record.IntegrityHash;
        await _db.SaveChangesAsync(ct);
        return record.IntegrityVerified;
    }

    private async Task<BackupPayload> BuildPayloadAsync(string scope, CancellationToken ct)
    {
        var payload = new BackupPayload
        {
            Scope = scope,
            CreatedAtUtc = DateTime.UtcNow,
            Hostname = Environment.MachineName
        };

        bool includeVault = scope is "All" or "VaultOnly";
        bool includeUsers = scope is "All" or "UsersOnly";
        bool includePolicies = scope is "All" or "PoliciesOnly";

        if (includeVault)
        {
            payload.Credentials = await _db.Credentials.IgnoreQueryFilters()
                .Select(c => new BackupCredentialDto
                {
                    Id = c.Id, Name = c.Name, Username = c.Username,
                    PasswordEnc = c.PasswordEnc, PrivateKeyEnc = c.PrivateKeyEnc,
                    CredentialType = c.CredentialType.ToString(),
                    FolderId = c.FolderId, KeyVersion = c.KeyVersion, Tags = c.Tags
                }).ToListAsync(ct);

            payload.VaultFolders = await _db.VaultFolders
                .Select(f => new BackupVaultFolderDto
                {
                    Id = f.Id, Name = f.Name, Description = f.Description,
                    ParentFolderId = f.ParentFolderId, OwnerUserId = f.OwnerUserId
                }).ToListAsync(ct);
        }

        if (includeUsers)
        {
            payload.Users = await _db.Users.IgnoreQueryFilters()
                .Select(u => new BackupUserDto
                {
                    Id = u.Id, Username = u.Username, Email = u.Email,
                    DisplayName = u.DisplayName ?? u.Username, PasswordHash = u.PasswordHash
                }).ToListAsync(ct);
        }

        if (includePolicies)
        {
            payload.Policies = await _db.Policies
                .Select(p => new BackupPolicyDto
                {
                    Id = p.Id, Name = p.Name, PolicyType = p.PolicyType, PolicyJson = p.PolicyJson
                }).ToListAsync(ct);
        }

        return payload;
    }

    private static byte[] EncryptWithPassphrase(byte[] plaintext, string passphrase)
    {
        var salt = RandomNumberGenerator.GetBytes(16);
        var nonce = RandomNumberGenerator.GetBytes(12);
        using var kdf = new Rfc2898DeriveBytes(passphrase, salt, 200_000, HashAlgorithmName.SHA256);
        var key = kdf.GetBytes(32);

        var ciphertext = new byte[plaintext.Length];
        var tag = new byte[16];
        using var aes = new AesGcm(key, 16);
        aes.Encrypt(nonce, plaintext, ciphertext, tag);

        var magic = Encoding.ASCII.GetBytes(Magic);
        using var ms = new MemoryStream();
        ms.Write(magic);
        ms.WriteByte(FormatVersion);
        ms.Write(salt);
        ms.Write(nonce);
        ms.Write(BitConverter.GetBytes(ciphertext.Length));
        ms.Write(ciphertext);
        ms.Write(tag);
        return ms.ToArray();
    }

    private static byte[] DecryptWithPassphrase(byte[] data, string passphrase)
    {
        using var ms = new MemoryStream(data);
        var magic = new byte[4]; ms.ReadExactly(magic);
        if (Encoding.ASCII.GetString(magic) != Magic) throw new InvalidDataException("Not a PAM backup file");
        ms.ReadByte();

        var salt = new byte[16]; ms.ReadExactly(salt);
        var nonce = new byte[12]; ms.ReadExactly(nonce);
        var lenBytes = new byte[4]; ms.ReadExactly(lenBytes);
        var ciphertextLen = BitConverter.ToInt32(lenBytes);
        var ciphertext = new byte[ciphertextLen]; ms.ReadExactly(ciphertext);
        var tag = new byte[16]; ms.ReadExactly(tag);

        using var kdf = new Rfc2898DeriveBytes(passphrase, salt, 200_000, HashAlgorithmName.SHA256);
        var key = kdf.GetBytes(32);

        var plaintext = new byte[ciphertextLen];
        using var aes = new AesGcm(key, 16);
        aes.Decrypt(nonce, ciphertext, tag, plaintext);
        return plaintext;
    }
}

public class BackupCredentialDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Username { get; set; }
    public byte[]? PasswordEnc { get; set; }
    public byte[]? PrivateKeyEnc { get; set; }
    public string CredentialType { get; set; } = "Password";
    public Guid FolderId { get; set; }
    public int KeyVersion { get; set; }
    public string? Tags { get; set; }
}

public class BackupVaultFolderDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string? Description { get; set; }
    public Guid? ParentFolderId { get; set; }
    public Guid? OwnerUserId { get; set; }
}

public class BackupUserDto
{
    public Guid Id { get; set; }
    public string Username { get; set; } = string.Empty;
    public string? Email { get; set; }
    public string DisplayName { get; set; } = string.Empty;
    public string? PasswordHash { get; set; }
}

public class BackupPolicyDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = string.Empty;
    public string PolicyType { get; set; } = string.Empty;
    public string PolicyJson { get; set; } = "{}";
}

public class BackupPayload
{
    public string Version { get; set; } = "1.0";
    public string Scope { get; set; } = "All";
    public DateTime CreatedAtUtc { get; set; }
    public string Hostname { get; set; } = string.Empty;
    public List<BackupCredentialDto>? Credentials { get; set; }
    public List<BackupVaultFolderDto>? VaultFolders { get; set; }
    public List<BackupUserDto>? Users { get; set; }
    public List<BackupPolicyDto>? Policies { get; set; }
}

/// <summary>
/// Runs scheduled backups based on SystemConfig["backup.schedule.enabled"] and ["backup.schedule.hourUtc"].
/// </summary>
public sealed class BackupSchedulerService : BackgroundService
{
    private readonly IServiceScopeFactory _scopeFactory;
    private readonly ILogger<BackupSchedulerService> _logger;

    public BackupSchedulerService(IServiceScopeFactory scopeFactory, ILogger<BackupSchedulerService> logger)
    {
        _scopeFactory = scopeFactory;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        await Task.Delay(TimeSpan.FromMinutes(2), stoppingToken);

        while (!stoppingToken.IsCancellationRequested)
        {
            try { await RunIfScheduledAsync(stoppingToken); }
            catch (OperationCanceledException) { break; }
            catch (Exception ex) { _logger.LogError(ex, "Backup scheduler error"); }
            await Task.Delay(TimeSpan.FromMinutes(60), stoppingToken);
        }
    }

    private async Task RunIfScheduledAsync(CancellationToken ct)
    {
        using var scope = _scopeFactory.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<OrkunPamDbContext>();

        var enabled = await db.SystemConfigs.FindAsync(new object[] { "backup.schedule.enabled" }, ct);
        if (enabled?.Value != "true") return;

        var hourCfg = await db.SystemConfigs.FindAsync(new object[] { "backup.schedule.hourUtc" }, ct);
        int scheduledHour = int.TryParse(hourCfg?.Value, out var h) ? h : 2;
        if (DateTime.UtcNow.Hour != scheduledHour) return;

        var lastRun = await db.BackupRecords
            .Where(b => b.Status == "Completed" && b.InitiatedBy == "system")
            .OrderByDescending(b => b.CompletedAtUtc)
            .FirstOrDefaultAsync(ct);

        if (lastRun?.CompletedAtUtc.HasValue == true &&
            (DateTime.UtcNow - lastRun.CompletedAtUtc.Value).TotalHours < 23)
            return;

        var passphraseCfg = await db.SystemConfigs.FindAsync(new object[] { "backup.schedule.passphrase" }, ct);
        var passphrase = passphraseCfg?.Value;
        if (string.IsNullOrEmpty(passphrase))
        {
            _logger.LogWarning("Scheduled backup skipped — backup.schedule.passphrase not configured");
            return;
        }

        var backupSvc = scope.ServiceProvider.GetRequiredService<IBackupService>();
        var scopeCfg = await db.SystemConfigs.FindAsync(new object[] { "backup.schedule.scope" }, ct);
        var backupScope = scopeCfg?.Value ?? "All";

        _logger.LogInformation("Running scheduled backup (scope: {Scope})", backupScope);
        await backupSvc.CreateBackupAsync(backupScope, passphrase, "system", ct);
    }
}
