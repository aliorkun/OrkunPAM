using OrkunPAM.Domain.Enums;

namespace OrkunPAM.Domain.Entities.Crypto;

public class MasterKey
{
    public int Id { get; set; }
    public int KeyVersion { get; set; }
    public byte[] EncryptedKeyMaterial { get; set; } = [];
    public KeyStatus KeyStatus { get; set; } = KeyStatus.Active;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? RotatedAtUtc { get; set; }
}

public class DataEncryptionKey
{
    public int Id { get; set; }
    public int KeyVersion { get; set; }
    public string Purpose { get; set; } = string.Empty; // "VaultCredentials", "SessionRecordings", etc.
    public int EncryptedByMasterKeyVersion { get; set; }
    public byte[] EncryptedKeyMaterial { get; set; } = [];
    public bool IsActive { get; set; } = true;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
