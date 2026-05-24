namespace OrkunPAM.Domain.Entities.Identity;

public class HardwareToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string SerialNumber { get; set; } = "";
    public byte[] SecretKeyEnc { get; set; } = [];
    public HardwareTokenType TokenType { get; set; } = HardwareTokenType.Totp;
    public long CounterValue { get; set; }
    public HardwareTokenAlgorithm Algorithm { get; set; } = HardwareTokenAlgorithm.Sha1;
    public int Digits { get; set; } = 6;
    public int PeriodSeconds { get; set; } = 30;
    public bool IsActive { get; set; } = true;
    public string? Label { get; set; }
    public DateTime ProvisionedAtUtc { get; set; } = DateTime.UtcNow;

    public User? User { get; set; }
}

public enum HardwareTokenType { Totp, Hotp }
public enum HardwareTokenAlgorithm { Sha1, Sha256, Sha512 }
