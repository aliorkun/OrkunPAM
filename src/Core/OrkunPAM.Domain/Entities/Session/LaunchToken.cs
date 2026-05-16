namespace OrkunPAM.Domain.Entities.Session;

public class LaunchToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public Guid DeviceId { get; set; }
    public Guid CredentialId { get; set; }
    public string Protocol { get; set; } = "";      // "ssh" | "rdp"
    public string TargetHost { get; set; } = "";
    public int TargetPort { get; set; }
    public DateTime ExpiresAtUtc { get; set; }
    public bool IsUsed { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public string? CreatedByUsername { get; set; }
    public string? RedeemedFromIp { get; set; }
    public DateTime? RedeemedAtUtc { get; set; }
}
