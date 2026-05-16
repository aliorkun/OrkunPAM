namespace OrkunPAM.Domain.Entities.Identity;

public class EmailOtpToken
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }
    public string HashedCode { get; set; } = "";
    public DateTime ExpiresAtUtc { get; set; }
    public bool IsUsed { get; set; }
    public int FailedAttempts { get; set; }
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public string? RequestedFromIp { get; set; }
}
