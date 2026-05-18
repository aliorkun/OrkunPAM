namespace OrkunPAM.Domain.Entities.Session;

public class SessionObserverLog
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid SessionId { get; set; }
    public Guid ObserverUserId { get; set; }
    public string? ObserverUsername { get; set; }
    public DateTime JoinedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? LeftAtUtc { get; set; }
}
