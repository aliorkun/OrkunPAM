using OrkunPAM.SharedKernel;

namespace OrkunPAM.Domain.Entities.Session;

public class SessionAnnotation : Entity
{
    public Guid SessionId { get; set; }
    public Guid AuthorUserId { get; set; }
    public string AuthorUsername { get; set; } = string.Empty;
    public string Note { get; set; } = string.Empty;
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
}
