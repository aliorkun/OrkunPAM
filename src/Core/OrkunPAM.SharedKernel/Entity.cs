namespace OrkunPAM.SharedKernel;

public abstract class Entity
{
    public Guid Id { get; set; } = Guid.NewGuid();

    public override bool Equals(object? obj) =>
        obj is Entity other && Id == other.Id;

    public override int GetHashCode() => Id.GetHashCode();
}

public abstract class AuditableEntity : Entity
{
    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime UpdatedAtUtc { get; set; } = DateTime.UtcNow;
    public Guid? CreatedBy { get; set; }
    public Guid? UpdatedBy { get; set; }
}

public abstract class SoftDeletableEntity : AuditableEntity
{
    public bool IsDeleted { get; set; }
    public DateTime? DeletedAtUtc { get; set; }
    public Guid? DeletedBy { get; set; }
}
