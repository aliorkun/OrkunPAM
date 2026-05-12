using Microsoft.EntityFrameworkCore;
using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.Persistence;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Identity.Services;

public interface IPasswordPolicyService
{
    Task<Result> ValidateAsync(string password, Guid? userId = null, CancellationToken ct = default);
    Task RecordPasswordAsync(Guid userId, string passwordHash, CancellationToken ct = default);
    DateTime ComputeExpiry();
}

public sealed class PasswordPolicyService : IPasswordPolicyService
{
    private const int MinLength = 12;
    private const int HistoryCount = 12;
    private const int MaxAgeDays = 90;
    private static readonly char[] SpecialChars = "!@#$%^&*()_+-=[]{}|;':\",./<>?".ToCharArray();

    private readonly OrkunPamDbContext _db;
    private readonly IPasswordHasher _hasher;

    public PasswordPolicyService(OrkunPamDbContext db, IPasswordHasher hasher)
    {
        _db = db;
        _hasher = hasher;
    }

    public async Task<Result> ValidateAsync(string password, Guid? userId = null, CancellationToken ct = default)
    {
        var errors = new List<string>();

        if (password.Length < MinLength)
            errors.Add($"Password must be at least {MinLength} characters");
        if (!password.Any(char.IsUpper))
            errors.Add("Password must contain at least one uppercase letter");
        if (!password.Any(char.IsLower))
            errors.Add("Password must contain at least one lowercase letter");
        if (!password.Any(char.IsDigit))
            errors.Add("Password must contain at least one digit");
        if (!password.Any(c => SpecialChars.Contains(c)))
            errors.Add("Password must contain at least one special character (!@#$%^&*...)");

        if (errors.Count > 0)
            return Result.Failure(Error.Validation(string.Join("; ", errors)));

        if (userId.HasValue)
        {
            var history = await _db.UserPasswordHistories
                .Where(h => h.UserId == userId.Value)
                .OrderByDescending(h => h.CreatedAtUtc)
                .Take(HistoryCount)
                .Select(h => h.PasswordHash)
                .ToListAsync(ct);

            if (history.Any(h => _hasher.Verify(password, h)))
                return Result.Failure(Error.Validation($"Password cannot match any of the last {HistoryCount} passwords"));
        }

        return Result.Success();
    }

    public async Task RecordPasswordAsync(Guid userId, string passwordHash, CancellationToken ct = default)
    {
        _db.UserPasswordHistories.Add(new UserPasswordHistory
        {
            UserId = userId,
            PasswordHash = passwordHash,
            CreatedAtUtc = DateTime.UtcNow
        });
        await _db.SaveChangesAsync(ct);
    }

    public DateTime ComputeExpiry() => DateTime.UtcNow.AddDays(MaxAgeDays);
}
