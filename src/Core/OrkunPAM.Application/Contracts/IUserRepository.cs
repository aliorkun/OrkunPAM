using OrkunPAM.Domain.Entities.Identity;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Extended user repository with query capabilities beyond generic IRepository.
/// </summary>
public interface IUserRepository : IRepository<User>
{
    Task<User?> GetByUsernameAsync(string username, CancellationToken ct = default);
    Task<PagedResult<User>> GetPagedAsync(int page, int pageSize, string? search, CancellationToken ct = default);
}
