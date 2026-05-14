using OrkunPAM.Domain.Entities.Session;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Extended session repository with paged query and filter support.
/// </summary>
public interface ISessionRepository : IRepository<ProxySession>
{
    Task<PagedResult<ProxySession>> GetPagedAsync(int page, int pageSize, SessionStatus? status, SessionType? type, Guid? userId, CancellationToken ct = default);
}
