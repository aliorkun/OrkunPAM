using OrkunPAM.Domain.Entities.Vault;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Contracts;

/// <summary>
/// Extended credential repository with paged query support.
/// </summary>
public interface ICredentialRepository : IRepository<Credential>
{
    Task<PagedResult<Credential>> GetPagedAsync(int page, int pageSize, string? search, Guid? folderId, CancellationToken ct = default);
    Task<PagedResult<CheckOutHistory>> GetCheckOutHistoryAsync(int page, int pageSize, Guid? credentialId, Guid? userId, CancellationToken ct = default);
}
