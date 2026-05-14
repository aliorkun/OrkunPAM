using MediatR;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Vault;

public record GetCredentialsQuery(
    int Page = 1,
    int PageSize = 20,
    string? Search = null,
    Guid? FolderId = null) : IRequest<Result<PagedResultDto<CredentialDto>>>;
