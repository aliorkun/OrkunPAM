using MediatR;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Vault;

public record GetCheckOutHistoryQuery(
    int Page = 1,
    int PageSize = 20,
    Guid? CredentialId = null,
    Guid? UserId = null) : IRequest<Result<PagedResultDto<CheckOutHistoryDto>>>;
