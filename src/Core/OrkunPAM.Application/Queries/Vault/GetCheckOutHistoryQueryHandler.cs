using MediatR;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Vault;

public sealed class GetCheckOutHistoryQueryHandler : IRequestHandler<GetCheckOutHistoryQuery, Result<PagedResultDto<CheckOutHistoryDto>>>
{
    private readonly ICredentialRepository _credentials;

    public GetCheckOutHistoryQueryHandler(ICredentialRepository credentials) => _credentials = credentials;

    public async Task<Result<PagedResultDto<CheckOutHistoryDto>>> Handle(GetCheckOutHistoryQuery request, CancellationToken cancellationToken)
    {
        var paged = await _credentials.GetCheckOutHistoryAsync(
            request.Page, request.PageSize, request.CredentialId, request.UserId, cancellationToken);

        var dto = paged.ToDto(h => new CheckOutHistoryDto(
            h.Id, h.CredentialId, h.UserId,
            h.CheckedOutAtUtc, h.CheckedInAtUtc,
            h.Reason, h.TicketNumber, h.WasAutoCheckedIn));

        return Result<PagedResultDto<CheckOutHistoryDto>>.Success(dto);
    }
}
