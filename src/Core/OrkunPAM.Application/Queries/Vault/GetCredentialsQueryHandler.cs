using MediatR;
using OrkunPAM.Application.Contracts;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Vault;

public sealed class GetCredentialsQueryHandler : IRequestHandler<GetCredentialsQuery, Result<PagedResultDto<CredentialDto>>>
{
    private readonly ICredentialRepository _credentials;

    public GetCredentialsQueryHandler(ICredentialRepository credentials) => _credentials = credentials;

    public async Task<Result<PagedResultDto<CredentialDto>>> Handle(GetCredentialsQuery request, CancellationToken cancellationToken)
    {
        var paged = await _credentials.GetPagedAsync(request.Page, request.PageSize, request.Search, request.FolderId, cancellationToken);

        var dto = paged.ToDto(c => new CredentialDto(
            c.Id, c.Name, c.Description, c.CredentialType, c.Username,
            c.FolderId, c.DeviceId, c.Status, c.RequiresApproval,
            c.CheckedOutByUserId, c.CheckedOutAtUtc,
            c.LastRotatedAtUtc, c.NextRotationAtUtc, c.CreatedAtUtc));

        return Result<PagedResultDto<CredentialDto>>.Success(dto);
    }
}
