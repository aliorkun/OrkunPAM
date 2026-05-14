using MediatR;
using OrkunPAM.Application.DTOs;
using OrkunPAM.Domain.Enums;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Queries.Sessions;

public record GetSessionsQuery(
    int Page = 1,
    int PageSize = 20,
    SessionStatus? Status = null,
    SessionType? Type = null,
    Guid? UserId = null) : IRequest<Result<PagedResultDto<SessionDto>>>;
