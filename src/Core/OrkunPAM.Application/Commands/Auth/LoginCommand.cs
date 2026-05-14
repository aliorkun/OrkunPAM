using MediatR;
using OrkunPAM.Application.DTOs;
using OrkunPAM.SharedKernel;

namespace OrkunPAM.Application.Commands.Auth;

public record LoginCommand(
    string Username,
    string Password,
    string? TotpCode,
    string IpAddress) : IRequest<Result<LoginResponse>>;
