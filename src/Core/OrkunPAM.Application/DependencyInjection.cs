using FluentValidation;
using MediatR;
using Microsoft.Extensions.DependencyInjection;
using OrkunPAM.Application.Behaviors;

namespace OrkunPAM.Application;

public static class DependencyInjection
{
    /// <summary>
    /// Registers Application layer services: MediatR handlers, FluentValidation validators,
    /// and pipeline behaviors (validation + logging).
    /// </summary>
    public static IServiceCollection AddApplication(this IServiceCollection services)
    {
        var assembly = typeof(DependencyInjection).Assembly;

        // MediatR - auto-discover all handlers in this assembly
        services.AddMediatR(cfg => cfg.RegisterServicesFromAssembly(assembly));

        // FluentValidation - auto-discover all validators in this assembly
        services.AddValidatorsFromAssembly(assembly);

        // Pipeline behaviors (order matters: logging wraps validation wraps handler)
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(LoggingBehavior<,>));
        services.AddTransient(typeof(IPipelineBehavior<,>), typeof(ValidationBehavior<,>));

        return services;
    }
}
