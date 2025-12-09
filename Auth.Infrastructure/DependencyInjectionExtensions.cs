using System;
using Auth.Application.Abstractions;
using Auth.Application.Sessions;
using Auth.Application.Tokens;
using Auth.Domain.Tokens;
using Auth.EntityFramework;
using Auth.EntityFramework.Repositories;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Auth.Infrastructure;

public static class DependencyInjectionExtensions
{
    public static IServiceCollection AddAuthInfrastructure(
        this IServiceCollection services,
        Action<TokenOptions>? configureOptions = null)
    {
        ArgumentNullException.ThrowIfNull(services);

        services.TryAddSingleton<TokenOptions>(_ =>
        {
            var options = new TokenOptions();
            configureOptions?.Invoke(options);
            return options;
        });

        services.TryAddSingleton<ISystemClock, SystemClock>();
        services.TryAddSingleton<ITokenValueGenerator, DefaultTokenValueGenerator>();
        services.TryAddSingleton<ITokenClaimsFactory, DefaultTokenClaimsFactory>();

        services.TryAddScoped<ISessionRepository, SessionRepository>();
        services.TryAddScoped<ITokenRepository, TokenRepository>();
        services.TryAddScoped<IUnitOfWork, UnitOfWork>();

        services.TryAddScoped<SessionService>();
        services.TryAddScoped<TokenService>();
        services.TryAddScoped<TokenRefreshService>();

        return services;
    }
}
