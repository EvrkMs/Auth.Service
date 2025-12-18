using Auth.Oidc.Oidc;
using Auth.Oidc.Services;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Oidc.Extensions;

public static class OidcServiceCollectionExtensions
{
    public static IServiceCollection AddOidcCore(this IServiceCollection services, IConfiguration configuration)
    {
        var oidcSection = configuration.GetSection("Oidc");
        var oidcOptions = oidcSection.Get<OidcOptions>() ?? new OidcOptions();
        oidcOptions.SigningKey ??= configuration["OIDC__SIGNING_KEY"];
        var configuredIssuer =
            configuration["OIDC__ISSUER"]
            ?? configuration["AUTH_ISSUER"]
            ?? configuration["AUTH_DOMAIN"]
            ?? configuration["AUTH_HOST_DOMAIN"];

        if (!string.IsNullOrWhiteSpace(configuredIssuer))
        {
            oidcOptions.Issuer = configuredIssuer;
        }

        services.AddSingleton(oidcOptions);
        services.AddSingleton<OidcSigningKeyProvider>();
        services.AddSingleton<OidcIdTokenFactory>();
        services.AddSingleton<ClientRegistry>();
        services.AddSingleton<AuthorizationCodeStore>();

        return services;
    }

    public static IServiceCollection AddOidcCoreWithCors(this IServiceCollection services, IConfiguration configuration)
    {
        services.AddOidcCore(configuration);

        var origins = OidcClientOrigins.Resolve(configuration);
        services.AddCors(options =>
        {
            options.AddPolicy(OidcCorsDefaults.PolicyName, policy =>
            {
                policy.WithOrigins(origins)
                    .AllowAnyHeader()
                    .AllowAnyMethod()
                    .AllowCredentials();
            });
        });

        return services;
    }
}
