using System;
using System.IO;
using System.Threading.Tasks;
using Auth.Domain.Entity;
using Auth.EntityFramework;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Host.Extensions;

public static class AuthHostServiceCollectionExtensions
{
    public static IServiceCollection AddAuthDatabase(this IServiceCollection services, IConfiguration configuration)
    {
        var connectionString = configuration.GetConnectionString("Default")
            ?? configuration["DATABASE__CONNECTION"];

        services.AddDbContext<AppDbContext>(options =>
        {
            var resolvedConnection = connectionString
                ?? "Host=localhost;Port=5432;Database=auth;Username=auth;Password=authpassword";
            options.UseNpgsql(resolvedConnection);
        });

        return services;
    }

    public static IServiceCollection AddAuthDataProtection(this IServiceCollection services, IConfiguration configuration)
    {
        var dataProtectionPath = configuration["DATA_PROTECTION_PATH"] ?? "/app/keys/data-protection";
        services.AddDataProtection()
            .PersistKeysToFileSystem(new DirectoryInfo(dataProtectionPath));

        return services;
    }

    public static IServiceCollection AddAuthIdentity(this IServiceCollection services)
    {
        services
            .AddIdentityCore<Employee>()
            .AddRoles<IdentityRole<Guid>>()
            .AddEntityFrameworkStores<AppDbContext>()
            .AddSignInManager()
            .AddDefaultTokenProviders();

        services.ConfigureApplicationCookie(options =>
        {
            options.Events ??= new CookieAuthenticationEvents();
            options.Events.OnRedirectToLogin = context =>
            {
                if (ShouldReturnApiStatus(context.Request))
                {
                    context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                    return Task.CompletedTask;
                }

                context.Response.Redirect(context.RedirectUri);
                return Task.CompletedTask;
            };

            options.Events.OnRedirectToAccessDenied = context =>
            {
                if (ShouldReturnApiStatus(context.Request))
                {
                    context.Response.StatusCode = StatusCodes.Status403Forbidden;
                    return Task.CompletedTask;
                }

                context.Response.Redirect(context.RedirectUri);
                return Task.CompletedTask;
            };

            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });

        services.AddAuthentication(options =>
        {
            options.DefaultAuthenticateScheme = IdentityConstants.ApplicationScheme;
            options.DefaultChallengeScheme = IdentityConstants.ApplicationScheme;
            options.DefaultSignInScheme = IdentityConstants.ApplicationScheme;
        }).AddIdentityCookies();

        services.AddAuthorization();
        return services;
    }

    public static IServiceCollection AddAuthAntiforgery(this IServiceCollection services)
    {
        services.AddAntiforgery(options =>
        {
            options.HeaderName = "X-CSRF-TOKEN";
            options.Cookie.Name = "__Host-af";
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
            // Antiforgery cookie должен ходить между поддоменами, поэтому SameSite=None при сохранении Secure.
            options.Cookie.SameSite = SameSiteMode.None;
        });

        return services;
    }

    public static IServiceCollection AddAuthInfrastructureDefaults(this IServiceCollection services)
    {
        services.AddAuthInfrastructure(options =>
        {
            options.AccessTokenLifetime = TimeSpan.FromMinutes(5);
            options.RefreshTokenLifetime = TimeSpan.FromDays(30);
        });

        return services;
    }

    private static bool ShouldReturnApiStatus(HttpRequest request)
    {
        var path = request.Path;
        if (path.StartsWithSegments("/api", StringComparison.OrdinalIgnoreCase))
        {
            return true;
        }

        if (request.Headers.TryGetValue("Accept", out var accept) &&
            !Microsoft.Extensions.Primitives.StringValues.IsNullOrEmpty(accept) &&
            accept.Any(value => value.Contains("application/json", StringComparison.OrdinalIgnoreCase)))
        {
            return true;
        }

        return false;
    }
}
