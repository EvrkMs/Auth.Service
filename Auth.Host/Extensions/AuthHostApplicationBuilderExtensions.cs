using System;
using System.Threading.Tasks;
using Auth.EntityFramework;
using Auth.Host.Services;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Host.Extensions;

public static class AuthHostApplicationBuilderExtensions
{
    public static async Task<WebApplication> ApplyAuthMigrationsAsync(this WebApplication app)
    {
        using var scope = app.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
        db.Database.Migrate();

        var seeder = scope.ServiceProvider.GetRequiredService<IdentitySeeder>();
        await seeder.SeedAsync();

        return app;
    }

    public static IApplicationBuilder UseAuthCsp(this IApplicationBuilder app, IConfiguration configuration)
    {
        return app.Use(async (context, next) =>
        {
            var csp = configuration["SECURITY__CSP"];
            if (string.IsNullOrWhiteSpace(csp))
            {
                csp =
                    "default-src 'self'; " +
                    "base-uri 'self'; " +
                    "object-src 'none'; " +
                    "frame-ancestors 'none'; " +

                    // Telegram widget iframe
                    "frame-src https://oauth.telegram.org; " +

                    "form-action 'self'; " +
                    "img-src 'self' data: https://telegram.org; " +
                    "font-src 'self' https://cdnjs.cloudflare.com; " +
                    "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; " +

                    // telegram-widget.js uses eval()
                    "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://telegram.org https://cdn.tailwindcss.com; " +

                    // Telegram API calls
                    "connect-src 'self' https://telegram.org https://oauth.telegram.org; " +

                    "upgrade-insecure-requests";
            }
            context.Response.Headers["Content-Security-Policy"] = csp;
            await next();
        });
    }

    public static WebApplication UseAuthPipeline(this WebApplication app, IConfiguration configuration)
    {
        app.UseHttpsRedirection();
        app.UseAuthCsp(configuration);
        app.UseAuthentication();
        app.UseAuthorization();
        return app;
    }
}
