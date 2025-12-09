using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Auth.Telegram;

public static class ServiceCollectionExtensions
{
    public static IServiceCollection AddTelegramIntegration(this IServiceCollection services, IConfiguration configuration)
    {
        services.Configure<TelegramOptions>(configuration.GetSection("Telegram"));
        services.AddSingleton<TelegramAuthValidator>();
        services.AddScoped<TelegramBindingService>();
        return services;
    }
}
