using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;

namespace Auth.Host.Services;

public sealed class ClientRegistry
{
    private readonly ConcurrentDictionary<string, ClientRegistration> _clients;

    public ClientRegistry(IConfiguration configuration)
    {
        _clients = new ConcurrentDictionary<string, ClientRegistration>(StringComparer.Ordinal);

        var section = configuration.GetSection("AuthClients");
        if (section.Exists())
        {
            foreach (var child in section.GetChildren())
            {
                var registration = new ClientRegistration
                {
                    ClientId = child["ClientId"] ?? child.Key,
                    DisplayName = child["DisplayName"] ?? child.Key,
                    RedirectUri = child["RedirectUri"] ?? string.Empty,
                    AllowedScopes = child["Scopes"]?.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? Array.Empty<string>()
                };

                if (!string.IsNullOrWhiteSpace(registration.ClientId) && !string.IsNullOrWhiteSpace(registration.RedirectUri))
                {
                    _clients[registration.ClientId] = registration;
                }
            }
        }

        if (_clients.IsEmpty)
        {
            _clients["spa-localhost"] = new ClientRegistration
            {
                ClientId = "spa-localhost",
                DisplayName = "Localhost SPA",
                RedirectUri = "http://localhost:4173/callback",
                AllowedScopes = new[] { "openid", "profile", "offline_access" }
            };
        }
    }

    public ClientRegistration? Find(string clientId)
    {
        if (string.IsNullOrWhiteSpace(clientId))
        {
            return null;
        }

        _clients.TryGetValue(clientId, out var registration);
        return registration;
    }
}

public sealed class ClientRegistration
{
    public string ClientId { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public string RedirectUri { get; init; } = string.Empty;

    public IReadOnlyCollection<string> AllowedScopes { get; init; } = Array.Empty<string>();
}
