using System.Collections.Concurrent;
using Microsoft.Extensions.Configuration;
using System.Linq;

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
                    AllowedScopes = child["Scopes"]?.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries) ?? Array.Empty<string>(),
                    PostLogoutRedirectUri = child["PostLogoutRedirectUri"]
                };

                registration.PostLogoutRedirectUri ??= registration.RedirectUri;

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
                AllowedScopes = new[] { "openid", "profile", "offline_access" },
                PostLogoutRedirectUri = "http://localhost:4173/logout"
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

    public ClientRegistration? FindByLogoutRedirectUri(string? uri)
    {
        if (string.IsNullOrWhiteSpace(uri))
        {
            return null;
        }

        return _clients.Values.FirstOrDefault(client =>
            string.Equals(client.PostLogoutRedirectUri ?? client.RedirectUri, uri, StringComparison.Ordinal));
    }
}

public sealed class ClientRegistration
{
    public string ClientId { get; init; } = string.Empty;

    public string DisplayName { get; init; } = string.Empty;

    public string RedirectUri { get; init; } = string.Empty;

    public IReadOnlyCollection<string> AllowedScopes { get; init; } = Array.Empty<string>();

    public string? PostLogoutRedirectUri { get; set; }
}
