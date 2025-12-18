using Microsoft.Extensions.Configuration;

namespace Auth.Oidc.Extensions;

public static class OidcClientOrigins
{
    public static string[] Resolve(IConfiguration configuration)
    {
        var origins = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        var section = configuration.GetSection("AuthClients");
        if (section.Exists())
        {
            foreach (var child in section.GetChildren())
            {
                var redirect = child["RedirectUri"];
                if (string.IsNullOrWhiteSpace(redirect))
                {
                    continue;
                }

                if (Uri.TryCreate(redirect, UriKind.Absolute, out var uri))
                {
                    origins.Add(uri.GetLeftPart(UriPartial.Authority));
                }
            }
        }

        if (origins.Count == 0)
        {
            origins.Add("http://localhost:4173");
        }

        return origins.ToArray();
    }
}
