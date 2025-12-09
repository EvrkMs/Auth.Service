using Auth.Host.Oidc;
using Microsoft.AspNetCore.Http;
using Microsoft.IdentityModel.Tokens;

namespace Auth.Host.Endpoints;

public static class OidcEndpoints
{
    public static void MapOidcEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/.well-known/openid-configuration", (HttpContext context, OidcOptions options) =>
        {
            var issuer = ResolveIssuer(context, options);
            var metadata = new
            {
                issuer,
                authorization_endpoint = $"{issuer}/connect/authorize",
                token_endpoint = $"{issuer}/connect/token",
                userinfo_endpoint = $"{issuer}/connect/userinfo",
                jwks_uri = $"{issuer}/.well-known/jwks.json",
                response_types_supported = new[] { "code" },
                subject_types_supported = new[] { "public" },
                id_token_signing_alg_values_supported = new[] { SecurityAlgorithms.RsaSha256 },
                code_challenge_methods_supported = new[] { "S256" },
                grant_types_supported = new[] { "authorization_code", "refresh_token" },
                token_endpoint_auth_methods_supported = new[] { "none" },
                scopes_supported = new[] { "openid", "profile", "offline_access" },
                claims_supported = new[] { "sub", "name", "preferred_username", "sid" }
            };

            return Results.Json(metadata);
        });

        app.MapGet("/.well-known/jwks.json", (OidcSigningKeyProvider keyProvider) =>
        {
            var key = keyProvider.GetJsonWebKey();
            return Results.Json(new { keys = new[] { key } });
        });
    }

    private static string ResolveIssuer(HttpContext context, OidcOptions options)
    {
        if (!string.IsNullOrWhiteSpace(options.Issuer))
        {
            return options.Issuer.TrimEnd('/');
        }

        var request = context.Request;
        var issuer = $"{request.Scheme}://{request.Host}";
        return issuer.TrimEnd('/');
    }
}
