using Auth.Oidc.Endpoints;
using Microsoft.AspNetCore.Routing;

namespace Auth.Oidc.Extensions;

public static class OidcEndpointRouteBuilderExtensions
{
    public static IEndpointRouteBuilder MapOidcCoreEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapTokenEndpoints();
        app.MapConnectEndpoints();
        app.MapOidcEndpoints();
        return app;
    }
}
