using Microsoft.AspNetCore.Builder;

namespace Auth.Oidc.Extensions;

public static class OidcApplicationBuilderExtensions
{
    public static WebApplication UseOidcCore(this WebApplication app)
    {
        app.UseCors(OidcCorsDefaults.PolicyName);
        app.MapOidcCoreEndpoints();
        return app;
    }
}
