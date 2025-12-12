using Microsoft.AspNetCore.Antiforgery;

namespace Auth.Host.Endpoints;

public static class AntiforgeryEndpoints
{
    public static void MapAntiforgeryEndpoints(this IEndpointRouteBuilder app)
    {
        app.MapGet("/api/antiforgery/token", (IAntiforgery antiforgery, HttpContext context) =>
        {
            var tokens = antiforgery.GetAndStoreTokens(context);
            return Results.Ok(new { token = tokens.RequestToken });
        }).RequireAuthorization();
    }
}
