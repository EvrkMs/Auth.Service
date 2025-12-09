using Auth.Domain.Entity;
using Auth.Host.Models.Telegram;
using Auth.Telegram;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace Auth.Host.Endpoints;

public static class TelegramEndpoints
{
    public static IEndpointRouteBuilder MapTelegramEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/telegram").RequireAuthorization();

        group.MapGet("/me", GetTelegramProfileAsync);
        group.MapPost("/bind", BindTelegramAsync);
        group.MapPost("/unbind", UnbindTelegramAsync);

        return app;
    }

    private static async Task<IResult> GetTelegramProfileAsync(
        HttpContext context,
        UserManager<Employee> userManager,
        TelegramBindingService bindingService,
        CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var profile = await bindingService.GetProfileAsync(user, cancellationToken);
        if (profile is null)
        {
            return Results.NotFound();
        }

        return Results.Ok(MapResponse(profile));
    }

    private static async Task<IResult> BindTelegramAsync(
        HttpContext context,
        TelegramBindRequest request,
        UserManager<Employee> userManager,
        TelegramBindingService bindingService,
        CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var authData = new TelegramAuthData(
            request.Id,
            request.FirstName,
            request.LastName,
            request.Username,
            request.PhotoUrl,
            request.AuthDate,
            request.Hash ?? string.Empty);

        var command = new TelegramBindCommand(authData, request.Password ?? string.Empty);

        try
        {
            var profile = await bindingService.BindTelegramAsync(user, command, cancellationToken);
            return Results.Ok(MapResponse(profile));
        }
        catch (TelegramValidationException ex)
        {
            return Results.BadRequest(new { error = ex.Code, detail = ex.Message });
        }
        catch (TelegramBindingException ex)
        {
            return Results.BadRequest(new { error = ex.Code, detail = ex.Message });
        }
    }

    private static async Task<IResult> UnbindTelegramAsync(
        HttpContext context,
        TelegramUnbindRequest request,
        UserManager<Employee> userManager,
        TelegramBindingService bindingService,
        CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        try
        {
            await bindingService.UnbindAsync(user, new TelegramUnbindCommand(request.Password ?? string.Empty), cancellationToken);
            return Results.NoContent();
        }
        catch (TelegramBindingException ex)
        {
            return Results.BadRequest(new { error = ex.Code, detail = ex.Message });
        }
    }

    private static TelegramProfileResponse MapResponse(TelegramProfile profile) =>
        new(
            profile.Id,
            profile.Username,
            profile.FirstName,
            profile.LastName,
            profile.PhotoUrl,
            profile.BoundAt);
}
