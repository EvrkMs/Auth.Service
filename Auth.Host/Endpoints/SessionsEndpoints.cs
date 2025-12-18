using Auth.Application.Sessions;
using Auth.Application.Tokens;
using Auth.Domain.Entity;
using Auth.Host.Models.Sessions;
using Auth.Oidc.Sessions;
using Auth.Host.Filters;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using System.Linq;

namespace Auth.Host.Endpoints;

public static class SessionsEndpoints
{
    public static IEndpointRouteBuilder MapSessionsEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/api/sessions").RequireAuthorization();

        group.MapGet("/", GetSessionsAsync);
        group.MapGet("/current", GetCurrentSessionAsync);
        group.MapPost("/{id:guid}/revoke", RevokeSessionAsync).AddEndpointFilter<AntiforgeryValidationFilter>();
        group.MapPost("/revoke-all", RevokeAllSessionsAsync).AddEndpointFilter<AntiforgeryValidationFilter>();

        return app;
    }

    private static async Task<IResult> GetSessionsAsync(
        HttpContext context,
        UserManager<Employee> userManager,
        ISessionRepository sessionRepository,
        ITokenValueGenerator tokenValueGenerator,
        CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var sessions = await sessionRepository.GetByEmployeeIdAsync(user.Id, cancellationToken);
        var currentHash = SessionCookieHelper.GetSessionHandleHash(context, tokenValueGenerator);

        var filtered = sessions.Where(s => s.RevokedAt is null);
        var response = filtered
            .Select(session => MapSession(session, currentHash))
            .ToList();

        return Results.Ok(response);
    }

    private static async Task<IResult> GetCurrentSessionAsync(
        HttpContext context,
        ISessionRepository sessionRepository,
        ITokenValueGenerator tokenValueGenerator,
        CancellationToken cancellationToken)
    {
        var hash = SessionCookieHelper.GetSessionHandleHash(context, tokenValueGenerator);
        if (string.IsNullOrEmpty(hash))
        {
            return Results.NotFound();
        }

        var session = await sessionRepository.FindByHandleHashAsync(hash, cancellationToken);
        if (session is null)
        {
            return Results.NotFound();
        }

        return Results.Ok(MapSession(session, hash));
    }

    private static async Task<IResult> RevokeSessionAsync(
        HttpContext context,
        Guid id,
        UserManager<Employee> userManager,
        ISessionRepository sessionRepository,
        SessionService sessionService,
        ITokenValueGenerator tokenValueGenerator,
        CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var session = await sessionRepository.FindByIdAsync(id, cancellationToken);
        if (session is null || session.EmployeeId != user.Id)
        {
            return Results.NotFound();
        }

        if (session.RevokedAt is null)
        {
            await sessionService.RevokeAsync(session, "User revoked session", cancellationToken);
        }

        var currentHash = SessionCookieHelper.GetSessionHandleHash(context, tokenValueGenerator);
        if (!string.IsNullOrEmpty(currentHash) && session.HandleHash == currentHash)
        {
            context.Response.Cookies.Delete(SessionCookieHelper.SessionCookieName);
            await context.SignOutAsync(IdentityConstants.ApplicationScheme);
        }

        return Results.NoContent();
    }

    private static async Task<IResult> RevokeAllSessionsAsync(
        HttpContext context,
        UserManager<Employee> userManager,
        ISessionRepository sessionRepository,
        SessionService sessionService,
        ITokenValueGenerator tokenValueGenerator,
        CancellationToken cancellationToken)
    {
        var user = await userManager.GetUserAsync(context.User);
        if (user is null)
        {
            return Results.Unauthorized();
        }

        var sessions = await sessionRepository.GetByEmployeeIdAsync(user.Id, cancellationToken);
        var currentHash = SessionCookieHelper.GetSessionHandleHash(context, tokenValueGenerator);
        var revoked = 0;
        foreach (var session in sessions)
        {
            if (session.RevokedAt is not null)
            {
                continue;
            }

            if (!string.IsNullOrEmpty(currentHash) && session.HandleHash == currentHash)
            {
                continue;
            }

            await sessionService.RevokeAsync(session, "User revoked all sessions", cancellationToken);
            revoked++;
        }

        return Results.Ok(new { revoked });
    }

    private static SessionResponse MapSession(Session session, string? currentHash)
    {
        var lastSeen = session.Tokens?.Count > 0
            ? session.Tokens.Max(t => t.CreatedAt)
            : session.CreatedAt;

        var metadata = ParseMetadata(session.Metadata);
        var revoked = session.RevokedAt is not null;

        return new SessionResponse(
            session.Id,
            session.Device ?? "Browser",
            metadata.UserAgent,
            session.IpAddress ?? metadata.IpAddress,
            session.CreatedAt,
            session.ExpiresAt,
            lastSeen,
            revoked,
            session.RevokedAt,
            session.RevokedReason,
            currentHash is not null && session.HandleHash == currentHash);
    }

    private static (string? UserAgent, string? IpAddress) ParseMetadata(string? metadata)
    {
        if (string.IsNullOrWhiteSpace(metadata))
        {
            return (null, null);
        }

        string? ua = null;
        string? ip = null;

        var segments = metadata.Split('|', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        foreach (var segment in segments)
        {
            if (segment.StartsWith("ua=", StringComparison.OrdinalIgnoreCase))
            {
                ua = segment["ua=".Length..];
            }
            else if (segment.StartsWith("ip=", StringComparison.OrdinalIgnoreCase))
            {
                ip = segment["ip=".Length..];
            }
        }

        return (ua, ip);
    }
}
