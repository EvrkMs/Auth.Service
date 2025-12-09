using Auth.Application.Sessions;
using Auth.Application.Tokens;
using Auth.Domain.Entity;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

namespace Auth.Host.Sessions;

public static class SessionCookieHelper
{
    public const string SessionCookieName = "ava.auth.session";

    public static string? GetSessionHandle(HttpContext context) =>
        context.Request.Cookies.TryGetValue(SessionCookieName, out var value) && !string.IsNullOrEmpty(value)
            ? value
            : null;

    public static string? GetSessionHandleHash(HttpContext context, ITokenValueGenerator tokenValueGenerator)
    {
        var handle = GetSessionHandle(context);
        return string.IsNullOrEmpty(handle) ? null : tokenValueGenerator.ComputeHash(handle);
    }

    public static async Task RevokeCurrentSessionAsync(
        HttpContext context,
        SessionService sessionService,
        ISessionRepository sessionRepository,
        ITokenValueGenerator tokenValueGenerator,
        CancellationToken cancellationToken)
    {
        var handle = GetSessionHandle(context);
        if (!string.IsNullOrEmpty(handle))
        {
            var hash = tokenValueGenerator.ComputeHash(handle);
            var session = await sessionRepository.FindByHandleHashForUpdateAsync(hash, cancellationToken);
            if (session is not null)
            {
                await sessionService.RevokeAsync(session, "User logout", cancellationToken);
            }

            context.Response.Cookies.Delete(SessionCookieName);
        }

        await context.SignOutAsync(IdentityConstants.ApplicationScheme);
    }
}
