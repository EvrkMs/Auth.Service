using Auth.Application.Sessions;
using Auth.Application.Tokens;
using Auth.Domain.Entity;
using Auth.Domain.Tokens;
using Auth.Host.Services;
using Auth.Host.Oidc;
using Auth.Host.Sessions;
using Auth.Infrastructure;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.WebUtilities;
using System;
using System.Collections.Generic;
using System.Linq;

namespace Auth.Host.Endpoints;

public static class ConnectEndpoints
{

    public static void MapConnectEndpoints(this IEndpointRouteBuilder app)
    {
        var group = app.MapGroup("/connect");
        group.MapGet("/authorize", AuthorizeAsync);
        group.MapPost("/token", ExchangeTokenAsync);
        group.MapGet("/userinfo", UserInfoAsync);
        group.MapGet("/logout", LogoutAsync);
    }

    private static async Task<IResult> AuthorizeAsync(
        HttpContext httpContext,
        [AsParameters] AuthorizeRequest request,
        ClientRegistry clients,
        AuthorizationCodeStore codeStore,
        UserManager<Employee> userManager,
        SessionService sessionService,
        ISessionRepository sessionRepository,
        ITokenValueGenerator tokenValueGenerator)
    {
        var client = clients.Find(request.ClientId ?? string.Empty);
        var errorResult = ValidateAuthorizeRequest(request, client);
        if (errorResult is not null)
        {
            return errorResult;
        }

        if (client is null)
        {
            throw new InvalidOperationException("Client not found during validation.");
        }

        var returnUrl = httpContext.Request.Path + httpContext.Request.QueryString;

        if (!(httpContext.User.Identity?.IsAuthenticated ?? false))
        {
            var loginUrl = $"/Account/Login?ReturnUrl={Uri.EscapeDataString(returnUrl)}";
            return Results.Redirect(loginUrl);
        }

        var user = await userManager.GetUserAsync(httpContext.User);
        if (user is null)
        {
            var loginUrl = $"/Account/Login?ReturnUrl={Uri.EscapeDataString(returnUrl)}";
            return Results.Redirect(loginUrl);
        }

        var scopes = ResolveScopes(request.Scope, client);
        if (scopes is null)
        {
            return Results.BadRequest(new { error = "invalid_scope" });
        }

        if (!ContainsScope(scopes, "openid"))
        {
            return Results.BadRequest(new { error = "invalid_scope", error_description = "Scope 'openid' is required." });
        }

        var session = await EnsureSessionAsync(
            httpContext,
            user,
            client.ClientId,
            sessionService,
            sessionRepository,
            tokenValueGenerator,
            httpContext.RequestAborted);
        if (session is null)
        {
            var loginUrl = $"/Account/Login?ReturnUrl={Uri.EscapeDataString(returnUrl)}";
            return Results.Redirect(loginUrl);
        }

        var code = await codeStore.CreateAsync(
            user.Id,
            client.ClientId,
            request.RedirectUri!,
            request.CodeChallenge!,
            request.CodeChallengeMethod ?? "S256",
            session.Id,
            scopes,
            request.Nonce);

        var redirectUrl = AppendQuery(request.RedirectUri!, new Dictionary<string, string?>
        {
            ["code"] = code,
            ["state"] = request.State ?? string.Empty
        });

        return Results.Redirect(redirectUrl);
    }

    private static IResult? ValidateAuthorizeRequest(AuthorizeRequest request, ClientRegistration? client)
    {
        if (!string.Equals(request.ResponseType, "code", StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(new { error = "unsupported_response_type" });
        }

        if (string.IsNullOrWhiteSpace(request.ClientId))
        {
            return Results.BadRequest(new { error = "invalid_request" });
        }

        if (client is null)
        {
            return Results.BadRequest(new { error = "invalid_client" });
        }

        if (!string.Equals(client.RedirectUri, request.RedirectUri, StringComparison.Ordinal))
        {
            return Results.BadRequest(new { error = "invalid_redirect_uri" });
        }

        if (string.IsNullOrWhiteSpace(request.CodeChallenge))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "Missing code_challenge" });
        }

        if (string.IsNullOrWhiteSpace(request.CodeChallengeMethod))
        {
            request.CodeChallengeMethod = "S256";
        }

        return null;
    }

    private static async Task<IResult> ExchangeTokenAsync(
        HttpContext httpContext,
        AuthorizationCodeStore codeStore,
        UserManager<Employee> userManager,
        ISessionRepository sessionRepository,
        TokenService tokenService,
        TokenRefreshService refreshService,
        OidcIdTokenFactory idTokenFactory)
    {
        var form = await httpContext.Request.ReadFormAsync();
        var grantType = form["grant_type"].ToString();
        if (string.Equals(grantType, "refresh_token", StringComparison.OrdinalIgnoreCase))
        {
            return await HandleRefreshGrantAsync(httpContext, form, refreshService);
        }

        if (!string.Equals(grantType, "authorization_code", StringComparison.OrdinalIgnoreCase))
        {
            return Results.BadRequest(new { error = "unsupported_grant_type" });
        }

        var code = form["code"].ToString();
        var redirectUri = form["redirect_uri"].ToString();
        var clientId = form["client_id"].ToString();
        var codeVerifier = form["code_verifier"].ToString();

        var entry = await codeStore.TryRedeemAsync(code);
        if (entry is null)
        {
            return Results.BadRequest(new { error = "invalid_grant" });
        }

        if (!string.Equals(entry.ClientId, clientId, StringComparison.Ordinal) ||
            !string.Equals(entry.RedirectUri, redirectUri, StringComparison.Ordinal))
        {
            return Results.BadRequest(new { error = "invalid_grant" });
        }

        if (!AuthorizationCodeStore.ValidatePkce(codeVerifier, entry.CodeChallenge, entry.CodeChallengeMethod))
        {
            return Results.BadRequest(new { error = "invalid_grant", error_description = "PKCE validation failed" });
        }

        var user = await userManager.FindByIdAsync(entry.UserId.ToString());
        if (user is null)
        {
            return Results.BadRequest(new { error = "invalid_grant" });
        }

        var session = await sessionRepository.FindByIdAsync(entry.SessionId, httpContext.RequestAborted);
        if (session is null || !session.IsActive(DateTimeOffset.UtcNow))
        {
            return Results.BadRequest(new { error = "invalid_grant" });
        }

        var includeRefresh = ContainsScope(entry.Scopes, "offline_access");

        var result = await tokenService.IssueAsync(new IssueTokenRequest(
            user,
            session,
            clientId,
            entry.Scopes,
            includeRefresh,
            ParentRefreshToken: null));

        string? idToken = null;
        if (ContainsScope(entry.Scopes, "openid"))
        {
            idToken = await idTokenFactory.CreateAsync(user, session, clientId, entry.Nonce, httpContext.RequestAborted);
        }

        var scopeString = string.Join(' ', result.Scopes);
        return Results.Json(new
        {
            access_token = result.AccessToken.Value,
            expires_in = (int)(result.AccessToken.ExpiresAt - DateTimeOffset.UtcNow).TotalSeconds,
            token_type = "Bearer",
            refresh_token = includeRefresh ? result.RefreshToken?.Value : null,
            refresh_token_expires_at = includeRefresh ? result.RefreshToken?.ExpiresAt : null,
            scope = scopeString,
            id_token = idToken
        });
    }

    private static async Task<IResult> HandleRefreshGrantAsync(
        HttpContext httpContext,
        IFormCollection form,
        TokenRefreshService refreshService)
    {
        var refreshToken = form["refresh_token"].ToString();
        if (string.IsNullOrWhiteSpace(refreshToken))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "Missing refresh_token" });
        }

        try
        {
            var result = await refreshService.RefreshAsync(refreshToken, cancellationToken: httpContext.RequestAborted);
            var scopeString = string.Join(' ', result.Scopes);
            return Results.Json(new
            {
                access_token = result.AccessToken.Value,
                expires_in = (int)(result.AccessToken.ExpiresAt - DateTimeOffset.UtcNow).TotalSeconds,
                token_type = "Bearer",
                refresh_token = result.RefreshToken?.Value,
                refresh_token_expires_at = result.RefreshToken?.ExpiresAt,
                scope = scopeString
            });
        }
        catch (Exception ex)
        {
            return Results.BadRequest(new { error = "invalid_grant", error_description = ex.Message });
        }
    }

    private static async Task<IResult> LogoutAsync(
        HttpContext httpContext,
        [AsParameters] LogoutRequest request,
        ClientRegistry clients,
        SessionService sessionService,
        ISessionRepository sessionRepository,
        ITokenValueGenerator tokenValueGenerator)
    {
        var validation = ValidateLogoutRequest(request, clients, out var redirectUri);
        if (validation is not null)
        {
            return validation;
        }

        await SessionCookieHelper.RevokeCurrentSessionAsync(httpContext, sessionService, sessionRepository, tokenValueGenerator, httpContext.RequestAborted);

        var target = redirectUri ?? "/";
        if (!string.IsNullOrWhiteSpace(request.State))
        {
            target = AppendQuery(target, new Dictionary<string, string?>
            {
                ["state"] = request.State
            });
        }

        return Results.Redirect(target);
    }

    private static async Task<IResult> UserInfoAsync(
        HttpContext httpContext,
        ITokenValueGenerator tokenValueGenerator,
        ITokenRepository tokenRepository,
        Auth.Application.Abstractions.ISystemClock clock,
        UserManager<Employee> userManager)
    {
        if (!TryGetBearerToken(httpContext.Request, out var tokenValue))
        {
            return Results.Unauthorized();
        }

        var hash = tokenValueGenerator.ComputeHash(tokenValue);
        var token = await tokenRepository.FindByHashAsync(hash, httpContext.RequestAborted);
        if (token is null || token.Type != TokenType.Access)
        {
            return Results.Unauthorized();
        }

        if (!token.IsActive(clock.UtcNow))
        {
            return Results.Unauthorized();
        }

        var scopes = ParseScopes(token.Scopes);
        if (!ContainsScope(scopes, "openid"))
        {
            return Results.Unauthorized();
        }

        var employee = token.Employee ?? throw new InvalidOperationException("Token is missing employee navigation property.");
        var roles = await userManager.GetRolesAsync(employee);
        var roleArray = roles?.ToArray() ?? Array.Empty<string>();

        var response = new Dictionary<string, object?>
        {
            ["sub"] = employee.Id.ToString(),
            ["email"] = employee.Email,
            ["phone_number"] = employee.PhoneNumber
        };

        if (!string.IsNullOrWhiteSpace(employee.DisplayName))
        {
            response["name"] = employee.DisplayName;
        }

        if (!string.IsNullOrWhiteSpace(employee.UserName))
        {
            response["preferred_username"] = employee.UserName!;
        }

        if (!string.IsNullOrWhiteSpace(token.SessionHandleHash))
        {
            response["sid"] = token.SessionHandleHash;
        }

        if (roleArray.Length > 0)
        {
            response["roles"] = roleArray;
        }

        if (scopes.Count > 0)
        {
            response["scope"] = string.Join(' ', scopes);
        }

        return Results.Json(response);
    }

    private static string AppendQuery(string uri, IDictionary<string, string?> parameters)
    {
        var filtered = parameters
            .Where(kvp => !string.IsNullOrEmpty(kvp.Value))
            .ToDictionary(kvp => kvp.Key, kvp => kvp.Value!, StringComparer.Ordinal);
        return QueryHelpers.AddQueryString(uri, filtered);
    }

    public sealed record AuthorizeRequest
    {
        [FromQuery(Name = "response_type")]
        public string? ResponseType { get; init; }

        [FromQuery(Name = "client_id")]
        public string? ClientId { get; init; }

        [FromQuery(Name = "redirect_uri")]
        public string? RedirectUri { get; init; }

        [FromQuery(Name = "scope")]
        public string? Scope { get; init; }

        [FromQuery(Name = "state")]
        public string? State { get; init; }

        [FromQuery(Name = "code_challenge")]
        public string? CodeChallenge { get; set; }

        [FromQuery(Name = "code_challenge_method")]
        public string? CodeChallengeMethod { get; set; }

        [FromQuery(Name = "nonce")]
        public string? Nonce { get; init; }
    }

    public sealed record LogoutRequest
    {
        [FromQuery(Name = "post_logout_redirect_uri")]
        public string? PostLogoutRedirectUri { get; init; }

        [FromQuery(Name = "state")]
        public string? State { get; init; }

        [FromQuery(Name = "client_id")]
        public string? ClientId { get; init; }

        [FromQuery(Name = "id_token_hint")]
        public string? IdTokenHint { get; init; }
    }

    private static async Task<Session?> EnsureSessionAsync(
        HttpContext httpContext,
        Employee employee,
        string clientId,
        SessionService sessionService,
        ISessionRepository sessionRepository,
        ITokenValueGenerator tokenValueGenerator,
        CancellationToken cancellationToken)
    {
        var now = DateTimeOffset.UtcNow;
        var existingHandle = SessionCookieHelper.GetSessionHandle(httpContext);
        if (!string.IsNullOrEmpty(existingHandle))
        {
            var hash = tokenValueGenerator.ComputeHash(existingHandle);
            var existing = await sessionRepository.FindByHandleHashAsync(hash, cancellationToken);
            if (existing is not null && existing.IsActive(now))
            {
                return existing;
            }

            httpContext.Response.Cookies.Delete(SessionCookieHelper.SessionCookieName);
            await httpContext.SignOutAsync(IdentityConstants.ApplicationScheme);
            return null;
        }

        var userAgent = httpContext.Request.Headers.UserAgent.ToString();
        var ip = httpContext.Connection.RemoteIpAddress?.ToString();
        var metadata = BuildSessionMetadata(userAgent, ip);

        var sessionResult = await sessionService.CreateAsync(new CreateSessionRequest(
            employee.Id,
            clientId,
            string.IsNullOrWhiteSpace(userAgent) ? "Browser" : userAgent,
            ip,
            metadata,
            null,
            IssueHandle: true), cancellationToken);

        var session = await sessionRepository.FindByIdAsync(sessionResult.SessionId, cancellationToken)
            ?? throw new InvalidOperationException("Session was not persisted.");

        SetSessionCookie(httpContext, sessionResult.SessionHandle);

        return session;
    }

    private static void SetSessionCookie(HttpContext context, string? handle)
    {
        if (string.IsNullOrWhiteSpace(handle))
        {
            return;
        }

        var options = new CookieOptions
        {
            HttpOnly = true,
            Secure = context.Request.IsHttps,
            SameSite = SameSiteMode.Strict,
            Path = "/",
            Expires = DateTimeOffset.UtcNow.AddDays(30)
        };

        context.Response.Cookies.Append(SessionCookieHelper.SessionCookieName, handle, options);
    }

    private static string? BuildSessionMetadata(string? userAgent, string? ip)
    {
        var parts = new List<string>();
        if (!string.IsNullOrWhiteSpace(userAgent))
        {
            parts.Add($"ua={userAgent}");
        }

        if (!string.IsNullOrWhiteSpace(ip))
        {
            parts.Add($"ip={ip}");
        }

        return parts.Count > 0 ? string.Join(" | ", parts) : null;
    }

    private static bool TryGetBearerToken(HttpRequest request, out string token)
    {
        token = string.Empty;
        var header = request.Headers.Authorization.ToString();
        if (string.IsNullOrWhiteSpace(header) || !header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
        {
            return false;
        }

        token = header["Bearer ".Length..].Trim();
        return token.Length > 0;
    }

    private static IReadOnlyCollection<string>? ResolveScopes(string? scopeValue, ClientRegistration client)
    {
        var requested = string.IsNullOrWhiteSpace(scopeValue)
            ? client.AllowedScopes
            : scopeValue.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
                .Distinct(StringComparer.Ordinal)
                .ToArray();

        if (requested.Count == 0)
        {
            return client.AllowedScopes;
        }

        if (client.AllowedScopes.Count == 0)
        {
            return null;
        }

        var allowed = new HashSet<string>(client.AllowedScopes, StringComparer.Ordinal);
        foreach (var scope in requested)
        {
            if (!allowed.Contains(scope))
            {
                return null;
            }
        }

        return requested;
    }

    private static bool ContainsScope(IEnumerable<string> scopes, string scopeName) =>
        scopes.Any(scope => string.Equals(scope, scopeName, StringComparison.Ordinal));

    private static IReadOnlyCollection<string> ParseScopes(string? scopes) =>
        string.IsNullOrWhiteSpace(scopes)
            ? Array.Empty<string>()
            : scopes.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

    private static IResult? ValidateLogoutRequest(LogoutRequest request, ClientRegistry clients, out string? redirectUri)
    {
        redirectUri = null;

        if (!string.IsNullOrWhiteSpace(request.PostLogoutRedirectUri) &&
            !Uri.TryCreate(request.PostLogoutRedirectUri, UriKind.Absolute, out _))
        {
            return Results.BadRequest(new { error = "invalid_request", error_description = "Invalid post_logout_redirect_uri" });
        }

        if (!string.IsNullOrWhiteSpace(request.ClientId))
        {
            var client = clients.Find(request.ClientId);
            if (client is null)
            {
                return Results.BadRequest(new { error = "invalid_client" });
            }

            if (string.IsNullOrWhiteSpace(request.PostLogoutRedirectUri))
            {
                redirectUri = client.PostLogoutRedirectUri ?? client.RedirectUri;
                return null;
            }

            var allowed = client.PostLogoutRedirectUri ?? client.RedirectUri;
            if (!string.Equals(allowed, request.PostLogoutRedirectUri, StringComparison.Ordinal))
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Unregistered post_logout_redirect_uri" });
            }

            redirectUri = request.PostLogoutRedirectUri;
            return null;
        }

        if (!string.IsNullOrWhiteSpace(request.PostLogoutRedirectUri))
        {
            var match = clients.FindByLogoutRedirectUri(request.PostLogoutRedirectUri);
            if (match is null)
            {
                return Results.BadRequest(new { error = "invalid_request", error_description = "Unregistered post_logout_redirect_uri" });
            }

            redirectUri = request.PostLogoutRedirectUri;
        }

        return null;
    }

}
