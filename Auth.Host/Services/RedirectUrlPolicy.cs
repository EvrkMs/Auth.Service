using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;
using Auth.Oidc.Services;

namespace Auth.Host.Services;

public sealed class RedirectUrlPolicy
{
    private readonly HashSet<string> _allowedAuthorities;
    private readonly ClientRegistry _clients;

    public RedirectUrlPolicy(IEnumerable<string> allowedOrigins, ClientRegistry clients)
    {
        _allowedAuthorities = new HashSet<string>(allowedOrigins, StringComparer.OrdinalIgnoreCase);
        _clients = clients;
    }

    public SafeReturnUrlResult GetSafeReturnUrl(IUrlHelper? urlHelper, string? returnUrl)
    {
        var fallback = urlHelper?.Content("~/") ?? "/";

        if (!string.IsNullOrWhiteSpace(returnUrl) && (urlHelper?.IsLocalUrl(returnUrl) == true))
        {
            return new SafeReturnUrlResult(returnUrl, true);
        }

        if (!string.IsNullOrWhiteSpace(returnUrl) &&
            Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri) &&
            _allowedAuthorities.Contains(uri.GetLeftPart(UriPartial.Authority)))
        {
            return new SafeReturnUrlResult(returnUrl, false);
        }

        return new SafeReturnUrlResult(fallback, true);
    }

    public RedirectValidationResult ValidateClientReturnUrl(string? clientId, string? returnUrl)
    {
        if (string.IsNullOrWhiteSpace(clientId) || string.IsNullOrWhiteSpace(returnUrl))
        {
            return RedirectValidationResult.Invalid("ClientId или returnUrl не заданы.");
        }

        var client = _clients.Find(clientId);
        if (client is null)
        {
            return RedirectValidationResult.Invalid("Клиент не найден.");
        }

        var expectedRedirect = client.RedirectUri;
        var expectedLogout = client.PostLogoutRedirectUri;

        if (string.Equals(returnUrl, expectedRedirect, StringComparison.Ordinal) ||
            (!string.IsNullOrWhiteSpace(expectedLogout) && string.Equals(returnUrl, expectedLogout, StringComparison.Ordinal)))
        {
            return RedirectValidationResult.Valid(new SafeReturnUrlResult(returnUrl, false));
        }

        return RedirectValidationResult.Invalid("Недопустимый returnUrl для клиента.");
    }

    public SafeReturnUrlResult ResolveReturnUrl(IUrlHelper? urlHelper, string? returnUrl, string? clientId)
    {
        var validation = ValidateClientReturnUrl(clientId, returnUrl);
        return validation.IsValid ? validation.SafeReturnUrl! : GetSafeReturnUrl(urlHelper, returnUrl);
    }
}

public sealed record SafeReturnUrlResult(string Url, bool IsLocal);

public sealed record RedirectValidationResult(bool IsValid, string? Error, SafeReturnUrlResult? SafeReturnUrl)
{
    public static RedirectValidationResult Valid(SafeReturnUrlResult result) => new(true, null, result);
    public static RedirectValidationResult Invalid(string error) => new(false, error, null);
}
