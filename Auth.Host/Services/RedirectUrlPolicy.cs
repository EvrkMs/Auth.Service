using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;

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

    public SafeReturnUrlResult GetTelegramReturnUrl(IUrlHelper? urlHelper, string? returnUrl, string? clientId)
    {
        if (!string.IsNullOrWhiteSpace(clientId) && TryResolveClientUrl(clientId, returnUrl, out var resolvedUrl, out _))
        {
            return new SafeReturnUrlResult(resolvedUrl, false);
        }

        return GetSafeReturnUrl(urlHelper, returnUrl);
    }

    public bool IsTelegramReturnUrlAllowed(string? returnUrl, string? clientId)
    {
        return !string.IsNullOrWhiteSpace(clientId) &&
               !string.IsNullOrWhiteSpace(returnUrl) &&
               TryResolveClientUrl(clientId, returnUrl, out _, out var accepted) &&
               accepted;
    }

    private bool TryResolveClientUrl(string clientId, string? returnUrl, out string resolvedUrl, out bool accepted)
    {
        resolvedUrl = string.Empty;
        accepted = false;
        var client = _clients.Find(clientId);
        if (client is null)
        {
            return false;
        }

        var expectedRedirect = client.RedirectUri;
        var expectedLogout = client.PostLogoutRedirectUri;

        if (!string.IsNullOrWhiteSpace(returnUrl) &&
            (string.Equals(returnUrl, expectedRedirect, StringComparison.Ordinal) ||
             (!string.IsNullOrWhiteSpace(expectedLogout) && string.Equals(returnUrl, expectedLogout, StringComparison.Ordinal))))
        {
            resolvedUrl = returnUrl;
            accepted = true;
            return true;
        }

        resolvedUrl = client.RedirectUri;
        return true;
    }
}

public sealed record SafeReturnUrlResult(string Url, bool IsLocal);
