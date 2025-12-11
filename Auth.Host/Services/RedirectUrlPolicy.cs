using Microsoft.AspNetCore.Mvc;
using System;
using System.Collections.Generic;

namespace Auth.Host.Services;

public sealed class RedirectUrlPolicy
{
    private readonly HashSet<string> _allowedAuthorities;

    public RedirectUrlPolicy(IEnumerable<string> allowedOrigins)
    {
        _allowedAuthorities = new HashSet<string>(allowedOrigins, StringComparer.OrdinalIgnoreCase);
    }

    public SafeReturnUrlResult GetSafeReturnUrl(IUrlHelper? urlHelper, string? returnUrl)
    {
        var fallback = urlHelper?.Content("~/") ?? "/";

        if (!string.IsNullOrWhiteSpace(returnUrl))
        {
            if (urlHelper?.IsLocalUrl(returnUrl) == true)
            {
                return new SafeReturnUrlResult(returnUrl, true);
            }

            if (Uri.TryCreate(returnUrl, UriKind.Absolute, out var uri))
            {
                var authority = uri.GetLeftPart(UriPartial.Authority);
                if (_allowedAuthorities.Contains(authority))
                {
                    return new SafeReturnUrlResult(returnUrl, false);
                }
            }
        }

        return new SafeReturnUrlResult(fallback, true);
    }
}

public sealed record SafeReturnUrlResult(string Url, bool IsLocal);
