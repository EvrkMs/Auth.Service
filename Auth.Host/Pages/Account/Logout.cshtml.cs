using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace Auth.Host.Pages.Account;

[Authorize]
public sealed class LogoutModel : PageModel
{
    private readonly SignInManager<Auth.Domain.Entity.Employee> _signInManager;

    public LogoutModel(SignInManager<Auth.Domain.Entity.Employee> signInManager)
    {
        _signInManager = signInManager;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public void OnGet()
    {
        ReturnUrl ??= Url.Page("/Index") ?? "/";
    }

public async Task<IActionResult> OnPostAsync()
    {
        await _signInManager.SignOutAsync();
        var redirectUrl = Url.IsLocalUrl(ReturnUrl) ? ReturnUrl : Url.Page("/Index") ?? "/";
        return LocalRedirect(redirectUrl!);
    }
}
