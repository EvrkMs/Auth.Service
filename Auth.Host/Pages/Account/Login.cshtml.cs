using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;

namespace Auth.Host.Pages.Account;

[AllowAnonymous]
public sealed class LoginModel : PageModel
{
    private readonly SignInManager<Auth.Domain.Entity.Employee> _signInManager;

    public LoginModel(SignInManager<Auth.Domain.Entity.Employee> signInManager)
    {
        _signInManager = signInManager;
    }

    [BindProperty, Required]
    public string UserName { get; set; } = string.Empty;

    [BindProperty, Required, DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    [BindProperty]
    public bool RememberMe { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (!ModelState.IsValid)
        {
            return Page();
        }

        var result = await _signInManager.PasswordSignInAsync(UserName, Password, RememberMe, lockoutOnFailure: true);

        if (result.Succeeded)
        {
            return LocalRedirect(GetSafeReturnUrl(ReturnUrl));
        }

        if (result.RequiresTwoFactor)
        {
            ModelState.AddModelError(string.Empty, "Требуется двухфакторная аутентификация");
            return Page();
        }

        if (result.IsLockedOut)
        {
            ModelState.AddModelError(string.Empty, "Пользователь временно заблокирован");
            return Page();
        }

        ModelState.AddModelError(string.Empty, "Неверное имя пользователя или пароль");
        return Page();
    }

    private string GetSafeReturnUrl(string? returnUrl)
    {
        if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return returnUrl;
        }

        return Url.Page("/Index") ?? "/";
    }
}
