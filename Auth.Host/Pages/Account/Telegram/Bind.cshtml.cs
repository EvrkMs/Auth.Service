using Auth.Telegram;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Auth.Host.Pages.Account.Telegram;

[Authorize]
public sealed class BindModel : PageModel
{
    private readonly TelegramOptions _options;

    public BindModel(IOptions<TelegramOptions> options)
    {
        _options = options.Value;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? BotUsername => string.IsNullOrWhiteSpace(_options.BotUsername) ? null : _options.BotUsername;

    public string SafeReturnUrl => GetSafeReturnUrl(ReturnUrl);

    public void OnGet()
    {
    }

    private string GetSafeReturnUrl(string? returnUrl)
    {
        if (!string.IsNullOrWhiteSpace(returnUrl) && Url.IsLocalUrl(returnUrl))
        {
            return returnUrl;
        }

        return Url.Content("~/") ?? "/";
    }
}
