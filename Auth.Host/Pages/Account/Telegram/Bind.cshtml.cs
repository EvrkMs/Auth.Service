using Auth.Host.Services;
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
    private readonly RedirectUrlPolicy _redirectPolicy;

    public BindModel(IOptions<TelegramOptions> options, RedirectUrlPolicy redirectPolicy)
    {
        _options = options.Value;
        _redirectPolicy = redirectPolicy;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    public string? BotUsername => string.IsNullOrWhiteSpace(_options.BotUsername) ? null : _options.BotUsername;

    public SafeReturnUrlResult SafeReturnUrlInfo => _redirectPolicy.GetSafeReturnUrl(Url, ReturnUrl);
    public string SafeReturnUrl => SafeReturnUrlInfo.Url;

    public void OnGet()
    {
    }

}
