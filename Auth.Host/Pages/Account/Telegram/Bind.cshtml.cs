using Auth.Host.Services;
using Auth.Telegram;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Logging;

namespace Auth.Host.Pages.Account.Telegram;

[Authorize]
public sealed class BindModel : PageModel
{
    private readonly TelegramOptions _options;
    private readonly RedirectUrlPolicy _redirectPolicy;
    private readonly ILogger<BindModel> _logger;

    public BindModel(IOptions<TelegramOptions> options, RedirectUrlPolicy redirectPolicy, ILogger<BindModel> logger)
    {
        _options = options.Value;
        _redirectPolicy = redirectPolicy;
        _logger = logger;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty(SupportsGet = true)]
    [FromQuery(Name = "client_id")]
    public string? ClientId { get; set; }

    public string? BotUsername => string.IsNullOrWhiteSpace(_options.BotUsername) ? null : _options.BotUsername;

    public SafeReturnUrlResult SafeReturnUrlInfo => _redirectPolicy.GetTelegramReturnUrl(Url, ReturnUrl, ClientId);
    public string SafeReturnUrl => SafeReturnUrlInfo.Url;

    public IActionResult OnGet()
    {
        if (!IsReturnUrlValid())
        {
            _logger.LogWarning("Invalid Telegram bind returnUrl={ReturnUrl} client_id={ClientId}", ReturnUrl, ClientId);
            return BadRequest("Недопустимый returnUrl или client_id для Telegram-связки.");
        }

        return Page();
    }

    private bool IsReturnUrlValid()
    {
        return _redirectPolicy.IsTelegramReturnUrlAllowed(ReturnUrl, ClientId);
    }

}
