using Auth.Domain.Entity;
using Auth.Host.Services;
using Auth.Telegram;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.Extensions.Options;

namespace Auth.Host.Pages.Account.Telegram;

[AllowAnonymous]
public sealed class LoginModel : PageModel
{
    private readonly TelegramBindingService _bindingService;
    private readonly SignInManager<Employee> _signInManager;
    private readonly TelegramOptions _options;
    private readonly RedirectUrlPolicy _redirectPolicy;

    public LoginModel(
        TelegramBindingService bindingService,
        SignInManager<Employee> signInManager,
        IOptions<TelegramOptions> options,
        RedirectUrlPolicy redirectPolicy)
    {
        _bindingService = bindingService;
        _signInManager = signInManager;
        _options = options.Value;
        _redirectPolicy = redirectPolicy;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty(SupportsGet = true)]
    public string? ClientId { get; set; }

    [BindProperty(Name = "id")]
    public long TelegramId { get; set; }

    [BindProperty(Name = "first_name")]
    public string? FirstName { get; set; }

    [BindProperty(Name = "last_name")]
    public string? LastName { get; set; }

    [BindProperty(Name = "username")]
    public string? Username { get; set; }

    [BindProperty(Name = "photo_url")]
    public string? PhotoUrl { get; set; }

    [BindProperty(Name = "auth_date")]
    public long AuthDate { get; set; }

    [BindProperty(Name = "hash")]
    public string Hash { get; set; } = string.Empty;

    public string? BotUsername => string.IsNullOrWhiteSpace(_options.BotUsername) ? null : _options.BotUsername;

    public SafeReturnUrlResult SafeReturnUrlInfo => _redirectPolicy.ResolveReturnUrl(Url, ReturnUrl, ClientId);
    public string SafeReturnUrl => SafeReturnUrlInfo.Url;

    public string? ErrorMessage { get; private set; }

    public void OnGet()
    {
    }

    public async Task<IActionResult> OnPostAsync()
    {
        if (string.IsNullOrWhiteSpace(BotUsername))
        {
            ErrorMessage = "Авторизация через Telegram недоступна.";
            return Page();
        }

        if (TelegramId <= 0 || string.IsNullOrWhiteSpace(Hash))
        {
            ErrorMessage = "Не удалось получить данные Telegram.";
            return Page();
        }

        var validation = _redirectPolicy.ValidateClientReturnUrl(ClientId, ReturnUrl);
        if (!validation.IsValid)
        {
            ErrorMessage = validation.Error ?? "Недопустимый returnUrl или client_id.";
            return Page();
        }

        try
        {
            var data = new TelegramAuthData(
                TelegramId,
                FirstName,
                LastName,
                Username,
                PhotoUrl,
                AuthDate,
                Hash);

            var user = await _bindingService.AuthenticateAsync(data, HttpContext.RequestAborted);
            if (user is null)
            {
                ErrorMessage = "Этот Telegram не привязан ни к одному аккаунту.";
                return Page();
            }

            if (!await _signInManager.CanSignInAsync(user))
            {
                ErrorMessage = "Пользователь временно не может войти.";
                return Page();
            }

            await _signInManager.SignInAsync(user, isPersistent: false);
            return validation.SafeReturnUrl!.IsLocal
                ? LocalRedirect(validation.SafeReturnUrl.Url)
                : Redirect(validation.SafeReturnUrl.Url);
        }
        catch (TelegramValidationException ex)
        {
            ErrorMessage = ex.Message;
            return Page();
        }
    }

}
