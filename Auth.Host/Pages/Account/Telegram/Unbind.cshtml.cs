using Auth.Domain.Entity;
using Auth.Host.Services;
using Auth.Telegram;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using System.ComponentModel.DataAnnotations;
using Microsoft.Extensions.Logging;

namespace Auth.Host.Pages.Account.Telegram;

[Authorize]
public sealed class UnbindModel : PageModel
{
    private readonly UserManager<Employee> _userManager;
    private readonly TelegramBindingService _bindingService;
    private readonly RedirectUrlPolicy _redirectPolicy;
    private readonly ILogger<UnbindModel> _logger;

    public UnbindModel(
        UserManager<Employee> userManager,
        TelegramBindingService bindingService,
        RedirectUrlPolicy redirectPolicy,
        ILogger<UnbindModel> logger)
    {
        _userManager = userManager;
        _bindingService = bindingService;
        _redirectPolicy = redirectPolicy;
        _logger = logger;
    }

    [BindProperty(SupportsGet = true)]
    public string? ReturnUrl { get; set; }

    [BindProperty(SupportsGet = true)]
    [FromQuery(Name = "client_id")]
    public string? ClientId { get; set; }

    [BindProperty, Required(ErrorMessage = "Пароль обязателен"), DataType(DataType.Password)]
    public string Password { get; set; } = string.Empty;

    public SafeReturnUrlResult SafeReturnUrlInfo => _redirectPolicy.GetTelegramReturnUrl(Url, ReturnUrl, ClientId);
    public string SafeReturnUrl => SafeReturnUrlInfo.Url;

    public string? ErrorMessage { get; private set; }

    public IActionResult OnGet()
    {
        if (!IsReturnUrlValid())
        {
            _logger.LogWarning("Invalid Telegram unbind returnUrl={ReturnUrl} client_id={ClientId}", ReturnUrl, ClientId);
            return BadRequest("Недопустимый returnUrl или client_id для Telegram-отвязки.");
        }

        return Page();
    }

    private bool IsReturnUrlValid()
    {
        return _redirectPolicy.IsTelegramReturnUrlAllowed(ReturnUrl, ClientId);
    }

    public async Task<IActionResult> OnPostAsync(CancellationToken cancellationToken)
    {
        if (!IsReturnUrlValid())
        {
            _logger.LogWarning("Invalid Telegram unbind returnUrl={ReturnUrl} client_id={ClientId}", ReturnUrl, ClientId);
            return BadRequest("Недопустимый returnUrl или client_id для Telegram-отвязки.");
        }

        var user = await _userManager.GetUserAsync(User);
        if (user is null)
        {
            return Unauthorized();
        }

        var providedPassword = !string.IsNullOrWhiteSpace(Password)
            ? Password.Trim()
            : Request.Form["Password"].ToString();

        if (Request.Form.ContainsKey("Password"))
        {
            var raw = Request.Form["Password"].ToString();
            _logger.LogInformation("Raw form value for Password: '{Value}' (len {Length})", raw, raw.Length);
        }

        _logger.LogInformation("Form keys: {Keys}", string.Join(",", Request.Form.Keys));

        if (!ModelState.IsValid)
        {
            var errors = ModelState[nameof(Password)]?.Errors.Select(e => e.ErrorMessage).ToArray() ?? Array.Empty<string>();
            _logger.LogInformation("Telegram unbind validation failed; password errors: {Errors}; posted password length: {Length}", string.Join("; ", errors), providedPassword?.Length ?? 0);
            if (!ModelState.ContainsKey(nameof(Password)))
            {
                ModelState.AddModelError(nameof(Password), "Пароль обязателен");
            }
            return Page();
        }

        if (string.IsNullOrWhiteSpace(providedPassword))
        {
            ModelState.AddModelError(nameof(Password), "Пароль обязателен");
            return Page();
        }

        Password = providedPassword;

        try
        {
            await _bindingService.UnbindAsync(user, new TelegramUnbindCommand(Password), cancellationToken);
            return SafeReturnUrlInfo.IsLocal
                ? LocalRedirect(SafeReturnUrlInfo.Url)
                : Redirect(SafeReturnUrlInfo.Url);
        }
        catch (TelegramBindingException ex)
        {
            ErrorMessage = ex.Message;
            return Page();
        }
    }

}
