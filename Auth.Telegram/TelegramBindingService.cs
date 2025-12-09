using Auth.Domain.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;

namespace Auth.Telegram;

public sealed class TelegramBindingService
{
    private readonly UserManager<Employee> _userManager;
    private readonly TelegramAuthValidator _validator;
    private readonly ILogger<TelegramBindingService> _logger;
    private readonly TimeProvider _timeProvider;

    public TelegramBindingService(
        UserManager<Employee> userManager,
        TelegramAuthValidator validator,
        ILogger<TelegramBindingService> logger,
        TimeProvider? timeProvider = null)
    {
        _userManager = userManager;
        _validator = validator;
        _logger = logger;
        _timeProvider = timeProvider ?? TimeProvider.System;
    }

    public async Task<TelegramProfile?> GetProfileAsync(Employee employee, CancellationToken cancellationToken)
    {
        if (employee.TelegramId is null)
        {
            return null;
        }

        var boundAt = employee.TelegramBoundAt ?? _timeProvider.GetUtcNow();
        return new TelegramProfile(
            employee.TelegramId.Value,
            employee.TelegramUsername,
            employee.TelegramFirstName,
            employee.TelegramLastName,
            employee.TelegramPhotoUrl,
            boundAt);
    }

    public async Task<TelegramProfile> BindAsync(Employee employee, TelegramBindCommand command, CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(command.Password))
        {
            throw new TelegramBindingException("password_required", "Для привязки необходимо указать пароль.");
        }

        var passwordValid = await _userManager.CheckPasswordAsync(employee, command.Password);
        if (!passwordValid)
        {
            throw new TelegramBindingException("invalid_password", "Неверный пароль.");
        }

        var payload = _validator.Validate(command.AuthData);

        if (employee.TelegramId.HasValue && employee.TelegramId.Value == payload.Id)
        {
            return await GetProfileAsync(employee, cancellationToken)
                ?? throw new TelegramBindingException("bind_failed", "Не удалось обновить данные Telegram.");
        }

        var existing = await _userManager.Users
            .Where(u => u.TelegramId == payload.Id && u.Id != employee.Id)
            .FirstOrDefaultAsync(cancellationToken);

        if (existing is not null)
        {
            throw new TelegramBindingException("telegram_in_use", "Этот Telegram уже привязан к другому пользователю.");
        }

        employee.TelegramId = payload.Id;
        employee.TelegramUsername = payload.Username;
        employee.TelegramFirstName = payload.FirstName;
        employee.TelegramLastName = payload.LastName;
        employee.TelegramPhotoUrl = payload.PhotoUrl;
        employee.TelegramBoundAt = _timeProvider.GetUtcNow();

        var result = await _userManager.UpdateAsync(employee);
        if (!result.Succeeded)
        {
            var error = string.Join(';', result.Errors.Select(e => e.Description));
            _logger.LogWarning("Failed to update Telegram binding: {Error}", error);
            throw new TelegramBindingException("update_failed", "Не удалось сохранить данные Telegram.");
        }

        var boundAt = employee.TelegramBoundAt ?? _timeProvider.GetUtcNow();
        return new TelegramProfile(
            payload.Id,
            payload.Username,
            payload.FirstName,
            payload.LastName,
            payload.PhotoUrl,
            boundAt);
    }

    public async Task UnbindAsync(Employee employee, TelegramUnbindCommand command, CancellationToken cancellationToken)
    {
        if (!employee.TelegramId.HasValue)
        {
            return;
        }

        if (string.IsNullOrWhiteSpace(command.Password))
        {
            throw new TelegramBindingException("password_required", "Для отвязки необходимо указать пароль.");
        }

        var passwordValid = await _userManager.CheckPasswordAsync(employee, command.Password);
        if (!passwordValid)
        {
            throw new TelegramBindingException("invalid_password", "Неверный пароль.");
        }

        employee.TelegramId = null;
        employee.TelegramUsername = null;
        employee.TelegramFirstName = null;
        employee.TelegramLastName = null;
        employee.TelegramPhotoUrl = null;
        employee.TelegramBoundAt = null;

        var result = await _userManager.UpdateAsync(employee);
        if (!result.Succeeded)
        {
            var error = string.Join(';', result.Errors.Select(e => e.Description));
            _logger.LogWarning("Failed to unbind Telegram: {Error}", error);
            throw new TelegramBindingException("update_failed", "Не удалось отвязать Telegram.");
        }
    }

    public async Task<Employee?> AuthenticateAsync(TelegramAuthData data, CancellationToken cancellationToken)
    {
        var payload = _validator.Validate(data);
        return await _userManager.Users.FirstOrDefaultAsync(u => u.TelegramId == payload.Id, cancellationToken);
    }
}
