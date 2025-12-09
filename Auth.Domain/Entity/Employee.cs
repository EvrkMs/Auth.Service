using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Entity;

public class Employee : IdentityUser<Guid>
{
    public string DisplayName { get; set; } = null!;

    public long? TelegramId { get; set; }

    public string? TelegramUsername { get; set; }

    public string? TelegramFirstName { get; set; }

    public string? TelegramLastName { get; set; }

    public string? TelegramPhotoUrl { get; set; }

    public DateTimeOffset? TelegramBoundAt { get; set; }
}
