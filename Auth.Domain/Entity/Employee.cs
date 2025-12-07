using Microsoft.AspNetCore.Identity;

namespace Auth.Domain.Entity;

public class Employee : IdentityUser<Guid>
{
    public string DisplayName { get; set; } = null!;
}
