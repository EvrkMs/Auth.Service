using Microsoft.AspNetCore.Identity;
using System.Globalization;

namespace Auth.Domain.Entities;

public class User : IdentityUser<Guid>
{
    public string DispayName { get; set; } = null!;
}
