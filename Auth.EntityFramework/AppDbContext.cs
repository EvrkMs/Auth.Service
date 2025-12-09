using Auth.Domain.Entity;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace Auth.EntityFramework;

public class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<Employee, IdentityRole<Guid>, Guid>(options)
{
    public DbSet<Session> Sessions => Set<Session>();

    public DbSet<Token> Tokens => Set<Token>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);

        builder.ApplyConfigurationsFromAssembly(typeof(AppDbContext).Assembly);
    }
}
