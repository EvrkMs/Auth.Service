using Auth.Domain.Entity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.EntityFramework.Configurations;

internal sealed class EmployeeConfiguration : IEntityTypeConfiguration<Employee>
{
    public void Configure(EntityTypeBuilder<Employee> builder)
    {
        builder.Property(x => x.DisplayName)
            .HasMaxLength(256)
            .IsRequired();

        builder.Property(x => x.TelegramUsername)
            .HasMaxLength(64);

        builder.Property(x => x.TelegramFirstName)
            .HasMaxLength(128);

        builder.Property(x => x.TelegramLastName)
            .HasMaxLength(128);

        builder.Property(x => x.TelegramPhotoUrl)
            .HasMaxLength(512);

        builder.HasIndex(x => x.TelegramId)
            .IsUnique();
    }
}
