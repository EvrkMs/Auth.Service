using Auth.Domain.Entity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.EntityFramework.Configurations;

internal sealed class SessionConfiguration : IEntityTypeConfiguration<Session>
{
    public void Configure(EntityTypeBuilder<Session> builder)
    {
        builder.ToTable("sessions");
        builder.HasKey(x => x.Id);

        builder.Property(x => x.ClientId)
            .HasMaxLength(256)
            .IsRequired();

        builder.Property(x => x.Device)
            .HasMaxLength(256);

        builder.Property(x => x.IpAddress)
            .HasMaxLength(64);

        builder.Property(x => x.Metadata)
            .HasMaxLength(2048);

        builder.Property(x => x.HandleHash)
            .HasMaxLength(512);

        builder.Property(x => x.RevokedReason)
            .HasMaxLength(512);

        builder.HasIndex(x => x.HandleHash);

        builder.HasOne(x => x.Employee)
            .WithMany()
            .HasForeignKey(x => x.EmployeeId)
            .OnDelete(DeleteBehavior.Cascade);
    }
}
