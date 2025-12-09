using Auth.Domain.Entity;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Metadata.Builders;

namespace Auth.EntityFramework.Configurations;

internal sealed class TokenConfiguration : IEntityTypeConfiguration<Token>
{
    public void Configure(EntityTypeBuilder<Token> builder)
    {
        builder.ToTable("tokens");
        builder.HasKey(x => x.Id);

        builder.Property(x => x.ClientId)
            .HasMaxLength(256)
            .IsRequired();

        builder.Property(x => x.Hash)
            .HasMaxLength(512)
            .IsRequired();

        builder.Property(x => x.Metadata)
            .HasMaxLength(2048);

        builder.Property(x => x.Scopes)
            .HasMaxLength(1024);

        builder.Property(x => x.Payload)
            .HasMaxLength(4096);

        builder.Property(x => x.SessionHandleHash)
            .HasMaxLength(512);

        builder.HasIndex(x => x.Hash)
            .IsUnique();

        builder.HasIndex(x => x.SessionHandleHash);

        builder.HasIndex(x => new { x.EmployeeId, x.ClientId, x.Type });

        builder.HasOne(x => x.Employee)
            .WithMany()
            .HasForeignKey(x => x.EmployeeId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(x => x.Session)
            .WithMany(x => x.Tokens)
            .HasForeignKey(x => x.SessionId)
            .OnDelete(DeleteBehavior.Cascade);

        builder.HasOne(x => x.ParentToken)
            .WithMany(x => x.Children)
            .HasForeignKey(x => x.ParentTokenId)
            .OnDelete(DeleteBehavior.Restrict);
    }
}
