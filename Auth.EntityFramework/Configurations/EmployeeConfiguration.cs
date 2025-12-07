using Auth.Domain.Entity;
using Microsoft.EntityFrameworkCore.Metadata.Builders;
using System;
using System.Collections.Generic;
using System.Text;

namespace Auth.EntityFramework.Configurations;

internal class EmployeeConfiguration
{
    public void Configure(EntityTypeBuilder<Employee> builder)
    {
        builder.Property(x => x.DisplayName)
            .HasMaxLength(256)
            .IsRequired();
    }
}
