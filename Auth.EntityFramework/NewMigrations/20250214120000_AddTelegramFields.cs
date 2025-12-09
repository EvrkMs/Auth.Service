using System;
using Microsoft.EntityFrameworkCore.Migrations;

#nullable disable

namespace Auth.EntityFramework.Migrations
{
    /// <inheritdoc />
    public partial class AddTelegramFields : Migration
    {
        /// <inheritdoc />
        protected override void Up(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.AddColumn<DateTimeOffset>(
                name: "TelegramBoundAt",
                table: "AspNetUsers",
                type: "timestamp with time zone",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TelegramFirstName",
                table: "AspNetUsers",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<long>(
                name: "TelegramId",
                table: "AspNetUsers",
                type: "bigint",
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TelegramLastName",
                table: "AspNetUsers",
                type: "character varying(128)",
                maxLength: 128,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TelegramPhotoUrl",
                table: "AspNetUsers",
                type: "character varying(512)",
                maxLength: 512,
                nullable: true);

            migrationBuilder.AddColumn<string>(
                name: "TelegramUsername",
                table: "AspNetUsers",
                type: "character varying(64)",
                maxLength: 64,
                nullable: true);

            migrationBuilder.CreateIndex(
                name: "IX_AspNetUsers_TelegramId",
                table: "AspNetUsers",
                column: "TelegramId",
                unique: true);
        }

        /// <inheritdoc />
        protected override void Down(MigrationBuilder migrationBuilder)
        {
            migrationBuilder.DropIndex(
                name: "IX_AspNetUsers_TelegramId",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "TelegramBoundAt",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "TelegramFirstName",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "TelegramId",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "TelegramLastName",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "TelegramPhotoUrl",
                table: "AspNetUsers");

            migrationBuilder.DropColumn(
                name: "TelegramUsername",
                table: "AspNetUsers");
        }
    }
}
