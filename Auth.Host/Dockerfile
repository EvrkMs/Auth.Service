FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS base
WORKDIR /app
EXPOSE 8080
ENV ASPNETCORE_URLS=http://+:8080

FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY ["Auth.Host/Auth.Host.csproj", "Auth.Host/"]
COPY ["Auth.Infrastructure/Auth.Infrastructure.csproj", "Auth.Infrastructure/"]
COPY ["Auth.EntityFramework/Auth.EntityFramework.csproj", "Auth.EntityFramework/"]
COPY ["Auth.Application/Auth.Application.csproj", "Auth.Application/"]
COPY ["Auth.Domain/Auth.Domain.csproj", "Auth.Domain/"]
COPY ["Auth.Telegram/Auth.Telegram.csproj", "Auth.Telegram/"]
RUN dotnet restore "Auth.Host/Auth.Host.csproj"
COPY . .
WORKDIR "/src/Auth.Host"
RUN dotnet publish "Auth.Host.csproj" -c Release -o /app/publish

FROM base AS final
WORKDIR /app
COPY --from=build /app/publish .
ENTRYPOINT ["dotnet", "Auth.Host.dll"]
