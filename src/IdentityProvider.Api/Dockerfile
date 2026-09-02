FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
# Copy solution + csproj files first (layer caching)
COPY SecureIdentityData.slnx .
COPY src/IdentityProvider.Api/IdentityProvider.Api.csproj src/IdentityProvider.Api/
# Restore only IdentityProvider.Api
RUN dotnet restore src/IdentityProvider.Api/IdentityProvider.Api.csproj
# Copy source
COPY src/IdentityProvider.Api/ src/IdentityProvider.Api/
# Build and publish
RUN dotnet publish src/IdentityProvider.Api/IdentityProvider.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
# HTTPS certificate: in Docker compose, we'll use HTTP (port 80) to keep it simple
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080
ENTRYPOINT ["dotnet", "IdentityProvider.Api.dll"]
