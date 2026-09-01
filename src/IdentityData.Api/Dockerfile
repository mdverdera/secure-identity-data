# ── Build stage ───────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Copy solution and project files first for layer caching
COPY SecureIdentityData.slnx ./
COPY src/IdentityData.Api/IdentityData.Api.csproj ./src/IdentityData.Api/

# Restore only the IdentityData.Api project dependencies
RUN dotnet restore src/IdentityData.Api/IdentityData.Api.csproj

# Copy the rest of the source
COPY src/IdentityData.Api/ ./src/IdentityData.Api/

# Publish
RUN dotnet publish src/IdentityData.Api/IdentityData.Api.csproj \
    -c Release \
    -o /app/publish \
    --no-restore

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app

# Create a non-root user for security
RUN adduser --disabled-password --gecos "" appuser && chown -R appuser /app
USER appuser

# Copy published output
COPY --from=build --chown=appuser:appuser /app/publish .

# Listen on HTTP port 8080 (TLS termination handled by load balancer in production)
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production

EXPOSE 8080

ENTRYPOINT ["dotnet", "IdentityData.Api.dll"]
