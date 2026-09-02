FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src
COPY SecureIdentityData.slnx .
COPY src/IdentityProvider.Api/IdentityProvider.Api.csproj src/IdentityProvider.Api/
COPY src/IdentityData.Api/IdentityData.Api.csproj src/IdentityData.Api/
RUN dotnet restore src/IdentityData.Api/IdentityData.Api.csproj
COPY src/IdentityData.Api/ src/IdentityData.Api/
RUN dotnet publish src/IdentityData.Api/IdentityData.Api.csproj -c Release -o /app/publish --no-restore

FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .
ENV ASPNETCORE_URLS=http://+:8080
ENV ASPNETCORE_ENVIRONMENT=Production
EXPOSE 8080
ENTRYPOINT ["dotnet", "IdentityData.Api.dll"]
