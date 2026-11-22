# ---------- Etapa 1: compilar ----------
FROM mcr.microsoft.com/dotnet/sdk:10.0 AS build
WORKDIR /src

# Primero solo el .csproj: Docker reutiliza la cache de paquetes si no cambiaron
COPY ShadowAudit.API/ShadowAudit.API.csproj ShadowAudit.API/
RUN dotnet restore ShadowAudit.API/ShadowAudit.API.csproj

COPY ShadowAudit.API/ ShadowAudit.API/
RUN dotnet publish ShadowAudit.API/ShadowAudit.API.csproj \
    -c Release -o /app/publish --no-restore /p:UseAppHost=false

# ---------- Etapa 2: imagen final (solo lo necesario para ejecutar) ----------
FROM mcr.microsoft.com/dotnet/aspnet:10.0 AS final
WORKDIR /app

ENV ASPNETCORE_HTTP_PORTS=8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DataProtection__KeysPath=/keys

# Carpeta para las claves de cifrado (Data Protection), con permisos para el usuario sin privilegios
RUN mkdir -p /keys && chown $APP_UID:$APP_UID /keys

COPY --from=build /app/publish .

# No se ejecuta como root
USER $APP_UID

EXPOSE 8080
ENTRYPOINT ["dotnet", "ShadowAudit.API.dll"]