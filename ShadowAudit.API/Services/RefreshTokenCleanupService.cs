using Microsoft.EntityFrameworkCore;
using ShadowAudit.API.Data;

namespace ShadowAudit.API.Services;

// Limpieza periódica de refresh tokens vencidos hace tiempo.
// Se conservan 30 días después del vencimiento (configurable en
// "JwtSettings:RefreshCleanupRetentionDays") para no perder la detección de reutilización.
public class RefreshTokenCleanupService : BackgroundService
{
    private static readonly TimeSpan Interval = TimeSpan.FromHours(6);

    private readonly IServiceScopeFactory _scopeFactory;
    private readonly IConfiguration _config;
    private readonly ILogger<RefreshTokenCleanupService> _logger;

    public RefreshTokenCleanupService(
        IServiceScopeFactory scopeFactory,
        IConfiguration config,
        ILogger<RefreshTokenCleanupService> logger)
    {
        _scopeFactory = scopeFactory;
        _config = config;
        _logger = logger;
    }

    protected override async Task ExecuteAsync(CancellationToken stoppingToken)
    {
        try
        {
            // Pequeña espera inicial para no competir con el arranque de la API
            await Task.Delay(TimeSpan.FromSeconds(30), stoppingToken);

            using var timer = new PeriodicTimer(Interval);
            do
            {
                await CleanAsync(stoppingToken);
            }
            while (await timer.WaitForNextTickAsync(stoppingToken));
        }
        catch (OperationCanceledException)
        {
            // La API se está cerrando: no es un error
        }
    }

    private async Task CleanAsync(CancellationToken ct)
    {
        try
        {
            var days = _config.GetValue<int?>("JwtSettings:RefreshCleanupRetentionDays") ?? 30;
            var cutoff = DateTime.UtcNow.AddDays(-days);

            using var scope = _scopeFactory.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<ShadowAuditDbContext>();

            var deleted = await db.RefreshTokens
                .Where(t => t.ExpiresAtUtc < cutoff)
                .ExecuteDeleteAsync(ct);

            if (deleted > 0)
            {
                _logger.LogInformation("Limpieza de refresh tokens: {Count} eliminados.", deleted);
            }
        }
        catch (OperationCanceledException) when (ct.IsCancellationRequested)
        {
            throw;
        }
        catch (Exception ex)
        {
            // Un fallo de limpieza no debe tumbar la API: se registra y se reintenta en el próximo ciclo
            _logger.LogError(ex, "Falló la limpieza de refresh tokens.");
        }
    }
}