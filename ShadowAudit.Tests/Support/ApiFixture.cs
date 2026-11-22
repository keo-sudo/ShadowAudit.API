using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.DependencyInjection;
using ShadowAudit.API.Data;
using Testcontainers.PostgreSql;

namespace ShadowAudit.Tests.Support;

// Levanta UNA base PostgreSQL temporal en Docker y UNA copia de la API para todas las pruebas
// de integracion. Todo se destruye al terminar. Las claves son falsas: nada toca tu base real
// ni tus user-secrets (las variables de entorno tienen prioridad sobre la configuracion normal).
public sealed class ApiFixture : IAsyncLifetime
{
    private readonly PostgreSqlContainer _postgres = new PostgreSqlBuilder()
        .WithImage("postgres:17-alpine")
        .WithDatabase("shadowaudit_tests")
        .WithUsername("postgres")
        .WithPassword("clave-falsa-de-pruebas")
        .Build();

    private readonly string _keysPath =
        Path.Combine(Path.GetTempPath(), "shadowaudit-tests-keys-" + Guid.NewGuid().ToString("N"));

    public TestApiFactory Factory { get; private set; } = null!;

    public async Task InitializeAsync()
    {
        await _postgres.StartAsync();

        Environment.SetEnvironmentVariable("ConnectionStrings__DefaultConnection", _postgres.GetConnectionString());
        Environment.SetEnvironmentVariable("JwtSettings__SecretKey",
            "clave-falsa-solo-para-pruebas-automaticas-no-es-un-secreto-0123456789");
        Environment.SetEnvironmentVariable("DataProtection__KeysPath", _keysPath);

        // Claves falsas: en estas pruebas nunca se llama a servicios externos.
        Environment.SetEnvironmentVariable("VirusTotal__ApiKey", "clave-falsa");
        Environment.SetEnvironmentVariable("AbuseIPDB__ApiKey", "clave-falsa");

        Factory = new TestApiFactory();

        // Aplica TODAS las migraciones reales sobre la base temporal (tambien las prueba).
        using var scope = Factory.Services.CreateScope();
        var db = scope.ServiceProvider.GetRequiredService<ShadowAuditDbContext>();
        await db.Database.MigrateAsync();
    }

    public async Task DisposeAsync()
    {
        await Factory.DisposeAsync();
        await _postgres.DisposeAsync();

        try { Directory.Delete(_keysPath, true); } catch { /* no importa */ }
    }
}

[CollectionDefinition("api")]
public sealed class ApiCollection : ICollectionFixture<ApiFixture>
{
}
