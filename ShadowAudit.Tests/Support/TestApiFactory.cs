using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;

namespace ShadowAudit.Tests.Support;

// La API completa, en memoria. Cada cliente de prueba simula venir de una IP distinta
// (cabecera X-Test-Ip) para que los limites de solicitudes por IP no se mezclen entre pruebas.
public sealed class TestApiFactory : WebApplicationFactory<Program>
{
    private static int _ipCounter;

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            services.AddTransient<IStartupFilter, TestIpStartupFilter>();
        });
    }

    public static string NextIp()
    {
        var n = Interlocked.Increment(ref _ipCounter);
        return $"10.{(n >> 16) & 255}.{(n >> 8) & 255}.{n & 255}";
    }

    public HttpClient NewClient(string? ip = null)
    {
        var client = CreateClient(new WebApplicationFactoryClientOptions
        {
            BaseAddress = new Uri("https://localhost"),
            AllowAutoRedirect = false
        });
        client.DefaultRequestHeaders.Add(TestIpStartupFilter.HeaderName, ip ?? NextIp());
        return client;
    }
}

public sealed class TestIpStartupFilter : IStartupFilter
{
    public const string HeaderName = "X-Test-Ip";

    public Action<IApplicationBuilder> Configure(Action<IApplicationBuilder> next) => app =>
    {
        app.Use(async (context, nextMiddleware) =>
        {
            if (context.Request.Headers.TryGetValue(HeaderName, out var value) &&
                IPAddress.TryParse(value.ToString(), out var ip))
            {
                context.Connection.RemoteIpAddress = ip;
            }

            await nextMiddleware();
        });

        next(app);
    };
}
