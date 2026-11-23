using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using ShadowAudit.API.Services;

namespace ShadowAudit.Tests.Support;

// La API completa, en memoria. Cada cliente de prueba simula venir de una IP distinta
// (cabecera X-Test-Ip) para que los limites de solicitudes por IP no se mezclen entre pruebas.
// El escaner web usa DNS, TLS y HTTP falsos: nunca sale a internet.
public sealed class TestApiFactory : WebApplicationFactory<Program>
{
    private static int _ipCounter;

    public FakeDnsTxtResolver Dns { get; } = new();

    public FakeTlsProbe Tls { get; } = new();

    public Func<SentRequest, HttpResponseMessage> SiteResponder { get; set; } = FakeSites.Healthy;

    public FakeHttpHandler SiteHandler { get; }

    public TestApiFactory()
    {
        SiteHandler = new FakeHttpHandler(request => SiteResponder(request));
        WebScanner.DefaultProbeDelay = TimeSpan.Zero;
    }

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            services.AddTransient<IStartupFilter, TestIpStartupFilter>();
        });

        builder.ConfigureTestServices(services =>
        {
            services.AddSingleton<IDnsTxtResolver>(Dns);
            services.AddSingleton<ITlsProbe>(Tls);
            services.AddHttpClient<SiteProbe>()
                .ConfigurePrimaryHttpMessageHandler(() => SiteHandler)
                .SetHandlerLifetime(Timeout.InfiniteTimeSpan);
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