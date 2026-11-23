namespace ShadowAudit.API.Services;

public static class WebScannerSetup
{
    public static IServiceCollection AddWebScanner(this IServiceCollection services)
    {
        services.AddSingleton<IDnsTxtResolver, DnsClientTxtResolver>();
        services.AddSingleton<ITlsProbe, TlsProbe>();

        services.AddHttpClient<SiteProbe>(client =>
        {
            client.Timeout = TimeSpan.FromSeconds(8);
            client.DefaultRequestHeaders.UserAgent.ParseAdd("ShadowAudit-Scanner (+https://github.com/keo-sudo/ShadowAudit.API)");
            client.DefaultRequestHeaders.Accept.ParseAdd("*/*");
        }).ConfigurePrimaryHttpMessageHandler(() => SafeConnect.CreateHandler());

        services.AddScoped<OwnershipVerifier>();
        services.AddScoped<WebScanner>();

        return services;
    }
}