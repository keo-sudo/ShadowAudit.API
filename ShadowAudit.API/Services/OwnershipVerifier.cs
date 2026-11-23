using System.Security.Cryptography;
using DnsClient;

namespace ShadowAudit.API.Services;

public interface IDnsTxtResolver
{
    Task<IReadOnlyList<string>> GetTxtAsync(string name, CancellationToken ct);
}

public class DnsClientTxtResolver : IDnsTxtResolver
{
    private readonly LookupClient _client = new(new LookupClientOptions
    {
        UseCache = false,
        Timeout = TimeSpan.FromSeconds(5),
        Retries = 1
    });

    public async Task<IReadOnlyList<string>> GetTxtAsync(string name, CancellationToken ct)
    {
        try
        {
            var result = await _client.QueryAsync(name, QueryType.TXT, cancellationToken: ct);
            return result.Answers.TxtRecords().Select(t => string.Concat(t.Text)).ToList();
        }
        catch (DnsResponseException)
        {
            return Array.Empty<string>();
        }
    }
}

public record VerificationResult(bool Verified, string? Method);

// Comprueba que el usuario controla el dominio: un registro DNS TXT o un archivo en el sitio.
public class OwnershipVerifier
{
    public const string Prefix = "shadowaudit-verify=";

    private readonly IDnsTxtResolver _dns;
    private readonly SiteProbe _probe;

    public OwnershipVerifier(IDnsTxtResolver dns, SiteProbe probe)
    {
        _dns = dns;
        _probe = probe;
    }

    public static string NewToken() =>
        Convert.ToBase64String(RandomNumberGenerator.GetBytes(32))
            .TrimEnd('=').Replace('+', '-').Replace('/', '_');

    public static string DnsName(string host) => $"_shadowaudit-verify.{host}";

    public static string DnsValue(string token) => Prefix + token;

    public static string FileUrl(string host) => $"https://{host}/.well-known/shadowaudit-verify.txt";

    public async Task<VerificationResult> VerifyAsync(string host, string token, CancellationToken ct)
    {
        var txts = await _dns.GetTxtAsync(DnsName(host), ct);
        if (txts.Any(t => t.Trim() == DnsValue(token)))
            return new VerificationResult(true, "dns");

        var urls = new[] { FileUrl(host), $"http://{host}/.well-known/shadowaudit-verify.txt" };
        foreach (var url in urls)
        {
            var response = await _probe.GetAsync(url, 4096, ct);
            if (response is { StatusCode: 200 } && response.BodyText.Contains(token, StringComparison.Ordinal))
                return new VerificationResult(true, "archivo");
        }

        return new VerificationResult(false, null);
    }
}