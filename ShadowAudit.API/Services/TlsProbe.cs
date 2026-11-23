using System.Net.Security;
using System.Net.Sockets;
using System.Security.Authentication;
using System.Security.Cryptography.X509Certificates;

namespace ShadowAudit.API.Services;

public record TlsInfo(bool Connected, SslProtocols Protocol, DateTime? NotAfterUtc, SslPolicyErrors PolicyErrors);

public interface ITlsProbe
{
    Task<TlsInfo> InspectAsync(string host, CancellationToken ct);
}

public class TlsProbe : ITlsProbe
{
    public async Task<TlsInfo> InspectAsync(string host, CancellationToken ct)
    {
        try
        {
            using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
            cts.CancelAfter(TimeSpan.FromSeconds(8));

            await using var network = await SafeConnect.OpenStreamAsync(host, 443, cts.Token);

            var errors = SslPolicyErrors.None;
            DateTime? notAfter = null;

            await using var ssl = new SslStream(network, false, (_, certificate, _, policyErrors) =>
            {
                errors = policyErrors;
                if (certificate is not null)
                {
                    var cert = certificate as X509Certificate2 ?? new X509Certificate2(certificate);
                    notAfter = cert.NotAfter.ToUniversalTime();
                }
                return true;
            });

            await ssl.AuthenticateAsClientAsync(new SslClientAuthenticationOptions { TargetHost = host }, cts.Token);

            return new TlsInfo(true, ssl.SslProtocol, notAfter, errors);
        }
        catch (Exception ex) when (ex is HttpRequestException or IOException or AuthenticationException
                                       or SocketException or OperationCanceledException)
        {
            return new TlsInfo(false, SslProtocols.None, null, SslPolicyErrors.None);
        }
    }
}