using System.Net;
using System.Net.Http;
using System.Net.Security;
using System.Net.Sockets;

namespace ShadowAudit.API.Services;

// Protección contra SSRF: el escáner NUNCA se conecta a direcciones privadas o internas.
// La IP se valida en el momento de conectar (no antes), así que un DNS que cambia
// de respuesta no puede engañarlo.
public static class SafeConnect
{
    public static async Task<IPAddress[]> ResolvePublicAddressesAsync(string host, CancellationToken ct)
    {
        IPAddress[] addresses;
        try
        {
            addresses = await Dns.GetHostAddressesAsync(host, ct);
        }
        catch (SocketException)
        {
            throw new HttpRequestException("No se pudo resolver el dominio.");
        }

        if (addresses.Length == 0)
            throw new HttpRequestException("No se pudo resolver el dominio.");

        if (addresses.Any(a => !PublicIp.IsPublic(a)))
            throw new HttpRequestException("El dominio apunta a una dirección no pública.");

        return addresses;
    }

    public static async Task<Stream> OpenStreamAsync(string host, int port, CancellationToken ct)
    {
        var addresses = await ResolvePublicAddressesAsync(host, ct);
        Exception? last = null;

        foreach (var address in addresses)
        {
            var socket = new Socket(address.AddressFamily, SocketType.Stream, ProtocolType.Tcp) { NoDelay = true };
            try
            {
                using var cts = CancellationTokenSource.CreateLinkedTokenSource(ct);
                cts.CancelAfter(TimeSpan.FromSeconds(5));
                await socket.ConnectAsync(new IPEndPoint(address, port), cts.Token);
                return new NetworkStream(socket, ownsSocket: true);
            }
            catch (Exception ex) when (ex is SocketException or OperationCanceledException)
            {
                socket.Dispose();
                last = ex;
                if (ct.IsCancellationRequested) throw;
            }
        }

        throw new HttpRequestException("No se pudo conectar.", last);
    }

    public static async ValueTask<Stream> ConnectAsync(SocketsHttpConnectionContext context, CancellationToken ct)
    {
        var port = context.DnsEndPoint.Port;
        if (port != 80 && port != 443)
            throw new HttpRequestException("Puerto no permitido.");

        return await OpenStreamAsync(context.DnsEndPoint.Host, port, ct);
    }

    public static SocketsHttpHandler CreateHandler() => new()
    {
        AllowAutoRedirect = false,
        UseCookies = false,
        UseProxy = false,
        ConnectTimeout = TimeSpan.FromSeconds(5),
        ConnectCallback = ConnectAsync,
        // Solo lectura: se inspecciona el sitio aunque tenga el certificado mal.
        // El certificado se evalúa aparte en TlsProbe.
        SslOptions = new SslClientAuthenticationOptions
        {
            RemoteCertificateValidationCallback = (_, _, _, _) => true
        }
    };
}