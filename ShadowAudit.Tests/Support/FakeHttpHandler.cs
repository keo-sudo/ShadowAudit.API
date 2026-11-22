using System.Net;

namespace ShadowAudit.Tests.Support;

public sealed record SentRequest(HttpMethod Method, Uri Uri, string? Body);

// Servidor HTTP falso: devuelve respuestas preparadas y recuerda lo que se le envio. No usa internet.
public sealed class FakeHttpHandler : HttpMessageHandler
{
    private readonly Func<SentRequest, HttpResponseMessage> _respond;

    public FakeHttpHandler(Func<SentRequest, HttpResponseMessage> respond)
    {
        _respond = respond;
    }

    public List<SentRequest> Sent { get; } = new();

    public static FakeHttpHandler Always(HttpStatusCode status, string body = "") =>
        new(_ => Response(status, body));

    public static FakeHttpHandler Throwing(Exception exception) =>
        new(_ => throw exception);

    public static HttpResponseMessage Response(HttpStatusCode status, string body = "") =>
        new(status) { Content = new StringContent(body) };

    protected override async Task<HttpResponseMessage> SendAsync(
        HttpRequestMessage request, CancellationToken cancellationToken)
    {
        var body = request.Content is null
            ? null
            : await request.Content.ReadAsStringAsync(cancellationToken);

        var sent = new SentRequest(request.Method, request.RequestUri!, body);
        Sent.Add(sent);

        return _respond(sent);
    }
}