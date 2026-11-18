using System.Net;
using System.Net.Sockets;
using System.Text;
using System.Text.RegularExpressions;

namespace ShadowAudit.API.Services;

public record EmailFinding(string Severity, string Message);

public record EmailAnalysis(
    int Score,
    string Risk,
    string Verdict,
    string Spf,
    string Dkim,
    string Dmarc,
    string? FromName,
    string? FromAddress,
    string? FromDomain,
    string? ReplyToDomain,
    string? ReturnPathDomain,
    string? DkimDomain,
    int Hops,
    List<string> PublicIps,
    List<EmailFinding> Findings);

// Análisis propio de cabeceras de correo. Heurístico: solo mira las cabeceras,
// nunca el contenido, los enlaces ni los adjuntos.
public static class EmailHeaderAnalyzer
{
    // Marca -> dominio oficial
    private static readonly Dictionary<string, string> Brands = new(StringComparer.OrdinalIgnoreCase)
    {
        ["paypal"] = "paypal.com",
        ["microsoft"] = "microsoft.com",
        ["google"] = "google.com",
        ["apple"] = "apple.com",
        ["amazon"] = "amazon.com",
        ["netflix"] = "netflix.com",
        ["facebook"] = "facebook.com",
        ["instagram"] = "instagram.com",
        ["whatsapp"] = "whatsapp.com",
        ["linkedin"] = "linkedin.com",
        ["mercadolibre"] = "mercadolibre.com",
        ["interbank"] = "interbank.pe",
        ["scotiabank"] = "scotiabank.com.pe",
        ["bbva"] = "bbva.pe",
        ["viabcp"] = "viabcp.com",
        ["sunat"] = "sunat.gob.pe",
        ["yape"] = "yape.com.pe"
    };

    // Dominios legítimos que contienen el nombre de una marca sin ser la marca
    private static readonly HashSet<string> KnownLegit = new(StringComparer.OrdinalIgnoreCase)
    {
        "amazonaws.com", "amazonses.com", "googlemail.com", "googlegroups.com",
        "googleusercontent.com", "microsoftonline.com", "facebookmail.com"
    };

    public static EmailAnalysis Analyze(string raw)
    {
        var headers = ParseHeaders(raw);
        var findings = new List<EmailFinding>();
        var score = 0;

        void Add(string severity, string message, int points)
        {
            findings.Add(new EmailFinding(severity, message));
            score += points;
        }

        // --- Autenticación (solo la cabecera más reciente, la de más arriba) ---
        var authResults = First(headers, "Authentication-Results");
        var receivedSpf = First(headers, "Received-SPF");

        var spf = AuthResult(authResults, "spf");
        if (spf == "desconocido" && receivedSpf is not null)
        {
            var m = Regex.Match(receivedSpf, @"^\s*(pass|fail|softfail|neutral|none|temperror|permerror)",
                RegexOptions.IgnoreCase);
            if (m.Success) spf = m.Groups[1].Value.ToLowerInvariant();
        }

        var dkim = AuthResult(authResults, "dkim");
        var dmarc = AuthResult(authResults, "dmarc");

        if (spf == "desconocido" && dkim == "desconocido" && dmarc == "desconocido")
            Add("baja", "No se encontraron resultados de SPF, DKIM ni DMARC. Copia las cabeceras completas (en Gmail: \"Mostrar original\").", 1);

        if (spf == "fail") Add("alta", "SPF falló: el servidor que envió el correo no está autorizado por el dominio del remitente.", 3);
        else if (spf == "softfail") Add("media", "SPF dio softfail: el servidor emisor no está autorizado, aunque el dominio no es estricto.", 2);

        if (dkim == "fail") Add("alta", "DKIM falló: la firma del mensaje no es válida o el contenido fue alterado.", 3);
        else if (dkim == "none") Add("baja", "El mensaje no tiene firma DKIM.", 1);

        if (dmarc == "fail") Add("alta", "DMARC falló: el correo no cumple la política del dominio del remitente.", 4);
        else if (dmarc == "none") Add("baja", "El dominio del remitente no publica política DMARC.", 1);

        // --- Remitente ---
        var (fromName, fromAddress) = ParseAddress(First(headers, "From"));
        var fromDomain = DomainOf(fromAddress);

        var (_, replyToAddress) = ParseAddress(First(headers, "Reply-To"));
        var replyToDomain = DomainOf(replyToAddress);

        var (_, returnPathAddress) = ParseAddress(First(headers, "Return-Path"));
        var returnPathDomain = DomainOf(returnPathAddress);

        string? dkimDomain = null;
        var dkimSignature = First(headers, "DKIM-Signature");
        if (dkimSignature is not null)
        {
            var m = Regex.Match(dkimSignature, @"\bd=([^;\s]+)", RegexOptions.IgnoreCase);
            if (m.Success) dkimDomain = m.Groups[1].Value.ToLowerInvariant();
        }

        if (fromDomain is null)
        {
            Add("media", "No se pudo leer el dominio del remitente (cabecera From).", 1);
        }
        else
        {
            if (replyToDomain is not null && !Aligned(fromDomain, replyToDomain))
                Add("media", $"Las respuestas irían a otro dominio ({replyToDomain}) distinto del remitente ({fromDomain}).", 2);

            if (returnPathDomain is not null && !Aligned(fromDomain, returnPathDomain))
                Add("baja", $"El dominio de rebote (Return-Path: {returnPathDomain}) no coincide con el del remitente. Es común en envíos masivos legítimos.", 1);

            if (dkim == "pass" && dkimDomain is not null && !Aligned(fromDomain, dkimDomain))
                Add("baja", $"La firma DKIM es de otro dominio ({dkimDomain}), no del remitente.", 1);

            if (fromDomain.Contains("xn--"))
                Add("alta", "El dominio del remitente usa punycode (xn--), que puede ocultar caracteres que imitan letras conocidas.", 3);
            else if (fromDomain.Any(c => c > 127))
                Add("alta", "El dominio del remitente tiene caracteres no ASCII que pueden imitar letras conocidas.", 3);

            // Dominios parecidos a marcas conocidas
            var lookalike = false;
            foreach (var brandDomain in Brands.Values.Distinct())
            {
                if (fromDomain == brandDomain || fromDomain.EndsWith("." + brandDomain)) continue;
                if (fromDomain.Length > 100 || brandDomain.Length < 6) continue;

                if (Distance(fromDomain, brandDomain) <= 2)
                {
                    Add("alta", $"El dominio {fromDomain} se parece mucho a {brandDomain}, pero no es el mismo.", 4);
                    lookalike = true;
                    break;
                }
            }

            if (!lookalike && !KnownLegit.Any(k => fromDomain == k || fromDomain.EndsWith("." + k)))
            {
                foreach (var (label, brandDomain) in Brands)
                {
                    if (label.Length < 5) continue;
                    if (fromDomain == brandDomain || fromDomain.EndsWith("." + brandDomain)) continue;

                    if (fromDomain.Contains(label, StringComparison.OrdinalIgnoreCase))
                    {
                        Add("media", $"El dominio {fromDomain} contiene el nombre \"{label}\" pero no es el dominio oficial ({brandDomain}).", 3);
                        break;
                    }
                }
            }

            // Suplantación por nombre visible
            if (!string.IsNullOrWhiteSpace(fromName))
            {
                var spoofedBrand = false;
                foreach (var (label, brandDomain) in Brands)
                {
                    if (!Regex.IsMatch(fromName, $@"\b{Regex.Escape(label)}\b", RegexOptions.IgnoreCase)) continue;
                    if (fromDomain == brandDomain || fromDomain.EndsWith("." + brandDomain)) continue;

                    Add("alta", $"El nombre visible menciona \"{label}\", pero el correo viene de {fromDomain}.", 3);
                    spoofedBrand = true;
                    break;
                }

                if (!spoofedBrand)
                {
                    var shown = Regex.Match(fromName,
                        @"[a-z0-9\-]+(\.[a-z0-9\-]+)*\.[a-z]{2,}|\S+@\S+", RegexOptions.IgnoreCase);
                    if (shown.Success)
                    {
                        var shownDomain = shown.Value.Contains('@')
                            ? shown.Value[(shown.Value.LastIndexOf('@') + 1)..].ToLowerInvariant()
                            : shown.Value.ToLowerInvariant();

                        if (!Aligned(fromDomain, shownDomain))
                            Add("media", $"El nombre visible muestra \"{shown.Value}\", pero el correo viene de {fromDomain}.", 3);
                    }
                }
            }
        }

        // --- Ruta del mensaje ---
        var received = headers
            .Where(h => h.Key.Equals("Received", StringComparison.OrdinalIgnoreCase))
            .Select(h => h.Value)
            .ToList();

        var publicIps = new List<string>();
        foreach (var hop in Enumerable.Reverse(received))
        {
            foreach (Match m in Regex.Matches(hop, @"\[(?:IPv6:)?([0-9a-fA-F:.]{3,45})\]"))
            {
                if (IPAddress.TryParse(m.Groups[1].Value, out var ip) && IsPublic(ip))
                {
                    var text = ip.ToString();
                    if (!publicIps.Contains(text)) publicIps.Add(text);
                }
            }
            if (publicIps.Count >= 10) break;
        }

        var (risk, verdict) = score switch
        {
            >= 7 => ("alto",
                "Muy probablemente es phishing o suplantación. No abras enlaces ni adjuntos de este correo."),
            >= 3 => ("medio",
                "Hay señales sospechosas. Verifica al remitente por otro medio antes de actuar."),
            _ => ("bajo",
                "No se encontraron señales fuertes en las cabeceras. Esto NO garantiza que sea seguro: el análisis no mira el contenido, los enlaces ni los adjuntos.")
        };

        return new EmailAnalysis(
            score, risk, verdict, spf, dkim, dmarc,
            fromName, fromAddress, fromDomain, replyToDomain, returnPathDomain, dkimDomain,
            received.Count, publicIps, findings);
    }

    private static List<KeyValuePair<string, string>> ParseHeaders(string raw)
    {
        var result = new List<KeyValuePair<string, string>>();
        var lines = raw.Replace("\r\n", "\n").Replace('\r', '\n').Split('\n');

        string? name = null;
        var value = new StringBuilder();

        void Flush()
        {
            if (name is not null)
                result.Add(new KeyValuePair<string, string>(name, value.ToString().Trim()));
            name = null;
            value.Clear();
        }

        foreach (var line in lines)
        {
            // Línea en blanco: termina el bloque de cabeceras
            if (line.Length == 0)
            {
                Flush();
                if (result.Count > 0) break;
                continue;
            }

            // Línea de continuación de la cabecera anterior
            if (line[0] == ' ' || line[0] == '\t')
            {
                if (name is not null) value.Append(' ').Append(line.Trim());
                continue;
            }

            var idx = line.IndexOf(':');
            if (idx <= 0) continue;

            var candidate = line[..idx];
            if (candidate.Any(char.IsWhiteSpace)) continue;

            Flush();
            name = candidate;
            value.Append(line[(idx + 1)..].Trim());
        }

        Flush();
        return result;
    }

    private static string? First(List<KeyValuePair<string, string>> headers, string name) =>
        headers.FirstOrDefault(h => h.Key.Equals(name, StringComparison.OrdinalIgnoreCase)).Value;

    private static string AuthResult(string? text, string mechanism)
    {
        if (string.IsNullOrEmpty(text)) return "desconocido";

        var matches = Regex.Matches(text,
            $@"\b{mechanism}\s*=\s*(pass|fail|softfail|neutral|none|temperror|permerror|policy)",
            RegexOptions.IgnoreCase);

        if (matches.Count == 0) return "desconocido";

        // DKIM puede tener varias firmas: basta con que una sea válida
        foreach (Match m in matches)
            if (m.Groups[1].Value.Equals("pass", StringComparison.OrdinalIgnoreCase))
                return "pass";

        return matches[0].Groups[1].Value.ToLowerInvariant();
    }

    private static (string? Name, string? Address) ParseAddress(string? value)
    {
        if (string.IsNullOrWhiteSpace(value)) return (null, null);

        var m = Regex.Match(value, @"^\s*(?<name>.*?)\s*<(?<addr>[^<>]*)>\s*$");
        if (m.Success)
        {
            var addr = m.Groups["addr"].Value.Trim();
            return (m.Groups["name"].Value.Trim().Trim('"'), addr.Length == 0 ? null : addr);
        }

        return (null, value.Trim().Trim('<', '>'));
    }

    private static string? DomainOf(string? address)
    {
        if (address is null) return null;

        var at = address.LastIndexOf('@');
        if (at < 0 || at == address.Length - 1) return null;

        return address[(at + 1)..].Trim().Trim('>').ToLowerInvariant();
    }

    // Alineación relajada: mismo dominio, o uno es subdominio del otro
    private static bool Aligned(string a, string b) =>
        a == b || a.EndsWith("." + b) || b.EndsWith("." + a);

    private static int Distance(string a, string b)
    {
        var d = new int[a.Length + 1, b.Length + 1];
        for (var i = 0; i <= a.Length; i++) d[i, 0] = i;
        for (var j = 0; j <= b.Length; j++) d[0, j] = j;

        for (var i = 1; i <= a.Length; i++)
        {
            for (var j = 1; j <= b.Length; j++)
            {
                var cost = a[i - 1] == b[j - 1] ? 0 : 1;
                d[i, j] = Math.Min(Math.Min(d[i - 1, j] + 1, d[i, j - 1] + 1), d[i - 1, j - 1] + cost);
            }
        }

        return d[a.Length, b.Length];
    }

    private static bool IsPublic(IPAddress ip)
    {
        if (IPAddress.IsLoopback(ip)) return false;

        if (ip.AddressFamily == AddressFamily.InterNetwork)
        {
            var b = ip.GetAddressBytes();
            return !(b[0] == 0 || b[0] == 10 || b[0] == 127
                     || (b[0] == 169 && b[1] == 254)
                     || (b[0] == 172 && b[1] >= 16 && b[1] <= 31)
                     || (b[0] == 192 && b[1] == 168));
        }

        if (ip.AddressFamily == AddressFamily.InterNetworkV6)
            return !(ip.IsIPv6LinkLocal || ip.IsIPv6SiteLocal || ip.IsIPv6UniqueLocal);

        return false;
    }
}