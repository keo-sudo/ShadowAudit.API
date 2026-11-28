using System.Net;
using System.Net.Sockets;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public record AccessEvent(string Action, string Ip, string UserAgent, DateTime At);

public record AccessResult(
    string Risk, bool HasBaseline, int LoginSuccesses, int FailedLast24h,
    IReadOnlyList<string> NewIps, IReadOnlyList<string> NewDevices, IReadOnlyList<string> Findings);

// Revisa el registro de accesos de la propia cuenta y busca actividad rara.
public static class AccessAudit
{
    private static readonly string[] FailActions = { "LoginFailed", "LoginFailed2FA", "LoginBlocked" };

    public static AccessResult Analyze(IReadOnlyCollection<AccessEvent> events, DateTime nowUtc)
    {
        var findings = new List<string>();
        var risk = RiskLevels.Low;

        var successes = events.Where(e => e.Action == "LoginSuccess").OrderBy(e => e.At).ToList();
        var recentFrom = nowUtc.AddDays(-7);
        var baseline = successes.Where(e => e.At < recentFrom).ToList();
        var recent = successes.Where(e => e.At >= recentFrom).ToList();
        var hasBaseline = baseline.Count > 0;

        var newIps = new List<string>();
        var newDevices = new List<string>();
        if (hasBaseline)
        {
            var knownIps = baseline.Select(e => e.Ip).ToHashSet();
            var knownAgents = baseline.Select(e => e.UserAgent).ToHashSet();
            newIps = recent.Where(e => !knownIps.Contains(e.Ip)).Select(e => Mask(e.Ip)).Distinct().ToList();
            newDevices = recent.Where(e => !knownAgents.Contains(e.UserAgent)).Select(e => ShortAgent(e.UserAgent)).Distinct().ToList();
        }
        else
        {
            findings.Add("Todavía no hay historial de más de 7 días para detectar IPs o navegadores nuevos.");
        }

        if (newIps.Count > 0)
        {
            findings.Add($"Entraste desde {newIps.Count} IP(s) que no habías usado antes.");
            risk = Max(risk, RiskLevels.Medium);
        }
        if (newDevices.Count > 0)
        {
            findings.Add($"Entraste con {newDevices.Count} navegador(es) o dispositivo(s) nuevo(s).");
            risk = Max(risk, RiskLevels.Medium);
        }

        var failed = events.Count(e => FailActions.Contains(e.Action) && e.At >= nowUtc.AddHours(-24));
        if (failed >= 10)
        {
            findings.Add($"{failed} intentos de acceso fallidos en las últimas 24 horas.");
            risk = Max(risk, "alto");
        }
        else if (failed >= 5)
        {
            findings.Add($"{failed} intentos de acceso fallidos en las últimas 24 horas.");
            risk = Max(risk, RiskLevels.Medium);
        }

        var fastChange = successes.Any(s => successes
            .Where(o => o.At >= s.At && o.At <= s.At.AddHours(1))
            .Select(o => o.Ip).Distinct().Count() >= 3);
        if (fastChange)
        {
            findings.Add("Se usaron 3 o más IPs distintas en menos de una hora.");
            risk = Max(risk, RiskLevels.Medium);
        }

        if (events.Any(e => e.Action == "RefreshTokenReuse"))
        {
            findings.Add("Se detectó la reutilización de un token de sesión: podría haber sido robado.");
            risk = Max(risk, "alto");
        }

        if (risk == RiskLevels.Low && hasBaseline)
            findings.Add("No se detectó actividad sospechosa en tu cuenta.");

        return new AccessResult(risk, hasBaseline, successes.Count, failed, newIps, newDevices, findings);
    }

    private static int Rank(string risk) => risk == "alto" ? 2 : risk == RiskLevels.Medium ? 1 : 0;

    private static string Max(string a, string b) => Rank(a) >= Rank(b) ? a : b;

    private static string ShortAgent(string agent) =>
        agent.Length == 0 ? "(sin dato)" : agent.Length <= 60 ? agent : agent[..60] + "...";

    // Oculta el último número de la IP para no mostrarla completa.
    private static string Mask(string ip)
    {
        if (!IPAddress.TryParse(ip, out var addr)) return "(desconocida)";
        if (addr.IsIPv4MappedToIPv6) addr = addr.MapToIPv4();
        var text = addr.ToString();
        if (addr.AddressFamily == AddressFamily.InterNetwork)
        {
            var p = text.Split('.');
            return $"{p[0]}.{p[1]}.{p[2]}.x";
        }
        return string.Join(":", text.Split(':').Take(3)) + "::x";
    }
}