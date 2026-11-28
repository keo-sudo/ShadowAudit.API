using System.ComponentModel.DataAnnotations;
using System.Net;
using System.Text.RegularExpressions;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public record NetworkDevicesRequest(
    [Required(ErrorMessage = "Pega la salida del comando.")]
    [StringLength(20000, MinimumLength = 10, ErrorMessage = "La salida debe tener entre 10 y 20000 caracteres.")]
    string Output,

    [MaxLength(100, ErrorMessage = "Puedes enviar hasta 100 direcciones MAC conocidas.")]
    string[]? KnownMacs = null,

    [StringLength(100, ErrorMessage = "La etiqueta no puede pasar de 100 caracteres.")]
    string? Label = null);

public record NetworkDevice(string Ip, string Mac, string Type, bool PrivateMac, bool? Known);

public record DevicesAudit(
    string Risk, int Total, int Unknown, List<NetworkDevice> Devices, List<string> SharedMacs, string Advice);

// Analiza la salida de "arp -a" pegada por el usuario. No ejecuta nada ni guarda el texto.
public static class DeviceAudit
{
    private static readonly Regex Line = new(
        @"^\s*(\d{1,3}(?:\.\d{1,3}){3})\s+([0-9a-f]{2}(?:[-:][0-9a-f]{2}){5})\s+(\S+)",
        RegexOptions.IgnoreCase | RegexOptions.Multiline);

    private static readonly Regex MacShape = new(@"^[0-9a-f]{2}([-:][0-9a-f]{2}){5}$", RegexOptions.IgnoreCase);

    // Devuelve la MAC en formato aa-bb-cc-dd-ee-ff, o null si no tiene forma de MAC.
    public static string? NormalizeMac(string? mac) =>
        mac is not null && MacShape.IsMatch(mac.Trim())
            ? mac.Trim().ToLowerInvariant().Replace(':', '-')
            : null;

    public static DevicesAudit? Analyze(string text, IReadOnlyCollection<string>? knownMacs)
    {
        var known = (knownMacs ?? Array.Empty<string>())
            .Select(NormalizeMac).Where(m => m is not null).Select(m => m!).ToHashSet();

        var seen = new HashSet<string>();
        var devices = new List<NetworkDevice>();
        foreach (Match m in Line.Matches(text))
        {
            if (!IPAddress.TryParse(m.Groups[1].Value, out var ip)) continue;
            var mac = NormalizeMac(m.Groups[2].Value)!;
            if (IsNoise(ip, mac) || !seen.Add($"{ip}|{mac}")) continue;

            var firstByte = Convert.ToInt32(mac[..2], 16);
            devices.Add(new NetworkDevice(ip.ToString(), mac, m.Groups[3].Value,
                (firstByte & 0x02) != 0, known.Count == 0 ? null : known.Contains(mac)));
        }
        if (devices.Count == 0) return null;

        var shared = devices.GroupBy(d => d.Mac).Where(g => g.Count() > 1).Select(g => g.Key).ToList();
        var unknown = known.Count == 0 ? 0 : devices.Count(d => d.Known == false);

        var risk = unknown >= 3 ? "alto"
                 : unknown > 0 || shared.Count > 0 ? RiskLevels.Medium
                 : RiskLevels.Low;

        var advice = new List<string>();
        if (unknown > 0)
            advice.Add("Hay dispositivos que no reconoces. Revisa en el panel de tu router la lista de conectados y cambia la clave del wifi si no son tuyos.");
        if (shared.Count > 0)
            advice.Add("Dos IPs comparten la misma MAC: suele ser un router con varias direcciones, pero también puede indicar un ataque a la red. Revísalo en el router.");
        if (advice.Count == 0)
            advice.Add(known.Count == 0
                ? "Para saber cuáles no reconoces, vuelve a enviar con knownMacs (las MAC de tus dispositivos)."
                : "Todos los dispositivos de la lista son conocidos.");

        return new DevicesAudit(risk, devices.Count, unknown, devices, shared, string.Join(" ", advice));
    }

    // Direcciones de difusión y multicast: no son dispositivos reales.
    private static bool IsNoise(IPAddress ip, string mac) =>
        ip.GetAddressBytes()[0] >= 224 || mac == "ff-ff-ff-ff-ff-ff" || mac.StartsWith("01-00-5e");
}