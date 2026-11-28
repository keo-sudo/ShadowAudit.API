using System.Globalization;
using MetadataExtractor;
using MetadataExtractor.Formats.Exif;
using ShadowAudit.API.Models;

namespace ShadowAudit.API.Services;

public record ExifResult(
    string Risk, bool HasGps, double? Latitude, double? Longitude, string? MapUrl,
    string? Device, string? TakenAt, IReadOnlyList<string> Findings);

// Lee los metadatos ocultos (EXIF) de una foto y avisa que datos personales revela.
public static class ExifAudit
{
    public static bool TryAnalyze(Stream stream, out ExifResult? result)
    {
        result = null;
        try
        {
            var dirs = ImageMetadataReader.ReadMetadata(stream);
            var gps = dirs.OfType<GpsDirectory>().FirstOrDefault()?.GetGeoLocation();
            var ifd0 = dirs.OfType<ExifIfd0Directory>().FirstOrDefault();
            var sub = dirs.OfType<ExifSubIfdDirectory>().FirstOrDefault();

            DateTime? taken = null;
            if (sub is not null && sub.TryGetDateTime(ExifDirectoryBase.TagDateTimeOriginal, out var dt)) taken = dt;

            result = Build(gps?.Latitude, gps?.Longitude,
                ifd0?.GetString(ExifDirectoryBase.TagMake), ifd0?.GetString(ExifDirectoryBase.TagModel),
                taken, ifd0?.GetString(ExifDirectoryBase.TagArtist));
            return true;
        }
        catch (Exception ex) when (ex is ImageProcessingException or IOException)
        {
            return false;
        }
    }

    public static ExifResult Build(double? lat, double? lon, string? make, string? model, DateTime? takenAt, string? author)
    {
        var findings = new List<string>();

        var hasGps = lat is not null && lon is not null && !(lat == 0 && lon == 0);
        string? map = null;
        if (hasGps)
        {
            var la = lat!.Value.ToString("F6", CultureInfo.InvariantCulture);
            var lo = lon!.Value.ToString("F6", CultureInfo.InvariantCulture);
            map = $"https://www.google.com/maps?q={la},{lo}";
            findings.Add("La foto trae coordenadas GPS: revela el lugar exacto donde se tomó.");
        }

        var device = string.Join(" ", new[] { make, model }
            .Where(s => !string.IsNullOrWhiteSpace(s)).Select(s => s!.Trim()));
        if (device.Length > 0) findings.Add($"Revela el modelo del dispositivo: {device}.");

        if (takenAt is not null) findings.Add("Incluye la fecha y hora exactas en que se tomó.");

        var hasAuthor = !string.IsNullOrWhiteSpace(author);
        if (hasAuthor) findings.Add("Incluye un nombre de autor.");

        if (findings.Count == 0) findings.Add("No se encontraron datos sensibles en los metadatos.");

        var risk = hasGps ? "alto" : hasAuthor ? RiskLevels.Medium : RiskLevels.Low;

        return new ExifResult(risk, hasGps,
            hasGps ? lat : null, hasGps ? lon : null, map,
            device.Length > 0 ? device : null,
            takenAt?.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
            findings);
    }
}