namespace ShadowAudit.API.Models;

// Hallazgo que el usuario decide guardar al hacer una consulta (con "label").
// Guarda solo el resultado, NUNCA el dato consultado: ni la contraseña, ni la URL,
// ni el hash, ni la IP, ni las cabeceras del correo.
public class ExposureFinding
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid UserId { get; set; }

    // password, url, file, email o ip
    public string Source { get; set; } = string.Empty;

    // Riesgo normalizado: bajo, medio o alto
    public string Risk { get; set; } = string.Empty;

    // Nombre que le pone el usuario, por ejemplo "correo del banco"
    public string Label { get; set; } = string.Empty;

    public DateTime CreatedAtUtc { get; set; } = DateTime.UtcNow;
    public DateTime? ResolvedAtUtc { get; set; }
}

public static class FindingSource
{
    public const string Password = "password";
    public const string Url = "url";
    public const string File = "file";
    public const string Email = "email";
    public const string Ip = "ip";
}