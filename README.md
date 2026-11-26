# ShadowAudit API

[![CI](https://github.com/keo-sudo/ShadowAudit.API/actions/workflows/ci.yml/badge.svg)](https://github.com/keo-sudo/ShadowAudit.API/actions/workflows/ci.yml)

API de auditoría de exposición digital. Responde con datos reales a una pregunta: **¿qué tan expuesto estoy ante un atacante?**

Todo se audita sobre **cuentas, dispositivos y sitios propios**, de forma ética y legal. El proyecto no incluye acceso a cámaras ajenas, rastreo de terceros ni reconocimiento facial de terceros.

> **Estado: en desarrollo.** Esta es una API solo de backend. Los módulos marcados como pendientes aparecen en la sección de hoja de ruta.

## Qué hace hoy

| Módulo | Qué hace |
|---|---|
| **Autenticación** | Registro y login con contraseñas hasheadas (BCrypt), tokens JWT de 15 minutos y refresh tokens rotativos con detección de robo. |
| **Sesiones** | Cierre de sesión inmediato (una o todas) y cambio de contraseña que cierra las demás sesiones. |
| **2FA (TOTP)** | Verificación en dos pasos compatible con Google Authenticator, con códigos de un solo uso y códigos de recuperación. El secreto se guarda cifrado. |
| **Registro de auditoría** | Cada evento de seguridad (registro, login, intentos fallidos, consultas) queda anotado con hora, IP y navegador. |
| **Auditor de contraseñas** | Comprueba si una contraseña apareció en filtraciones reales (Have I Been Pwned) y estima su fortaleza. |
| **Detector de amenazas** | Analiza URLs y huellas de archivos con VirusTotal, la reputación de una IP con AbuseIPDB, y cabeceras de correo para detectar phishing (SPF, DKIM, DMARC y suplantación). |
| **Escáner web** | Revisión pasiva y liviana de sitios propios (HTTPS, certificado, cabeceras de seguridad, cookies y archivos expuestos). Solo funciona si demuestras que el sitio es tuyo. |
| **Reporte de exposición** | Junta los resultados que el usuario decide guardar en un puntaje de 0 a 100, con lo más urgente primero y recomendaciones. |

### Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/auth/register` | Crear cuenta |
| POST | `/api/auth/login` | Iniciar sesión (con código 2FA o de recuperación si está activado) |
| POST | `/api/auth/refresh` | Renovar la sesión con un refresh token |
| POST | `/api/auth/logout` | Cerrar la sesión actual |
| POST | `/api/auth/logout-all` | Cerrar todas las sesiones |
| POST | `/api/auth/change-password` | Cambiar la contraseña (cierra las demás sesiones) |
| GET | `/api/auth/me` | Datos de la cuenta |
| GET | `/api/auth/audit-log` | Historial de eventos de la cuenta |
| GET | `/api/2fa/status` | Estado del 2FA y códigos de recuperación restantes |
| POST | `/api/2fa/setup` | Generar secreto y QR para el 2FA |
| POST | `/api/2fa/enable` | Activar el 2FA con el primer código (entrega los códigos de recuperación) |
| POST | `/api/2fa/recovery-codes` | Generar códigos de recuperación nuevos |
| POST | `/api/2fa/disable` | Desactivar el 2FA |
| POST | `/api/passwords/check` | Revisar si una contraseña está filtrada y qué tan fuerte es |
| POST | `/api/threats/url` | Analizar una URL |
| GET | `/api/threats/file/{sha256}` | Consultar la huella de un archivo (el archivo nunca se sube) |
| POST | `/api/threats/email-headers` | Analizar las cabeceras de un correo (SPF, DKIM, DMARC y suplantación) |
| GET | `/api/threats/ip/{ip}` | Consultar la reputación de una IP pública |
| GET | `/api/sites` | Lista de tus sitios registrados y si están verificados |
| POST | `/api/sites` | Registrar un sitio propio (entrega las instrucciones de verificación) |
| POST | `/api/sites/{id}/verify` | Verificar que el sitio es tuyo (registro DNS o archivo) |
| POST | `/api/sites/{id}/scan` | Escanear un sitio verificado (`?label=` guarda el resultado como hallazgo) |
| DELETE | `/api/sites/{id}` | Borrar un sitio |
| GET | `/api/report` | Reporte de exposición: puntaje de 0 a 100, lo más urgente primero y recomendaciones |
| GET | `/api/findings` | Lista de hallazgos guardados (`?includeResolved=true` incluye los resueltos) |
| POST | `/api/findings/{id}/resolve` | Marcar un hallazgo como resuelto (deja de contar en el puntaje) |
| DELETE | `/api/findings/{id}` | Borrar un hallazgo |

La documentación interactiva está en `/scalar` cuando la API corre en modo desarrollo.

## Escáner web de sitios propios

Es un escáner **pasivo y liviano**: solo hace peticiones normales de lectura (GET), sin ataques ni pruebas de inyección. No reemplaza una auditoría completa ni a herramientas como OWASP ZAP.

### Verificación de propiedad

Un sitio solo se puede escanear si demuestras que es tuyo. Al registrarlo, la API entrega un token aleatorio de 43 caracteres y dos formas de demostrarlo (con cualquiera basta):

- **Registro DNS TXT:** nombre `_shadowaudit-verify.tu-dominio.com`, valor `shadowaudit-verify=<token>`.
- **Archivo:** `https://tu-dominio.com/.well-known/shadowaudit-verify.txt` con el token adentro.

Luego llamas a `POST /api/sites/{id}/verify`. La verificación dura **30 días**; después hay que repetirla.

### Qué revisa

| Área | Revisiones |
|---|---|
| HTTPS y certificado | HTTPS activo, vencimiento, certificado de confianza, versión de TLS y redirección de HTTP a HTTPS |
| Cabeceras | HSTS, Content-Security-Policy, X-Content-Type-Options, protección contra clickjacking, Referrer-Policy, Permissions-Policy y fuga de versión del servidor |
| Cookies | Atributos Secure, HttpOnly y SameSite (nunca se devuelven nombres ni valores) |
| Archivos expuestos | `/.env`, `/.git/HEAD`, `/.git/config`, `/backup.zip`, `/backup.sql`, `/dump.sql`, `/appsettings.json`, `/phpinfo.php`, `/server-status` y `/.DS_Store`. Solo cuenta si el contenido parece de verdad ese archivo; nunca se devuelve su contenido. |

Cada revisión sale como `pasa` o `falla`, con gravedad (bajo, medio o alto) y cómo corregirla. El riesgo general es la mayor gravedad entre las que fallan. El resultado del escaneo **no se guarda**: solo se guarda un hallazgo si envías `?label=`, y esa etiqueta no puede contener el dominio.

### Protecciones del propio escáner

- **Contra SSRF:** el dominio se resuelve en el momento de conectar y se rechaza si **alguna** de sus direcciones es privada, local o reservada (la validación está dentro de la conexión, así que un DNS que cambia de respuesta no puede engañarlo). Solo usa los puertos 80 y 443, no sigue redirecciones automáticamente y no usa proxy.
- **Redirecciones controladas:** sigue hasta 4, y solo dentro del mismo sitio (el dominio o su variante `www`, por HTTPS).
- **Entradas validadas:** solo nombres de dominio (sin IPs, esquemas, puertos, rutas ni sufijos internos como `.local` o `.lan`).
- **Límites:** hasta 5 sitios por usuario, 3 escaneos por hora y 10 verificaciones cada 10 minutos por IP. Entre prueba y prueba de archivos hay una pausa corta para no cargar el sitio.
- **Auditoría sin el dominio:** el registro solo anota la acción (`SiteAdd`, `SiteVerify`, `SiteVerifyFailed`, `SiteScan`, `SiteDelete`).

## Módulos de análisis de datos propios

Estos módulos no escanean nada por sí mismos: analizan datos que el usuario aporta sobre sus propias cuentas y dispositivos. Lo pegado no se guarda; solo se guarda un hallazgo (sin el dato consultado) si se envía una etiqueta `label`.

### Huella digital (OSINT)
- `POST /api/footprint/username`: revisa si un nombre de usuario propio existe en GitHub, GitLab, DEV, Keybase y Codeberg.
- Cada sitio responde `existe`, `no_existe` o `indeterminado` (si el sitio bloquea o redirige). Límite: 5 consultas por hora por IP.

### Red y wifi
- `POST /api/network/wifi`: analiza la salida de `netsh wlan show interfaces`.
- `POST /api/network/ports`: analiza la salida de `netstat -an`.

### Dispositivos IoT
- `POST /api/iot/ports`: analiza la salida de `nmap` sobre un dispositivo propio.
- Riesgo alto: puertos 21, 23, 5555 y 37777. Riesgo medio: 554, 1883 y 8000.

## Reporte y puntaje de riesgo

Las consultas de contraseñas, URLs, archivos, correos, IPs y escaneos web aceptan un campo opcional `label`. Si lo envías, el resultado se guarda como **hallazgo** para el reporte; si no, no se guarda nada.

```json
POST /api/passwords/check
{ "password": "tu-contraseña", "label": "clave del correo" }

GET /api/threats/ip/8.8.8.8?label=DNS de Google

POST /api/sites/{id}/scan?label=mi sitio web
```

Qué se guarda y qué no:

- Se guarda **solo** la fuente (contraseña, URL, archivo, correo, IP o web), el nivel de riesgo, la fecha y tu etiqueta.
- **Nunca** se guarda el dato consultado: ni la contraseña, ni la URL, ni el hash, ni la IP, ni las cabeceras del correo, ni el dominio escaneado.
- El riesgo lo calcula el servidor; el cliente no puede dictarlo.
- La etiqueta tiene hasta 100 caracteres y no puede contener el dato consultado.
- Cada usuario puede guardar hasta 500 hallazgos.

### Un solo nivel de riesgo

Cada fuente se normaliza a **bajo, medio o alto**:

| Fuente | Cómo se decide |
|---|---|
| Contraseñas | Filtrada o puntaje 0-1: alto. Puntaje 2: medio. Puntaje 3-4: bajo. |
| URLs y archivos (VirusTotal) | 3 o más motores lo marcan como malicioso: alto. 1 o más lo marcan como malicioso o sospechoso: medio. Sin detecciones: bajo. |
| IPs (AbuseIPDB) | En lista blanca: bajo. Puntaje de abuso de 75 o más: alto. De 25 o más: medio. Menos: bajo. |
| Correos | Análisis propio de cabeceras (SPF, DKIM, DMARC y suplantación): bajo, medio o alto. |
| Sitios web | La mayor gravedad entre las revisiones que fallan; si ninguna falla: bajo. |

### Puntaje de 0 a 100

Solo cuentan los hallazgos **sin resolver**. Cada uno aporta una probabilidad de problema (alto 50 %, medio 20 %, bajo 5 %) y se combinan así:

`puntaje = 100 × (1 − producto de (1 − probabilidad de cada hallazgo))`

| Puntaje | Nivel |
|---|---|
| 0 a 24 | bajo |
| 25 a 49 | medio |
| 50 a 74 | alto |
| 75 a 100 | crítico |

Un solo hallazgo de riesgo alto ya da 50; dos dan 75. Si no hay hallazgos, el nivel es `sin_hallazgos`. El puntaje no es una garantía de seguridad: solo refleja lo que guardaste con etiqueta.

## Decisiones de seguridad

- **Contraseñas:** BCrypt. La política exige 12 o más caracteres, mayúscula, minúscula y número, y rechaza claves comunes o que contengan el usuario o el correo.
- **Fuerza bruta:** la cuenta se bloquea 15 minutos tras 5 intentos fallidos. Un código 2FA incorrecto, o un error de contraseña al cambiarla o al desactivar el 2FA, también cuenta.
- **Sin filtrar cuentas:** un correo inexistente, una cuenta bloqueada y una clave incorrecta responden igual, y se iguala el tiempo de respuesta.
- **Sesiones revocables:** el token de acceso dura 15 minutos y lleva el identificador de su sesión, que se comprueba en cada petición. Un cierre de sesión surte efecto al instante.
- **Refresh tokens rotativos:** cada renovación entrega uno nuevo e invalida el anterior. Si un token ya usado vuelve a presentarse, se asume robo y se cierra toda la sesión. Solo se guarda su huella SHA-256. Los tokens vencidos hace más de 30 días se borran solos, cada 6 horas.
- **2FA:** los códigos de recuperación son de un solo uso y se guardan como huella. Los secretos TOTP se cifran con ASP.NET Data Protection y las claves de cifrado quedan fuera del proyecto y de la base de datos.
- **Límite de solicitudes** por IP en login, registro, renovación de sesión, contraseñas, cabeceras de correo, verificación y escaneo de sitios, y límites globales para proteger la cuota de VirusTotal y AbuseIPDB.
- **Escáner con protección SSRF:** el escáner nunca se conecta a direcciones privadas o internas y exige demostrar la propiedad del sitio (ver la sección del escáner web).
- **Contraseñas auditadas con k-anonimato:** solo salen 5 caracteres de la huella SHA-1. La contraseña nunca sale del servidor y **no se guarda ni se registra**.
- **Datos analizados no guardados:** ni las direcciones, huellas, IPs, dominios y cabeceras de correo que se consultan ni las contraseñas quedan en la base de datos. El registro de auditoría solo anota que hubo una consulta. Solo si envías una etiqueta se guarda un hallazgo, con su nivel de riesgo y esa etiqueta, nunca el dato consultado.
- **Logs sin datos sensibles (Serilog):** una línea por petición con método, ruta, estado, duración e IP. No se registran cuerpos ni query strings, y los logs de `HttpClient` están silenciados para que no quede rastro de qué URL, hash, IP o dominio se consultó. En producción salen en JSON.
- **Falla segura:** si un servicio externo no responde, la API lo dice y nunca declara "seguro".
- **Cabeceras de seguridad HTTP**, errores genéricos hacia el cliente (el detalle queda solo en el log) y CORS cerrado por defecto.
- **Contenedor sin root:** la imagen de Docker ejecuta la API con un usuario sin privilegios.
- **Secretos fuera del repositorio:** claves JWT, contraseña de la base de datos y claves de los servicios externos en user-secrets o variables de entorno (el archivo `.env` está en `.gitignore`). La base de datos nunca se expone fuera de tu equipo.
- **Entradas validadas:** las URLs solo aceptan `http`/`https`, sin usuario y contraseña dentro y sin direcciones locales; las IPs consultadas deben ser públicas; los dominios del escáner deben ser nombres públicos; las cabeceras de correo tienen un tamaño máximo; las etiquetas de los hallazgos tienen un largo máximo y no admiten el dato consultado.

## Pruebas

Más de 300 pruebas automáticas (xUnit):

- **Unitarias:** puntaje y normalización de riesgo, validación de etiquetas, bloqueo por fuerza bruta, tokens JWT, fortaleza de contraseñas, los tres servicios externos (VirusTotal, AbuseIPDB y Have I Been Pwned) con respuestas simuladas, y el escáner web (validación de dominios, filtro de IPs privadas, revisiones de HTTPS, cabeceras, cookies y archivos expuestos, y verificación de propiedad): sin internet y sin claves.
- **Integración:** la API completa contra una base **PostgreSQL real y temporal** (Testcontainers), con todas las migraciones reales y claves falsas. Cubren registro, login, bloqueo, refresh con rotación y reutilización, cierre de sesiones, 2FA con códigos de recuperación, cifrado en la base, hallazgos, reporte, aislamiento entre usuarios, límites de solicitudes, cabeceras de seguridad y el flujo completo de sitios (registro, verificación por DNS y por archivo, vencimiento, escaneo y auditoría), con DNS, TLS y servidores web falsos.

```powershell
dotnet test    # requiere Docker abierto
```

## Integración continua

Cada `push` y cada pull request a `main` pasan por GitHub Actions (`.github/workflows/ci.yml`): restaura, compila en Release y corre todas las pruebas. La insignia de arriba muestra el estado.

## Tecnologías

ASP.NET Core (.NET 10) · Entity Framework Core · PostgreSQL 17 · JWT · BCrypt · OtpNet y QRCoder (2FA) · DnsClient (verificación DNS) · Serilog · Scalar (documentación OpenAPI) · Docker y Docker Compose · xUnit y Testcontainers · GitHub Actions

## Cómo correrlo

Necesitas Docker Desktop. Para desarrollar también necesitas el SDK de .NET 10 y la herramienta `dotnet-ef` (`dotnet tool install --global dotnet-ef`).

### Con Docker (todo en contenedores)

Levanta la API y PostgreSQL con un solo comando. Las migraciones se aplican solas al arrancar.

```powershell
cd ShadowAudit.API

# 1. Archivo .env con valores aleatorios (no se sube al repositorio)
$b = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
$p = New-Object byte[] 24; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($p)
@"
POSTGRES_PASSWORD=$(-join ($p | ForEach-Object { $_.ToString('x2') }))
JWT_SECRET_KEY=$([Convert]::ToBase64String($b))
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
"@ | Out-File -Encoding ascii .env

# 2. Construir y levantar
docker compose up -d --build
```

La API queda en `http://localhost:8080` (solo accesible desde tu equipo). La documentación de Scalar no está disponible en este modo porque solo existe en desarrollo. Las claves de VirusTotal y AbuseIPDB son opcionales: pégalas en `.env` si las tienes. En Linux o macOS puedes generar los valores con `openssl rand -base64 48`.

Para apagarlo: `docker compose down` (conserva los datos) o `docker compose down -v` (borra también la base y las claves de cifrado).

> En Linux, las claves de Data Protection se guardan en el volumen `dpkeys` sin cifrar (Windows las protege con DPAPI). Protege ese volumen y hazle copia de seguridad: sin esas claves no se pueden descifrar los secretos 2FA.

### Para desarrollar (Visual Studio o `dotnet run`)

```powershell
cd ShadowAudit.API

# 1. Base de datos de desarrollo (puerto solo en 127.0.0.1)
docker run -d --name shadowaudit-db `
  -e POSTGRES_DB=shadowaudit -e POSTGRES_USER=postgres -e POSTGRES_PASSWORD=TU_CONTRASEÑA `
  -p 127.0.0.1:5432:5432 -v shadowaudit-dev-pgdata:/var/lib/postgresql/data `
  postgres:17-alpine

# 2. Secretos de la API (no se guardan en el repositorio)
dotnet user-secrets set "JwtSettings:SecretKey" "UNA_CLAVE_ALEATORIA_DE_AL_MENOS_64_CARACTERES" --project ShadowAudit.API
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=shadowaudit;Username=postgres;Password=TU_CONTRASEÑA" --project ShadowAudit.API
dotnet user-secrets set "VirusTotal:ApiKey" "TU_CLAVE_DE_VIRUSTOTAL" --project ShadowAudit.API   # opcional: solo para URLs y archivos
dotnet user-secrets set "AbuseIPDB:ApiKey" "TU_CLAVE_DE_ABUSEIPDB" --project ShadowAudit.API     # opcional: solo para reputación de IPs

# 3. Tablas y arranque
dotnet ef database update --project ShadowAudit.API
dotnet run --project ShadowAudit.API --launch-profile https
```

Luego abre `https://localhost:7280/scalar`.

Sin las claves de VirusTotal y AbuseIPDB, la API funciona igual: esas consultas responden que el servicio no está configurado, y el resto (incluido el análisis de cabeceras de correo y el escáner web) no las necesita. La API de VirusTotal en su plan gratuito permite 4 consultas por minuto y 500 por día, y es solo para uso no comercial.

### Configuración

Todo se puede definir con variables de entorno (en `appsettings` los `__` son `:`).

| Variable | Para qué sirve |
|---|---|
| `ConnectionStrings__DefaultConnection` | Conexión a PostgreSQL |
| `JwtSettings__SecretKey` | Clave que firma los tokens (64 caracteres o más, aleatoria) |
| `VirusTotal__ApiKey` / `AbuseIPDB__ApiKey` | Claves de los servicios externos (opcionales) |
| `DataProtection__KeysPath` | Carpeta persistente para las claves de cifrado del 2FA |
| `Database__MigrateOnStartup` | `true` aplica las migraciones al arrancar (apagado por defecto; Docker Compose lo enciende) |
| `ForwardedHeaders__Enabled` y `ForwardedHeaders__KnownProxies__0` | Detrás de un proxy inverso, lee la IP real del cliente, y **solo** si la petición viene de un proxy listado |
| `Cors__AllowedOrigins__0` | Origen permitido para un frontend (cerrado por defecto) |

## Hoja de ruta

- [x] Autenticación, 2FA con códigos de recuperación, sesiones revocables y registro de auditoría
- [x] Auditor de contraseñas (Have I Been Pwned)
- [x] Detector de amenazas: URLs, archivos, IPs y cabeceras de correo
- [x] Reporte final con puntaje de riesgo
- [x] Pruebas automáticas, integración continua, Docker y logs estructurados
- [x] Escáner web pasivo para sitios propios (con verificación de propiedad)
- [ ] Despliegue público
- [x] Huella digital (OSINT sobre cuentas propias)
- [x] Auditor de red y wifi propios
- [x] Detección de dispositivos IoT propios expuestos