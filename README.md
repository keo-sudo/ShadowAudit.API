# ShadowAudit API

[![CI](https://github.com/keo-sudo/ShadowAudit.API/actions/workflows/ci.yml/badge.svg)](https://github.com/keo-sudo/ShadowAudit.API/actions/workflows/ci.yml)

API de auditoría de exposición digital. Responde con datos reales a una pregunta: **¿qué tan expuesto estoy ante un atacante?**

Todo se audita sobre **cuentas y dispositivos propios**, de forma ética y legal. El proyecto no incluye acceso a cámaras ajenas, rastreo de terceros ni reconocimiento facial de terceros.

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
| GET | `/api/report` | Reporte de exposición: puntaje de 0 a 100, lo más urgente primero y recomendaciones |
| GET | `/api/findings` | Lista de hallazgos guardados (`?includeResolved=true` incluye los resueltos) |
| POST | `/api/findings/{id}/resolve` | Marcar un hallazgo como resuelto (deja de contar en el puntaje) |
| DELETE | `/api/findings/{id}` | Borrar un hallazgo |

La documentación interactiva está en `/scalar` cuando la API corre en modo desarrollo.

## Reporte y puntaje de riesgo

Las consultas de contraseñas, URLs, archivos, correos e IPs aceptan un campo opcional `label`. Si lo envías, el resultado se guarda como **hallazgo** para el reporte; si no, no se guarda nada.

```json
POST /api/passwords/check
{ "password": "tu-contraseña", "label": "clave del correo" }

GET /api/threats/ip/8.8.8.8?label=DNS de Google
```

Qué se guarda y qué no:

- Se guarda **solo** la fuente (contraseña, URL, archivo, correo o IP), el nivel de riesgo, la fecha y tu etiqueta.
- **Nunca** se guarda el dato consultado: ni la contraseña, ni la URL, ni el hash, ni la IP, ni las cabeceras del correo.
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
- **Límite de solicitudes** por IP en login, registro, renovación de sesión, contraseñas y cabeceras de correo, y límites globales para proteger la cuota de VirusTotal y AbuseIPDB.
- **Contraseñas auditadas con k-anonimato:** solo salen 5 caracteres de la huella SHA-1. La contraseña nunca sale del servidor y **no se guarda ni se registra**.
- **Datos analizados no guardados:** ni las direcciones, huellas, IPs y cabeceras de correo que se consultan ni las contraseñas quedan en la base de datos. El registro de auditoría solo anota que hubo una consulta. Solo si envías una etiqueta se guarda un hallazgo, con su nivel de riesgo y esa etiqueta, nunca el dato consultado.
- **Falla segura:** si un servicio externo no responde, la API lo dice y nunca declara "seguro".
- **Cabeceras de seguridad HTTP**, errores genéricos hacia el cliente (el detalle queda solo en el log) y CORS cerrado por defecto.
- **Secretos fuera del repositorio:** claves JWT, contraseña de la base de datos y claves de los servicios externos en user-secrets o variables de entorno. La base de datos escucha solo en `127.0.0.1`.
- **Entradas validadas:** las URLs solo aceptan `http`/`https`, sin usuario y contraseña dentro y sin direcciones locales; las IPs consultadas deben ser públicas; las cabeceras de correo tienen un tamaño máximo; las etiquetas de los hallazgos tienen un largo máximo y no admiten el dato consultado.

## Tecnologías

ASP.NET Core (.NET 10) · Entity Framework Core · PostgreSQL 17 (Docker) · JWT · BCrypt · OtpNet y QRCoder (2FA) · Scalar (documentación OpenAPI)

## Cómo correrlo

Necesitas el SDK de .NET 10, Docker Desktop y, para los comandos de migración, la herramienta `dotnet-ef` (`dotnet tool install --global dotnet-ef`).

```powershell
cd ShadowAudit.API

# 1. Contraseña de la base de datos (elige una larga y aleatoria)
"POSTGRES_PASSWORD=TU_CONTRASEÑA" | Out-File -Encoding ascii .env

# 2. Base de datos
docker compose up -d

# 3. Secretos de la API (no se guardan en el repositorio)
dotnet user-secrets set "JwtSettings:SecretKey" "UNA_CLAVE_ALEATORIA_DE_AL_MENOS_64_CARACTERES"
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "Host=localhost;Port=5432;Database=shadowaudit;Username=postgres;Password=TU_CONTRASEÑA"
dotnet user-secrets set "VirusTotal:ApiKey" "TU_CLAVE_DE_VIRUSTOTAL"   # opcional: solo para URLs y archivos
dotnet user-secrets set "AbuseIPDB:ApiKey" "TU_CLAVE_DE_ABUSEIPDB"     # opcional: solo para reputación de IPs

# 4. Tablas y arranque
dotnet ef database update
dotnet run --launch-profile https
```

Luego abre `https://localhost:7280/scalar`.

Sin las claves de VirusTotal y AbuseIPDB, la API funciona igual: esas consultas responden que el servicio no está configurado, y el resto (incluido el análisis de cabeceras de correo) no las necesita. La API de VirusTotal en su plan gratuito permite 4 consultas por minuto y 500 por día, y es solo para uso no comercial.

## Hoja de ruta

- [x] Autenticación, 2FA con códigos de recuperación, sesiones revocables y registro de auditoría
- [x] Auditor de contraseñas (Have I Been Pwned)
- [x] Detector de amenazas: URLs, archivos, IPs y cabeceras de correo
- [x] Reporte final con puntaje de riesgo
- [ ] Huella digital (OSINT sobre cuentas propias)
- [ ] Auditor de red y wifi propios
- [ ] Escáner de vulnerabilidades web para sitios propios
- [ ] Detección de dispositivos IoT propios expuestos
- [ ] Pruebas automáticas, CI/CD y despliegue
