# ShadowAudit API

API de auditoría de exposición digital. Responde con datos reales a una pregunta: **¿qué tan expuesto estoy ante un atacante?**

Todo se audita sobre **cuentas y dispositivos propios**, de forma ética y legal. El proyecto no incluye acceso a cámaras ajenas, rastreo de terceros ni reconocimiento facial de terceros.

> **Estado: en desarrollo.** Esta es una API solo de backend. Los módulos marcados como pendientes aparecen en la sección de hoja de ruta.

## Qué hace hoy

| Módulo | Qué hace |
|---|---|
| **Autenticación** | Registro y login con contraseñas hasheadas (BCrypt) y tokens JWT. |
| **2FA (TOTP)** | Verificación en dos pasos compatible con Google Authenticator, con códigos de un solo uso. El secreto se guarda cifrado. |
| **Registro de auditoría** | Cada evento de seguridad (registro, login, intentos fallidos, consultas) queda anotado con hora, IP y navegador. |
| **Auditor de contraseñas** | Comprueba si una contraseña apareció en filtraciones reales (Have I Been Pwned) y estima su fortaleza. |
| **Detector de amenazas** | Analiza URLs y huellas de archivos con VirusTotal. |

### Endpoints

| Método | Ruta | Descripción |
|---|---|---|
| POST | `/api/auth/register` | Crear cuenta |
| POST | `/api/auth/login` | Iniciar sesión (con código 2FA si está activado) |
| GET | `/api/auth/me` | Datos de la cuenta |
| GET | `/api/auth/audit-log` | Historial de eventos de la cuenta |
| POST | `/api/2fa/setup` | Generar secreto y QR para el 2FA |
| POST | `/api/2fa/enable` | Activar el 2FA con el primer código |
| POST | `/api/passwords/check` | Revisar si una contraseña está filtrada y qué tan fuerte es |
| POST | `/api/threats/url` | Analizar una URL |
| GET | `/api/threats/file/{sha256}` | Consultar la huella de un archivo (el archivo nunca se sube) |

La documentación interactiva está en `/scalar` cuando la API corre en modo desarrollo.

## Decisiones de seguridad

- **Contraseñas:** BCrypt. La política exige 12 o más caracteres, mayúscula, minúscula y número, y rechaza claves comunes o que contengan el usuario o el correo.
- **Fuerza bruta:** la cuenta se bloquea 15 minutos tras 5 intentos fallidos, y un código 2FA incorrecto también cuenta.
- **Sin filtrar cuentas:** un correo inexistente, una cuenta bloqueada y una clave incorrecta responden igual, y se iguala el tiempo de respuesta.
- **Límite de solicitudes por IP** en login, registro y revisión de contraseñas, y un límite global para proteger la cuota de VirusTotal.
- **Contraseñas auditadas con k-anonimato:** solo salen 5 caracteres de la huella SHA-1. La contraseña nunca sale del servidor y **no se guarda ni se registra**.
- **Falla segura:** si un servicio externo no responde, la API lo dice y nunca declara "seguro".
- **Secretos 2FA cifrados** con ASP.NET Data Protection; las claves de cifrado se guardan fuera del proyecto y de la base de datos.
- **Cabeceras de seguridad HTTP**, errores genéricos hacia el cliente (el detalle queda solo en el log) y CORS cerrado por defecto.
- **Secretos fuera del repositorio:** claves JWT, contraseña de la base de datos y clave de VirusTotal en user-secrets o variables de entorno. La base de datos escucha solo en `127.0.0.1`.
- **Entradas validadas:** las URLs solo aceptan `http`/`https`, sin usuario y contraseña dentro y sin direcciones locales.

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
dotnet user-secrets set "VirusTotal:ApiKey" "TU_CLAVE_DE_VIRUSTOTAL"   # opcional: solo para /api/threats

# 4. Tablas y arranque
dotnet ef database update
dotnet run --launch-profile https
```

Luego abre `https://localhost:7280/scalar`.

Sin clave de VirusTotal, la API funciona igual y `/api/threats` responde que el servicio no está configurado. La API de VirusTotal en su plan gratuito permite 4 consultas por minuto y 500 por día, y es solo para uso no comercial.

## Hoja de ruta

- [x] Autenticación, 2FA, bloqueo por fuerza bruta y registro de auditoría
- [x] Auditor de contraseñas (Have I Been Pwned)
- [x] Detector de amenazas: URLs y archivos (VirusTotal)
- [ ] Detector de amenazas: cabeceras de correo (phishing) y reputación de IPs
- [ ] Reporte final con puntaje de riesgo
- [ ] Huella digital (OSINT sobre cuentas propias)
- [ ] Auditor de red y wifi propios
- [ ] Escáner de vulnerabilidades web para sitios propios
- [ ] Detección de dispositivos IoT propios expuestos
- [ ] Pruebas automáticas, CI/CD y despliegue
