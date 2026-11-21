# ShadowAudit API

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

GET
