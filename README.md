# Ecom Sentinel

Agente residente para Windows (.NET 8) que **vigila en tiempo real** señales de
*infostealer* / RAT en el equipo de quien administra una tienda y **avisa al instante**
(consola, registro, webhook, WhatsApp o correo). **Detecta y avisa; no bloquea.**

> **Qué NO es:** no es un antivirus ni un EDR blindado. Corre en modo usuario: un atacante
> con permisos de administrador puede pararlo. Es un **cable-trampa** de alta señal, no una
> garantía. No sustituye a Defender/EDR: los complementa.

## Qué detecta

| Detector | Señal |
|---|---|
| **Robo de credenciales (estrella)** | Aparece una **copia** de la base de credenciales/cookies del navegador (`Login Data`, `Cookies`, `Web Data`, `logins.json`, `cookies.sqlite`, `key4.db`) en `%TEMP%`, Descargas, `ProgramData` o `Public` — lo que un *infostealer* hace antes de exfiltrar. Evento en tiempo real (`FileSystemWatcher`). **No** vigila el perfil real del navegador, así que el navegador escribiendo sus propias cookies **no** dispara. |
| **Control remoto** | Ejecución de AnyDesk, RustDesk, TeamViewer, ScreenConnect, Atera, Splashtop, Supremo, DWAgent, UltraViewer, Chrome Remote Desktop… |
| **Proceso sospechoso** | Ejecutable **sin firma** corriendo desde `%TEMP%`/`%AppData%`/`ProgramData`. |
| **Red** | Conexión saliente de un proceso ya marcado como sospechoso (correlación, para no dar ruido). |
| **Persistencia** | Nuevo arranque automático (claves `Run`/`RunOnce` de HKCU/HKLM y carpetas de Inicio). |

## Estado y pruebas (verificado el 2026-10-12)

- `--selftest` (lógica pura): **13/13 OK**.
- `scan-once` sobre un equipo real: detecta control remoto, exe sin firma en temp y
  correlaciona sus conexiones salientes.
- **Residente + alerta en tiempo real:** al crear un fichero `Cookies` en `%TEMP%` el agente
  emite al instante `CRITICAL credential-staging`.
- Compila con **0 avisos / 0 errores** (`dotnet build -c Release`).

Pendiente de probar en un equipo real con permisos de administrador: cobertura total de
procesos protegidos, y el modo servicio bajo arranque previo al inicio de sesión.

## Requisitos

- Windows 10/11.
- La release publicada es **autocontenida** (`win-x64`): no necesita instalar .NET.
- Para compilar: **.NET 8 SDK**.

## Uso

```text
EcomSentinel run         # modo residente (por defecto): vigila y avisa hasta Ctrl+C
EcomSentinel scan-once   # una pasada y sale (procesos, persistencia, red)
EcomSentinel selftest    # prueba la lógica de detección (sin tocar el sistema)
```

Ejecutar **como administrador** para ver más procesos y conexiones.

### Dejarlo residente (servicio)

Como Tarea programada al iniciar sesión, o como servicio con NSSM:

```text
nssm install EcomSentinel "C:\ruta\EcomSentinel.exe" run
nssm start   EcomSentinel
```

## Configuración (`appsettings.json`)

```jsonc
{
  "ScanIntervalSeconds": 15,
  "WhitelistProcessNames": ["language_server_windows_x64"],  // tus herramientas de confianza
  "WhitelistHosts": [],
  "Alerts": {
    "Console": true,
    "LogFile": "sentinel.log",
    "MinSeverity": "Medium",                 // Info | Medium | High | Critical
    "WebhookUrl": "",
    "WhatsApp": { "ApiUrl": "", "ApiKey": "", "To": "" },  // p. ej. tu servicio mensajero
    "Smtp": { "Host": "", "Port": 587, "User": "", "Password": "", "From": "", "To": "", "UseSsl": true }
  }
}
```

> **Falsos positivos:** marcar un ejecutable sin firma en temp es correcto; algunas
> herramientas legítimas de desarrollo lo son. Añádelas a `WhitelistProcessNames`. **Nunca
> metas una clave secreta en el repositorio**: rellena los canales en el equipo.

## Limitaciones honestas

- Modo usuario: cobertura parcial de procesos protegidos; un malware con administrador puede
  detenerlo. Ejecútalo como administrador y, a ser posible, como servicio.
- La detección de robo de credenciales es por **copias en zonas de staging**. La detección
  del **acceso en vivo** al fichero real (vía ETW/kernel) está prevista para v1.1 y necesita
  administrador.
- **Que no encuentre nada NO significa que el equipo esté limpio** (un *infostealer* roba y se
  borra). Si sospechas: desconecta el equipo de la red, cambia las contraseñas **desde otro
  PC limpio**, invalida sesiones y activa 2FA.

## Multiplataforma

- **Windows:** este agente (donde están los *infostealers*).
- **macOS:** posible, pero es **otro proyecto nativo** (Swift + *Endpoint Security* de Apple,
  con permiso de Apple y notarización). .NET por sí solo no vigila el sistema en Mac.
- **Android / iPhone:** un detector que vigile el propio móvil **no es posible** por el
  aislamiento del sistema (en iOS está directamente prohibido; en Android haría falta *root*).
  Lo viable en móvil es una **app compañera** que **reciba las alertas** de este agente.

## Licencia

AFL-3.0 — Ecom Experts.
