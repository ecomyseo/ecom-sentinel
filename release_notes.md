## Ecom Sentinel v0.1.0 (Windows, .NET 8)

Agente residente que vigila en tiempo real señales de infostealer/RAT y **avisa** (consola, log, webhook, WhatsApp o correo). **Detecta y avisa; no bloquea.**

**Detecta:** copia de credenciales/cookies del navegador en zonas de staging (en tiempo real) · herramientas de control remoto · ejecutables sin firma en temp · conexiones salientes de procesos sospechosos · persistencia nueva.

**Probado (2026-10-12):** `--selftest` 13/13 · `scan-once` sobre equipo real · alerta residente en vivo al aparecer un fichero `Cookies` en `%TEMP%` → `CRITICAL credential-staging`. Compila con 0 avisos / 0 errores.

**Descarga:** `EcomSentinel-v0.1.0-win-x64.zip` — binario **autocontenido** (no necesita instalar .NET). Descomprime y ejecuta, **como administrador**:
```
EcomSentinel.exe run        (residente)
EcomSentinel.exe scan-once  (una pasada)
EcomSentinel.exe selftest   (prueba la lógica)
```
Configura avisos y lista blanca en `appsettings.json` (ver README).

**Honestidad:** es un cable-trampa en modo usuario, **no un antivirus**; un atacante con administrador puede pararlo; que no encuentre nada no significa "equipo limpio". Detalles y limitaciones en el README.

> CI: `ci-build.yml.txt` — muévelo a `.github/workflows/build.yml` cuando tu token tenga scope `workflow` (o súbelo desde la web) para que GitHub compile la release sola.
