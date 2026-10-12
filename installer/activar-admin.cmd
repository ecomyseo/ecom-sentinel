@echo off
rem Crea una tarea programada que ejecuta Ecom Sentinel CON PERMISOS DE ADMINISTRADOR
rem al iniciar sesion (mas cobertura de procesos). Ejecutar este fichero como administrador.
rem Para quitarla:  schtasks /Delete /TN "Ecom Sentinel (admin)" /F

setlocal
schtasks /Create /TN "Ecom Sentinel (admin)" /TR "\"%~dp0EcomSentinel.exe\"" /SC ONLOGON /RL HIGHEST /F
if %errorlevel%==0 (
  echo.
  echo Listo: Ecom Sentinel se ejecutara como administrador al iniciar sesion.
  echo Para evitar que arranque dos veces, borra el acceso directo "Ecom Sentinel"
  echo de la carpeta de Inicio comun.
) else (
  echo.
  echo No se pudo crear la tarea. Ejecuta este fichero como administrador.
)
echo.
pause
