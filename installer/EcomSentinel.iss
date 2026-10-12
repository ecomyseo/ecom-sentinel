; Instalador de Ecom Sentinel (Inno Setup 6).
; Compilar:  "C:\Program Files (x86)\Inno Setup 6\ISCC.exe" EcomSentinel.iss
; FIRMA (recomendado para clientes): con un certificado de firma de codigo, descomenta
;   SignTool=... abajo y registra la herramienta en Inno (Tools > Configure Sign Tools).
;   Sin firma, Windows mostrara "Editor desconocido" (SmartScreen) al instalar.

#define AppName "Ecom Sentinel"
#define AppVer "0.2.5"
#define Publisher "Ecom Experts"

[Setup]
AppId={{8F2B6B1A-9C4D-4E7F-A1B2-C3D4E5F60718}
AppName={#AppName}
AppVersion={#AppVer}
AppPublisher={#Publisher}
DefaultDirName={autopf}\Ecom Sentinel
DefaultGroupName=Ecom Sentinel
DisableProgramGroupPage=yes
UninstallDisplayName=Ecom Sentinel
UninstallDisplayIcon={app}\EcomSentinel.exe
OutputDir={#SourcePath}\..\dist
OutputBaseFilename=EcomSentinel-Setup-{#AppVer}
SetupIconFile={#SourcePath}\..\icon.ico
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
PrivilegesRequired=admin
ArchitecturesInstallIn64BitMode=x64
; Cierra el agente en ejecucion antes de actualizar (para poder reemplazar el .exe).
CloseApplications=yes
RestartApplications=no
; SignTool=standard

[Languages]
Name: "es"; MessagesFile: "compiler:Languages\Spanish.isl"

[Tasks]
Name: "desktopicon"; Description: "Crear un acceso directo en el escritorio"; GroupDescription: "Accesos directos adicionales:"

[Files]
; Todo lo publicado excepto la configuracion (que se conserva entre actualizaciones).
Source: "{#SourcePath}\..\publish\*"; DestDir: "{app}"; Excludes: "appsettings.json"; Flags: recursesubdirs ignoreversion
Source: "{#SourcePath}\..\publish\appsettings.json"; DestDir: "{app}"; Flags: onlyifdoesntexist
Source: "{#SourcePath}\activar-admin.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#SourcePath}\..\README.md"; DestDir: "{app}"; Flags: ignoreversion

[Icons]
; Autoarranque para todos los usuarios al iniciar sesion (icono en la bandeja).
Name: "{commonstartup}\Ecom Sentinel"; Filename: "{app}\EcomSentinel.exe"
Name: "{group}\Ecom Sentinel"; Filename: "{app}\EcomSentinel.exe"
Name: "{autodesktop}\Ecom Sentinel"; Filename: "{app}\EcomSentinel.exe"; Tasks: desktopicon
Name: "{group}\Activar modo administrador"; Filename: "{app}\activar-admin.cmd"
Name: "{group}\Desinstalar Ecom Sentinel"; Filename: "{uninstallexe}"

[Run]
Filename: "{app}\EcomSentinel.exe"; Description: "Iniciar Ecom Sentinel ahora"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Al desinstalar: cerrar el agente y quitar la tarea de administrador si se creo.
Filename: "{sys}\taskkill.exe"; Parameters: "/F /IM EcomSentinel.exe"; Flags: runhidden; RunOnceId: "killsentinel"
Filename: "{sys}\schtasks.exe"; Parameters: "/Delete /TN ""Ecom Sentinel (admin)"" /F"; Flags: runhidden; RunOnceId: "deltask"
