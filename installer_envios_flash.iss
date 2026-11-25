#define MyAppName "Envios Flash - Sistema de Balcão"
#define MyAppVersion "1.0"
#define MyAppExeName "EnviosFlash.exe"
[Setup]
AppId={{BD7AF65D-4079-4E2E-BA46-7897FF6EA61C}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\Envios Flash
DefaultGroupName={#MyAppName}
OutputBaseFilename=Setup_Envios_Flash_v1_0
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
[Files]
Source: "dist\EnviosFlash\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Envios Flash"; Filename: "{app}\{#MyAppExeName}"
[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Abrir Envios Flash"; Flags: nowait postinstall skipifsilent
