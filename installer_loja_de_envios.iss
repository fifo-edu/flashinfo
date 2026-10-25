#define MyAppName "Loja de Envios - Sistema de Balcão"
#define MyAppVersion "1.0"
#define MyAppExeName "LojaDeEnvios.exe"
[Setup]
AppId={{04C1B327-57D0-4AC8-A9B8-LOJADEENVIOS13}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
DefaultDirName={autopf}\Loja de Envios
DefaultGroupName={#MyAppName}
OutputBaseFilename=Setup_Loja_de_Envios_v1_0
Compression=lzma
SolidCompression=yes
ArchitecturesInstallIn64BitMode=x64compatible
[Files]
Source: "dist\LojaDeEnvios\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs
[Icons]
Name: "{autoprograms}\{#MyAppName}"; Filename: "{app}\{#MyAppExeName}"
Name: "{autodesktop}\Loja de Envios"; Filename: "{app}\{#MyAppExeName}"
[Run]
Filename: "{app}\{#MyAppExeName}"; Description: "Abrir Loja de Envios"; Flags: nowait postinstall skipifsilent
