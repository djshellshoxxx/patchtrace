#define AppName "PatchTrace"
#define AppExeName "PatchTrace.exe"
#ifndef AppVersion
  #define AppVersion "0.1.0"
#endif

[Setup]
AppId={{9B871A4E-2F28-47D4-9C35-7C4E31064201}
AppName={#AppName}
AppVersion={#AppVersion}
AppPublisher=djshellshoxxx
AppPublisherURL=https://github.com/djshellshoxxx/patchtrace
AppSupportURL=https://github.com/djshellshoxxx/patchtrace/issues
DefaultDirName={localappdata}\Programs\PatchTrace
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64
ArchitecturesInstallIn64BitMode=x64
MinVersion=10.0
OutputDir=..\dist
OutputBaseFilename=PatchTrace-Windows-x64-Setup
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayIcon={app}\{#AppExeName}
Uninstallable=yes
LicenseFile=..\LICENSE
CloseApplications=no
RestartIfNeededByRun=no

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Files]
Source: "..\dist\PatchTrace\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs

[Icons]
Name: "{autoprograms}\{#AppName}"; Filename: "{app}\{#AppExeName}"; WorkingDir: "{app}"

[Run]
Filename: "{app}\{#AppExeName}"; Description: "Launch PatchTrace"; Flags: postinstall nowait skipifsilent
