#ifndef MyVersion
  #error MyVersion must be defined
#endif
#ifndef MyArch
  #error MyArch must be defined
#endif
#ifndef MyBinary
  #error MyBinary must be defined
#endif

#define MyAppName "ASVP Agent"
#define MyExeName "asvp-agent.exe"

[Setup]
AppId={{5F108EBC-A86C-4B3A-A60F-7451012D5172}
AppName={#MyAppName}
AppVersion={#MyVersion}
AppPublisher=ASVP
DefaultDirName={autopf}\ASVP Agent
DefaultGroupName=ASVP Agent
OutputDir=..\..\..\dist\win-{#MyArch}
OutputBaseFilename=asvp-agent-{#MyVersion}-windows-{#MyArch}-setup
Compression=lzma2
SolidCompression=yes
PrivilegesRequired=admin
UninstallDisplayIcon={app}\{#MyExeName}
ArchitecturesAllowed={#MyArch}
ArchitecturesInstallIn64BitMode={#MyArch}
WizardStyle=modern

[Files]
Source: "{#MyBinary}"; DestDir: "{app}"; DestName: "{#MyExeName}"; Flags: ignoreversion
Source: "..\\..\\..\\config\\default.json"; DestDir: "{app}\\config"; Flags: ignoreversion onlyifdoesntexist
Source: "..\\..\\..\\src\\dashboard\\public\\index.html"; DestDir: "{app}\\public"; Flags: ignoreversion

[Dirs]
Name: "{app}\var"; Permissions: users-modify

[Icons]
Name: "{group}\ASVP Agent Command Prompt"; Filename: "{cmd}"; Parameters: "/K cd /d ""{app}"""

[Run]
Filename: "{app}\\{#MyExeName}"; Parameters: "--config ""{app}\\config\\default.json"" service install"; Description: "Install and start the ASVP Agent Windows service"; Flags: postinstall skipifsilent waituntilterminated

[Code]
function InitializeSetup(): Boolean;
begin
  MsgBox('This installer and executable are not code-signed. Windows SmartScreen may display an Unknown publisher warning.', mbInformation, MB_OK);
  Result := True;
end;
