#ifndef MyVersion
  #error MyVersion must be defined
#endif
#ifndef MyArch
  #error MyArch must be defined
#endif
#ifndef MyBinary
  #error MyBinary must be defined
#endif
#ifndef MyConfig
  #error MyConfig must be defined
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
Source: "{#MyConfig}"; DestDir: "{app}\\config"; DestName: "default.json"; Flags: ignoreversion onlyifdoesntexist
Source: "..\\..\\..\\src\\dashboard\\public\\index.html"; DestDir: "{app}\\public"; Flags: ignoreversion

[Dirs]
Name: "{app}\var"; Permissions: users-modify

[Icons]
Name: "{group}\ASVP Agent Command Prompt"; Filename: "{cmd}"; Parameters: "/K cd /d ""{app}"""

[Run]
Filename: "{app}\\{#MyExeName}"; Parameters: "--config ""{app}\\config\\default.json"" service install"; Description: "Install and start the ASVP Agent Windows service"; Flags: postinstall waituntilterminated; Check: ShouldInstallService

[UninstallRun]
Filename: "{app}\\{#MyExeName}"; Parameters: "--config ""{app}\\config\\default.json"" service uninstall"; Flags: runhidden waituntilterminated skipifdoesntexist

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
var
  EnrollmentPage: TInputQueryWizardPage;
  EnrollmentSaved: Boolean;
  BakedEnrollment: Boolean;

function IsDigits(const Value: String): Boolean;
var
  I: Integer;
begin
  Result := Value <> '';
  for I := 1 to Length(Value) do
    if (Value[I] < '0') or (Value[I] > '9') then
    begin
      Result := False;
      Exit;
    end;
end;

function IsLoopbackAuthority(const Authority: String): Boolean;
var
  ColonAt: Integer;
  Host, Port: String;
begin
  ColonAt := Pos(':', Authority);
  if ColonAt = 0 then
  begin
    Result := (Authority = '127.0.0.1') or (Authority = 'localhost');
    Exit;
  end;
  Host := Copy(Authority, 1, ColonAt - 1);
  Port := Copy(Authority, ColonAt + 1, Length(Authority));
  Result := ((Host = '127.0.0.1') or (Host = 'localhost')) and IsDigits(Port);
end;

function IsValidManagementUrl(const Value: String): Boolean;
var
  LowerValue, Remainder, Authority: String;
  SlashAt: Integer;
begin
  LowerValue := Lowercase(Trim(Value));
  Result := False;
  if (Pos(' ', LowerValue) > 0) or (Pos('@', LowerValue) > 0) or
    (Pos('#', LowerValue) > 0) then Exit;

  if Pos('https://', LowerValue) = 1 then
    Remainder := Copy(LowerValue, 9, Length(LowerValue))
  else if Pos('http://', LowerValue) = 1 then
    Remainder := Copy(LowerValue, 8, Length(LowerValue))
  else
    Exit;

  SlashAt := Pos('/', Remainder);
  if SlashAt = 0 then Authority := Remainder
  else Authority := Copy(Remainder, 1, SlashAt - 1);
  if Authority = '' then Exit;

  if Pos('https://', LowerValue) = 1 then Result := True
  else Result := IsLoopbackAuthority(Authority);
end;

function InitializeUninstall(): Boolean;
var
  Answer: String;
begin
  Answer := '';
  Result := InputQuery('Remove ASVP Agent',
    'This removes the service, identity, queued results, logs, configuration, and every file under ' + ExpandConstant('{app}') + '. Type "yes" to confirm:',
    False, Answer) and (Lowercase(Trim(Answer)) = 'yes');
  if not Result then
    MsgBox('Uninstall was cancelled. No ASVP installation data was removed.', mbInformation, MB_OK);
end;

function InitializeSetup(): Boolean;
begin
  MsgBox('This installer and executable are not code-signed. Windows SmartScreen may display an Unknown publisher warning.', mbInformation, MB_OK);
  Result := True;
end;

procedure InitializeWizard();
var
  ConfigContents: AnsiString;
  LowerConfig: String;
begin
  BakedEnrollment := False;
  if LoadStringFromFile(ExpandConstant('{#MyConfig}'), ConfigContents) then
  begin
    LowerConfig := Lowercase(String(ConfigContents));
    BakedEnrollment := (Pos('management.example.invalid', LowerConfig) = 0) and
      ((Pos('"url": "https://', LowerConfig) > 0) or
       (Pos('"url": "http://127.0.0.1', LowerConfig) > 0) or
       (Pos('"url": "http://localhost', LowerConfig) > 0));
  end;
  EnrollmentPage := CreateInputQueryPage(wpSelectDir,
    'Enroll ASVP Agent',
    'Connect this installation to its management server',
    'Enter the real management server URL supplied by your administrator. The optional enrollment token is used only for initial registration.');
  EnrollmentPage.Add('Management server URL:', False);
  EnrollmentPage.Add('Enrollment token (optional):', True);
  EnrollmentPage.Values[0] := 'https://';
end;

function ShouldSkipPage(PageID: Integer): Boolean;
begin
  Result := BakedEnrollment and (PageID = EnrollmentPage.ID);
end;

function ShouldInstallService(): Boolean;
begin
  Result := BakedEnrollment or EnrollmentSaved;
end;

function NextButtonClick(CurPageID: Integer): Boolean;
var
  ServerUrl: String;
begin
  Result := True;
  if CurPageID = EnrollmentPage.ID then
  begin
    ServerUrl := Trim(EnrollmentPage.Values[0]);
    if Lowercase(ServerUrl) = 'https://management.example.invalid' then
    begin
      MsgBox('Enter your real management server URL; https://management.example.invalid is only a placeholder.', mbError, MB_OK);
      Result := False;
    end
    else if not IsValidManagementUrl(ServerUrl) then
    begin
      MsgBox('Enter a well-formed HTTPS URL. HTTP is allowed only for 127.0.0.1 or localhost testing.', mbError, MB_OK);
      Result := False;
    end;
  end;
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
  Parameters: String;
  InputPath: String;
  EnrollmentSucceeded: Boolean;
begin
  if (CurStep = ssPostInstall) and not BakedEnrollment and not EnrollmentSaved then
  begin
    InputPath := ExpandConstant('{tmp}\asvp-enrollment.txt');
    if not SaveStringToFile(InputPath, Trim(EnrollmentPage.Values[0]) + #13#10 +
      Trim(EnrollmentPage.Values[1]), False) then
      RaiseException('Unable to prepare ASVP enrollment configuration.');
    if not Exec(ExpandConstant('{sys}\icacls.exe'), '"' + InputPath +
      '" /inheritance:r /grant:r *S-1-5-18:F *S-1-5-32-544:F',
      '', SW_HIDE, ewWaitUntilTerminated, ResultCode) or (ResultCode <> 0) then
    begin
      DeleteFile(InputPath);
      RaiseException('Unable to restrict the temporary enrollment file. The service was not installed.');
    end;
    Parameters := '--config "' + ExpandConstant('{app}\config\default.json') +
      '" enroll --input-file "' + InputPath + '"';
    EnrollmentSucceeded := Exec(ExpandConstant('{app}\{#MyExeName}'), Parameters,
      ExpandConstant('{app}'), SW_HIDE, ewWaitUntilTerminated, ResultCode) and
      (ResultCode = 0);
    DeleteFile(InputPath);
    if not EnrollmentSucceeded then
      RaiseException('Unable to save ASVP enrollment configuration. The service was not installed.');
    EnrollmentSaved := True;
  end;
end;
