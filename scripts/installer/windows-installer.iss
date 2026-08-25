#ifndef AppVersion
  #error AppVersion must be defined
#endif
#ifndef StageDir
  #error StageDir must be defined
#endif
#ifndef OutputDir
  #error OutputDir must be defined
#endif

[Setup]
AppId={{2F118E45-186F-4DC2-BA6B-9AF06C85F149}
AppName=Copilot IM Gateway
AppVersion={#AppVersion}
AppPublisher=cloga
AppPublisherURL=https://github.com/cloga/copilot-im-gateway
AppSupportURL=https://github.com/cloga/copilot-im-gateway/issues
DefaultDirName={localappdata}\Programs\Copilot IM Gateway
DefaultGroupName=Copilot IM Gateway
DisableProgramGroupPage=yes
PrivilegesRequired=lowest
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
OutputDir={#OutputDir}
OutputBaseFilename=Copilot-IM-Gateway-Setup-v{#AppVersion}-x64
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=Copilot IM Gateway
VersionInfoVersion={#AppVersion}
VersionInfoCompany=cloga
VersionInfoDescription=Copilot IM Gateway Setup
VersionInfoProductName=Copilot IM Gateway
VersionInfoProductVersion={#AppVersion}

[Files]
Source: "{#StageDir}\app\*"; DestDir: "{app}\app"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StageDir}\runtime\*"; DestDir: "{app}\runtime"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StageDir}\extension\*"; DestDir: "{code:GetExtensionDir}"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "{#StageDir}\start-daemon.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\open-status.cmd"; DestDir: "{app}"; Flags: ignoreversion
Source: "{#StageDir}\stop-daemon.ps1"; Flags: dontcopy

[Icons]
Name: "{userprograms}\Copilot IM Gateway\Start Copilot IM Gateway"; Filename: "{app}\start-daemon.cmd"; WorkingDir: "{app}\app"
Name: "{userprograms}\Copilot IM Gateway\Gateway status"; Filename: "{app}\open-status.cmd"
Name: "{userprograms}\Copilot IM Gateway\Documentation"; Filename: "{app}\app\README.md"
Name: "{userprograms}\Copilot IM Gateway\Uninstall Copilot IM Gateway"; Filename: "{uninstallexe}"

[Code]
function GetExtensionDir(Param: String): String;
var
  CustomDirectory: String;
begin
  CustomDirectory := ExpandConstant('{param:EXTENSIONDIR|}');
  if CustomDirectory <> '' then
    Result := CustomDirectory
  else
    Result := ExpandConstant('{%USERPROFILE}\.copilot\extensions\im-gateway');
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
  PowerShellPath: String;
  StopScriptPath: String;
  Arguments: String;
  DataDirectory: String;
  TokenFile: String;
  PortText: String;
  GatewayPort: Integer;
begin
  Result := '';
  try
    ExtractTemporaryFile('stop-daemon.ps1');
  except
    Result := 'Unable to prepare the daemon upgrade guard.';
    exit;
  end;

  PowerShellPath := ExpandConstant('{sys}\WindowsPowerShell\v1.0\powershell.exe');
  StopScriptPath := ExpandConstant('{tmp}\stop-daemon.ps1');
  Arguments :=
    '-NoProfile -NonInteractive -ExecutionPolicy Bypass -File "' +
    StopScriptPath + '" -InstallDirectory "' + ExpandConstant('{app}') + '"';
  DataDirectory := ExpandConstant('{param:GATEWAYDATADIR|}');
  TokenFile := ExpandConstant('{param:GATEWAYTOKENFILE|}');
  PortText := ExpandConstant('{param:GATEWAYPORT|}');
  if (Pos('"', DataDirectory) > 0) or (Pos('"', TokenFile) > 0) then
  begin
    Result := 'Gateway data and token paths cannot contain quotation marks.';
    exit;
  end;
  if DataDirectory <> '' then
    Arguments := Arguments + ' -DataDirectory "' + DataDirectory + '"';
  if TokenFile <> '' then
    Arguments := Arguments + ' -TokenFile "' + TokenFile + '"';
  if PortText <> '' then
  begin
    GatewayPort := StrToIntDef(PortText, -1);
    if (GatewayPort < 0) or (GatewayPort > 65535) then
    begin
      Result := 'Gateway port must be an integer from 0 to 65535.';
      exit;
    end;
    Arguments := Arguments + ' -Port ' + IntToStr(GatewayPort);
  end;
  if not Exec(
    PowerShellPath,
    Arguments,
    '',
    SW_HIDE,
    ewWaitUntilTerminated,
    ResultCode
  ) then
    Result := 'Unable to run the daemon upgrade guard.'
  else if ResultCode <> 0 then
    Result :=
      'The existing gateway could not be stopped with authenticated v2 shutdown. ' +
      'Exit the old Copilot IM Gateway and retry.';
end;
