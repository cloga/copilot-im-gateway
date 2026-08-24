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
