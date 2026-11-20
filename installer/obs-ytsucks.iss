; Inno Setup script for the obs-ytsucks Windows installer.
; Built in CI by .github/scripts/Package-Windows.ps1:
;   ISCC.exe /DAppVersion=0.1.0 /DSourceDir=<release\RelWithDebInfo\obs-ytsucks>
;            /DOutputDir=<release> /DOutputName=obs-ytsucks-0.1.0-windows-x64-Installer
;            installer\obs-ytsucks.iss
;
; Installs into the OBS 30+ per-machine plugin folder:
;   C:\ProgramData\obs-studio\plugins\obs-ytsucks\bin\64bit\obs-ytsucks.dll
;   C:\ProgramData\obs-studio\plugins\obs-ytsucks\data\...

#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef SourceDir
  #define SourceDir "..\release\RelWithDebInfo\obs-ytsucks"
#endif
#ifndef OutputDir
  #define OutputDir "..\release"
#endif
#ifndef OutputName
  #define OutputName "obs-ytsucks-" + AppVersion + "-windows-x64-Installer"
#endif

[Setup]
AppId={{6D1C4E52-3F0B-4B7A-9C51-0B7A2F3E9D41}
AppName=obs-ytsucks PII Redaction for OBS
AppVersion={#AppVersion}
AppPublisher=obs-ytsucks contributors
AppPublisherURL=https://github.com/temperne/obs-ytsucks
AppSupportURL=https://github.com/temperne/obs-ytsucks/issues
DefaultDirName={commonappdata}\obs-studio\plugins\obs-ytsucks
DisableDirPage=yes
DisableProgramGroupPage=yes
DefaultGroupName=obs-ytsucks
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0
LicenseFile=..\LICENSE
OutputDir={#OutputDir}
OutputBaseFilename={#OutputName}
Compression=lzma2
SolidCompression=yes
WizardStyle=modern
UninstallDisplayName=obs-ytsucks PII Redaction for OBS
CloseApplications=yes
CloseApplicationsFilter=obs64.exe

[Messages]
WelcomeLabel2=This installs the "PII Redaction (OCR)" video filter for OBS Studio 30 or newer.%n%nIt uses the text recognition built into Windows, so nothing else needs to be installed.%n%nPlease close OBS before continuing.

[Files]
Source: "{#SourceDir}\bin\64bit\*.dll"; DestDir: "{app}\bin\64bit"; Flags: ignoreversion
Source: "{#SourceDir}\bin\64bit\*.pdb"; DestDir: "{app}\bin\64bit"; Flags: ignoreversion skipifsourcedoesntexist
Source: "{#SourceDir}\data\*"; DestDir: "{app}\data"; Flags: ignoreversion recursesubdirs createallsubdirs

[UninstallDelete]
Type: filesandordirs; Name: "{app}"

[Code]
function OBSInstalled(): Boolean;
begin
  Result := RegKeyExists(HKLM, 'SOFTWARE\OBS Studio') or
            FileExists(ExpandConstant('{commonpf64}\obs-studio\bin\64bit\obs64.exe'));
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  if not OBSInstalled() then
    Result := MsgBox('OBS Studio was not found on this computer. Install the plugin anyway?',
                     mbConfirmation, MB_YESNO) = IDYES;
end;
