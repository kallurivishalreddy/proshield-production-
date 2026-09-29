; ============================================================================
;  ProShield Windows installer (Inno Setup 6)
;
;  Compile (normally driven by deploy/build_windows.py):
;      ISCC.exe /DAppVersion=1.0.0 /DStageRoot=<...>_stage ^
;               /DOutputDir=<...> /DOutputBase=ProShieldSetup-v1.0.0 ^
;               /DUpdateUrl=http://host/ /DTestMode=0 deploy\inno\ProShieldSetup.iss
;
;  Responsibilities
;  ----------------
;    * install the desktop application        -> <app>\desktop\ProShield.exe
;    * install the service components         -> <app>\service\ProShieldService.exe
;    * install the backend planes + runtime   -> <app>\app, <app>\scripts, <app>\runtime
;    * install the authoritative React UI     -> <app>\frontend\soc
;    * register the Windows Service           -> auto-start + recovery + MongoDB ordering
;    * create Start Menu / optional Desktop shortcut, and an uninstaller
;
;  Upgrade safety
;  --------------
;    Inno performs an in-place upgrade for the same AppId (no uninstall of the
;    previous version), reusing the previous install directory, so there is no
;    duplicate installation, no duplicate service and no duplicate shortcut.
;    Runtime data lives in ProgramData and is never in the [Files] set, so an
;    upgrade cannot touch it.  MongoDB is an independent Windows service and is
;    never touched by this installer at all.
; ============================================================================

#define AppName "ProShield"
#define AppPublisher "ProShield Security"
#define AppExeName "ProShield.exe"
#define ServiceExeName "ProShieldService.exe"
#define ServiceName "ProShieldService"
#define DataDirName "ProShield"
#define DesktopMutex "Global\ProShieldDesktopShell"

; ---------------------------------------------------------------- parameters
#ifndef AppVersion
  #define AppVersion "0.0.0"
#endif
#ifndef VersionInfoVersion
  #define VersionInfoVersion "0.0.0.0"
#endif
#ifndef StageRoot
  #define StageRoot "..\..\dist\windows\0.0.0\_stage"
#endif
#ifndef OutputDir
  #define OutputDir "..\..\dist\windows\0.0.0"
#endif
#ifndef OutputBase
  #define OutputBase "ProShieldSetup-v0.0.0"
#endif
#ifndef UpdateUrl
  #define UpdateUrl ""
#endif
#ifndef TestMode
  #define TestMode "0"
#endif

#if TestMode == "1"
  #define TestFlag 1
  #define MyPrivileges "lowest"
  #define MyDefaultDir "{localappdata}\ProShield"
#else
  #define TestFlag 0
  #define MyPrivileges "admin"
  #define MyDefaultDir "{autopf}\ProShield"
#endif

[Setup]
AppId={{7C4B9E62-1F4A-4C3D-9E7B-2A5F8D1C6B04}
AppName={#AppName}
AppVersion={#AppVersion}
AppVerName={#AppName} {#AppVersion}
AppPublisher={#AppPublisher}
VersionInfoVersion={#VersionInfoVersion}
VersionInfoProductName={#AppName}
VersionInfoDescription={#AppName} setup
VersionInfoCompany={#AppPublisher}
DefaultDirName={#MyDefaultDir}
DefaultGroupName={#AppName}
DisableProgramGroupPage=yes
DisableDirPage=auto
UsePreviousAppDir=yes
AllowNoIcons=yes
PrivilegesRequired={#MyPrivileges}
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.17763
OutputDir={#OutputDir}
OutputBaseFilename={#OutputBase}
Compression=lzma2/max
SolidCompression=yes
WizardStyle=modern
SetupLogging=yes
UninstallDisplayName={#AppName} {#AppVersion}
UninstallDisplayIcon={app}\desktop\{#AppExeName}
CloseApplications=no
RestartApplications=no
ChangesEnvironment=no
AllowUNCPath=no
; The GUI holds no lock the installer needs, and we stop the service ourselves
; in PrepareToInstall so the file replacement order is deterministic.
AppMutex={#DesktopMutex}

[Languages]
Name: "english"; MessagesFile: "compiler:Default.isl"

[Tasks]
Name: "desktopicon"; Description: "Create a &desktop shortcut"; GroupDescription: "Additional shortcuts:"; Flags: unchecked
Name: "autostart"; Description: "Start ProShield automatically when I sign in (the Windows Service always starts with Windows)"; GroupDescription: "Startup:"; Flags: unchecked; Check: NotTestMode

[Files]
; The complete install payload.  _stage is produced by
; packaging/build_windows.py and contains ONLY allow-listed files: no
; __pycache__, no pytest cache, no audit probes, no demo scripts, no legacy
; frontend files, no development secrets.
Source: "{#StageRoot}\*"; DestDir: "{app}"; Flags: ignoreversion recursesubdirs createallsubdirs; Excludes: "__pycache__\*,*.pyc,*.pyo,.pytest_cache\*"

[Dirs]
; Runtime data directories.  They live outside {app} so no upgrade can replace
; them.
;
; Note on Inno's Permissions parameter: it only ADDS ACEs, and it accepts the
; access types 'full', 'modify' and 'write' (not 'read').  Inherited
; permissions from C:\ProgramData are therefore NOT removed here.  The
; security-relevant directories (secrets, updates, backup) are additionally
; hardened in [Code] by HardenRestrictedDirs(), which uses icacls to break
; inheritance and grant Administrators + SYSTEM only.
Name: "{commonappdata}\{#DataDirName}"; Permissions: admins-full users-modify; Check: NotTestMode
Name: "{commonappdata}\{#DataDirName}\config"; Permissions: admins-full users-modify; Check: NotTestMode
Name: "{commonappdata}\{#DataDirName}\logs"; Permissions: admins-full users-modify; Check: NotTestMode
Name: "{commonappdata}\{#DataDirName}\state"; Permissions: admins-full users-modify; Check: NotTestMode
; Administrator-only: holds the HMAC signing keys and the subject credentials.
Name: "{commonappdata}\{#DataDirName}\secrets"; Permissions: admins-full; Check: NotTestMode
; Administrator-only: staged update packages and the detached update helper.
Name: "{commonappdata}\{#DataDirName}\updates"; Permissions: admins-full; Check: NotTestMode
; Administrator-only: previous install trees used for rollback.
Name: "{commonappdata}\{#DataDirName}\backup"; Permissions: admins-full; Check: NotTestMode

[Registry]
; Test-mode installs keep their data in the user profile (no elevation needed).
Root: HKCU; Subkey: "Environment"; ValueType: string; ValueName: "PROSHIELD_DATA_DIR"; ValueData: "{localappdata}\ProShield"; Flags: preservestringtype uninsdeletevalue; Check: IsTestMode
; A configurable update endpoint means the same build can point at the testing
; channel now and a stable channel later without rebuilding the installer.
Root: HKCU; Subkey: "Environment"; ValueType: string; ValueName: "PROSHIELD_UPDATE_URL"; ValueData: "{#UpdateUrl}"; Flags: preservestringtype uninsdeletevalue; Check: HasUpdateUrl

[Icons]
Name: "{group}\{#AppName}"; Filename: "{app}\desktop\{#AppExeName}"; Comment: "ProShield security console"
Name: "{group}\{#AppName} logs"; Filename: "{code:GetDataDir}"; Comment: "ProShield runtime logs"
Name: "{group}\Uninstall {#AppName}"; Filename: "{uninstallexe}"
Name: "{autodesktop}\{#AppName}"; Filename: "{app}\desktop\{#AppExeName}"; Tasks: desktopicon
Name: "{userstartup}\{#AppName}"; Filename: "{app}\desktop\{#AppExeName}"; Tasks: autostart

[Run]
; Register (or repair) the Windows Service: auto-start, MongoDB dependency and
; SCM failure recovery, then start it and wait for RUNNING.
Filename: "{app}\service\{#ServiceExeName}"; Parameters: "install --wait 180"; StatusMsg: "Registering the ProShield Service (automatic startup + recovery)..."; Flags: runhidden waituntilterminated; Check: NotTestMode
; Launch the console once the install finished (never during a silent update).
Filename: "{app}\desktop\{#AppExeName}"; Description: "Launch {#AppName}"; Flags: nowait postinstall skipifsilent

[UninstallRun]
; Runs BEFORE the files are removed (Inno semantics), so the service is gone
; before its image is deleted.
Filename: "{sys}\taskkill.exe"; Parameters: "/IM {#AppExeName} /F"; Flags: runhidden; RunOnceId: "ProShieldStopGui"
Filename: "{app}\service\{#ServiceExeName}"; Parameters: "uninstall"; Flags: runhidden waituntilterminated; RunOnceId: "ProShieldRemoveService"; Check: NotTestMode

[UninstallDelete]
Type: filesandordirs; Name: "{app}\desktop"
Type: filesandordirs; Name: "{app}\service"
Type: filesandordirs; Name: "{app}\frontend"
Type: filesandordirs; Name: "{app}\deploy"
Type: filesandordirs; Name: "{app}\scripts"
Type: filesandordirs; Name: "{app}\app"
Type: filesandordirs; Name: "{app}\runtime"
Type: dirifempty; Name: "{app}"

[Code]
var
  WasGuiRunning: Boolean;

function IsTestMode(): Boolean;
begin
  Result := {#TestFlag} = 1;
end;

function NotTestMode(): Boolean;
begin
  Result := not IsTestMode();
end;

function HasUpdateUrl(): Boolean;
begin
  Result := '{#UpdateUrl}' <> '';
end;

function GetDataDir(Param: String): String;
begin
  if IsTestMode() then
    Result := ExpandConstant('{localappdata}\ProShield\logs')
  else
    Result := ExpandConstant('{commonappdata}\ProShield\logs');
end;

{ tasklist piped through find: exit code 0 means the image is present. }
function ImageRunning(const ImageName: String): Boolean;
var
  ResultCode: Integer;
begin
  Result :=
    Exec('cmd.exe',
         '/C tasklist /FI "IMAGENAME eq ' + ImageName + '" /NH | find /I "' + ImageName + '" >nul',
         '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);
end;

function ServiceRegistered(): Boolean;
var
  ResultCode: Integer;
begin
  Result :=
    Exec('sc.exe', 'query {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);
end;

procedure StopServiceForUpgrade();
var
  Attempt: Integer;
  ResultCode: Integer;
begin
  if not ServiceRegistered() then
    exit;

  { 'net stop' blocks until the SCM reports the service stopped.  ProShield
    handles SERVICE_CONTROL_PRESHUTDOWN/STOP by terminating its two planes and
    flushing logs, so this returns cleanly. }
  Exec('net.exe', 'stop {#ServiceName}', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);

  for Attempt := 1 to 45 do
  begin
    if not ImageRunning('{#ServiceExeName}') then
      break;
    Sleep(1000);
  end;

  if ImageRunning('{#ServiceExeName}') then
  begin
    Log('Service did not stop gracefully; forcing termination.');
    Exec('taskkill.exe', '/IM {#ServiceExeName} /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  end;
end;

procedure StopPlanesForUpgrade();
var
  ResultCode: Integer;
begin
  { The upgrade replaces runtime\python.exe, which Windows locks while a backend
    plane is running.  'net stop' below covers a registered service, but not a
    test-mode install, a plane that outlived its supervisor, or a supervisor
    started by hand.  stop-planes terminates exactly the processes whose image
    lives inside the install directory - never any other python.exe on the
    machine.  (Note: the install path is written without Inno's brace syntax
    here, because a brace would terminate this Pascal comment.) }
  if FileExists(ExpandConstant('{app}\service\{#ServiceExeName}')) then
  begin
    Exec(ExpandConstant('{app}\service\{#ServiceExeName}'),
         'stop-planes --timeout 25', '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
    Log('stop-planes -> exit ' + IntToStr(ResultCode));
  end;
end;

function PrepareToInstall(var NeedsRestart: Boolean): String;
var
  ResultCode: Integer;
begin
  Result := '';
  NeedsRestart := False;

  { Close the desktop application so its image is not locked.  taskkill exits
    128 when no matching process exists, which tells us whether to relaunch it. }
  WasGuiRunning :=
    Exec('taskkill.exe', '/IM {#AppExeName} /F', '', SW_HIDE, ewWaitUntilTerminated, ResultCode)
    and (ResultCode = 0);

  StopServiceForUpgrade();
  StopPlanesForUpgrade();
end;

procedure WriteInstallInfo();
var
  InfoPath, Body, DataDir, ServiceNote, InstallDirJson, DataDirJson: String;
begin
  if IsTestMode() then
  begin
    DataDir := ExpandConstant('{localappdata}\ProShield');
    ServiceNote := 'false';
  end
  else
  begin
    DataDir := ExpandConstant('{commonappdata}\ProShield');
    ServiceNote := 'true';
  end;

  InfoPath := DataDir + '\config\install-info.json';
  ForceDirectories(DataDir + '\config');

  { StringChangeEx takes its first argument by reference, so the JSON escaping
    has to go through local variables. }
  InstallDirJson := ExpandConstant('{app}');
  StringChangeEx(InstallDirJson, '\', '\\', True);
  DataDirJson := DataDir;
  StringChangeEx(DataDirJson, '\', '\\', True);

  Body := '{' + #13#10;
  Body := Body + '  "product_name": "{#AppName}",' + #13#10;
  Body := Body + '  "version": "{#AppVersion}",' + #13#10;
  Body := Body + '  "install_dir": "' + InstallDirJson + '",' + #13#10;
  Body := Body + '  "data_dir": "' + DataDirJson + '",' + #13#10;
  Body := Body + '  "service_name": "{#ServiceName}",' + #13#10;
  Body := Body + '  "service_registered": ' + ServiceNote + ',' + #13#10;
  Body := Body + '  "test_mode": {#TestFlag},' + #13#10;
  Body := Body + '  "update_url": "{#UpdateUrl}",' + #13#10;
  Body := Body + '  "installer": "{#OutputBase}.exe",' + #13#10;
  Body := Body + '  "installed_at": "' + GetDateTimeString('yyyy-mm-dd hh:nn:ss', ':', '-') + '"' + #13#10;
  Body := Body + '}' + #13#10;

  SaveStringToFile(InfoPath, Body, False);
  Log('Wrote ' + InfoPath);
end;

{ Inno's Permissions parameter can only ADD ACEs, so the inherited
  'Users: Read & execute' on C:\ProgramData would still let a non-admin user
  read the HMAC signing keys in \secrets.  Break inheritance and grant
  Administrators + LOCAL SYSTEM only.  SIDs are used instead of localized group
  names so this works on every Windows language. }
procedure HardenRestrictedDirs();
var
  DataDir, Target: String;
  ResultCode: Integer;
begin
  if IsTestMode() then
    exit;

  DataDir := ExpandConstant('{commonappdata}\ProShield');

  Target := DataDir + '\secrets';
  Exec('icacls.exe',
       '"' + Target + '" /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('icacls on secrets -> exit ' + IntToStr(ResultCode));

  Target := DataDir + '\updates';
  Exec('icacls.exe',
       '"' + Target + '" /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('icacls on updates -> exit ' + IntToStr(ResultCode));

  Target := DataDir + '\backup';
  Exec('icacls.exe',
       '"' + Target + '" /inheritance:r /grant:r "*S-1-5-32-544:(OI)(CI)F" "*S-1-5-18:(OI)(CI)F"',
       '', SW_HIDE, ewWaitUntilTerminated, ResultCode);
  Log('icacls on backup -> exit ' + IntToStr(ResultCode));
end;

procedure CurStepChanged(CurStep: TSetupStep);
var
  ResultCode: Integer;
begin
  if CurStep = ssPostInstall then
  begin
    HardenRestrictedDirs();
    WriteInstallInfo();

    if WasGuiRunning and (not WizardSilent()) then
      Exec(ExpandConstant('{app}\desktop\{#AppExeName}'), '', '', SW_SHOWNORMAL,
           ewNoWait, ResultCode);
  end;
end;

procedure CurUninstallStepChanged(CurUninstallStep: TUninstallStep);
var
  DataDir: String;
  Response: Integer;
begin
  if CurUninstallStep = usUninstall then
  begin
    if IsTestMode() then
      DataDir := ExpandConstant('{localappdata}\ProShield')
    else
      DataDir := ExpandConstant('{commonappdata}\ProShield');

    if UninstallSilent() then
      exit;

    Response := MsgBox(
      'Remove the ProShield runtime data as well?' + #13#10 + #13#10 +
      DataDir + #13#10 +
      '(configuration, logs, staged updates and rollback backups)' + #13#10 + #13#10 +
      'MongoDB security data - events, detections, correlations, cases and ' +
      'evidence - is NEVER removed by the ProShield installer.',
      mbConfirmation, MB_YESNO or MB_DEFBUTTON2);

    if Response = IDYES then
    begin
      DelTree(DataDir, True, True, True);
      Log('Removed runtime data at ' + DataDir);
    end
    else
      Log('Runtime data preserved at ' + DataDir);
  end;
end;
