; GeDefense Windows 6.0.0 — branded Inno Setup installer
; Build with Inno Setup 7: ISCC.exe GeDefense.iss
; The outer installer is signed after compilation; the embedded beta certificate
; is imported only after a hard thumbprint pin check (FIND-WIN-014). The payload
; is extracted to {tmp} for the signed bootstrap transaction and removed again;
; no permanent {app}\payload directory is left behind.

#define MyAppName "GeDefense Titan"
#define MyAppVersion "6.0.0"
#define MyAppPublisher "VisionGaia Technology"
#define MyAppURL "https://visiongaiatechnology.de"
#define MyAppExeName "GeDefenseCenter.exe"
; Hard pin of the release certificate thumbprint (certificates/release-thumbprint.txt).
#define ExpectedReleaseThumbprint "1E7B1641FC2E8EB82735216829C13721E3B9D895"

[Setup]
AppId={{A7C4F1E2-9B7D-4C1E-8F6A-2D5E9B3C7A10}
AppName={#MyAppName}
AppVersion={#MyAppVersion}
AppVerName={#MyAppName} {#MyAppVersion}
AppPublisher={#MyAppPublisher}
AppPublisherURL={#MyAppURL}
AppSupportURL={#MyAppURL}
AppUpdatesURL={#MyAppURL}
DefaultDirName={autopf}\VGT\GeDefense
DisableDirPage=yes
DisableProgramGroupPage=yes
LicenseFile=terms\license.txt
OutputDir=..\..\release
OutputBaseFilename=GeDefense-Setup-Inno-x64-v{#MyAppVersion}
SetupIconFile=assets\gedefense.ico
Compression=lzma2/ultra64
SolidCompression=yes
WizardStyle=modern dynamic
WizardSizePercent=110
WizardImageFile=assets\wizard-left.bmp
WizardImageStretch=yes
WizardSmallImageFile=assets\wizard-small.bmp
PrivilegesRequired=admin
ArchitecturesAllowed=x64compatible
ArchitecturesInstallIn64BitMode=x64compatible
MinVersion=10.0.22000
UsePreviousAppDir=yes
ShowLanguageDialog=yes
LanguageDetectionMethod=uilanguage
Uninstallable=yes
CreateUninstallRegKey=no
UninstallDisplayName={#MyAppName}
UninstallDisplayIcon={app}\bin\{#MyAppExeName}
CloseApplications=no
RestartApplications=no
SetupLogging=yes
VersionInfoVersion=6.0.0.0
VersionInfoCompany={#MyAppPublisher}
VersionInfoDescription={#MyAppName} Setup
VersionInfoProductName={#MyAppName}
VersionInfoProductVersion={#MyAppVersion}

[Languages]
Name: "de"; MessagesFile: "compiler:Languages\German.isl"
Name: "en"; MessagesFile: "compiler:Default.isl"
Name: "ru"; MessagesFile: "compiler:Languages\Russian.isl"
Name: "zh"; MessagesFile: "compiler:Languages\ChineseSimplified.isl"

[CustomMessages]
de.BetaPageTitle=Beta-Programm und Zertifikatsvertrauen
de.BetaPageDesc=GeDefense 6.0.0 ist eine öffentliche Beta. Bitte lesen Sie den Beta-Hinweis, bevor die signierte Installation startet.
de.BetaTrustInfo=GeDefense 6.0.0 ist eine öffentliche Beta-Version und kann Fehler oder Sicherheitsdefekte enthalten. Der Installer importiert das selbstsignierte VGT-Release-Zertifikat in die lokalen Windows-Zertifikatspeicher "Vertrauenswürdige Stammzertifizierungsstellen" und "Vertrauenswürdige Herausgeber", damit die signierten Installations- und Wartungsskripte ausgeführt werden können. Danach kann Windows Code als vertrauenswürdig behandeln, der mit dem zugehörigen VGT-Schlüssel signiert wurde. Mit der Annahme der Beta-Bedingungen auf der Lizenzseite stimmen Sie diesem Import ausdrücklich zu. Installieren Sie die Beta nur auf einem Testsystem mit vollständigem Backup und nur, wenn Sie dem Build und seiner Herkunft vertrauen.
de.CertFailed=Das VGT-Beta-Zertifikat konnte nicht importiert werden. Die Installation wurde abgebrochen.
de.InstallFailed=Die GeDefense-Installationstransaktion ist fehlgeschlagen.
de.InstallLogHint=Details stehen in C:\ProgramData\VGT\InstallerLogs\install.log und im Diagnoseverzeichnis des angemeldeten Benutzers unter %LocalAppData%\VGT\InstallerDiagnostics.
de.DowngradeRejected=Eine neuere GeDefense-Version (%1) ist bereits installiert. Ein Downgrade auf %2 wird aus Sicherheitsgründen blockiert.
de.UpgradeDetected=Vorhandene Installation erkannt: GeDefense %1 wird auf Version %2 aktualisiert. Bestehende Einstellungen, Quarantäne und Evidenz bleiben erhalten.
de.RepairDetected=Vorhandene Installation erkannt: GeDefense %1 wird repariert bzw. aktualisiert.
de.ApplyingTransaction=Signierte GeDefense-Installationstransaktion und Datenmigration werden ausgeführt...
en.BetaPageTitle=Beta program and certificate trust
en.BetaPageDesc=GeDefense 6.0.0 is a public beta. Please read the beta notice before the signed installation starts.
en.BetaTrustInfo=GeDefense 6.0.0 is a public beta and may contain errors or security defects. The installer imports the self-signed VGT release certificate into the local Windows certificate stores "Trusted Root Certification Authorities" and "Trusted Publishers" so that the signed installation and maintenance scripts can run. Windows may afterwards treat code signed with the corresponding VGT key as trusted. By accepting the beta terms on the license page you expressly consent to this import. Only install the beta on a test system with a full backup, and only if you trust the build and its origin.
en.CertFailed=The VGT beta certificate could not be imported. Installation was cancelled.
en.InstallFailed=The GeDefense installation transaction failed.
en.InstallLogHint=Details are in C:\ProgramData\VGT\InstallerLogs\install.log and in the signed-in user's diagnostics directory under %LocalAppData%\VGT\InstallerDiagnostics.
en.DowngradeRejected=A newer GeDefense version (%1) is already installed. Downgrading to %2 is blocked for security reasons.
en.UpgradeDetected=Existing installation detected: GeDefense %1 will be upgraded to version %2. Existing settings, quarantine and evidence will be preserved.
en.RepairDetected=Existing installation detected: GeDefense %1 will be repaired / updated in place.
en.ApplyingTransaction=Running signed GeDefense installation transaction and state migration...
ru.BetaPageTitle=Бета-программа и доверие сертификату
ru.BetaPageDesc=GeDefense 6.0.0 — публичная бета-версия. Прочитайте бета-уведомление перед запуском подписанной установки.
ru.BetaTrustInfo=GeDefense 6.0.0 — публичная бета-версия, которая может содержать ошибки или дефекты безопасности. Установщик импортирует самоподписанный сертификат выпуска VGT в локальные хранилища сертификатов Windows «Доверенные корневые центры сертификации» и «Доверенные издатели», чтобы подписанные скрипты установки и обслуживания могли выполняться. После этого Windows может считать доверенным код, подписанный соответствующим ключом VGT. Принимая бета-условия на странице лицензии, вы явно соглашаетесь на этот импорт. Устанавливайте бету только на тестовой системе с полной резервной копией и только если доверяете сборке и её происхождению.
ru.CertFailed=Не удалось импортировать бета-сертификат VGT. Установка отменена.
ru.InstallFailed=Транзакция установки GeDefense завершилась ошибкой.
ru.InstallLogHint=Подробности: C:\ProgramData\VGT\InstallerLogs\install.log и каталог диагностики пользователя %LocalAppData%\VGT\InstallerDiagnostics.
ru.DowngradeRejected=Уже установлена более новая версия GeDefense (%1). Понижение версии до %2 заблокировано по соображениям безопасности.
ru.UpgradeDetected=Обнаружена установленная версия: GeDefense %1 будет обновлена до версии %2. Настройки, карантин и журнал событий сохранятся.
ru.RepairDetected=Обнаружена установленная версия: GeDefense %1 будет восстановлена / обновлена.
ru.ApplyingTransaction=Выполняется подписанная транзакция установки и миграция данных GeDefense...
zh.BetaPageTitle=测试计划与证书信任
zh.BetaPageDesc=GeDefense 6.0.0 是公开测试版。请在开始签名安装前阅读测试版提示。
zh.BetaTrustInfo=GeDefense 6.0.0 是公开测试版，可能包含错误或安全缺陷。安装程序会将自签名的 VGT 发布证书导入本地 Windows 证书存储“受信任的根证书颁发机构”和“受信任的发布者”，以便运行已签名的安装和维护脚本。此后 Windows 可能将以相应 VGT 密钥签名的代码视为可信。接受许可证页面上的测试条款，即表示您明确同意此导入。请仅在具备完整备份的测试系统上安装测试版，并且仅在您信任该构建及其来源时安装。
zh.CertFailed=无法导入 VGT 测试版证书。安装已取消。
zh.InstallFailed=GeDefense 安装事务失败。
zh.InstallLogHint=详情请见 C:\ProgramData\VGT\InstallerLogs\install.log 以及当前用户诊断目录 %LocalAppData%\VGT\InstallerDiagnostics。
zh.DowngradeRejected=已安装更高版本的 GeDefense（%1）。出于安全原因，禁止降级到 %2。
zh.UpgradeDetected=检测到现有安装：GeDefense %1 将升级到版本 %2。现有设置、隔离区和证据链将被保留。
zh.RepairDetected=检测到现有安装：将就地修复/更新 GeDefense %1。
zh.ApplyingTransaction=正在执行已签名的 GeDefense 安装事务与状态迁移...

[Files]
; The payload is staged into the Setup temp directory only. It is consumed by the
; signed Install-GeDefense.ps1 transaction (which copies it into an
; Administrators/SYSTEM-only staging directory and verifies it there) and removed
; again, so no writable/permanent second payload copy remains in {app}.
Source: "..\..\payload\VGT\GeDefense\*"; DestDir: "{tmp}\vgt-payload"; Flags: ignoreversion recursesubdirs createallsubdirs
Source: "..\..\certificates\vgt-release.cer"; DestDir: "{tmp}"; Flags: dontcopy
Source: "terms\terms.de.txt"; DestDir: "{tmp}"; Flags: dontcopy
Source: "terms\terms.en.txt"; DestDir: "{tmp}"; Flags: dontcopy
Source: "terms\terms.ru.txt"; DestDir: "{tmp}"; Flags: dontcopy
Source: "terms\terms.zh.txt"; DestDir: "{tmp}"; Flags: dontcopy

[InstallDelete]
Type: filesandordirs; Name: "{app}\payload"

[UninstallDelete]
Type: files; Name: "{app}\GeDefense-Setup.exe"
Type: filesandordirs; Name: "{app}\installer"
Type: dirifempty; Name: "{app}"

[UninstallRun]
; The install transaction copied the signed uninstaller support files and the
; thumbprint marker into {app}\installer. The uninstall transaction is run
; directly (no second payload extraction) and must complete before Inno removes
; the support directory (FIND-WIN-014).
Filename: "{sysnative}\WindowsPowerShell\v1.0\powershell.exe"; Parameters: "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File ""{app}\installer\Uninstall-GeDefense.ps1"" -PayloadRoot ""{app}"""; Flags: runhidden waituntilterminated; RunOnceId: "VgtUninstall"

[Code]
const
  ReleaseThumbprint = '{#ExpectedReleaseThumbprint}';

var
  BetaPage: TWizardPage;
  BetaMemo: TNewMemo;
  DetectedOldVersion: String;
  DetectedCompareResult: Integer;

function TrimVersionString(Value: String): String;
begin
  Result := Trim(Value);
end;

procedure SplitCoreAndPre(Value: String; var Core, Pre: String);
var
  DashPos: Integer;
begin
  DashPos := Pos('-', Value);
  if DashPos > 0 then
  begin
    Core := Copy(Value, 1, DashPos - 1);
    Pre := Copy(Value, DashPos + 1, Length(Value) - DashPos);
  end
  else
  begin
    Core := Value;
    Pre := '';
  end;
end;

function ParseVersionTuple(Core: String; var Major, Minor, Patch: Integer): Boolean;
var
  P1, P2: Integer;
  S1, S2, S3: String;
begin
  Result := False;
  P1 := Pos('.', Core);
  if P1 <= 1 then Exit;
  S1 := Copy(Core, 1, P1 - 1);
  Delete(Core, 1, P1);
  P2 := Pos('.', Core);
  if P2 <= 1 then Exit;
  S2 := Copy(Core, 1, P2 - 1);
  S3 := Copy(Core, P2 + 1, Length(Core) - P2);
  Major := StrToIntDef(S1, -1);
  Minor := StrToIntDef(S2, -1);
  Patch := StrToIntDef(S3, -1);
  Result := (Major >= 0) and (Minor >= 0) and (Patch >= 0);
end;

function CompareSemVer(LeftVer, RightVer: String): Integer;
var
  LCore, LPre, RCore, RPre: String;
  LMaj, LMin, LPat, RMaj, RMin, RPat: Integer;
begin
  Result := 0;
  SplitCoreAndPre(TrimVersionString(LeftVer), LCore, LPre);
  SplitCoreAndPre(TrimVersionString(RightVer), RCore, RPre);
  if (not ParseVersionTuple(LCore, LMaj, LMin, LPat)) or (not ParseVersionTuple(RCore, RMaj, RMin, RPat)) then
  begin
    Result := CompareStr(LeftVer, RightVer);
    Exit;
  end;
  if LMaj <> RMaj then begin if LMaj > RMaj then Result := 1 else Result := -1; Exit; end;
  if LMin <> RMin then begin if LMin > RMin then Result := 1 else Result := -1; Exit; end;
  if LPat <> RPat then begin if LPat > RPat then Result := 1 else Result := -1; Exit; end;
  if (LPre = '') and (RPre = '') then begin Result := 0; Exit; end;
  if LPre = '' then begin Result := 1; Exit; end;
  if RPre = '' then begin Result := -1; Exit; end;
  Result := CompareStr(LPre, RPre);
end;

function ReadInstalledVersion: String;
var
  InstallLoc, VersionFile, RegVer: String;
  Lines: TArrayOfString;
begin
  Result := '';
  InstallLoc := '';
  if not RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense', 'InstallLocation', InstallLoc) then
    InstallLoc := ExpandConstant('{autopf}\VGT\GeDefense');
  VersionFile := AddBackslash(InstallLoc) + 'VERSION';
  if FileExists(VersionFile) and LoadStringsFromFile(VersionFile, Lines) then
  begin
    if GetArrayLength(Lines) > 0 then
      Result := TrimVersionString(Lines[0]);
  end;
  if Result = '' then
  begin
    if RegQueryStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense', 'DisplayVersion', RegVer) then
      Result := TrimVersionString(RegVer);
  end;
end;

function InitializeSetup(): Boolean;
begin
  Result := True;
  DetectedOldVersion := ReadInstalledVersion;
  DetectedCompareResult := 0;
  if DetectedOldVersion <> '' then
  begin
    DetectedCompareResult := CompareSemVer(DetectedOldVersion, '{#MyAppVersion}');
    if DetectedCompareResult > 0 then
    begin
      MsgBox(FmtMessage(CustomMessage('DowngradeRejected'), [DetectedOldVersion, '{#MyAppVersion}']), mbError, MB_OK);
      Result := False;
    end;
  end;
end;

function ReadLatestDiagnosticFailure: String;
var
  DiagPath: String;
  Lines: TArrayOfString;
  I: Integer;
begin
  Result := '';
  DiagPath := ExpandConstant('{localappdata}\VGT\InstallerDiagnostics\latest-transaction.log');
  if FileExists(DiagPath) and LoadStringsFromFile(DiagPath, Lines) then
  begin
    for I := GetArrayLength(Lines) - 1 downto 0 do
    begin
      if Pos('|FAILED|', Lines[I]) > 0 then
      begin
        Result := Trim(Lines[I]);
        Break;
      end;
    end;
  end;
end;

function TermsFileName: String;
begin
  Result := 'terms.' + ActiveLanguage + '.txt';
end;

procedure LoadTermsForLanguage;
var
  TermsPath: String;
begin
  TermsPath := ExpandConstant('{tmp}\') + TermsFileName;
  if not FileExists(TermsPath) then
  begin
    ExtractTemporaryFile(TermsFileName);
  end;
  if FileExists(TermsPath) then
  begin
    WizardForm.LicenseMemo.Lines.LoadFromFile(TermsPath);
  end;
end;

// Hard thumbprint pin (FIND-WIN-014): the extracted certificate must match the
// release thumbprint that is compiled into this installer before any
// certification-authority trust store is touched. A swapped certificate aborts
// the installation instead of being silently self-rooted.
procedure VerifyEmbeddedCertificateThumbprint(CertificatePath: String);
var
  PowerShell: String;
  Parameters: String;
  Command: String;
  ResultCode: Integer;
begin
  PowerShell := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');
  Command :=
    '$ErrorActionPreference=''Stop''; try { $c = New-Object System.Security.Cryptography.X509Certificates.X509Certificate2(''' + CertificatePath + '''); if ($c.Thumbprint -ne ''' + ReleaseThumbprint + ''') { exit 41 }; exit 0 } catch { exit 42 }';
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Command + '"';
  if (not Exec(PowerShell, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
  begin
    RaiseException(CustomMessage('CertFailed'));
  end;
end;

// Read back the imported anchors: both the Root and the TrustedPublisher store
// must contain exactly the pinned release certificate after the import.
procedure VerifyImportedCertificate;
var
  PowerShell: String;
  Parameters: String;
  Command: String;
  ResultCode: Integer;
begin
  PowerShell := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');
  Command :=
    '$ErrorActionPreference=''Stop''; try { $root = @(Get-ChildItem Cert:\LocalMachine\Root | Where-Object { $_.Thumbprint -eq ''' + ReleaseThumbprint + ''' }); $publisher = @(Get-ChildItem Cert:\LocalMachine\TrustedPublisher | Where-Object { $_.Thumbprint -eq ''' + ReleaseThumbprint + ''' }); if (($root.Count -lt 1) -or ($publisher.Count -lt 1)) { exit 51 }; exit 0 } catch { exit 52 }';
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "' + Command + '"';
  if (not Exec(PowerShell, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
  begin
    RaiseException(CustomMessage('CertFailed'));
  end;
end;

procedure ImportBetaCertificate;
var
  CertificatePath: String;
  CertUtil: String;
  Parameters: String;
  ResultCode: Integer;
begin
  CertificatePath := ExpandConstant('{tmp}\vgt-release.cer');
  if not FileExists(CertificatePath) then
  begin
    ExtractTemporaryFile('vgt-release.cer');
  end;
  if not FileExists(CertificatePath) then
  begin
    RaiseException(CustomMessage('CertFailed'));
  end;
  VerifyEmbeddedCertificateThumbprint(CertificatePath);
  CertUtil := ExpandConstant('{sysnative}\certutil.exe');
  Parameters := '-addstore -f Root "' + CertificatePath + '"';
  if (not Exec(CertUtil, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
  begin
    RaiseException(CustomMessage('CertFailed'));
  end;
  Parameters := '-addstore -f TrustedPublisher "' + CertificatePath + '"';
  if (not Exec(CertUtil, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
  begin
    RaiseException(CustomMessage('CertFailed'));
  end;
  VerifyImportedCertificate;
  // Product-import marker: the uninstall transaction removes the Root anchor
  // only when this marker matches the verified release certificate.
  RegWriteStringValue(HKEY_LOCAL_MACHINE, 'SOFTWARE\VGT\GeDefense', 'RootCertImportedThumbprint', ReleaseThumbprint);
end;

procedure RunBootstrap;
var
  PowerShell: String;
  PayloadRoot: String;
  Parameters: String;
  ResultCode: Integer;
  Uninstaller: String;
  ProgramDataRoot: String;
  DiagLine: String;
  ErrorText: String;
begin
  // Transient payload stage; the signed Install transaction copies it into a
  // protected ProgramData staging directory and verifies the final destination.
  WizardForm.StatusLabel.Caption := CustomMessage('ApplyingTransaction');
  WizardForm.FilenameLabel.Caption := 'Bootstrap-GeDefense.ps1';
  PayloadRoot := ExpandConstant('{tmp}\vgt-payload');
  PowerShell := ExpandConstant('{sysnative}\WindowsPowerShell\v1.0\powershell.exe');
  Parameters := '-NoLogo -NoProfile -NonInteractive -ExecutionPolicy AllSigned -File "' +
    PayloadRoot + '\installer\Bootstrap-GeDefense.ps1" -PayloadRoot "' + PayloadRoot +
    '" -Operation Install';
  if (not Exec(PowerShell, Parameters, '', SW_HIDE, ewWaitUntilTerminated, ResultCode)) or (ResultCode <> 0) then
  begin
    ErrorText := CustomMessage('InstallFailed');
    DiagLine := ReadLatestDiagnosticFailure;
    if DiagLine <> '' then
      ErrorText := ErrorText + #13#10#13#10 + DiagLine;
    ErrorText := ErrorText + #13#10#13#10 + CustomMessage('InstallLogHint');
    SuppressibleMsgBox(ErrorText, mbError, MB_OK, IDOK);
    Abort;
  end;
  // No permanent {app}\payload: the transient stage is removed immediately after
  // the verified installation. Inno also removes {tmp} at exit.
  DelTree(PayloadRoot, True, True, True);
  ProgramDataRoot := ExpandConstant('{commonappdata}\VGT\GeDefense\staging');
  if DirExists(ProgramDataRoot) then
  begin
    DelTree(ProgramDataRoot, True, True, True);
  end;
  Uninstaller := ExpandConstant('{app}\unins000.exe');
  if FileExists(Uninstaller) then
  begin
    RegWriteStringValue(HKEY_LOCAL_MACHINE,
      'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense',
      'UninstallString', '"' + Uninstaller + '"');
    RegWriteStringValue(HKEY_LOCAL_MACHINE,
      'SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\VGTGeDefense',
      'DisplayIcon', ExpandConstant('{app}\bin\GeDefenseCenter.exe'));
  end;
end;

function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
  Notice: String;
begin
  Result := '';
  if DetectedOldVersion <> '' then
  begin
    if DetectedCompareResult < 0 then
      Notice := FmtMessage(CustomMessage('UpgradeDetected'), [DetectedOldVersion, '{#MyAppVersion}'])
    else
      Notice := FmtMessage(CustomMessage('RepairDetected'), [DetectedOldVersion]);
    Result := Notice + NewLine + NewLine;
  end;
  if MemoDirInfo <> '' then
    Result := Result + MemoDirInfo + NewLine + NewLine
  else
    Result := Result + ExpandConstant('{app}') + NewLine + NewLine;
end;

procedure InitializeWizard;
var
  UpgradeNotice: String;
begin
  if DetectedOldVersion <> '' then
  begin
    if DetectedCompareResult < 0 then
      UpgradeNotice := FmtMessage(CustomMessage('UpgradeDetected'), [DetectedOldVersion, '{#MyAppVersion}'])
    else
      UpgradeNotice := FmtMessage(CustomMessage('RepairDetected'), [DetectedOldVersion]);
    WizardForm.WelcomeLabel2.Caption := WizardForm.WelcomeLabel2.Caption + #13#10#13#10 + UpgradeNotice;
  end;

  WizardForm.LicenseAcceptedRadio.Checked := False;
  WizardForm.LicenseNotAcceptedRadio.Checked := True;
  LoadTermsForLanguage;

  BetaPage := CreateCustomPage(wpLicense, CustomMessage('BetaPageTitle'), CustomMessage('BetaPageDesc'));
  BetaMemo := TNewMemo.Create(BetaPage);
  BetaMemo.Parent := BetaPage.Surface;
  BetaMemo.Left := 0;
  BetaMemo.Top := 0;
  BetaMemo.Width := BetaPage.SurfaceWidth;
  BetaMemo.Height := BetaPage.SurfaceHeight - 70;
  BetaMemo.ReadOnly := True;
  BetaMemo.ScrollBars := ssVertical;
  BetaMemo.Text := CustomMessage('BetaTrustInfo');
  BetaMemo.WordWrap := True;

end;


procedure CurStepChanged(CurStep: TSetupStep);
begin
  if CurStep = ssInstall then
  begin
    ImportBetaCertificate;
  end
  else if CurStep = ssPostInstall then
  begin
    RunBootstrap;
  end;
end;
