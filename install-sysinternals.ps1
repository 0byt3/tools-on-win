param(
  [Switch]$Force
)
if (!([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
  throw "You must be running as an administrator, please restart as administrator.";
}

#region definitions

$SYSINTERNALS_URL = "https://download.sysinternals.com/files/SysinternalsSuite.zip";
$SYSINTERNALS_DIR = "$($env:ProgramFiles)\Sysinternals";

$SYSINTERNALS_FILENAMES = @('accesschk.exe', 'accesschk64.exe', 'AccessEnum.exe', 'AdExplorer.chm', 'ADExplorer.exe', 'ADExplorer64.exe', 'ADInsight.chm', 'ADInsight.exe', 'ADInsight64.exe', 'adrestore.exe', 'adrestore64.exe', 'Autologon.exe', 'Autologon64.exe', 'autoruns.chm', 'Autoruns.exe', 'Autoruns64.exe', 'autorunsc.exe', 'autorunsc64.exe', 'Bginfo.exe', 'Bginfo64.exe', 'Cacheset.exe', 'Cacheset64.exe', 'Clockres.exe', 'Clockres64.exe', 'Contig.exe', 'Contig64.exe', 'Coreinfo.exe', 'Coreinfo64.exe', 'CPUSTRES.EXE', 'CPUSTRES64.EXE', 'ctrl2cap.amd.sys', 'ctrl2cap.exe', 'Dbgview.chm', 'Dbgview.exe', 'dbgview64.exe', 'Desktops.exe', 'Desktops64.exe', 'Disk2vhd.chm', 'disk2vhd.exe', 'disk2vhd64.exe', 'diskext.exe', 'diskext64.exe', 'Diskmon.exe', 'Diskmon64.exe', 'DiskView.exe', 'DiskView64.exe', 'du.exe', 'du64.exe', 'efsdump.exe', 'Eula.txt', 'FindLinks.exe', 'FindLinks64.exe', 'handle.exe', 'handle64.exe', 'hex2dec.exe', 'hex2dec64.exe', 'junction.exe', 'junction64.exe', 'ldmdump.exe', 'Listdlls.exe', 'Listdlls64.exe', 'livekd.exe', 'livekd64.exe', 'LoadOrd.exe', 'LoadOrd64.exe', 'LoadOrdC.exe', 'LoadOrdC64.exe', 'logonsessions.exe', 'logonsessions64.exe', 'movefile.exe', 'movefile64.exe', 'notmyfault.exe', 'notmyfault64.exe', 'notmyfaultc.exe', 'notmyfaultc64.exe', 'ntfsinfo.exe', 'ntfsinfo64.exe', 'pendmoves.exe', 'pendmoves64.exe', 'pipelist.exe', 'pipelist64.exe', 'portmon.exe', 'procdump.exe', 'procdump64.exe', 'procexp.chm', 'procexp.exe', 'procexp64.exe', 'procmon.chm', 'Procmon.exe', 'Procmon64.exe', 'PsExec.exe', 'PsExec64.exe', 'psfile.exe', 'psfile64.exe', 'PsGetsid.exe', 'PsGetsid64.exe', 'PsInfo.exe', 'PsInfo64.exe', 'pskill.exe', 'pskill64.exe', 'pslist.exe', 'pslist64.exe', 'PsLoggedon.exe', 'PsLoggedon64.exe', 'psloglist.exe', 'psloglist64.exe', 'pspasswd.exe', 'pspasswd64.exe', 'psping.exe', 'psping64.exe', 'PsService.exe', 'PsService64.exe', 'psshutdown.exe', 'psshutdown64.exe', 'pssuspend.exe', 'pssuspend64.exe', 'Pstools.chm', 'psversion.txt', 'RAMMap.exe', 'RAMMap64.exe', 'RDCMan.exe', 'readme.txt', 'RegDelNull.exe', 'RegDelNull64.exe', 'regjump.exe', 'ru.exe', 'ru64.exe', 'sdelete.exe', 'sdelete64.exe', 'ShareEnum.exe', 'ShareEnum64.exe', 'ShellRunas.exe', 'sigcheck.exe', 'sigcheck64.exe', 'streams.exe', 'streams64.exe', 'strings.exe', 'strings64.exe', 'sync.exe', 'sync64.exe', 'Sysmon.exe', 'Sysmon64.exe', 'tcpvcon.exe', 'tcpvcon64.exe', 'tcpview.chm', 'tcpview.exe', 'tcpview64.exe', 'Testlimit.exe', 'Testlimit64.exe', 'Vmmap.chm', 'vmmap.exe', 'vmmap64.exe', 'Volumeid.exe', 'Volumeid64.exe', 'whois.exe', 'whois64.exe', 'Winobj.exe', 'Winobj64.exe', 'ZoomIt.exe', 'ZoomIt64.exe');

Function Get-RandomChars {
  param([Int]$Count);
  $characters = 65..90 | Foreach-Object -Process { [char]$_ }
  $characters += @(0,1,2,3,4,5,6,7,8,9);
  ($characters | Get-Random -Count $Count) -join '';
  Remove-Variable -Name characters -ErrorAction SilentlyContinue;
}

#endregion

#region validate arguments

$forceInstall = $false;
if ($PSBoundParameters.Keys -notcontains 'Force') {
  $validAnswer = $false;
  while (-not $validAnswer) {
    Write-Output "";
    $answer = Read-Host -Prompt "If SysinternalsSuite is already installed, `nForce fresh install? (Blank = no)? [y/N]";
    Switch -Regex ($answer) {
      "^[ \t]*(y(|es)|t(|rue))$" {
        $forceInstall = $true;
        $validAnswer = $true;
      }
      "^[ \t]*(|n(|o)|f(|alse))$" {
        $validAnswer = $true;
      }
      default {
        Write-Output "!!'$($answer)' not valid. Please answer yes or no (or blank for no).`n`n";
      }
    }
  }
  Remove-Variable -Name validAnswer -ErrorAction SilentlyContinue;
}

#endregion

$supportedTlsVers = [Enum]::GetNames([Net.SecurityProtocolType]);
$addTlsVerNames += @("Tls11", "Tls12", "Tls13");
foreach ($tlsVer in $addTlsVerNames) {
   if ($tlsVer -in $supportedTlsVers) {
      [Net.ServicePointManager]::SecurityProtocol = `
         [Net.ServicePointManager]::SecurityProtocol -bor `
         [Net.SecurityProtocolType]::$tlsVer;
   }
}
Remove-Variable -Name addTlsVernames,supportedTlsVers -ErrorAction SilentlyContinue;

#region update PATH variable
$sysPathVar = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::Machine) -Split ";" |
    Where-Object -FilterScript { $_ -notlike "$($SYSINTERNALS_DIR)" -and $_ -notlike "$($SYSINTERNALS_DIR)\" }
$sysPathVar += "$($SYSINTERNALS_DIR)";
[System.Environment]::SetEnvironmentVariable('PATH', "$($sysPathVar -join ';')", [System.EnvironmentVariableTarget]::Machine);

$userPathVar = [System.Environment]::GetEnvironmentVariable('PATH', [System.EnvironmentVariableTarget]::User) -Split ";" |
    Where-Object -FilterScript { $_ -notlike "$($SYSINTERNALS_DIR)" -and $_ -notlike "$($SYSINTERNALS_DIR)\" }
Set-ItemProperty -Path HKCU:\Environment -Name Path -Value "$($userPathVar -join ';')";

if (-not ($env:PATH -split ';' | Where-Object -FilterScript {$_ -like "$($SYSINTERNALS_DIR)" -or $_ -like "$($SYSINTERNALS_DIR)\"})) {
  $env:PATH = "$($env:PATH);$($SYSINTERNALS_DIR)";
}

#endregion

#region install sysinternals
if ((Test-Path -Path "$($SYSINTERNALS_DIR)" -ErrorAction SilentlyContinue) -and -not $forceInstall) {
  Write-Output "The directory '$($SYSINTERNALS_DIR)' exists. Checking for and missing Sysinternals Suite files.";
  $isSysinternalsInstalled = $true;
  foreach ($sysinternalsFileName in $SYSINTERNALS_FILENAMES) {
    if (-not (Test-Path -Path "$($SYSINTERNALS_DIR)\$sysinternalsFileName" -ErrorAction SilentlyContinue)) {
      Write-Output "Missing '$($sysinternalsFileName)'. Will re-install Sysinternals Suite.";
      Remove-Item -Path "$($SYSINTERNALS_DIR)" -Recurse -Force -Confirm:$false;
      $isSysinternalsInstalled = $false;
      break;
    }
  }
} elseif ($forceInstall) {
  Write-Output "The directory '$($SYSINTERNALS_DIR)' exists, but Force specified. Will re-install Sysinternals Suite.";
  Remove-Item -Path "$($SYSINTERNALS_DIR)" -Recurse -Force -Confirm:$false;
  $isSysinternalsInstalled = $false;
} else {
  Write-Output "Missing directory '$($SYSINTERNALS_DIR)'. Will install Sysinternals Suite.";
}

if (-not $isSysinternalsInstalled) {
  New-Item -Path "$($SYSINTERNALS_DIR)" -ItemType Directory -ErrorAction Stop | Out-Null;

  Write-Output "Downloading SysinternalsSuite.zip";
  $sysintDownloadPath = "$env:TEMP\SysinternalsSuite.$(Get-RandomChars -Count 5).zip";
  if (-not (Test-Path -Path "$($sysintDownloadPath)" -ErrorAction SilentlyContinue)) {
    [System.Net.WebClient]::new().DownloadFile($SYSINTERNALS_URL,$sysintDownloadPath);
    if (-not $?) {
      Write-Error -Message "Failed to download sysinternals.zip";
      Exit 1;
    }
  }
  Unblock-File -Path $sysintDownloadPath -Confirm:$false;
  Write-Output "Extracting to '$($SYSINTERNALS_DIR)'";
  Expand-Archive -Path "$($sysintDownloadPath)" -DestinationPath "$($SYSINTERNALS_DIR)" -Confirm:$false -Force -ErrorAction Stop;
  Remove-Item -Path "$($sysintDownloadPath)" -Confirm:$false -Force -ErrorAction SilentlyContinue;
} else {
  Write-Output "Sysinternals already installed.";
}
#endregion

#region pre-accept EULA
if (-not (Test-Path -Path "HKLM:\Software\Sysinternals" -ErrorAction SilentlyContinue)) {
  New-Item -Path "HKLM:\SOFTWARE\Sysinternals" | Out-Null;
}
Set-ItemProperty -Path "HKLM:\SOFTWARE\Sysinternals" -Name "EulaAccepted" -Value 1 -Type Dword -Force;
#endregion
