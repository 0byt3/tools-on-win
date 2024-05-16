#!/usr/bin/env -S pwsh -File
param(
   $UpgradeMsys,
   $OnUpgradeReAddPkgs
);

$mainBlock = {
   param(
      $UpgradeMsys,
      $OnUpgradeReAddPkgs
   );

   # If MSYS2 was already downloaded and was added to the system via the self extrating (sfx.exe) file, I couldn't find a way to
   #  determine the version number, so I used the kernel version number reported by `uname.exe -r` for version checking.
   $MSYS_KERNEL_VER = "3.4.10";
   $MSYS_INSTALLER_URL = "https://github.com/msys2/msys2-installer/releases/download/2024-05-07/msys2-x86_64-20240507.exe";
   $MSYS_CHKSUM_URL = "https://github.com/msys2/msys2-installer/releases/download/2024-05-07/msys2-x86_64-20240507.exe.sha256";
   $MSYS_INSTALLER_PATH = "$($env:TEMP)\msys2-x86_64-$($MSYS_KERNEL_VER).exe";

   Function AddTo-PathEnv {
      param([String]$Directory);

      if (-not (Test-Path -Path $Directory -ErrorAction SilentlyContinue)) {
         throw "The Directory '$Directory' does not exist.";
      }

      $pathVar = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PATH).PATH.Split(";") |
         Where-Object -FilterScript { $_ -match ".+" }

      $pathVarCheck = $pathVar -replace "\\`$","" |
         Foreach-Object -Process { $_.ToLower() }
      $dir = ( $Directory -replace "\\`$","" ).ToLower();
      if ($pathVarCheck -notcontains $dir) {
         $pathVar += $Directory;
         Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PATH -Value "$($pathVar -join ";")";
      }
      Remove-Variable -Name pathVar,pathVarCheck -ErrorAction SilentlyContinue;

      $livePathVar = $env:PATH.Split(";") |
         Where-Object -FilterScript { $_ -match ".+" } |
         Foreach-Object -Process { ($_ -replace "\\`$","" ).ToLower() }
      if ($livePathVar -notcontains $dir) {
         $env:PATH = "$($env:PATH -replace ';$','');$($Directory)";
      }
   }

   Function ConvertTo-Boolean {
      param($Value);

      if ($Value -is [Boolean]) {
         return $Value;
      }

      if ($Value -match "^[0-9]+$") {
         $v = [Int]::Parse($Value);
      } else {
         $v = $Value;
      }

      Switch ($v) {
         ({ $_ -match "^((\$|)true|t|y|yes)$" }) {
            return $true;
         }
         ({ $_ -match "^((\$|)false|f|n|no)$" }) {
            return $false;
         }
         ({ $_ -gt 0 }) {
            return $true;
         }
         0 {
            return $false;
         }
         default {
            throw "'$($Value)' cannot be converted to Boolean. Must be 'true', 'false', '`$true','`$false', yes, no, 1 or 0";
         }
      }
   }

   Function Download-MsysRuntime {
      param(
         [String]$InstallerDest,
         [String]$InstallerUrl
      );
      $InstallerChkUrl = "$($InstallerUrl).sha256";

      if (Test-Path -Path $InstallerDest -ErrorAction SilentlyContinue) {
         $installerHash = (Get-FileHash -Algorithm SHA256 -Path $InstallerDest).Hash.toLower();
         $downloadedHash = [System.Net.WebClient]::new().DownloadString($InstallerChkUrl) -replace "^([^ \t]+)[ \t]+.*","`$1" |
            Select-Object -First 1
         if (-not $?) {
            [Console]::Error.WriteLine("Unable to download $(Split-Path -Path $InstallerChkUrl -Leaf) to validate the installer that was already downloaded.");
         }
         if ($installerHash -eq $downloadedHash) {
            Remove-Variable -Name installerHash,downloadedHash -ErrorAction SilentlyContinue;
            return;
         } else {
            Remove-Item -Path $InstallerDest -Force -Confirm:$false -ErrorAction SilentlyContinue;
            Remove-Variable -Name installerHash,downloadedHash -ErrorAction SilentlyContinue;
         }
      }
      # save current progress preference, so it can be changed back
      $CurrentProgressPref = $ProgressPreference;
      # Invoke-WebRequest downloads hekken slow when it reports progress to the screen
      $ProgressPreference = "SilentlyContinue";
      Write-Output "Downloading MSYS2 installer from '$($InstallerUrl)'";
      try {
         Invoke-WebRequest -Uri $InstallerUrl -OutFile $InstallerDest -ErrorAction Stop;
      } finally {
         $ProgressPreference = $CurrentProgressPreference;
         Remove-Variable -Name CurrentProgressPreference -ErrorAction SilentlyContinue;
      }
   }

   Function Find-MsysInstallDir {
      $msysPkg = Get-Package -Name MSYS2 -ErrorAction SilentlyContinue;
      if ($msysPkg) {
         $msysInstallLoc = ([xml]$msysPkg.SwidTagText).SoftwareIdentity.Meta.InstallLocation;
         Remove-Variable -Name msysPkg -ErrorAction SilentlyContinue;
         return $msysInstallLoc;
      }

      $searchDirs = @();
      Get-ChildItem -Path "$($env:SystemDrive)\" -ErrorAction SilentlyContinue |
         Where-Object -FilterScript {$_.Name -notlike "Users"} |
         Foreach-Object -Process { $searchDirs += $_.FullName }
      Get-WmiObject -Class Win32_Volume -Filter "DriveType=3" -Property DriveLetter |
         Where-Object -FilterScript { $_.DriveLetter -notlike "$($env:SystemDrive)" -and $_.DriveLetter -match ".+" } |
         Foreach-Object -Process { $searchDirs += $_.DriveLetter }

      foreach ($searchDir in $searchDirs) {
         $msysExe = dir -Path $searchDir -Filter msys2.exe -Recurse -ErrorAction SilentlyContinue;
         if ($msysExe) {
            break;
         }
      }

      return $msysExe.DirectoryName;
   }

   Function Install-MsysRuntime {
      param([String]$InstallerPath);

      if (-not $?) {
         throw "Error in execution of MSYS installer.";
      }

      Remove-Variable -Name binariesDirPath -ErrorAction SilentlyContinue;
      return $true;
   }

   Function RemoveFrom-PathEnv {
      param([String]$Directory);

      $pathVar = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PATH).PATH.Split(";") |
         Where-Object -FilterScript { $_ -match ".+" } |
         Where-Object -Filterscript { "$($_ -replace '\\$','')" -notlike "$($Directory -replace '\\$','')" }

      Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Session Manager\Environment" -Name PATH -Value "$($pathVar -join ";")";

      $pathVar = $env:PATH.Split(";") |
         Where-Object -FilterScript { $_ -match ".+" } |
         Where-Object -Filterscript { "$($_ -replace '\\$','')" -notlike "$($Directory -replace '\\$','')" }

      $env:PATH = "$($pathVar -join ";")";
   }

   Function Uninstall-MsysRuntime {
      param([String]$MsysDirPath);


      return $true;
   }

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

   if ($PSBoundParameters.Keys -notcontains 'UpgradeMsys') {
      $validAnswer = $false;
      while (-not $validAnswer) {
         Write-Output "";
         Write-Output "If installed MSYS2 version is lower than $($MSYS_KERNEL_VER),";
         $answer = Read-Host -Prompt "Upgrade? [Y/n]";
         Switch -Regex ($answer) {
            '^[ \t]*(y|yes|)$' {
                  $validAnswer = $true;
                  $UpdateMsys = $true;
               }
            '^[Nn]{1}[Oo]{,1}$' {
                  $validAnswer = $true;
                  $UpdateMsys = $false;
               }
            default {
                  Write-Output "!! '$($answer)' is not valid. Please answer y(es) or n(o) or blank for yes.`n";
               }
         }
         Remove-Variable -Name answer -ErrorAction SilentlyContinue;
      }
      Remove-Variable -Name validAnswer -ErrorAction SilentlyContinue;
   } else {
      try {
         $UpdateMsys = ConvertTo-Boolean -Value $UpgradeMsys;
      } catch {
         [Console]::Error.WriteLine("Invalid value for parameter 'UpgradeMsys'. $($_.Exception.Message)");
         Exit 1;
      }
   }

   if ($PSBoundParameters.Keys -notcontains 'OnUpgradeReAddPkgs' -and $UpdateMsys) {
      $validAnswer = $false;
      while (-not $validAnswer) {
         Write-Output "";
         Write-Output "If installed MSYS2 version must be upgraded,";
         $answer = Read-Host -Prompt "Reinstall existing packages? [Y/n]";
         Switch -Regex ($answer) {
            '^[ \t]*(y|yes|)$' {
                  $validAnswer = $true;
                  $reinstallPkgs = $true;
               }
            '^[Nn]{1}[Oo]{,1}$' {
                  $validAnswer = $true;
                  $reinstallPkgs = $false;
               }
            default {
                  Write-Output "!! '$($answer)' is not valid. Please answer y(es) or n(o) or blank for yes.`n";
               }
         }
         Remove-Variable -Name answer -ErrorAction SilentlyContinue;
      }
      Remove-Variable -Name validAnswer -ErrorAction SilentlyContinue;
   } else {
      try {
         $reinstallPkgs = ConvertTo-Boolean -Value $OnUpgradeReAddPkgs;
      } catch {
         [Console]::Error.WriteLine("Invalid value for parameter 'OnUpgradeReAddPkgs'. $($_.Exception.Message)");
         Exit 1;
      }
   }

   Write-Output "Searching for exisiting installation.";
   $msysDirPath = Find-MsysInstallDir;
   if ($msysDirPath) {
      Write-Output "Found existing installation @ '$($msysDirPath)'";
      $unameBin = dir -Path $msysDirPath -Filter uname.exe -Recurse |
         Select-Object -ExpandProperty FullName;
      $existMsysVer = [Version]$((& $unameBin -r) -replace "(^[0-9\.]+)\.[A-Za-z]{1}.*","`$1");
      Remove-Variable -Name unameBin -ErrorAction SilentlyContinue;
      $targetMsysVer = [Version]($MSYS_KERNEL_VER);

      if ($existMsysVer -lt $targetMsysVer) {
         Write-Output "Installed MSYS2 version is $($existMsysVer) which is lower than $($targetMsysVer)";
         if ($UpdateMsys) {
            Write-Output "Upgrade requeted. Removing existing version of MSYS2.";

            Download-MsysRuntime -InstallerDest $MSYS_INSTALLER_PATH -InstallerUrl $MSYS_INSTALLER_URL;

            Write-Ouput "First, recording installed packages.";
            $pacmanBin = dir -Path $msysDirPath -Filter pacman.exe -Recurse |
               Select-Object -ExpandProperty FullName;
            $existingPackages = (& $pacmanBin -Q) -replace "^([^ \t]+)[ \t]+.*","`$1";

            $uninstallerPath = dir -Path $msysDirPath -Filter uninstall.exe -Recurse |
               Select-Object -ExpandProperty FullName;
            if ($uninstallerPath) {
               Write-Output "Executing uninstaller.";
               & $uninstallerPath "pr" "--confirm-command" "--accept-messages" "AllUsers=true"

               if (-not $?) {
                  throw "Error in execution of MSYS uninstaller.";
               }
            } else {
               Write-Output "Did not find 'uninstaller.exe'"
            }

            if (Test-Path -Path $msysDirPath -ErrorAction SilentlyContinue) {
               Write-Output "Removing the '$($msysDirPath)' directory.";
               Remove-Item -Path $msysDirPath -Confirm:$false -Force -Recurse;
            }
            $binariesDirPath = Split-Path -Path $pacmanBin -Parent;
            Write-Output "Removing '$($binariesDirPath)' from the PATH environment variable.";
            RemoveFrom-PathEnv -Directory $binariesDirPath;

            Remove-Variable -Name binariesDirPath,uninstallerPath,pacmanBin,msysDirPath -ErrorAction SilentlyContinue;
         } else {
            Write-Output "Upgrade not requested. Not upgrading MSYS2 version.";
         }
      } else {
         Write-Output "MSYS2 already installed @ '$($msysDirPath)'.";
      }

      Remove-Variable -Name existMsysVer,targetMsysVer -ErrorAction SilentlyContinue;
   } else {
      Write-Output "Did not find an existing installation.";
   }

   if (-not $msysDirPath) {
      Write-Output "Installing MSYS2.";
      Download-MsysRuntime -InstallerDest $MSYS_INSTALLER_PATH -InstallerUrl $MSYS_INSTALLER_URL;

      Write-Output "Executing MSYS2 installer.";
      & $MSYS_INSTALLER_PATH "in" "--confirm-command" "--accept-messages" "--root" "$($env:SystemDrive)/msys64"  "AllUsers=true"
      $msysExitCode = $LASTEXITCODE;
      if ($msysExitCode -ne 0) {
         [Console]::Error.WriteLine("Error installing MSYS2");
         Exit $msysExitCode;
      }
      Remove-Variable -Name msysExitCode;

      $msysDirPath = "$($env:SystemDrive)\msys64";
      $pacmanBin = dir -Path $msysDirPath -Filter pacman.exe -Recurse |
         Select-Object -ExpandProperty FullName;

      $binariesDirPath = Split-Path -Path $pacmanBin -Parent;
      Write-Output "Adding '$($binariesDirPath)' to the PATH environment variable.";
      AddTo-PathEnv -Directory "$($binariesDirPath)";

      Remove-Variable -Name binariesPath -ErrorAction SilentlyContinue;
      if ($existingPackages) {
         $missingPackages = @();
         $installedPackages = (& $pacmanBin -Q) -replace "^([^ \t]+)[ \t]+.*","`$1"
         $missingPackages += $existingPackages |
            Where-Object -FilterScript { $installedPackages -notcontains $_ }

         Write-Output "Re-installing packages from previous install.";
         & $pacmanBin -yS @missingPackages

         Remove-Variable -Name missingPackages,installedPackages -ErrorAction SilentlyContinue;
      }
      Remove-Variable -Name existingPackages -ErrorAction SilentlyContinue;
   }

   if (-not (pacman.exe -Q git 2>$null)) {
      pacman.exe -S --noconfirm git
   }
}

$tempScriptFile = "$env:TEMP\msys2-plus-tools.ps1";
$mainBlock.ToString() | Set-Content -Path $tempScriptFile;

$powershellArgs = @(
   "-ExecutionPolicy",
   "UnRestricted",
   "-NoLogo",
   "-NoProfile",
   "-File",
   "`"$($tempScriptFile)`""
);
foreach ($key in $PSBoundParameters.Keys) {
   $powershellArgs += "-$($key)";
   $powershellArgs += "$($PSBoundParameters[$key])";
}

$startProcParams = @{
   FilePath = "powershell.exe";
   Wait = $true
   NoNewWindow = $true;
   ArgumentList = $powershellArgs
};

if (!([bool]([Security.Principal.WindowsPrincipal] [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole] "Administrator"))) {
   $startProcParams["Verb"] = "RunAs";
}

Start-Process @startProcParams;
