#!/usr/bin/env -S pwsh -File
param($UpgradeFzf);

$mainBlock = {
    param($UpgradeFzf);

    Add-Type -AssemblyName System.IO.Compression;
    Add-Type -AssemblyName System.IO.Compression.FileSystem;

    $global:FZF_DEFAULT_PATH = "$($env:windir)\fzf.exe";
    $global:FZF_URL = "https://github.com/junegunn/fzf/releases/download/0.52.1/fzf-0.52.1-windows_amd64.zip";
    $global:FZF_VER = [Version]"0.52.1";
    $global:FZF_ZIP_PATH = "$($env:TEMP)\fzf-0.52.1-windows_amd64.zip";

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

    Function Download-Fzf {
        param(
            [String]$Destination,
            [String]$Url
        );

        # save current progress preference, so it can be changed back
        $CurrentProgressPref = $ProgressPreference;
        # Invoke-WebRequest downloads hekken slow when it reports progress to the screen
        $ProgressPreference = "SilentlyContinue";
        try {
            Invoke-WebRequest -Uri $Url -OutFile $Destination -ErrorAction Stop;
        } finally {
            $ProgressPreference = $CurrentProgressPref;
            Remove-Variable -Name CurrentProgressPref -ErrorAction SilentlyContinue;
        }
    }

    Function Find-FzfPath {
        $fzfPath = $env:Path -split ";" |
            Foreach-Object -Process { "$($_ -replace '\\$','')\fzf.exe" } |
            Where-Object -FilterScript { Test-Path -Path $_ -ErrorAction SilentlyContinue } |
            Select-Object -First 1

        if (-not $fzfPath) {
            $searchDirs = @(
                $env:windir,
                $env:ProgramFiles,
                ${env:ProgramFiles(x86)}
            );

            foreach ($dir in $searchDirs) {
                dir -Path $dir -Filter "fzf.exe" -Recurse -ErrorAction SilentlyContinue |
                    Select-Object -First 1 |
                    Select-Object -ExpandProperty FullName

                if ($fzfPath) {
                    break;
                }
            }
            Remove-Variable -Name searchDirs -ErrorAction SilentlyContinue;
        }

        if (-not $fzfPath) {
            return $false,$([String]::Empty);
        } else {
            return $true,$fzfPath;
        }
    }

    Function Extract-Fzf {
        param(
            [String]$DestinationDir,
            [String]$Source
        );
        $fullSource = Resolve-Path -Path $Source;
        try {
            $zipArchive = [IO.Compression.ZipFile]::OpenRead($fullSource);
        } catch {
            throw "Exception $($_.Exception.GetType().Name) while reading zip file '$($fullSource)' data: $($_.Exception.Message)";
        }
        $fzfZipEntry = $zipArchive.Entries |
            Where-Object -FilterScript { $_.Name -like "fzf.exe" }
        if (-not $fzfZipEntry) {
            throw "'$($fullSource)' does not contain fzf.exe";
        }
        try {
            Remove-Item -Path "$($DestinationDir)\fzf.exe" -Confirm:$false -Force -ErrorAction Stop;
        } catch {
            throw "Exception $($_.Exception.GetType().Name) while trying to delete existing fzf.exe: $($_.Exception.Message)";
        }
        try {
            [IO.Compression.ZipFileExtensions]::ExtractToFile($fzfZipEntry, "$($DestinationDir)\fzf.exe");
        } catch {
            throw "Exception $($_.Exception.GetType().Name) while extracting fzf.exe from '$($fullSource)': $($_.Exception.Message)";
        } finally {
            $zipArchive.Dispose();
            Remove-Variable -Name fzfZipEntry,zipArchive -ErrorAction SilentlyContinue;
        }
    }

    if ($PSBoundParameters.Keys -notcontains 'UpgradeFzf') {
        $validAnswer = $false;
        while (-not $validAnswer) {
            Write-Output "";
            Write-Output "If installed fzf version is lower than $($global:FZF_VER),";
            $answer = Read-Host -Prompt "Upgrade? [Y/n]";
            Switch -Regex ($answer.Trim()) {
                '^(y|yes|)$' {
                    $validAnswer = $true;
                    $UpdateFzf = $true;
                }
                '^(n|no)$' {
                    $validAnswer = $true;
                    $UpdateFzf = $false;
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
            $UpdateFzf = ConvertTo-Boolean -Value $UpgradeFzf;
        } catch {
            [Console]::Error.WriteLine("Invalid value for parameter 'UpgradeFzf'. $($_.Exception.Message)");
            Exit 1;
        }
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

    Write-Output "Searching for an existing fzf.exe";
    $foundFzf, $fzfPath = Find-FzfPath;
    $downloadFzf = $false;
    if ($foundFzf) {
        Write-Output "Found fzf.exe @ '$($fzfPath)'";
        if ("$(& $fzfPath --version)" -match "^(?<vernum>[0-9\.]+)[ \t]+.*") {
            $existFzfVer = [Version]($Matches["vernum"]);
            Write-Output "Installed fzf.exe version is $($existFzfVer)";
        } else {
            [Console]::Error.WriteLine("Error determining version number of fzf.exe using ``fzf.exe --version``.");
            $existFzfVer = [Version]"0.0.0";
        }

        Switch ($existFzfVer) {
            [Version]"0.0.0" {
                Write-Output "Since existing fzf.exe version could not be determined, fzf.exe will be downloaded.";
                $downloadFzf = $true;
            }
            $global:FZF_VER {
                Write-Output "Existing fzf.exe version is already $($global:FZF_VER) . No download necessary.";
            }
            ({ $_ -gt $global:FZF_VER }) {
                Write-Output "Existing fzf.exe version is newer than the version @ '$($global:FZF_URL)'.";
                Write-Output "fzf will NOT be downloaded.";
            }
            default {
                if ($UpdateFzf) {
                    Write-Output "Existing fzf.exe version ($($existFzfVer)) is lower than $($global:FZF_VER) and UpgradeFzf chosen. fzf will be downloaded.";
                    $downloadFzf = $true;
                } else {
                    Write-Output "Existing fzf.exe version ($($existFzfVer)) is lower than $($global:FZF_VER) and UpgradeFzf not chosen. fzf will NOT be downloaded.";
                }
            }

        }
        Remove-Variable -Name existFzfVer -ErrorAction SilentlyContinue;
    } else {
        Write-Output "Could not find fzf.exe .";
        $downloadFzf = $true;
        $fzfPath = $global:FZF_DEFAULT_PATH;
    }
    Remove-Variable -Name UpdateFzf,foundFzf -ErrorAction SilentlyContinue;

    if ($downloadFzf) {
        if (Test-Path -Path $global:FZF_ZIP_PATH -ErrorAction SilentlyContinue) {
            Remove-Item -Path $global:FZF_ZIP_PATH -Confirm:$false -Force -ErrorAction SilentlyContinue;
        }
        Write-Output "Downloading fzf from '$($global:FZF_URL)'";
        try {
            Download-Fzf -Destination $global:FZF_ZIP_PATH -Url $global:FZF_URL;
        } catch {
            [Console]::Error.WriteLine("Error downloading fzf: $($_.Exception.Message)");
            Exit 1;
        }

        $fzfDir = Split-Path -Path $fzfPath -Parent;
        try {
            Write-Output "Performing install tasks";
            Extract-Fzf -Source $global:FZF_ZIP_PATH -DestinationDir $fzfDir;
        } catch {
            [Console]::Error.WriteLine("Error installing fzf.exe: $($_.Exception.Message)");
            Exit 2;
        }
        Remove-Variable -Name fzfDir -ErrorAction SilentlyContinue;
    }
    Remove-Variable -Name fzfPath,downloadFzf -ErrorAction SilentlyContinue;
}

$tempScriptFile = "$env:TEMP\install-fzf-$($global:FZF_VER).ps1";
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

Start-Process -FilePath pwsh.exe -ArgumentList $powershellArgs -Wait -NoNewWindow;
Remove-Item -Path $tempScriptFile -Force -Confirm:$false -ErrorAction SilentlyContinue;
