#!powershell
#Requires -RunAsAdministrator

# If for some reason winget is not installed, install it

$GITHUB_RELEASES_URL = "https://api.github.com/repos/microsoft/winget-cli/releases/latest"

$DOWNLOAD_DEST_DIR = `
    New-TemporaryFile -EA Stop `
    | %{
        Remove-Item -Force -Path $_.FullName -ErrorAction SilentlyContinue
        New-Item -ItemType Directory -Path $_.FullName -ErrorAction SilentlyContinue
    }

if (Get-Command -Name "winget.exe" -ErrorAction SilentlyContinue) {
    Write-Output "Winget is already installed."
    return
}

$osBuildNumber, $osProductType, $osArch, $osVersion = `
    Get-CimInstance -ClassName Win32_OperatingSystem -Property BuildNumber,ProductType,OSArchitecture,Version `
    | % {
        if ($_.ProductType -eq 1) {
            $osProductType = "Client"
        }
        else {
            $osProductType = "Server"
        }
        $osArch = `
            switch ($_.OSArchitecture) {
                "32-bit" { "x86" }
                "64-bit" { "x64" }
                "ARM 64-bit Processor" { "arm64" }
                default { throw "Unsupported architecture: ${_}" }
            }
        $_.BuildNumber, $osProductType, $osArch, [Version]$_.Version
        Remove-Variable -Name osProductType, osArch -ErrorAction SilentlyContinue
    }

if ($osVersion.Major -lt 10) {
    throw "Winget requires Windows 10 (version 1809 or later), Windows 11, or Windows Server 2022 or later."
}
elseif ($osProductType -eq "Server" -and $osBuildNumber -lt 20348) {
    throw "Winget requires Windows Server 2022 or later."
}
elseif ($osProductType -eq "Client" -and $osVersion.Major -eq 10 -and $osBuildNumber -lt 17763) {
    throw "Winget requires Windows 10 version 1809 or later."
}
Remove-Variable -Name osBuildNumber, osProductType, osVersion -ErrorAction SilentlyContinue

try {
    Invoke-RestMethod -Uri $GITHUB_RELEASES_URL -EA Stop -Headers @{ "User-Agent" = "PWSH Winget Installer" } `
        | Select-Object -ExpandProperty assets `
        | ? { $_.name -like "*.msixbundle" -or $_.name -like "*Dependencies.zip" } `
        | % {
            $downloadUrl = $_.browser_download_url
            $destPath = Join-Path -Path $DOWNLOAD_DEST_DIR -ChildPath $_.name
            # Invoke-WebRequest is very slow, so use BITS Transfer Service instead.
            Start-BitsTransfer -Source $downloadUrl -Destination $destPath -TransferType Download -Confirm:$false -Priority Foreground -ErrorAction Stop
            if (-not (Test-Path $destPath -EA SilentlyContinue)) {
                throw "Failed to download '${downloadUrl}'."
            }
        }
    $dependenciesDir = Join-Path -Path $DOWNLOAD_DEST_DIR -ChildPath "Dependencies"
    mkdir -Path $dependenciesDir -ErrorAction SilentlyContinue | Out-Null
    dir -Path $DOWNLOAD_DEST_DIR -File -Filter "*Dependencies.zip" `
        | % { tar -xf $_.FullName -C $dependenciesDir }
    
    $dependencies = @()
    $dependencies += `
        dir -Path $dependenciesDir -Recurse -File `
        | ? { $_.FullName -match "\\${osArch}\\" -and $_.Extension -match "(msixbundle|appx)" } `
        | % {
            $_.BaseName -match '^([^_]+)_([^_]+)_.*' | Out-Null
            [PSCustomObject]@{
                Name = $Matches[1]
                Version = [Version]$Matches[2]
                Path = $_.FullName
            }
        } `$m.Groups[1].Value
        | ? { -not (Get-AppxPackage -Name $_.Name -ErrorAction SilentlyContinue) } `
        | % { $_.Path }

    Remove-Variable -Name dependenciesDir -ErrorAction SilentlyContinue

    $wingetMsixBundle = `
        dir -Path $DOWNLOAD_DEST_DIR -File -Filter "*DesktopAppInstaller*.msixbundle" `
        | Select-Object -First 1
    if (-not $wingetMsixBundle) {
        throw "Could not find an MSIXBUNDLE asset after downloading the latest release."
    }

    if ($dependencies.Count -gt 0) {
        $dependencies `
            | % { Add-AppxPackage -Path $_ -Confirm:$false -ErrorAction Stop }
    }
    Add-AppxPackage -Path $wingetMsixBundle -Confirm:$false -ErrorAction Stop

}
finally {
    # Remove the temporary directory.
    Remove-Item -Recurse -Force -Confirm:$false -Path $DOWNLOAD_DEST_DIR -ErrorAction SilentlyContinue
}
