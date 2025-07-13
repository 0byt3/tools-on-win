#!powershell
#Requires -RunAsAdministrator

if (Get-Module -Name "Microsoft.WinGet.Client" -ListAvailable -ErrorAction SilentlyContinue) {
    Write-Output "Winget is already installed."
    return
}

$osBuildNumber, $osProductType, $osVersion = `
    Get-CimInstance -ClassName Win32_OperatingSystem -Property BuildNumber,ProductType,Version `
    | Select-Object -Property `
        BuildNumber,
        @{ Name="ProductType"; Expression={if($_.ProductType -eq 1) {"Client"} else {"Server"}} },
        @{ Name="Version"; Expression={[Version]$_.Version} } `
    | % { $_.BuildNumber, $_.ProductType, $_.Version }

Write-Host "Operating System: $($osVersion.ToString())" -ForegroundColor Cyan
Write-Host "OS Product Type: ${osProductType}" -ForegroundColor Cyan
Write-Host "OS Build Number: ${osBuildNumber}" -ForegroundColor Cyan

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

Install-Module -Name Microsoft.WinGet.Client -Force -ErrorAction Stop