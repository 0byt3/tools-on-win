The repo contains powershell scripts for the purposes of an easy copy and paste way of getting various posix tools installed as well as PowerShell core and OpenSSH on Windows.

Unfortunately as new versions are release this repo will need to be updated to reference the downloads of the newer release(s).

! Last update: June 2024

### PowerShell Core w/ OpenSSH Server
Installs PowerShell core, openssh server and enables PowerShell remoting over SSH

``` powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13;

[System.Net.WebClient]::new().DownloadString('https://github.com/0byt3/tools-on-win/raw/main/pwsh-over-ssh.ps1') | iex
```

### Sysinternals Tools
Downloads the Sysinternals Suite from Microsoft and extracts it to %ProgramFiles%\Sysinternals. Afterward %ProgramFiles%\Sysinternals is added to the system %PATH% variable.
```powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13;

[System.Net.WebClient]::new().DownloadString('https://github.com/0byt3/tools-on-win/raw/main/install-sysinternals.ps1') | iex
```

### MSYS2 (Includes sed, awk, ...)
Downloads and installs MSYS2 environment for running posix commands in Windows. MSYS2 doesn't install git or coreutils by default. This script will install those packages as well.
```powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13;

[System.Net.WebClient]::new().DownloadString('https://github.com/0byt3/tools-on-win/raw/main/msys2-plus-tools.ps1') | iex
```

### FZF.exe
Downloads the fzf.exe utility from github releases and places fzf.exe in %windir% (usually C:\Windows).
```powershell
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls11 -bor [System.Net.SecurityProtocolType]::Tls12 -bor [System.Net.SecurityProtocolType]::Tls13;

[System.Net.WebClient]::new().DownloadString('https://github.com/0byt3/tools-on-win/raw/main/install-fzf.ps1') | iex
```
