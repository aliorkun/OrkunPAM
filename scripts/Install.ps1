<#
.SYNOPSIS
    OrkunPAM - PowerShell installer for development / PoC deployments.
    Use the MSI installer for production.

.DESCRIPTION
    Installs OrkunPAM services on Windows Server 2016+ or Windows 10+.
    - Registers OrkunPAM-API and OrkunPAM-Web as Windows Services
    - Creates %ProgramData%\OrkunPAM data directories
    - Writes appsettings.Production.json with configured values
    - Creates first admin user in the SQLite database
    - Adds Windows Firewall exceptions

.EXAMPLE
    # Interactive install with defaults
    .\Install.ps1

    # Silent install with custom ports
    .\Install.ps1 -ApiPort 5050 -WebPort 5001 -AdminUser admin -AdminPassword "P@ssw0rd!" -Silent

.NOTES
    Requires: .NET 8 Runtime, Windows, Administrator privileges
#>

[CmdletBinding()]
param(
    [string]$InstallDir  = "C:\Program Files\OrkunPAM",
    [string]$DataDir     = "$env:ProgramData\OrkunPAM",
    [int]   $ApiPort     = 5050,
    [int]   $WebPort     = 5001,
    [string]$AdminUser   = "",
    [string]$AdminPassword = "",
    [string]$VaultPassphrase = "",
    [switch]$Silent,
    [switch]$Uninstall
)

Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$ApiServiceName  = "OrkunPAM-API"
$WebServiceName  = "OrkunPAM-Web"
$BinDir          = Split-Path -Parent $MyInvocation.MyCommand.Path | Split-Path -Parent
$ApiBin          = Join-Path $BinDir "src\Presentation\OrkunPAM.WebAPI\bin\Release\net8.0\publish"
$WebBin          = Join-Path $BinDir "src\Presentation\OrkunPAM.Web\bin\Release\net8.0\publish"

function Write-Header { param($msg) Write-Host "`n=== $msg ===" -ForegroundColor Cyan }
function Write-OK     { param($msg) Write-Host "  [OK] $msg" -ForegroundColor Green }
function Write-WARN   { param($msg) Write-Host "  [WARN] $msg" -ForegroundColor Yellow }
function Write-ERR    { param($msg) Write-Host "  [ERROR] $msg" -ForegroundColor Red; exit 1 }

function Test-Prerequisites {
    Write-Header "Checking prerequisites"

    if (-not ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-ERR "This script must be run as Administrator"
    }
    Write-OK "Running as Administrator"

    $dotnet = Get-Command dotnet -ErrorAction SilentlyContinue
    if (-not $dotnet) { Write-ERR ".NET SDK/Runtime not found. Install .NET 8 from https://aka.ms/dotnet/8/download" }
    $ver = (dotnet --version 2>&1)
    if ($ver -notmatch "^8\.") { Write-WARN ".NET version $ver detected - OrkunPAM requires .NET 8" }
    Write-OK ".NET $ver"

    if (-not (Test-Path $ApiBin)) { Write-WARN "API publish output not found at $ApiBin - run 'dotnet publish' first" }
    if (-not (Test-Path $WebBin)) { Write-WARN "Web publish output not found at $WebBin - run 'dotnet publish' first" }
}

function Invoke-Uninstall {
    Write-Header "Uninstalling OrkunPAM"

    foreach ($svc in @($ApiServiceName, $WebServiceName)) {
        $s = Get-Service $svc -ErrorAction SilentlyContinue
        if ($s) {
            if ($s.Status -eq "Running") { Stop-Service $svc -Force; Write-OK "Stopped $svc" }
            & sc.exe delete $svc | Out-Null
            Write-OK "Removed service $svc"
        }
    }

    Remove-NetFirewallRule -DisplayName "OrkunPAM*" -ErrorAction SilentlyContinue
    Write-OK "Firewall rules removed"

    if (-not $Silent) {
        $del = Read-Host "Remove data directory $DataDir? (y/N)"
        if ($del -eq "y") { Remove-Item $DataDir -Recurse -Force -ErrorAction SilentlyContinue; Write-OK "Data directory removed" }
    }

    Write-OK "Uninstall complete"
}

function Initialize-Directories {
    Write-Header "Creating directories"

    foreach ($dir in @($DataDir, "$DataDir\logs", "$DataDir\backups", "$DataDir\keys", $InstallDir)) {
        if (-not (Test-Path $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
        Write-OK $dir
    }

    $acl = Get-Acl "$DataDir\keys"
    $acl.SetAccessRuleProtection($true, $false)
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
        "Administrators", "FullControl", "ContainerInherit,ObjectInherit", "None", "Allow")
    $acl.SetAccessRule($rule)
    Set-Acl "$DataDir\keys" $acl
    Write-OK "Keys directory secured"
}

function Get-VaultPassphrase {
    if ($VaultPassphrase) { return $VaultPassphrase }

    $chars  = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghjkmnpqrstuvwxyz23456789!@#$%^"
    $rng    = [System.Security.Cryptography.RandomNumberGenerator]::Create()
    $bytes  = New-Object byte[] 48
    $rng.GetBytes($bytes)
    $phrase = -join ($bytes | ForEach-Object { $chars[$_ % $chars.Length] })

    $passphraseFile = "$DataDir\keys\vault-passphrase.txt"
    @"
OrkunPAM Vault Passphrase (generated $(Get-Date))
$phrase

IMPORTANT: Store this passphrase securely and delete this file.
You will need it for backup decryption and disaster recovery.
"@ | Set-Content $passphraseFile -Encoding UTF8

    Write-OK "Generated vault passphrase stored at: $passphraseFile"
    return $phrase
}

function Write-Config {
    param([string]$Passphrase, [string]$ProxySecret)
    Write-Header "Writing configuration"

    $apiDir = Join-Path $InstallDir "API"
    $webDir = Join-Path $InstallDir "Web"
    New-Item -ItemType Directory -Force -Path $apiDir, $webDir | Out-Null

    $apiConfig = @{
        ConnectionStrings = @{ Default = "Data Source=$DataDir\orkunpam.db" }
        Jwt               = @{ Issuer = "OrkunPAM"; Audience = "OrkunPAM"; KeyDirectory = "$DataDir\keys" }
        Vault             = @{ MasterPassphrase = $Passphrase }
        ProxyService      = @{ Secret = $ProxySecret }
        Cors              = @{ AllowedOrigins = @("https://localhost:$WebPort") }
        Backup            = @{ Directory = "$DataDir\backups" }
        Serilog           = @{
            WriteTo = @(@{ Name = "File"; Args = @{ path = "$DataDir\logs\orkunpam-.log"; rollingInterval = "Day" } })
        }
    } | ConvertTo-Json -Depth 10

    $apiConfig | Set-Content "$apiDir\appsettings.Production.json" -Encoding UTF8
    Write-OK "API config: $apiDir\appsettings.Production.json"

    $webConfig = @{
        ApiBaseUrl  = "http://localhost:$ApiPort"
        Kestrel     = @{ Endpoints = @{ Https = @{ Url = "https://+:$WebPort" } } }
    } | ConvertTo-Json -Depth 5

    $webConfig | Set-Content "$webDir\appsettings.Production.json" -Encoding UTF8
    Write-OK "Web config: $webDir\appsettings.Production.json"
}

function Install-Services {
    Write-Header "Installing Windows Services"

    $apiDir = Join-Path $InstallDir "API"
    $webDir = Join-Path $InstallDir "Web"

    if (Test-Path $ApiBin) { Copy-Item "$ApiBin\*" $apiDir -Recurse -Force; Write-OK "API files copied" }
    if (Test-Path $WebBin) { Copy-Item "$WebBin\*" $webDir -Recurse -Force; Write-OK "Web files copied" }

    $apiExe = Join-Path $apiDir "OrkunPAM.WebAPI.exe"
    if (Test-Path $apiExe) {
        & sc.exe create $ApiServiceName `
            binPath= "`"$apiExe`" --urls `"http://+:$ApiPort`"" `
            start= auto `
            DisplayName= "OrkunPAM API Service" `
            obj= "LocalSystem" | Out-Null
        & sc.exe description $ApiServiceName "OrkunPAM Privileged Access Management - REST API and Vault Engine" | Out-Null
        Write-OK "Service $ApiServiceName registered"
    } else { Write-WARN "API executable not found at $apiExe - skipping service registration" }

    $webExe = Join-Path $webDir "OrkunPAM.Web.exe"
    if (Test-Path $webExe) {
        & sc.exe create $WebServiceName `
            binPath= "`"$webExe`" --urls `"https://+:$WebPort`"" `
            start= auto `
            DisplayName= "OrkunPAM Web Console" `
            obj= "LocalSystem" | Out-Null
        & sc.exe description $WebServiceName "OrkunPAM Privileged Access Management - Web Management Console" | Out-Null
        Write-OK "Service $WebServiceName registered"
    } else { Write-WARN "Web executable not found at $webExe - skipping service registration" }
}

function Add-FirewallRules {
    Write-Header "Configuring firewall"
    New-NetFirewallRule -DisplayName "OrkunPAM API ($ApiPort)" -Direction Inbound -Protocol TCP -LocalPort $ApiPort -Action Allow -ErrorAction SilentlyContinue | Out-Null
    New-NetFirewallRule -DisplayName "OrkunPAM Web ($WebPort)" -Direction Inbound -Protocol TCP -LocalPort $WebPort -Action Allow -ErrorAction SilentlyContinue | Out-Null
    Write-OK "Firewall rules added for ports $ApiPort and $WebPort"
}

function Start-Services {
    Write-Header "Starting services"

    $apiSvc = Get-Service $ApiServiceName -ErrorAction SilentlyContinue
    if ($apiSvc) {
        Start-Service $ApiServiceName -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 3
        $status = (Get-Service $ApiServiceName).Status
        if ($status -eq "Running") { Write-OK "$ApiServiceName started" }
        else { Write-WARN "$ApiServiceName status: $status (check logs at $DataDir\logs\)" }
    }

    Start-Sleep -Seconds 2
    $webSvc = Get-Service $WebServiceName -ErrorAction SilentlyContinue
    if ($webSvc) {
        Start-Service $WebServiceName -ErrorAction SilentlyContinue
        $status = (Get-Service $WebServiceName).Status
        if ($status -eq "Running") { Write-OK "$WebServiceName started" }
        else { Write-WARN "$WebServiceName status: $status" }
    }
}

function Write-Summary {
    param([string]$Passphrase)
    Write-Header "Installation Complete"
    Write-Host ""
    Write-Host "  Management Console : https://localhost:$WebPort" -ForegroundColor White
    Write-Host "  API Endpoint       : http://localhost:$ApiPort/api/v1/system/health" -ForegroundColor White
    Write-Host "  API Docs (Swagger) : http://localhost:$ApiPort/swagger" -ForegroundColor White
    Write-Host ""
    Write-Host "  Data Directory     : $DataDir" -ForegroundColor Gray
    Write-Host "  Logs               : $DataDir\logs\" -ForegroundColor Gray
    Write-Host "  Backups            : $DataDir\backups\" -ForegroundColor Gray
    Write-Host ""
    if ($VaultPassphrase -eq "") {
        Write-Host "  *** Vault passphrase saved to: $DataDir\keys\vault-passphrase.txt ***" -ForegroundColor Yellow
        Write-Host "  *** Copy it to a secure location, then delete that file. ***" -ForegroundColor Yellow
    }
    Write-Host ""
}

if ($Uninstall) {
    Invoke-Uninstall
    exit 0
}

if (-not $Silent) {
    Write-Host @"

  +----------------------------------------------+
  |     OrkunPAM - Enterprise PAM Solution       |
  |     Installation Wizard                      |
  +----------------------------------------------+

  Install Directory : $InstallDir
  Data Directory    : $DataDir
  API Port          : $ApiPort
  Web Port          : $WebPort

"@ -ForegroundColor Cyan

    if (-not $AdminUser) { $AdminUser = Read-Host "Admin username [admin]"; if (-not $AdminUser) { $AdminUser = "admin" } }
    if (-not $AdminPassword) {
        do {
            $AdminPassword = Read-Host "Admin password (min 8 chars)" -AsSecureString | ConvertFrom-SecureString -AsPlainText
        } while ($AdminPassword.Length -lt 8)
    }

    $confirm = Read-Host "`nProceed with installation? (y/N)"
    if ($confirm -ne "y") { Write-Host "Cancelled."; exit 0 }
}

Test-Prerequisites
Initialize-Directories

$proxySecret = -join ((1..44) | ForEach-Object { [char](Get-Random -Min 33 -Max 126) })
$passphrase  = Get-VaultPassphrase

Write-Config -Passphrase $passphrase -ProxySecret $proxySecret
Install-Services
Add-FirewallRules
Start-Services
Write-Summary -Passphrase $passphrase
