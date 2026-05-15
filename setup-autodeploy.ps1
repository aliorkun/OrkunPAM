$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    # Step 1: Clone repo
    Write-Output "Cloning repo..."
    if (-not (Test-Path 'C:\OrkunPAM\Deploy\Source')) {
        New-Item -ItemType Directory -Path 'C:\OrkunPAM\Deploy' -Force | Out-Null
        git clone https://github.com/aliorkun/OrkunPAM.git 'C:\OrkunPAM\Deploy\Source' 2>&1
    } else {
        Set-Location 'C:\OrkunPAM\Deploy\Source'
        git pull --rebase 2>&1
    }
    Write-Output "Repo ready."

    # Step 2: Create deploy script on server
    $script = @'
@echo off
cd /d C:\OrkunPAM\Deploy\Source

REM Pull latest
git pull --rebase > C:\OrkunPAM\Logs\deploy.log 2>&1
if %ERRORLEVEL% NEQ 0 (
    echo [%date% %time%] Git pull failed >> C:\OrkunPAM\Logs\deploy-history.log
    exit /b 1
)

REM Get current and deployed commit
for /f %%i in ('git rev-parse --short HEAD') do set NEWCOMMIT=%%i
if exist C:\OrkunPAM\Deploy\last-commit.txt (
    set /p OLDCOMMIT=<C:\OrkunPAM\Deploy\last-commit.txt
) else (
    set OLDCOMMIT=none
)

REM Skip if no changes
if "%NEWCOMMIT%"=="%OLDCOMMIT%" (
    echo [%date% %time%] No changes (%NEWCOMMIT%) >> C:\OrkunPAM\Logs\deploy-history.log
    exit /b 0
)

echo [%date% %time%] Deploying %OLDCOMMIT% -> %NEWCOMMIT% >> C:\OrkunPAM\Logs\deploy-history.log

REM Publish all components
dotnet publish src/Presentation/OrkunPAM.WebAPI/OrkunPAM.WebAPI.csproj -c Release -o C:\OrkunPAM\WebAPI --self-contained false >> C:\OrkunPAM\Logs\deploy.log 2>&1
dotnet publish src/Presentation/OrkunPAM.Web/OrkunPAM.Web.csproj -c Release -o C:\OrkunPAM\Web --self-contained false >> C:\OrkunPAM\Logs\deploy.log 2>&1
dotnet publish src/Proxy/OrkunPAM.SshProxy/OrkunPAM.SshProxy.csproj -c Release -o C:\OrkunPAM\SshProxy --self-contained false >> C:\OrkunPAM\Logs\deploy.log 2>&1

REM Restore configs (publish overwrites them)
echo {"PamApi":{"BaseUrl":"http://localhost:5000"},"Urls":"http://0.0.0.0:5010"} > C:\OrkunPAM\Web\appsettings.json
echo {"PamApi":{"BaseUrl":"http://localhost:5000","ProxySecret":"OrkunPAM-ProxySecret-2026-VeryLongKey!"},"SshProxy":{"ListenPort":2222,"RecordingPath":"C:\\OrkunPAM\\Recordings\\SSH","IdleTimeoutMinutes":30}} > C:\OrkunPAM\SshProxy\appsettings.json

REM Restart services
schtasks /End /TN "OrkunPAM-WebAPI" >nul 2>&1
schtasks /End /TN "OrkunPAM-Web" >nul 2>&1
schtasks /End /TN "OrkunPAM-SshProxy" >nul 2>&1
timeout /t 3 /nobreak >nul
schtasks /Run /TN "OrkunPAM-WebAPI" >nul 2>&1
schtasks /Run /TN "OrkunPAM-Web" >nul 2>&1
schtasks /Run /TN "OrkunPAM-SshProxy" >nul 2>&1

REM Save deployed commit
echo %NEWCOMMIT% > C:\OrkunPAM\Deploy\last-commit.txt
echo [%date% %time%] Deploy complete: %NEWCOMMIT% >> C:\OrkunPAM\Logs\deploy-history.log
'@
    Set-Content -Path 'C:\OrkunPAM\Deploy\auto-deploy.bat' -Value $script
    Write-Output "Deploy script created."

    # Step 3: Run first deploy now
    Write-Output "Running initial deploy..."
    $proc = Start-Process -FilePath 'C:\OrkunPAM\Deploy\auto-deploy.bat' -Wait -PassThru -NoNewWindow
    Write-Output "Deploy exit: $($proc.ExitCode)"

    # Step 4: Create scheduled task - every 30 minutes
    Unregister-ScheduledTask -TaskName "OrkunPAM-AutoDeploy" -Confirm:$false -ErrorAction SilentlyContinue

    $action = New-ScheduledTaskAction -Execute 'C:\OrkunPAM\Deploy\auto-deploy.bat'
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes 30)
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -ExecutionTimeLimit (New-TimeSpan -Minutes 15) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries

    Register-ScheduledTask -TaskName "OrkunPAM-AutoDeploy" -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
    Write-Output "Auto-deploy scheduled (every 30 min)."

    # Verify
    Start-Sleep 8
    foreach ($p in @(@{N="WebAPI";P=5000}, @{N="Web";P=5010}, @{N="SSH";P=2222})) {
        $l = Get-NetTCPConnection -LocalPort $p.P -ErrorAction SilentlyContinue
        Write-Output "  $($p.N) :$($p.P) = $(if ($l) {'OK'} else {'STARTING...'})"
    }

    if (Test-Path 'C:\OrkunPAM\Logs\deploy-history.log') {
        Write-Output "`n=== Deploy History ==="
        Get-Content 'C:\OrkunPAM\Logs\deploy-history.log' -Tail 3
    }
}
