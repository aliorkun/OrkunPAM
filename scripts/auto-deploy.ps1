# OrkunPAM Auto-Deploy Script
# Called by GitHub Actions or manually
# Pulls latest code, publishes, deploys to target server

param(
    [string]$Server = "10.1.1.233",
    [string]$User = "Administrator",
    [string]$Pass,
    [string]$SourceDir = "C:\OrkunPAM\Deploy\Source",
    [string]$TargetDir = "C:\OrkunPAM"
)

$ErrorActionPreference = "Stop"

$cred = New-Object PSCredential($User, (ConvertTo-SecureString $Pass -AsPlainText -Force))

Write-Output "=== OrkunPAM Auto-Deploy ==="
Write-Output "Server: $Server"
Write-Output "Time: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"

# Step 1: Git pull on server
Write-Output "`n--- Step 1: Git Pull ---"
Invoke-Command -ComputerName $Server -Credential $cred -ScriptBlock {
    param($src)
    if (-not (Test-Path $src)) {
        git clone https://github.com/aliorkun/OrkunPAM.git $src
    } else {
        Set-Location $src
        git pull --rebase
    }
    Write-Output "Latest commit: $(git -C $src log --oneline -1)"
} -ArgumentList $SourceDir

# Step 2: Publish on server
Write-Output "`n--- Step 2: Publish ---"
Invoke-Command -ComputerName $Server -Credential $cred -ScriptBlock {
    param($src, $tgt)
    Set-Location $src

    $components = @(
        @{Name="WebAPI"; Proj="src/Presentation/OrkunPAM.WebAPI/OrkunPAM.WebAPI.csproj"},
        @{Name="Web"; Proj="src/Presentation/OrkunPAM.Web/OrkunPAM.Web.csproj"},
        @{Name="SshProxy"; Proj="src/Proxy/OrkunPAM.SshProxy/OrkunPAM.SshProxy.csproj"},
        @{Name="RdpProxy"; Proj="src/Proxy/OrkunPAM.RdpProxy/OrkunPAM.RdpProxy.csproj"},
        @{Name="HttpProxy"; Proj="src/Proxy/OrkunPAM.HttpProxy/OrkunPAM.HttpProxy.csproj"}
    )

    foreach ($c in $components) {
        $outDir = "$tgt\$($c.Name)"
        Write-Output "Publishing $($c.Name)..."
        dotnet publish $c.Proj -c Release -o $outDir --self-contained false 2>&1 | Select-Object -Last 1
    }
    Write-Output "Publish complete."
} -ArgumentList $SourceDir, $TargetDir

# Step 3: Restart services
Write-Output "`n--- Step 3: Restart Services ---"
Invoke-Command -ComputerName $Server -Credential $cred -ScriptBlock {
    $tasks = @("OrkunPAM-WebAPI", "OrkunPAM-Web", "OrkunPAM-SshProxy")
    foreach ($t in $tasks) {
        $task = Get-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
        if ($task) {
            Stop-ScheduledTask -TaskName $t -ErrorAction SilentlyContinue
            Start-Sleep 2
            Start-ScheduledTask -TaskName $t
            Write-Output "$t restarted."
        }
    }

    Start-Sleep 5

    foreach ($p in @(@{N="WebAPI";P=5000}, @{N="Web";P=5010}, @{N="SSH";P=2222})) {
        $l = Get-NetTCPConnection -LocalPort $p.P -ErrorAction SilentlyContinue
        Write-Output "  $($p.N) :$($p.P) = $(if ($l) {'OK'} else {'FAIL'})"
    }
}

Write-Output "`n=== Deploy Complete ==="
