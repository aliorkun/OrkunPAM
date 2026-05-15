$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    Write-Output "=== Services ==="
    foreach ($p in @(@{N="WebAPI";P=5000}, @{N="Web UI";P=5010}, @{N="SSH Proxy";P=2222})) {
        $l = Get-NetTCPConnection -LocalPort $p.P -ErrorAction SilentlyContinue
        Write-Output "  $($p.N) :$($p.P) = $(if ($l) {'RUNNING'} else {'DOWN'})"
    }

    Write-Output "`n=== Web Log (last 10) ==="
    $log = Get-ChildItem 'C:\OrkunPAM\Logs\OrkunPAM-Web*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($log) { Get-Content $log.FullName -Tail 10 }

    Write-Output "`n=== SQL Server ==="
    (Get-Service MSSQLSERVER -ErrorAction SilentlyContinue).Status
}
