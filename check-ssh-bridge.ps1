$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    # Check SSH proxy log
    $logs = Get-ChildItem 'C:\OrkunPAM\Logs\' -Filter 'OrkunPAM-SshProxy*' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($logs -and $logs.Length -gt 0) {
        Write-Output "=== SSH Proxy Log (last 20) ==="
        Get-Content $logs.FullName -Tail 20
    }

    # Check Web log for bridge
    $webLogs = Get-ChildItem 'C:\OrkunPAM\Logs\' -Filter 'OrkunPAM-Web*' | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($webLogs -and $webLogs.Length -gt 0) {
        Write-Output "`n=== Web Log (last 15) ==="
        Get-Content $webLogs.FullName -Tail 15
    }

    # Check SSH proxy port
    $l = Get-NetTCPConnection -LocalPort 2222 -ErrorAction SilentlyContinue
    Write-Output "`nSSH Proxy port 2222: $(if ($l) { 'LISTENING' } else { 'DOWN' })"
}
