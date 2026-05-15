$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    $ssh = Get-Command ssh -ErrorAction SilentlyContinue
    if ($ssh) { Write-Output "OpenSSH: $($ssh.Source)" }
    else { Write-Output "OpenSSH: NOT FOUND" }

    # Test SSH connectivity to target
    Write-Output "Testing SSH to 10.100.100.95..."
    $proc = Start-Process -FilePath "ssh" -ArgumentList "-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=NUL","-o","BatchMode=yes","root@10.100.100.95","echo","OK" -Wait -PassThru -NoNewWindow -RedirectStandardOutput 'C:\OrkunPAM\Logs\ssh-test-out.txt' -RedirectStandardError 'C:\OrkunPAM\Logs\ssh-test-err.txt'
    Write-Output "Exit: $($proc.ExitCode)"
    Get-Content 'C:\OrkunPAM\Logs\ssh-test-out.txt' -ErrorAction SilentlyContinue
    Get-Content 'C:\OrkunPAM\Logs\ssh-test-err.txt' -ErrorAction SilentlyContinue
}
