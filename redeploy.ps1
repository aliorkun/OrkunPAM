$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    Stop-ScheduledTask -TaskName "OrkunPAM-Web" -ErrorAction SilentlyContinue
    Start-Sleep 3
    $proc = Get-NetTCPConnection -LocalPort 5010 -ErrorAction SilentlyContinue
    if ($proc) { Stop-Process -Id $proc.OwningProcess -Force -ErrorAction SilentlyContinue }
    Start-Sleep 1
}

$session = New-PSSession -ComputerName 10.1.1.233 -Credential $cred
Copy-Item -Path "C:\Users\KRON\Downloads\Fatura\backpack\MronPAM\publish\Web\*" -Destination "C:\OrkunPAM\Web" -ToSession $session -Recurse -Force
Remove-PSSession $session
Write-Output "Files copied."

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    $config = @"
{
  "PamApi": {
    "BaseUrl": "http://localhost:5000"
  },
  "Urls": "http://0.0.0.0:5010"
}
"@
    Set-Content -Path 'C:\OrkunPAM\Web\appsettings.json' -Value $config
    Start-ScheduledTask -TaskName "OrkunPAM-Web"
    Start-Sleep 5
    $l = Get-NetTCPConnection -LocalPort 5010 -ErrorAction SilentlyContinue
    if ($l) { Write-Output "Web UI: RUNNING" }
    else { Write-Output "Web UI: FAILED" }
}
