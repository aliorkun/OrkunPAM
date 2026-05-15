$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    # Use -hostkey to skip cache
    $hostkey = 'SHA256:l1KNEEXPxUUVne/UmysEdRMoTbtZT9hPOLkxufzCXP0'

    $proc = Start-Process -FilePath 'C:\OrkunPAM\Tools\plink.exe' -ArgumentList '-ssh','-P','22','-l','root','-pw','root','10.100.100.95','-hostkey',$hostkey,'-batch','echo','HelloFromPAM' -Wait -PassThru -NoNewWindow -RedirectStandardOutput 'C:\OrkunPAM\Logs\plink-ok.txt' -RedirectStandardError 'C:\OrkunPAM\Logs\plink-err.txt'
    Write-Output "Exit: $($proc.ExitCode)"
    Get-Content 'C:\OrkunPAM\Logs\plink-ok.txt' -ErrorAction SilentlyContinue
    Get-Content 'C:\OrkunPAM\Logs\plink-err.txt' -ErrorAction SilentlyContinue
}
