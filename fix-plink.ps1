$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    # Accept host key by running plink with echo y piped
    Write-Output "Accepting host key..."
    $proc = Start-Process -FilePath 'cmd.exe' -ArgumentList '/c','echo','y','|','C:\OrkunPAM\Tools\plink.exe','-ssh','-P','22','-l','root','-pw','root','10.100.100.95','-no-antispoof','echo','OK' -Wait -PassThru -NoNewWindow -RedirectStandardOutput 'C:\OrkunPAM\Logs\plink-test-out.txt' -RedirectStandardError 'C:\OrkunPAM\Logs\plink-test-err.txt'
    Write-Output "Exit: $($proc.ExitCode)"
    Get-Content 'C:\OrkunPAM\Logs\plink-test-out.txt' -ErrorAction SilentlyContinue
    Get-Content 'C:\OrkunPAM\Logs\plink-test-err.txt' -ErrorAction SilentlyContinue

    # Now test batch mode
    Write-Output "`nBatch test..."
    $proc2 = Start-Process -FilePath 'C:\OrkunPAM\Tools\plink.exe' -ArgumentList '-ssh','-P','22','-l','root','-pw','root','10.100.100.95','-no-antispoof','-batch','echo','HelloFromPAM' -Wait -PassThru -NoNewWindow -RedirectStandardOutput 'C:\OrkunPAM\Logs\plink-test2-out.txt' -RedirectStandardError 'C:\OrkunPAM\Logs\plink-test2-err.txt'
    Write-Output "Exit: $($proc2.ExitCode)"
    Get-Content 'C:\OrkunPAM\Logs\plink-test2-out.txt' -ErrorAction SilentlyContinue
    Get-Content 'C:\OrkunPAM\Logs\plink-test2-err.txt' -ErrorAction SilentlyContinue
}
