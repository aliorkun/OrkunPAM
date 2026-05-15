$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    New-Item -ItemType Directory -Path 'C:\OrkunPAM\Tools' -Force | Out-Null

    Write-Output "Downloading plink.exe..."
    Invoke-WebRequest -Uri 'https://the.earth.li/~sgtatham/putty/latest/w64/plink.exe' -OutFile 'C:\OrkunPAM\Tools\plink.exe' -UseBasicParsing
    Write-Output "Downloaded: $(Test-Path 'C:\OrkunPAM\Tools\plink.exe')"

    # Test plink
    $proc = Start-Process -FilePath 'C:\OrkunPAM\Tools\plink.exe' -ArgumentList '-ssh','-P','22','-l','root','-pw','root','10.100.100.95','-no-antispoof','-batch','echo OK' -Wait -PassThru -NoNewWindow -RedirectStandardOutput 'C:\OrkunPAM\Logs\plink-test-out.txt' -RedirectStandardError 'C:\OrkunPAM\Logs\plink-test-err.txt'
    Write-Output "Plink exit: $($proc.ExitCode)"
    Get-Content 'C:\OrkunPAM\Logs\plink-test-out.txt' -ErrorAction SilentlyContinue
    Get-Content 'C:\OrkunPAM\Logs\plink-test-err.txt' -ErrorAction SilentlyContinue
}
