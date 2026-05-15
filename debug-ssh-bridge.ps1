$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    # Check web log for SSH bridge errors
    $log = Get-ChildItem 'C:\OrkunPAM\Logs\OrkunPAM-Web*' -ErrorAction SilentlyContinue | Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if ($log) {
        $content = Get-Content $log.FullName -Tail 30
        $sshLines = $content | Where-Object { $_ -match 'SSH|ssh|plink|bridge|error|Error' }
        if ($sshLines) {
            Write-Output "=== SSH Bridge Log ==="
            $sshLines
        } else {
            Write-Output "No SSH bridge log entries found"
            Write-Output "Last 10 lines:"
            $content | Select-Object -Last 10
        }
    }

    # Test the API calls the bridge makes
    $login = Invoke-WebRequest -Uri 'http://localhost:5000/api/v1/auth/login' -Method POST -Body '{"username":"admin","password":"P@ssw0rd2026!"}' -ContentType 'application/json' -UseBasicParsing
    $token = ($login.Content | ConvertFrom-Json).data.accessToken

    # Get device
    $deviceId = "2baac716-da8d-4591-a223-120dc85bf67a"
    $dr = Invoke-WebRequest -Uri "http://localhost:5000/api/v1/devices/$deviceId" -Headers @{Authorization="Bearer $token"} -UseBasicParsing
    Write-Output "`n=== Device ==="
    Write-Output $dr.Content

    # Get credentials for device
    $cr = Invoke-WebRequest -Uri "http://localhost:5000/api/v1/vault/credentials?deviceId=$deviceId&pageSize=10" -Headers @{Authorization="Bearer $token"} -UseBasicParsing
    Write-Output "`n=== Credentials ==="
    Write-Output $cr.Content

    # Try reveal
    $credId = "74c45ec5-4822-4804-a76f-c2f491b893bb"
    try {
        $rv = Invoke-WebRequest -Uri "http://localhost:5000/api/v1/vault/credentials/$credId/reveal" -Headers @{Authorization="Bearer $token"} -UseBasicParsing
        Write-Output "`n=== Reveal ==="
        Write-Output $rv.Content
    } catch {
        $status = $_.Exception.Response.StatusCode.value__
        $sr = New-Object System.IO.StreamReader($_.Exception.Response.GetResponseStream())
        Write-Output "Reveal error ($status): $($sr.ReadToEnd())"
    }
}
