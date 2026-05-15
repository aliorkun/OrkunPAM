$cred = New-Object PSCredential('Administrator',(ConvertTo-SecureString 'EF0P9Qnhf7RIi1' -AsPlainText -Force))

Invoke-Command -ComputerName 10.1.1.233 -Credential $cred -ScriptBlock {
    $connStr = "Server=localhost;Database=OrkunPAM;User Id=sa;Password=OrkunPAM2026!;TrustServerCertificate=True"
    $conn = New-Object System.Data.SqlClient.SqlConnection($connStr)
    $conn.Open()

    # Link credentials to device via DeviceCredentials table
    $deviceId = "2baac716-da8d-4591-a223-120dc85bf67a"
    $credIds = @("74c45ec5-4822-4804-a76f-c2f491b893bb", "8d09dc51-f604-47aa-a238-40c62258143f", "f0124920-7a96-473b-9b75-104013aab3f1")

    # Check DeviceCredentials schema
    $cmd = $conn.CreateCommand()
    $cmd.CommandText = "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_NAME='DeviceCredentials' ORDER BY ORDINAL_POSITION"
    $reader = $cmd.ExecuteReader()
    $cols = @()
    while ($reader.Read()) { $cols += $reader.GetString(0) }
    $reader.Close()
    Write-Output "DeviceCredentials columns: $($cols -join ', ')"

    foreach ($cId in $credIds) {
        $check = $conn.CreateCommand()
        $check.CommandText = "SELECT COUNT(*) FROM DeviceCredentials WHERE DeviceId='$deviceId' AND CredentialId='$cId'"
        $exists = $check.ExecuteScalar()
        if ($exists -eq 0) {
            $ins = $conn.CreateCommand()
            $ins.CommandText = "INSERT INTO DeviceCredentials (DeviceId, CredentialId, IsPrimary, Purpose) VALUES ('$deviceId', '$cId', 0, 0)"
            $ins.ExecuteNonQuery() | Out-Null
            Write-Output "Linked credential $cId to device"
        }
    }

    $conn.Close()

    # Check reveal endpoint
    $login = Invoke-WebRequest -Uri 'http://localhost:5000/api/v1/auth/login' -Method POST -Body '{"username":"admin","password":"P@ssw0rd2026!"}' -ContentType 'application/json' -UseBasicParsing
    $token = ($login.Content | ConvertFrom-Json).data.accessToken

    # Try different reveal paths
    $paths = @(
        "/api/v1/vault/credentials/74c45ec5-4822-4804-a76f-c2f491b893bb/reveal",
        "/api/v1/vault/credentials/74c45ec5-4822-4804-a76f-c2f491b893bb/checkout",
        "/api/v1/vault/74c45ec5-4822-4804-a76f-c2f491b893bb/reveal"
    )
    foreach ($path in $paths) {
        try {
            $r = Invoke-WebRequest -Uri "http://localhost:5000$path" -Headers @{Authorization="Bearer $token"} -UseBasicParsing
            Write-Output "GET $path : $($r.StatusCode)"
        } catch {
            $s = $_.Exception.Response.StatusCode.value__
            Write-Output "GET $path : $s"
        }
    }
}
