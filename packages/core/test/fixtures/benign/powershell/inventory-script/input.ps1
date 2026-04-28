# Pure local inventory — no network, no IEX, no encoded blobs.
$processes = Get-Process | Where-Object { $_.CPU -gt 10 } | Select-Object Name, Id, CPU
$processes | Export-Csv -Path "./inventory.csv" -NoTypeInformation
Write-Host "Wrote inventory.csv"
