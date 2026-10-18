param([int]$ControlPort = 18777)

$ErrorActionPreference = 'Stop'
$base = "http://127.0.0.1:$ControlPort"
$challenge = Invoke-RestMethod -Uri "$base/challenge" -Method Get
if ($challenge.seconds_remaining -le 0) { throw 'Pairing session expired. Restart Terminal 1 to open a fresh session.' }
Write-Host "Broker code: $($challenge.code)   Device: $($challenge.device_id)   Time remaining: $($challenge.seconds_remaining)s"
$code = Read-Host 'Read the six-digit code on the board and enter it here'
if ($code -cne $challenge.code) { throw 'Codes differ. Nothing was sent to the board; restart Terminal 1 for a fresh session.' }
$body = @{ code = $challenge.code; confirmation = $challenge.confirmation } | ConvertTo-Json -Compress
$result = Invoke-RestMethod -Uri "$base/confirm" -Method Post -ContentType 'application/json' -Body $body
if (-not $result.ok) { throw 'The enrollment broker did not confirm enrollment.' }
Write-Host "Enrolled device $($result.device_id); pairing file: $($result.pairing_file)"
Write-Host "Gateway instance: $($result.instance_id)"
