param(
    [string]$Board = '192.168.219.225',
    [string]$Workspace = '0f08ec6b-562f-4a09-b4fe-cfbc881d0ee6',
    [string]$DeviceId = 'esp32-f2324aa7',
    [string]$PairingFile = "$HOME\.masqai\device-esp32-f2324aa7.pair",
    [int]$ControlPort = 18777
)

$ErrorActionPreference = 'Stop'
$root = Split-Path -Parent $PSScriptRoot
Set-Location -LiteralPath $root

Write-Host 'Opening the owner-approved one-time enrollment window over OTA...'
python -m scripts.open_lan_enrollment
if ($LASTEXITCODE -ne 0) { throw 'Could not open the board enrollment window.' }

Write-Host 'Starting enrollment broker. Compare its fresh code with the board display.'
Write-Host 'Keep this terminal open. The management credential is read only after confirmation.'
python -m scripts.enroll_lan_device --board $Board --workspace $Workspace --device-id $DeviceId --control-port $ControlPort --pairing-file $PairingFile
if ($LASTEXITCODE -ne 0) { throw 'LAN enrollment failed; inspect the reported error before retrying.' }
