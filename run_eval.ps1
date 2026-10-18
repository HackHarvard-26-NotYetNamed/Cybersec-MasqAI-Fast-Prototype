<#
.SYNOPSIS
    One-kick MasqAI eval. Opens the Eval GUI, or runs a preset / config headless.

.EXAMPLE
    .\run_eval.ps1                                   # open the GUI (configure everything, press Start)
    .\run_eval.ps1 -Config selftest                  # headless, a preset from eval/presets/
    .\run_eval.ps1 -Config my-run.json -Runs 5 -Cases uc2-db-path,uc3-secret-roundtrip -Publish

The campaign starts and stops its own relay, one MasqAI gateway per masqai condition and (self-test)
the fake models. Results: eval/out/campaigns/<id>/.
#>
param (
    [string]$Config = "",
    [int]$Runs = 0,
    [string]$Cases = "",
    [int]$Concurrency = 0,
    [switch]$Publish,
    [int]$Port = 8790
)
$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

if (-not $Config) {
    & python -m eval.gui --port $Port
    exit $LASTEXITCODE
}
$argv = @("-m", "eval.run_eval", "--config", $Config)
if ($Runs -gt 0) { $argv += @("--runs", $Runs) }
if ($Cases) { $argv += @("--cases", $Cases) }
if ($Concurrency -gt 0) { $argv += @("--concurrency", $Concurrency) }
if ($Publish) { $argv += "--publish" }
& python @argv
exit $LASTEXITCODE
