<#
.SYNOPSIS
    One-kick eval: nemotron-3.5-lightning:30b on local Ollama as the security model, the untrusted model
    via the relay (OpenRouter). Starts/stops its own relay and gateway.
    Prefer .\run_eval.ps1 (GUI) for more baselines.
#>
param (
    [int]$Runs = 3,
    [string]$Cases = "all",
    [string]$SecurityModel = "nemotron-3.5-lightning:30b",
    [string]$UntrustedModel = "google/gemini-3.8-flash",
    [ValidateSet("local", "daytona")][string]$Sandbox = "local",
    [switch]$WithRaw
)
. (Join-Path $PSScriptRoot "run_eval_common.ps1")
exit (Invoke-MasqEval -Preset "local-security-models" -SecurityProvider "ollama-local" -SecurityModel $SecurityModel `
    -UntrustedModel $UntrustedModel -Runs $Runs -Cases $Cases -MasqaiOnly:(-not $WithRaw) -LocalSandbox:($Sandbox -eq "local"))
