<#
.SYNOPSIS
    One-kick eval: qwen3.5:4b on local Ollama as the security model, the untrusted model via the relay
    (OpenRouter). Starts/stops its own relay and gateway. Prefer .\run_eval.ps1 (GUI) for more baselines.
.PARAMETER Sandbox
    "local" (default, runs the model's commands on this machine) or "daytona".
#>
param (
    [int]$Runs = 3,
    [string]$Cases = "all",
    [string]$SecurityModel = "qwen3.5:4b",
    [string]$UntrustedModel = "google/gemini-3.8-flash",
    [bool]$Think = $false,
    [ValidateSet("local", "daytona")][string]$Sandbox = "local",
    [switch]$WithRaw
)
. (Join-Path $PSScriptRoot "run_eval_common.ps1")
exit (Invoke-MasqEval -Preset "local-security-models" -SecurityProvider "ollama-local" -SecurityModel $SecurityModel `
    -UntrustedModel $UntrustedModel -Runs $Runs -Cases $Cases -Think $Think -MasqaiOnly:(-not $WithRaw) `
    -LocalSandbox:($Sandbox -eq "local"))
