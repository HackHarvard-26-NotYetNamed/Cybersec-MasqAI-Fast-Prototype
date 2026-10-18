<#
.SYNOPSIS
    One-kick eval: a remote security model on OpenRouter (allow_remote_security_model is on in the preset),
    the untrusted model via the relay. Starts/stops its own relay and gateway.
    Prefer .\run_eval.ps1 (GUI) for more baselines.
#>
param (
    [int]$Runs = 3,
    [string]$Cases = "all",
    [string]$SecurityModel = "google/gemini-3.8-flash",
    [string]$UntrustedModel = "google/gemini-3.8-flash",
    [ValidateSet("local", "daytona")][string]$Sandbox = "local",
    [switch]$WithRaw
)
. (Join-Path $PSScriptRoot "run_eval_common.ps1")
exit (Invoke-MasqEval -Preset "remote-security-models" -SecurityProvider "openrouter-security" -SecurityModel $SecurityModel `
    -UntrustedModel $UntrustedModel -Runs $Runs -Cases $Cases -MasqaiOnly:(-not $WithRaw) -LocalSandbox:($Sandbox -eq "local"))
