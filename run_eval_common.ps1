<#
.SYNOPSIS
    Shared helper for the run_eval_<model>.ps1 wrappers: builds a run config from a preset, overrides the
    models, and runs it headless through the eval engine (python -m eval.run_eval --config <file>).
    Conditions: raw(untrusted) + masqai(security, untrusted). For several security models at once, use
    the GUI (.\run_eval.ps1) or a preset with more conditions.
#>
function Invoke-MasqEval {
    param (
        [Parameter(Mandatory)][string]$Preset,
        [Parameter(Mandatory)][string]$SecurityProvider,
        [Parameter(Mandatory)][string]$SecurityModel,
        [Parameter(Mandatory)][string]$UntrustedModel,
        [int]$Runs = 3,
        [string]$Cases = "all",
        [object]$Think = $null,
        [switch]$MasqaiOnly,
        [switch]$LocalSandbox
    )
    $ErrorActionPreference = "Continue"   # python's stderr (progress, warnings) is not a PowerShell error
    $cfg = Get-Content -LiteralPath (Join-Path $PSScriptRoot "eval/presets/$Preset.json") -Raw | ConvertFrom-Json
    $security = [ordered]@{ provider = $SecurityProvider; model = $SecurityModel }
    if ($null -ne $Think) { $security.think = [bool]$Think }
    $conditions = @()
    if (-not $MasqaiOnly) { $conditions += [ordered]@{ id = "raw"; kind = "raw"; untrusted = $UntrustedModel } }
    $id = ($SecurityModel -replace '[^A-Za-z0-9_-]+', '-').ToLower().Trim('-')
    if ($id.Length -gt 32) { $id = $id.Substring(0, 32) }
    $conditions += [ordered]@{ id = $id; kind = "masqai"; untrusted = $UntrustedModel; security = $security }
    $cfg.conditions = $conditions
    $cfg.runs = $Runs
    $cfg.name = $id
    if ($Cases -ne "all") { $cfg.cases = @($Cases -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ }) } else { $cfg.cases = "all" }
    if ($LocalSandbox) {
        $cfg.sandbox = "local"
        $cfg | Add-Member -NotePropertyName allow_local_untrusted -NotePropertyValue $true -Force
    }
    $tmp = Join-Path ([IO.Path]::GetTempPath()) "masq-eval.$([guid]::NewGuid().ToString('N')).json"
    try {
        [IO.File]::WriteAllText($tmp, ($cfg | ConvertTo-Json -Depth 12), (New-Object Text.UTF8Encoding $false))
        Push-Location -LiteralPath $PSScriptRoot
        try { & python -m eval.run_eval --config $tmp | Out-Host; $code = $LASTEXITCODE } finally { Pop-Location }
        return $code
    } finally {
        Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    }
}
