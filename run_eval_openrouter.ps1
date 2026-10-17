<#
.SYNOPSIS
    One-kick start script for MasqAI eval with remote security model on OpenRouter and local sandbox.

.DESCRIPTION
    Launches:
      1. Relay proxy on port 8788 forwarding to the untrusted model (google/gemini-4-argon) via OpenRouter
      2. MasqAI Gateway on port 8787 using google/gemini-3.8-flash on OpenRouter as the security model
         (with allow_remote_security_model = true)
      3. Preflight health check
      4. Eval harness in local sandbox mode

.PARAMETER Runs
    Number of evaluation runs per case per condition (default: 3).

.PARAMETER Cases
    Evaluation cases to run (default: "all").

.PARAMETER SecurityModel
    Remote security model name on OpenRouter (default: "google/gemini-3.8-flash").

.PARAMETER UntrustedModel
    Untrusted model forwarded by the relay (default: "google/gemini-4-argon").

.PARAMETER ConfigPath
    MasqAI gateway config path (default: "eval/masqai.eval.openrouter.json").
#>

param (
    [int]$Runs = 3,
    [string]$Cases = "all",
    [string]$SecurityModel = "google/gemini-3.8-flash",
    [string]$UntrustedModel = "google/gemini-3.8-flash",
    [string]$ConfigPath = "eval/masqai.eval.openrouter.json"
)

$ErrorActionPreference = "Stop"

# 1. Verify OPENROUTER_API_KEY
if (-not $env:OPENROUTER_API_KEY) {
    Write-Error "OPENROUTER_API_KEY is not set in the environment. Please export or set `$env:OPENROUTER_API_KEY and retry."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " MasqAI One-Kick Eval (OpenRouter Security Model)" -ForegroundColor Cyan
Write-Host " Security Model       : $SecurityModel (OpenRouter, remote allowed)"
Write-Host " Untrusted Model      : $UntrustedModel (OpenRouter via Relay)"
Write-Host " Sandbox Mode         : Local"
Write-Host " Runs Per Case        : $Runs"
Write-Host " Cases                : $Cases"
Write-Host " Config File          : $ConfigPath"
Write-Host "==========================================================" -ForegroundColor Cyan

# Allow local sandbox execution for the evaluation run
$env:MASQAI_ALLOW_LOCAL_SANDBOX = "1"
$env:RELAY_MAX_RECORDS = "5000"

$relayProc = $null
$gatewayProc = $null

function Stop-Processes {
    Write-Host "`nStopping background services..." -ForegroundColor Yellow
    if ($relayProc -and -not $relayProc.HasExited) {
        Stop-Process -Id $relayProc.Id -Force -ErrorAction SilentlyContinue
    }
    if ($gatewayProc -and -not $gatewayProc.HasExited) {
        Stop-Process -Id $gatewayProc.Id -Force -ErrorAction SilentlyContinue
    }
}

try {
    # 2. Start Relay Proxy (:8788) with the untrusted model
    Write-Host "[1/4] Starting Relay on :8788 forwarding to $UntrustedModel..." -ForegroundColor Green
    $relayProc = Start-Process -FilePath "python" `
        -ArgumentList "playground/relay.py", "--eval-model", $UntrustedModel `
        -PassThru -NoNewWindow

    # 3. Start MasqAI Gateway (:8787) with remote security config
    Write-Host "[2/4] Starting MasqAI Gateway on :8787..." -ForegroundColor Green
    $gatewayProc = Start-Process -FilePath "python" `
        -ArgumentList "run_gateway.py", "--config", $ConfigPath `
        -PassThru -NoNewWindow

    # 4. Wait for endpoints to become healthy
    Write-Host "[3/4] Waiting for services to become ready..." -ForegroundColor Green
    $ready = $false
    for ($i = 0; $i -lt 30; $i++) {
        Start-Sleep -Seconds 1
        $relayOk = $false
        $masqOk = $false

        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8788/relay/api/requests?tag=preflight" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
            if ($resp.StatusCode -eq 200) { $relayOk = $true }
        } catch {}

        try {
            $resp = Invoke-WebRequest -Uri "http://127.0.0.1:8787/" -TimeoutSec 2 -UseBasicParsing -ErrorAction SilentlyContinue
            if ($resp.StatusCode -eq 200) { $masqOk = $true }
        } catch {}

        if ($relayOk -and $masqOk) {
            $ready = $true
            break
        }
    }

    if (-not $ready) {
        Write-Error "Services failed to become healthy within 30 seconds."
        exit 1
    }
    Write-Host "Services are up and responsive." -ForegroundColor Green

    # 5. Run the Eval Harness
    Write-Host "[4/4] Executing Eval Benchmark..." -ForegroundColor Cyan
    & python -m eval.run_eval `
        --cases $Cases `
        --conditions "masqai" `
        --runs $Runs `
        --concurrency 4 `
        --sandbox local `
        --security-model $SecurityModel `
        --untrusted-model $UntrustedModel `
        --masqai-config $ConfigPath

    if ($LASTEXITCODE -eq 0) {
        Write-Host "`nEval completed successfully! Generating summary report..." -ForegroundColor Green
        & python -m eval.aggregate eval/out/runs.jsonl | Out-File -FilePath "web/public/data/results.json" -Encoding utf8
        Write-Host "Results written to web/public/data/results.json and eval/out/" -ForegroundColor Green
    } else {
        Write-Warning "Eval finished with exit code $LASTEXITCODE"
    }

} finally {
    Stop-Processes
}
