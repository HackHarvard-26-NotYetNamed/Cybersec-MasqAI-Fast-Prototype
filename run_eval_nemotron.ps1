<#
.SYNOPSIS
    One-kick start script for MasqAI eval with a local sandbox.

.DESCRIPTION
    Launches:
      1. Relay proxy on port 8788 forwarding to google/gemini-3.8-flash via OpenRouter
      2. MasqAI Gateway on port 8787 using nemotron-3.5-lightning:30b on local Ollama
      3. Preflight health check
      4. Eval harness in local sandbox mode

.PARAMETER Runs
    Number of evaluation runs per case per condition (default: 3).

.PARAMETER Cases
    Evaluation cases to run (default: "all").

.PARAMETER SecurityModel
    Ollama security model name (default: "nemotron-3.5-lightning:30b").

.PARAMETER UntrustedModel
    Untrusted model forwarded by relay (default: "google/gemini-3.8-flash").
#>

param (
    [int]$Runs = 3,
    [string]$Cases = "all",
    [string]$SecurityModel = "nemotron-3.5-lightning:30b",
    [string]$UntrustedModel = "google/gemini-3.8-flash"
)

$ErrorActionPreference = "Stop"

# 1. Verify OPENROUTER_API_KEY
if (-not $env:OPENROUTER_API_KEY) {
    Write-Error "OPENROUTER_API_KEY is not set in the environment. Please export or set `$env:OPENROUTER_API_KEY and retry."
    exit 1
}

Write-Host "==========================================================" -ForegroundColor Cyan
Write-Host " MasqAI One-Kick Eval Start" -ForegroundColor Cyan
Write-Host " Security Model  : $SecurityModel (Ollama)"
Write-Host " Untrusted Model : $UntrustedModel (OpenRouter)"
Write-Host " Sandbox Mode    : Local"
Write-Host " Runs Per Case   : $Runs"
Write-Host " Cases           : $Cases"
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
    # 2. Start Relay Proxy (:8788)
    Write-Host "[1/4] Starting Relay on :8788..." -ForegroundColor Green
    $relayProc = Start-Process -FilePath "python" `
        -ArgumentList "playground/relay.py", "--eval-model", $UntrustedModel `
        -PassThru -NoNewWindow

    # 3. Start MasqAI Gateway (:8787)
    Write-Host "[2/4] Starting MasqAI Gateway on :8787..." -ForegroundColor Green
    $gatewayProc = Start-Process -FilePath "python" `
        -ArgumentList "run_gateway.py", "--config", "eval/masqai.eval.json" `
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
        --concurrency 1 `
        --sandbox local `
        --security-model $SecurityModel `
        --untrusted-model $UntrustedModel

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
