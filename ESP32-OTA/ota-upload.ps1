param(
    [Parameter(Mandatory = $true, Position = 0)]
    [string]$File,

    [Parameter(Mandatory = $true)]
    [string]$HostAddress,

    [Parameter(Mandatory = $true)]
    [string]$Token,

    [string]$RemotePath = "/app.py",
    [double]$Timeout = 8,
    [switch]$CheckHealth
)

$ErrorActionPreference = "Stop"

$resolvedFile = (Resolve-Path -LiteralPath $File).Path
$portScript = Join-Path $PSScriptRoot "port.py"

if (-not (Test-Path -LiteralPath $portScript -PathType Leaf)) {
    throw "OTA client not found: $portScript"
}

# Use one client process for the complete operation so it is ready to run
# immediately and does not incur repeated Python startup overhead.
& python $portScript "--host=$HostAddress" "--token=$Token" "--timeout=$Timeout" put $resolvedFile $RemotePath
if ($LASTEXITCODE -ne 0) {
    throw "OTA upload failed with exit code $LASTEXITCODE"
}

if ($CheckHealth) {
    & python $portScript "--host=$HostAddress" "--token=$Token" "--timeout=$Timeout" health
    if ($LASTEXITCODE -ne 0) {
        throw "OTA health check failed with exit code $LASTEXITCODE"
    }
}
