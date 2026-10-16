$ErrorActionPreference = "Stop"
Set-Location -LiteralPath $PSScriptRoot

$jdk = $env:LEDGER_JDK
if (-not $jdk -and (Test-Path -LiteralPath .ledger-jdk)) {
    $jdk = (Get-Content -LiteralPath .ledger-jdk -TotalCount 1).Trim()
}
if (-not $jdk) {
    throw "No JDK configured: set LEDGER_JDK, or write the JDK home (the folder whose bin\ contains javaw.exe) into .ledger-jdk"
}
$javaw = Join-Path $jdk "bin\javaw.exe"
if (-not (Test-Path -LiteralPath $javaw)) {
    throw "javaw not found at $javaw"
}

$javac = Join-Path $jdk "bin\javac.exe"
$jar = Join-Path $jdk "bin\jar.exe"
$java = Join-Path $jdk "bin\java.exe"

if (Test-Path -LiteralPath out) { Remove-Item -Recurse -Force -LiteralPath out }
New-Item -ItemType Directory -Path out\classes | Out-Null

$sources = Get-ChildItem -Recurse -Filter *.java -Path src | ForEach-Object { $_.FullName }
& $javac -encoding UTF-8 -d out\classes $sources
if ($LASTEXITCODE -ne 0) { throw "javac failed" }

& $jar cfe out\ledger.jar com.acme.ledger.Main -C out\classes .
if ($LASTEXITCODE -ne 0) { throw "jar failed" }

& $java -jar out\ledger.jar data\accounts.csv data\transactions.csv
if ($LASTEXITCODE -ne 0) { throw "ledger failed" }
