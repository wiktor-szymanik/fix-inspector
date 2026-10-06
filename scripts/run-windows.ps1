param([Parameter(ValueFromRemainingArguments = $true)][string[]]$Arguments)
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPython)) { throw "Run scripts\setup-windows.ps1 first." }
Push-Location $projectRoot
try {
    & $venvPython (Join-Path $projectRoot "run.py") @Arguments
    if ($LASTEXITCODE -ne 0) { throw "FIX Inspector exited with code $LASTEXITCODE." }
} finally { Pop-Location }
