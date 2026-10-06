$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPython)) { throw "Run scripts\setup-windows.ps1 -Dev first." }
$previousQtPlatform = $env:QT_QPA_PLATFORM
$previousPythonPath = $env:PYTHONPATH
Push-Location $projectRoot
try {
    & $venvPython -c "import PySide6, cryptography"
    if ($LASTEXITCODE -ne 0) { throw "Missing test dependencies. Run scripts\setup-windows.ps1 -Dev." }
    $env:QT_QPA_PLATFORM = "offscreen"
    $env:PYTHONPATH = Join-Path $projectRoot "src"
    & $venvPython -m unittest discover -s tests -v
    if ($LASTEXITCODE -ne 0) { throw "Tests failed with exit code $LASTEXITCODE." }
} finally {
    $env:QT_QPA_PLATFORM = $previousQtPlatform
    $env:PYTHONPATH = $previousPythonPath
    Pop-Location
}
