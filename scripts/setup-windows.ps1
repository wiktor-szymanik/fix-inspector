param([string]$Python = "python", [switch]$Dev, [switch]$Build, [string]$Wheelhouse = "")
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
$versionCheck = "import sys,struct; assert (3,11) <= sys.version_info[:2] < (3,15) and struct.calcsize('P') == 8, 'Use 64-bit Python 3.11 through 3.14'"
if (-not (Test-Path -LiteralPath $venvPython)) {
    if (-not (Get-Command $Python -ErrorAction SilentlyContinue)) {
        throw "Python not found. Install 64-bit Python 3.11-3.14, or pass -Python <python.exe>."
    }
    & $Python -c $versionCheck
    if ($LASTEXITCODE -ne 0) { throw "Unsupported Python. Use 64-bit Python 3.11-3.14." }
    & $Python -m venv (Join-Path $projectRoot ".venv")
    if ($LASTEXITCODE -ne 0) { throw "Virtual environment creation failed." }
}
& $venvPython -c $versionCheck
if ($LASTEXITCODE -ne 0) { throw "Existing .venv uses an unsupported Python version." }
$pipOptions = @()
if ($Wheelhouse) {
    $pipOptions = @("--no-index", "--find-links", (Resolve-Path -LiteralPath $Wheelhouse).Path)
}
Push-Location $projectRoot
try {
    & $venvPython -m pip install @pipOptions "setuptools==80.9.0" "wheel==0.45.1"
    if ($LASTEXITCODE -ne 0) { throw "Packaging tools installation failed." }
    $dependencyFile = "requirements.txt"
    if ($Dev -or $Build) { $dependencyFile = "requirements-dev.txt" }
    & $venvPython -m pip install @pipOptions -r $dependencyFile
    if ($LASTEXITCODE -ne 0) { throw "Dependency installation failed." }
    if ($Build) {
        & $venvPython -m pip install @pipOptions -r requirements-build.txt
        if ($LASTEXITCODE -ne 0) { throw "Build dependency installation failed." }
    }
    & $venvPython -m pip install @pipOptions --no-build-isolation --no-deps -e .
    if ($LASTEXITCODE -ne 0) { throw "Project installation failed." }
    & $venvPython -m pip check
    if ($LASTEXITCODE -ne 0) { throw "Dependency consistency check failed." }
    Write-Host "Ready. Run: .\scripts\run-windows.ps1"
} finally { Pop-Location }
