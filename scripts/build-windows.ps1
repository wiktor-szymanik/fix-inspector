# Same PyInstaller onedir recipe and smoke checks as the existing portable build.
$ErrorActionPreference = "Stop"
$projectRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvPython = Join-Path $projectRoot ".venv\Scripts\python.exe"
if (-not (Test-Path -LiteralPath $venvPython)) { throw "Run scripts\setup-windows.ps1 -Build first." }
Push-Location $projectRoot
try {
    & $venvPython -c "import PyInstaller, PySide6, cryptography"
    if ($LASTEXITCODE -ne 0) { throw "Missing build dependencies. Run scripts\setup-windows.ps1 -Build." }
    $version = & $venvPython -c "from fixinspector import __version__; print(__version__)"
    if ($LASTEXITCODE -ne 0 -or $version -notmatch '^\d+\.\d+\.\d+(rc\d+)?$') { throw "Invalid application version." }
    & (Join-Path $PSScriptRoot "test-windows.ps1")
    $distPath = Join-Path $projectRoot "dist\$version"
    $buildPath = Join-Path $projectRoot "build\portable-$version"
    & $venvPython -m PyInstaller --clean --noconfirm --distpath $distPath --workpath $buildPath "packaging\fix-inspector.spec"
    if ($LASTEXITCODE -ne 0) { throw "PyInstaller failed with exit code $LASTEXITCODE." }
    $bundlePath = Join-Path $distPath "FIX Inspector"
    $portableExe = Join-Path $bundlePath "FIX Inspector.exe"
    $previousQtPlatform = $env:QT_QPA_PLATFORM
    $env:QT_QPA_PLATFORM = "offscreen"
    try {
        foreach ($smokeArgument in @("--self-test", "--smoke-gui")) {
            $smokeProcess = Start-Process -FilePath $portableExe -ArgumentList $smokeArgument -PassThru -WindowStyle Hidden
            if (-not $smokeProcess.WaitForExit(30000)) {
                Stop-Process -Id $smokeProcess.Id -Force
                throw "Portable $smokeArgument timed out."
            }
            if ($smokeProcess.ExitCode -ne 0) { throw "Portable $smokeArgument failed: $($smokeProcess.ExitCode)." }
        }
    } finally { $env:QT_QPA_PLATFORM = $previousQtPlatform }
    $releasePath = Join-Path $projectRoot "release"
    New-Item -ItemType Directory -Force -Path $releasePath | Out-Null
    $archivePath = Join-Path $releasePath "FIX-Inspector-$version-windows-x64.zip"
    Compress-Archive -Path (Join-Path $bundlePath "*") -DestinationPath $archivePath -CompressionLevel Optimal -Force
    Write-Host "Portable ZIP: $archivePath"
} finally { Pop-Location }
