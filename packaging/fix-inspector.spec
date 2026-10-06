# -*- mode: python ; coding: utf-8 -*-

from pathlib import Path

project_root = Path(SPECPATH).parent
application_icon = project_root / "resources" / "app.ico"
if not application_icon.is_file():
    raise FileNotFoundError("Required application icon is missing: resources/app.ico")
documentation = [
    project_root / "README.md",
    project_root / "docs" / "USER_GUIDE.md",
    project_root / "docs" / "TROUBLESHOOTING.md",
    project_root / "docs" / "DISPLAY_PRESENTATION.md",
    project_root / "CHANGELOG.md",
]
datas = [(str(path), "docs") for path in documentation if path.is_file()]
datas.append((str(application_icon), "resources"))

a = Analysis(
    [str(project_root / "packaging" / "entrypoint.py")],
    pathex=[str(project_root / "src")],
    binaries=[],
    datas=datas,
    # The GUI import is intentionally lazy so protocol/unit tests can run
    # without Qt. Declare it as a packaging root so PyInstaller includes Qt.
    hiddenimports=["fixinspector.gui.main_window"],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter", "pytest"],
    noarchive=False,
    optimize=1,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="FIX Inspector",
    icon=str(application_icon),
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="FIX Inspector",
)
