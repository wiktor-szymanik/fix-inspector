"""Source/frozen application resources; the repository owns a single icon file."""

from pathlib import Path
import sys


def application_icon_path() -> Path:
    root = Path(sys._MEIPASS) if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[2]
    return root / "resources" / "app.ico"


def configure_application_icon(application) -> None:
    from PySide6.QtGui import QIcon

    icon = QIcon(str(application_icon_path()))
    if icon.isNull():
        raise RuntimeError("Cannot load application icon: resources/app.ico")
    if sys.platform == "win32":
        # Separate taskbar grouping from the Python interpreter when run from source.
        import ctypes

        ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID("FIXInspector.Desktop")
    application.setWindowIcon(icon)
