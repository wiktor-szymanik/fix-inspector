from __future__ import annotations

import sys

from .app_logging import configure_logging
from .fix.checksum import checksum_ok
from .fix.fields import FixField
from .fix.parser import parse_message
from .fix.serializer import serialize_structured
from .project.redaction import SecretRedactionPolicy


def main() -> int:
    """Start the local-only FIX Inspector desktop application."""
    configure_logging(SecretRedactionPolicy())
    if "--self-test" in sys.argv:
        raw = serialize_structured(
            [
                FixField("8", b"FIX.4.4"),
                FixField("35", b"0"),
                FixField("34", b"1"),
            ]
        )
        message = parse_message(raw)
        return 0 if message.msg_type == "0" and checksum_ok(raw) else 2
    try:
        from PySide6.QtCore import QCoreApplication, QEvent
        from PySide6.QtWidgets import QApplication
    except ModuleNotFoundError as exc:
        if exc.name != "PySide6":
            raise
        raise SystemExit(
            "PySide6 is required to run FIX Inspector. "
            "Install it with: py -m pip install -r requirements.txt"
        ) from exc

    from .gui.main_window import MainWindow

    qt_arguments = [arg for arg in sys.argv if arg not in {"--smoke-gui"}]
    app = QApplication(qt_arguments)
    app.setApplicationName("FIX Inspector")
    from .app_resources import configure_application_icon

    configure_application_icon(app)
    window = MainWindow()
    window.show()
    if "--smoke-gui" in sys.argv:
        app.processEvents()
        window.close()
        # Exercise the same deferred-delete path as a real Qt event-loop
        # shutdown.  Explicitly draining it also avoids leaving native Qt
        # objects alive while a frozen Python interpreter is tearing down.
        window.deleteLater()
        QCoreApplication.sendPostedEvents(None, QEvent.Type.DeferredDelete)
        app.processEvents()
        app.quit()
        return 0
    return app.exec()
