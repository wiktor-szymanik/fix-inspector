"""Absolute-import entrypoint and deterministic frozen-process shutdown."""

import os

from fixinspector.app import main
from fixinspector.app_logging import shutdown_logging

result = main()
shutdown_logging()

# PyInstaller's windowed bootloader plus Qt can remain in native teardown after
# Python's main function has returned.  All application-owned cleanup runs in
# MainWindow.closeEvent before app.exec() returns; close the rotating log above,
# then avoid an indefinitely resident portable process.
os._exit(result)
