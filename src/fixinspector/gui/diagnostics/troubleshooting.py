"""On-demand, metadata-only diagnostics. Never export records, secrets or logs."""

import json
import platform
from pathlib import Path
import zipfile

from PySide6.QtWidgets import (
    QApplication, QDialog, QDialogButtonBox, QFileDialog, QHBoxLayout, QLabel,
    QMessageBox, QPushButton, QVBoxLayout,
)

from ... import __version__


class TroubleshootingDialog(QDialog):
    def __init__(self, window, diagnostics_page):
        super().__init__(window)
        self._owner = window
        self.setWindowTitle("Troubleshooting - FIX Inspector")
        self.resize(880, 720)
        layout = QVBoxLayout(self)
        self.runtime = QLabel(f"FIX Inspector {__version__} · Python {platform.python_version()} · {platform.system()} {platform.release()}")
        self.runtime.setWordWrap(True)
        layout.addWidget(self.runtime)
        # Move the existing scroll area, not its child. Reparenting only the
        # child leaves the old QScrollArea's resize/event filter attached.
        layout.addWidget(diagnostics_page, 1)
        diagnostics_page.show()
        actions = QHBoxLayout()
        self.copy_button = QPushButton("Copy diagnostics")
        self.export_button = QPushButton("Export diagnostic bundle…")
        self.copy_button.clicked.connect(self.copy_diagnostics)
        self.export_button.clicked.connect(self.export_bundle)
        actions.addWidget(self.copy_button)
        actions.addWidget(self.export_button)
        actions.addStretch(1)
        layout.addLayout(actions)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.hide)
        layout.addWidget(buttons)

    def report(self) -> dict:
        w = self._owner
        snapshot = w.engine.diagnostics()
        # Explicit allowlist: no FIX bytes, identity values, INI, file paths,
        # analyst notes, exception bodies or in-memory application logs.
        return {
            "application": {"version": __version__, "python": platform.python_version(),
                            "os": f"{platform.system()} {platform.release()}"},
            "proxy": {
                "listener_running": snapshot.listener_state.startswith("Listening "),
                "upstream_connected": snapshot.upstream_state.startswith("Connected "),
                "transport": str(w.upstream_transport.currentData()),
                "certificate_verification": w.verify_tls.isChecked(),
                "tls_protocol": snapshot.tls_version,
                "network_error_observed": bool(snapshot.last_transport_error),
            },
            "session": {
                "observed": bool(snapshot.client_session_id or snapshot.server_session_id),
                "client_sequence": snapshot.client_to_server_sequence,
                "server_sequence": snapshot.server_to_client_sequence,
                "heartbeat_seconds": snapshot.heartbeat_interval,
                "held": snapshot.held_count, "queued": snapshot.queued_count,
                "injection_waiting": snapshot.injection_waiting_count,
                "substitutions": snapshot.substitution_count,
                "recovery_conflicts": snapshot.recovery_conflict_count,
            },
            "dictionaries": {"fields": len(w.dictionary.fields_by_tag),
                             "messages": len(w.dictionary.messages),
                             "transport_configured": bool(w.transport_dict.text()),
                             "application_configured": bool(w.app_dict.text())},
            "capture": {"live_records": len(w.records), "malformed": snapshot.malformed_record_count},
            "privacy": "Metadata only. Payloads, identities, endpoints, paths, logs and error bodies omitted.",
        }

    def report_text(self) -> str:
        return json.dumps(self.report(), indent=2, ensure_ascii=False)

    def copy_diagnostics(self):
        QApplication.clipboard().setText(self.report_text())

    def write_bundle(self, path: Path):
        # Deliberately do not attach existing log/config/project files.
        with zipfile.ZipFile(path, "w", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("diagnostics.json", self.report_text())

    def export_bundle(self):
        path, _ = QFileDialog.getSaveFileName(self, "Export diagnostics", "FIX-Inspector-diagnostics.zip", "ZIP (*.zip)")
        if path:
            try:
                self.write_bundle(Path(path))
            except OSError as exc:
                QMessageBox.warning(self, "Export diagnostics", str(exc))
