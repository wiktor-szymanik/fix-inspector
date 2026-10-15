from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import QFormLayout, QGroupBox, QLabel, QVBoxLayout, QWidget

from ...transport.upstream import PLAIN_TCP_VERIFICATION
from ..theme import role


class DiagnosticsPanel(QWidget):
    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        layout = QVBoxLayout(self)
        transport_box = QGroupBox("Transport / TLS")
        transport_form = QFormLayout(transport_box)
        self.listener = QLabel("Stopped")
        self.upstream = QLabel("Disconnected")
        self.tls = QLabel("DISABLED - testing only")
        self.tls.setWordWrap(True)
        transport_form.addRow("Listener", self.listener)
        transport_form.addRow("Upstream", self.upstream)
        transport_form.addRow("TLS", self.tls)
        layout.addWidget(transport_box)

        session_box = QGroupBox("Observed FIX session")
        session_form = QFormLayout(session_box)
        self.client_session = QLabel("Not observed")
        self.server_session = QLabel("Not observed")
        self.sequences = QLabel("Client → Server - / Server → Client -")
        self.heartbeat = QLabel("Not observed")
        self.queue = QLabel("Held 0 / queued 0")
        self.paused = QLabel("Not paused")
        session_form.addRow("Client identity", self.client_session)
        session_form.addRow("Server identity", self.server_session)
        session_form.addRow("Observed sequence", self.sequences)
        session_form.addRow("HeartBtInt", self.heartbeat)
        session_form.addRow("Intercept queue", self.queue)
        session_form.addRow("Client → Server pause", self.paused)
        layout.addWidget(session_box)

        virtualization_box = QGroupBox("Active-session injection / recovery")
        virtualization_form = QFormLayout(virtualization_box)
        self.injection_queue = QLabel("Safe 0 / destructive 0")
        self.journal = QLabel("0 substitutions")
        self.recovery = QLabel("Idle")
        self.recovery.setWordWrap(True)
        virtualization_form.addRow("Waiting", self.injection_queue)
        virtualization_form.addRow("Substitution journal", self.journal)
        virtualization_form.addRow("Recovery awareness", self.recovery)
        layout.addWidget(virtualization_box)

        dictionary_box = QGroupBox("Dictionaries")
        dictionary_form = QFormLayout(dictionary_box)
        self.dictionaries = QLabel("0 fields / 0 messages")
        dictionary_form.addRow("Loaded", self.dictionaries)
        layout.addWidget(dictionary_box)

        health_box = QGroupBox("Runtime health / local storage")
        health_form = QFormLayout(health_box)
        self.parser_health = QLabel("0 observed / 0 malformed")
        self.parser_health.setWordWrap(True)
        self.transport_error = QLabel("None")
        self.transport_error.setWordWrap(True)
        self.history_memory = QLabel("0 / 10,000 live")
        self.project_history = QLabel("No project open")
        self.log_file = QLabel("Logging unavailable")
        self.log_file.setWordWrap(True)
        health_form.addRow("Raw/parser health", self.parser_health)
        health_form.addRow("Last network error", self.transport_error)
        health_form.addRow("History memory", self.history_memory)
        health_form.addRow("Durable History", self.project_history)
        health_form.addRow("Redacted rotating log", self.log_file)
        layout.addWidget(health_box)
        layout.addStretch(1)

    def update_state(self, snapshot, field_count: int, message_count: int) -> None:
        self.listener.setText(snapshot.listener_state)
        self.upstream.setText(snapshot.upstream_state)
        tls_details = [snapshot.tls_verification]
        if snapshot.tls_version:
            tls_details.append(snapshot.tls_version)
        if snapshot.tls_cipher:
            tls_details.append(snapshot.tls_cipher)
        self.tls.setText(" / ".join(tls_details))
        if snapshot.tls_verification == PLAIN_TCP_VERIFICATION:
            role(self.tls, "muted")
        elif snapshot.tls_verification.startswith("DISABLED"):
            role(self.tls, "warning")
        else:
            role(self.tls, "success")
        self.client_session.setText(snapshot.client_session_id or "Not observed")
        self.server_session.setText(snapshot.server_session_id or "Not observed")
        c2s = snapshot.client_to_server_sequence if snapshot.client_to_server_sequence is not None else "-"
        s2c = snapshot.server_to_client_sequence if snapshot.server_to_client_sequence is not None else "-"
        self.sequences.setText(f"Client → Server {c2s} / Server → Client {s2c}")
        heartbeat = snapshot.heartbeat_interval
        self.heartbeat.setText(f"{heartbeat}s" if heartbeat is not None else "Not observed")
        self.queue.setText(
            f"Client → Server held {snapshot.client_held_count} / queued {snapshot.client_queued_count}; "
            f"Server → Client held {snapshot.server_held_count} / queued {snapshot.server_queued_count}"
        )
        if snapshot.paused_client_sequence is None:
            self.paused.setText("Not paused")
        else:
            self.paused.setText(
                f"Paused at SeqNum {snapshot.paused_client_sequence}; "
                f"{snapshot.client_queued_count} subsequent message(s) queued"
            )
        self.injection_queue.setText(
            f"Safe {snapshot.injection_waiting_count} / "
            f"destructive {snapshot.destructive_replay_waiting_count}"
        )
        last_sequence = (
            f"; last SeqNum {snapshot.last_substituted_sequence}"
            if snapshot.last_substituted_sequence is not None
            else ""
        )
        self.journal.setText(f"{snapshot.substitution_count} substitution(s){last_sequence}")
        self.recovery.setText(
            f"Pending ranges {snapshot.recovery_pending_range_count}; "
            f"effective replays {snapshot.recovery_replay_count}; "
            f"conflicts {snapshot.recovery_conflict_count}"
            + (f" - {snapshot.recovery_detail}" if snapshot.recovery_detail else "")
        )
        role(self.recovery, "danger" if snapshot.recovery_conflict_count else "normal")
        self.dictionaries.setText(f"{field_count} fields / {message_count} messages")
        self.parser_health.setText(
            f"{snapshot.observed_record_count} observed / "
            f"{snapshot.malformed_record_count} malformed; "
            f"{snapshot.outstanding_wire_record_count} unresolved wire record(s)"
        )
        self.transport_error.setText(snapshot.last_transport_error or "None")
        role(self.transport_error, "danger" if snapshot.last_transport_error else "normal")

    def update_runtime(
        self,
        *,
        live_count: int,
        live_limit: int,
        evicted_count: int,
        durable_count: int | None,
        log_path: Path | None,
    ) -> None:
        self.history_memory.setText(
            f"{live_count:,} / {live_limit:,} live; {evicted_count:,} evicted this run"
        )
        self.project_history.setText(
            f"{durable_count:,} record(s) in SQLite" if durable_count is not None else "No project open"
        )
        self.log_file.setText(str(log_path) if log_path is not None else "Logging unavailable")
