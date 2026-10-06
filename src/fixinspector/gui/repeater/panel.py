from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt, Signal, QSignalBlocker
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...repeater.model import RepeaterItem
from ...fix.parser import parse_message, raw_to_editor_text
from ...presentation import display_direction, display_status
from ...records import TrafficRecord
from ...session.injection import (
    AutoUpdatePolicy,
    InjectionMode,
    InjectionRequest,
    RAW_MANUAL_POLICY,
    SESSION_AWARE_POLICY,
)
from ..widgets import MessageDiffWidget, MessageEditorWidget, MessageValidationWidget
from ..theme import contextual_hint, role
from ..widgets.flow_layout import FlowLayout
from ..widgets.presentation import Disclosure, table_columns


class RepeaterItemEditor(QWidget):
    queue_requested = Signal(str, bytes, object, object)
    new_connection_requested = Signal(str, bytes, object)
    close_connection_requested = Signal(str)
    navigate_history = Signal(int)
    fuzzer_requested = Signal(bytes, str, str)

    def __init__(
        self,
        item: RepeaterItem,
        dictionary_provider: Callable[[], object],
        secret_policy_provider: Callable[[], object],
        related_provider: Callable[[int], list[tuple[int, int, str, str, str, str]]],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.item = item
        self._dictionary_provider = dictionary_provider
        self._policy_provider = secret_policy_provider
        self._related_provider = related_provider
        layout = QVBoxLayout(self)
        toolbar = FlowLayout()
        self.mode = QComboBox()
        for mode in InjectionMode:
            self.mode.addItem(mode.value, mode.name)
        self.mode.setCurrentIndex(max(0, self.mode.findData(item.mode.name)))
        self._show_sensitive = False
        self.status = QLabel("Saved - ready")
        self.status.setWordWrap(True)
        self.queue_button = QPushButton()
        self.fuzzer_button = QPushButton("Create Fuzzer campaign")
        toolbar.addWidget(QLabel("Mode"))
        toolbar.addWidget(self.mode)
        toolbar.addStretch(1)
        toolbar.addWidget(self.status)
        toolbar.addWidget(self.fuzzer_button)
        toolbar.addWidget(self.queue_button)
        layout.addLayout(toolbar)

        auto_box = QGroupBox("Session fields")
        auto_layout = QGridLayout(auto_box)
        self.session_aware = QPushButton("Session-aware")
        self.raw_manual = QPushButton("Raw / Manual")
        self.auto_body_length = QCheckBox("BodyLength (9)")
        self.auto_msg_seq_num = QCheckBox("MsgSeqNum (34)")
        self.auto_sending_time = QCheckBox("SendingTime (52)")
        self.auto_checksum = QCheckBox("CheckSum (10)")
        self._auto_checkboxes = (
            self.auto_body_length,
            self.auto_msg_seq_num,
            self.auto_sending_time,
            self.auto_checksum,
        )
        auto_layout.addWidget(QLabel("Auto-update:"), 0, 0)
        for column, checkbox in enumerate(self._auto_checkboxes, start=1):
            auto_layout.addWidget(checkbox, 0, column)
        auto_layout.addWidget(self.session_aware, 1, 0, 1, 2)
        auto_layout.addWidget(self.raw_manual, 1, 2, 1, 2)
        self.new_connection = QPushButton("Send on new connection")
        self.close_connection = QPushButton("Close test connection")
        self.connection_status = QLabel("No isolated test connection")
        self.connection_status.setWordWrap(True)
        auto_layout.addWidget(self.new_connection, 1, 4)
        auto_layout.addWidget(self.close_connection, 1, 5)
        auto_layout.addWidget(self.connection_status, 2, 0, 1, 6)
        layout.addWidget(auto_box)
        self.session_fields = QComboBox()
        self.session_fields.addItems(["Managed", "Framing only", "Manual", "Custom"])
        self.session_fields.setToolTip("Managed: update 9/10/34/52 in the existing Heartbeat slot. Framing only: update 9/10, preserve 34/52; still uses the existing slot and identity policy. Manual: existing Exact Raw Replay, preserves edited bytes. 43/122 are never auto-generated. Custom retains older checkbox combinations.")
        self.session_badge = QLabel()
        role(self.session_badge, "badge")
        auto_layout.itemAtPosition(0, 0).widget().hide()
        auto_layout.addWidget(self.session_fields, 0, 0, 1, 3)
        auto_layout.addWidget(self.session_badge, 0, 3, 1, 3)
        self.advanced_session = Disclosure("Advanced field overrides")
        for checkbox in self._auto_checkboxes:
            self.advanced_session.body_layout.addWidget(checkbox)
        auto_layout.addWidget(self.advanced_session, 1, 0, 1, 4)
        self.session_aware.hide()
        self.raw_manual.hide()
        # Keep the isolated Logon connection controls, hidden for other types.
        logon = parse_message(item.working_raw).msg_type == "A"
        for control in (self.new_connection, self.close_connection, self.connection_status):
            control.setVisible(logon)
        self.identity = QLabel()
        self.identity.setWordWrap(True)
        layout.addWidget(self.identity)

        self.destructive_warning = QLabel(
            "SESSION-DESTRUCTIVE: sends these exact bytes immediately, reusing captured sequence/header/framing. "
            "It does not wait for a Heartbeat slot and can create sequence divergence."
        )
        self.destructive_warning.setWordWrap(True)
        contextual_hint(self.destructive_warning, "Raw mode · Automatic FIX field handling disabled ⓘ")
        role(self.destructive_warning, "warning")
        self.destructive_ack = QCheckBox("Allow session-destructive replay")
        layout.addWidget(self.destructive_warning)
        layout.addWidget(self.destructive_ack)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.editor = MessageEditorWidget(dictionary_provider, secret_policy_provider)
        self.editor.setToolTip("Message - edit ordered FIX fields or raw bytes")
        self.editor.set_raw(item.working_raw)
        splitter.addWidget(self.editor)

        activity = QTabWidget()
        self.timeline = QTableWidget(0, 6)
        self.timeline.setHorizontalHeaderLabels(["Time", "Mode", "Status", "Seq", "History", "Detail"])
        self.related = QTableWidget(0, 6)
        self.related.setHorizontalHeaderLabels(["Score", "History", "Direction", "Type", "Seq", "Evidence"])
        self.connection_traffic = QTableWidget(0, 6)
        self.connection_traffic.setHorizontalHeaderLabels(
            ["Time", "Direction", "Type", "Seq", "Status", "Raw"]
        )
        for table in (self.timeline, self.related, self.connection_traffic):
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
            table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
            table.horizontalHeader().setStretchLastSection(True)
            table.verticalHeader().setVisible(False)
        self.related.cellDoubleClicked.connect(self._related_double_clicked)
        activity.addTab(self.timeline, "Activity")
        activity.addTab(self.related, "Responses")
        activity.addTab(self.connection_traffic, "New connection traffic")
        activity.setTabVisible(2, logon)
        activity.setTabToolTip(1, "Asynchronous correlated responses; double-click a row to inspect it in History")
        self.diff = MessageDiffWidget()
        self.validation = MessageValidationWidget()
        activity.addTab(self.diff, "Diff")
        activity.addTab(self.validation, "Validation")
        splitter.addWidget(activity)
        splitter.setSizes([560, 250])
        layout.addWidget(splitter, 1)

        self.mode.currentIndexChanged.connect(self._mode_changed)
        self.session_aware.clicked.connect(self._set_session_aware)
        self.raw_manual.clicked.connect(self._set_raw_manual)
        self.new_connection.clicked.connect(self._send_new_connection)
        self.close_connection.clicked.connect(
            lambda: self.close_connection_requested.emit(self.item.item_id)
        )
        self.queue_button.clicked.connect(self._queue)
        self.fuzzer_button.clicked.connect(self._create_fuzzer)
        self._mode_changed()
        self._set_auto_update(
            RAW_MANUAL_POLICY
            if self.current_mode() is InjectionMode.EXACT_RAW
            else item.auto_update
        )
        self.refresh_timeline()
        self.refresh_related()
        self._refresh_analysis(item.working_raw)
        self.session_fields.currentIndexChanged.connect(self._session_fields_changed)
        for checkbox in self._auto_checkboxes:
            checkbox.toggled.connect(self._sync_session_fields)
        self._sync_session_fields()
        for table in (self.timeline, self.related, self.connection_traffic):
            table_columns(table)

    def set_reveal(self, reveal: bool) -> None:
        self._show_sensitive = bool(reveal)
        self.editor.set_reveal(reveal)
        self._refresh_analysis(self.editor._working_raw)
        for row in range(self.connection_traffic.rowCount()):
            item = self.connection_traffic.item(row, 5)
            raw = item.data(Qt.ItemDataRole.UserRole)
            visible = raw if reveal else self._policy_provider().redact(raw, self._dictionary_provider())
            item.setText(raw_to_editor_text(visible))

    def _session_fields_changed(self, index):
        if index == 0:
            self._set_session_aware()
        elif index == 1:
            self.mode.setCurrentIndex(self.mode.findData(InjectionMode.CLONE_EDIT.name))
            self._set_auto_update(AutoUpdatePolicy(True, False, False, True))
        elif index == 2:
            self._set_raw_manual()
        else:
            self.advanced_session.toggle.setChecked(True)
        self._sync_session_fields()

    def _sync_session_fields(self, *_):
        policy = self.auto_update_policy()
        index = 2 if self.current_mode() is InjectionMode.EXACT_RAW else 0 if policy.is_session_aware else 1 if policy == AutoUpdatePolicy(True, False, False, True) else 3
        blocker = QSignalBlocker(self.session_fields)
        self.session_fields.setCurrentIndex(index)
        del blocker
        self.session_badge.setText(self.session_fields.currentText())
        self.session_badge.setVisible(index != 0)

    def current_mode(self) -> InjectionMode:
        identifier = str(self.mode.currentData() or "")
        try:
            return InjectionMode[identifier]
        except KeyError:
            # Accept value-form data from an already constructed older widget.
            return InjectionMode(identifier)

    def _mode_changed(self) -> None:
        mode = self.current_mode()
        self.item.mode = mode
        self.editor.set_mode(mode)
        destructive = mode is InjectionMode.EXACT_RAW
        if destructive:
            self._set_auto_update(RAW_MANUAL_POLICY)
        for checkbox in self._auto_checkboxes:
            checkbox.setEnabled(not destructive)
        self.destructive_warning.setVisible(destructive)
        self.destructive_ack.setVisible(destructive)
        self.queue_button.setText(
            "Send raw now"
            if destructive
            else "Send replay"
            if mode is InjectionMode.BUSINESS_REPLAY
            else "Send request"
        )
        self.queue_button.setToolTip("Exact Raw Replay: sends immediately after the existing destructive confirmation" if destructive else "Queue through the existing active-session Heartbeat slot")
        role(self.queue_button, "danger" if destructive else "primary")
        self.new_connection.setEnabled(parse_message(self.item.working_raw).msg_type == "A")
        self._sync_session_fields()

    def auto_update_policy(self) -> AutoUpdatePolicy:
        return AutoUpdatePolicy(
            self.auto_body_length.isChecked(),
            self.auto_msg_seq_num.isChecked(),
            self.auto_sending_time.isChecked(),
            self.auto_checksum.isChecked(),
        )

    def _set_auto_update(self, policy: AutoUpdatePolicy) -> None:
        blockers = [QSignalBlocker(checkbox) for checkbox in self._auto_checkboxes]
        for checkbox, checked in zip(
            self._auto_checkboxes,
            (policy.body_length, policy.msg_seq_num, policy.sending_time, policy.checksum),
            strict=True,
        ):
            checkbox.setChecked(checked)
        del blockers
        if hasattr(self, "session_fields"):
            self._sync_session_fields()

    def _set_session_aware(self) -> None:
        self.mode.setCurrentIndex(self.mode.findData(InjectionMode.CLONE_EDIT.name))
        self._set_auto_update(SESSION_AWARE_POLICY)

    def _set_raw_manual(self) -> None:
        self.mode.setCurrentIndex(self.mode.findData(InjectionMode.EXACT_RAW.name))
        self._set_auto_update(RAW_MANUAL_POLICY)

    def _queue(self) -> None:
        mode = self.current_mode()
        if mode is InjectionMode.EXACT_RAW and not self.destructive_ack.isChecked():
            QMessageBox.warning(
                self,
                "Exact Raw Replay",
                "Acknowledge the session-destructive warning before sending exact raw bytes.",
            )
            return
        policy = self.auto_update_policy()
        try:
            raw = self.editor.outbound_raw(
                repair_raw=policy.body_length and policy.checksum
            )
        except (TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Sender editor", str(exc))
            return
        self.item.working_raw = raw
        self._refresh_analysis(raw)
        self.item.auto_update = policy
        self.queue_requested.emit(self.item.item_id, raw, mode, policy)

    def _send_new_connection(self) -> None:
        mode = self.current_mode()
        if mode is InjectionMode.EXACT_RAW and not self.destructive_ack.isChecked():
            QMessageBox.warning(
                self,
                "Raw / Manual Logon",
                "Acknowledge the session-destructive warning before sending exact raw bytes.",
            )
            return
        policy = self.auto_update_policy()
        try:
            raw = self.editor.outbound_raw(
                repair_raw=policy.body_length and policy.checksum
            )
        except (TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Sender editor", str(exc))
            return
        if parse_message(raw, self._dictionary_provider()).msg_type != "A":
            QMessageBox.information(
                self, "Send on new connection", "This isolated transport is available only for Logon (35=A)."
            )
            return
        self.item.working_raw = raw
        self.item.auto_update = policy
        self._refresh_analysis(raw)
        self.new_connection_requested.emit(self.item.item_id, raw, policy)

    def _refresh_analysis(self, raw: bytes) -> None:
        dictionary = self._dictionary_provider()
        policy = self._policy_provider()
        visible = lambda value: value if self._show_sensitive else policy.redact(value, dictionary)
        self.diff.set_messages(visible(self.item.original_raw), visible(raw))
        self.validation.set_message(visible(raw), dictionary)
        parsed = parse_message(visible(raw), dictionary)
        values = [f"{dictionary.message_name(parsed.msg_type)} [{parsed.msg_type}]"]
        for tag, title in (("1", "Account"), ("11", "ClOrdID"), ("34", "Seq")):
            value = parsed.first(tag)
            if value is not None:
                values.append(f"{title}: {value.decode('utf-8', errors='replace')}")
        self.identity.setText(" · ".join(values))

    def _create_fuzzer(self) -> None:
        try:
            raw = self.editor.outbound_raw()
        except (TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Fuzzer baseline", str(exc))
            return
        self.item.working_raw = raw
        self.fuzzer_requested.emit(raw, self.item.title, self.item.item_id)

    def apply_event(self, request: InjectionRequest) -> None:
        self.status.setText(display_status(request.status.value) + (f" - {request.detail}" if request.detail else ""))
        if "destructive" in request.status.value.casefold() or request.status.value == "Failed":
            role(self.status, "danger")
        elif "Injected" in request.status.value or "recovery" in request.status.value.casefold():
            role(self.status, "success")
        else:
            role(self.status, "muted")
        self.refresh_timeline()
        self.refresh_related()

    def refresh_timeline(self) -> None:
        self.timeline.setRowCount(0)
        for run in self.item.runs:
            row = self.timeline.rowCount()
            self.timeline.insertRow(row)
            values = [
                run.queued_at.astimezone().strftime("%H:%M:%S.%f")[:-3],
                run.mode.value,
                display_status(run.status),
                str(run.sequence_number or ""),
                str(run.result_record_id or ""),
                run.detail,
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                if column == 4 and run.result_record_id is not None:
                    cell.setData(Qt.ItemDataRole.UserRole, run.result_record_id)
                self.timeline.setItem(row, column, cell)

    def refresh_related(self) -> None:
        self.related.setRowCount(0)
        seen: set[int] = set()
        for run in self.item.runs:
            if run.result_record_id is None:
                continue
            for score, record_id, direction, msg_type, sequence, evidence in self._related_provider(
                run.result_record_id
            ):
                if record_id in seen:
                    continue
                seen.add(record_id)
                row = self.related.rowCount()
                self.related.insertRow(row)
                for column, value in enumerate(
                    [str(score), str(record_id), display_direction(direction), msg_type, sequence, evidence]
                ):
                    cell = QTableWidgetItem(value)
                    if column == 1:
                        cell.setData(Qt.ItemDataRole.UserRole, record_id)
                    self.related.setItem(row, column, cell)

    def _related_double_clicked(self, row: int, _column: int) -> None:
        item = self.related.item(row, 1)
        record_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        if record_id is not None:
            self.navigate_history.emit(int(record_id))

    def apply_connection_status(self, text: str) -> None:
        self.connection_status.setText(text)
        self.close_connection.setEnabled("open" in text.casefold() or "connecting" in text.casefold())

    def apply_connection_record(self, record: TrafficRecord) -> None:
        row = self.connection_traffic.rowCount()
        self.connection_traffic.insertRow(row)
        policy = self._policy_provider()
        visible = record.raw if self._show_sensitive else policy.redact(record.raw, self._dictionary_provider())
        values = [
            record.timestamp.astimezone().strftime("%H:%M:%S.%f")[:-3],
            display_direction(record.direction),
            f"{record.msg_type} {self._dictionary_provider().message_name(record.msg_type)}",
            str(record.sequence_number or ""),
            record.status,
            raw_to_editor_text(visible),
        ]
        for column, value in enumerate(values):
            self.connection_traffic.setItem(row, column, QTableWidgetItem(value))
        self.connection_traffic.item(row, 5).setData(Qt.ItemDataRole.UserRole, record.raw)
        self.connection_traffic.scrollToBottom()


class RepeaterPanel(QWidget):
    injection_event = Signal(object)
    queue_requested = Signal(str, bytes, object, object)
    new_connection_requested = Signal(str, bytes, object)
    close_connection_requested = Signal(str)
    connection_status = Signal(str, str)
    connection_record = Signal(str, object)
    navigate_history = Signal(int)
    fuzzer_requested = Signal(bytes, str, str)

    def __init__(
        self,
        dictionary_provider: Callable[[], object],
        secret_policy_provider: Callable[[], object],
        related_provider: Callable[[int], list[tuple[int, int, str, str, str, str]]],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._dictionary_provider = dictionary_provider
        self._policy_provider = secret_policy_provider
        self._related_provider = related_provider
        self._editors: dict[str, RepeaterItemEditor] = {}
        self._show_sensitive = False
        layout = QVBoxLayout(self)
        help_text = QLabel(
            "Safe Business Replay and Clone/Edit wait for a plain outbound Heartbeat and substitute only that "
            "sequence slot. Correlated traffic is asynchronous; zero, one, or many later messages may appear."
        )
        help_text.setWordWrap(True)
        contextual_hint(help_text, "Active-session replay ⓘ")
        layout.addWidget(help_text)
        self.tabs = QTabWidget()
        self.tabs.setMovable(True)
        layout.addWidget(self.tabs, 1)
        self.empty = QLabel("Use History → Open in Sender to create a saved item.")
        self.empty.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.tabs.addTab(self.empty, "No items")
        self.connection_status.connect(self._apply_connection_status)
        self.connection_record.connect(self._apply_connection_record)

    def set_reveal(self, reveal: bool) -> None:
        self._show_sensitive = bool(reveal)
        for editor in self._editors.values():
            editor.set_reveal(reveal)

    def add_item(self, item: RepeaterItem) -> RepeaterItemEditor:
        existing = self._editors.get(item.item_id)
        if existing is not None:
            self.tabs.setCurrentWidget(existing)
            return existing
        if self.tabs.indexOf(self.empty) >= 0:
            self.tabs.removeTab(self.tabs.indexOf(self.empty))
        editor = RepeaterItemEditor(
            item,
            self._dictionary_provider,
            self._policy_provider,
            self._related_provider,
        )
        editor.queue_requested.connect(self.queue_requested.emit)
        editor.set_reveal(self._show_sensitive)
        editor.new_connection_requested.connect(self.new_connection_requested.emit)
        editor.close_connection_requested.connect(self.close_connection_requested.emit)
        editor.navigate_history.connect(self.navigate_history.emit)
        editor.fuzzer_requested.connect(self.fuzzer_requested.emit)
        self._editors[item.item_id] = editor
        self.tabs.addTab(editor, item.title)
        self.tabs.setCurrentWidget(editor)
        return editor

    def restore_items(self, items: tuple[RepeaterItem, ...]) -> None:
        while self.tabs.count():
            self.tabs.removeTab(0)
        self._editors.clear()
        if not items:
            self.tabs.addTab(self.empty, "No items")
            return
        for item in items:
            self.add_item(item)

    def apply_event(self, item: RepeaterItem, request: InjectionRequest) -> None:
        editor = self._editors.get(item.item_id)
        if editor is not None:
            editor.apply_event(request)

    def refresh_correlated(self) -> None:
        for editor in self._editors.values():
            editor.refresh_related()

    def _apply_connection_status(self, item_id: str, text: str) -> None:
        editor = self._editors.get(item_id)
        if editor is not None:
            editor.apply_connection_status(text)

    def _apply_connection_record(self, item_id: str, record: TrafficRecord) -> None:
        editor = self._editors.get(item_id)
        if editor is not None:
            editor.apply_connection_record(record)


__all__ = ["RepeaterItemEditor", "RepeaterPanel"]
