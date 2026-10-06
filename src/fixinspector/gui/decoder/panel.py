from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

from PySide6.QtCore import Qt, QSignalBlocker
from PySide6.QtWidgets import (
    QAbstractItemView,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...decoder import DecodedFrame, OfflineDecoder
from ...fix.parser import decode_value, raw_to_editor_text
from ...project.redaction import SecretRedactionPolicy
from ..theme import contextual_hint, role
from ..widgets.flow_layout import FlowLayout
from ..widgets.presentation import table_columns
from ..widgets.message_view import MessageViewTools


class DecoderPanel(QWidget):
    """Offline decode/repair workspace. It never receives a transport object."""

    def __init__(
        self,
        dictionary_provider: Callable[[], object],
        secret_policy_provider: Callable[[], SecretRedactionPolicy],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._dictionary_provider = dictionary_provider
        self._policy_provider = secret_policy_provider
        self._frames: list[DecodedFrame] = []
        layout = QVBoxLayout(self)
        help_text = QLabel(
            "Offline only - paste FIX with real SOH, ␁, |, ^A, <SOH>, or \\x01. "
            "Decode preserves duplicate fields and malformed raw bytes; Repair recalculates BodyLength/CheckSum."
        )
        help_text.setWordWrap(True)
        help_text.setObjectName("mutedLabel")
        contextual_hint(help_text, "Offline Decoder ⓘ")
        layout.addWidget(help_text)

        actions = FlowLayout()
        self.load_button = QPushButton("Load text/raw file…")
        self.decode_button = QPushButton("Decode")
        role(self.decode_button, "primary")
        self.repair_button = QPushButton("Repair selected framing")
        self.repair_button.setEnabled(False)
        self._show_sensitive = False
        self._input_source = ""
        self._input_display = ""
        actions.addWidget(self.load_button)
        actions.addWidget(self.decode_button)
        actions.addWidget(self.repair_button)
        actions.addStretch(1)
        layout.addLayout(actions)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.input = QPlainTextEdit()
        self.input.setPlaceholderText("8=FIXT.1.1|9=...|35=...|10=...|")
        self.input.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        splitter.addWidget(self.input)

        lower = QWidget()
        lower_layout = QVBoxLayout(lower)
        self.frames = QTableWidget(0, 5)
        self.frames.setHorizontalHeaderLabels(["#", "MsgType", "Fields", "Bytes", "Status"])
        self.frames.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.frames.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.frames.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
        self.frames.horizontalHeader().setStretchLastSection(True)
        self.frames.verticalHeader().setVisible(False)
        lower_layout.addWidget(self.frames)
        self.details = QTabWidget()
        self.fields = QTableWidget(0, 4)
        self.fields.setProperty("displayRole", "message")
        self.fields.setHorizontalHeaderLabels(["Wire", "Tag", "Name", "Value"])
        self.fields.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.fields.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.fields.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.fields.horizontalHeader().setStretchLastSection(True)
        self.fields.verticalHeader().setVisible(False)
        self.raw = QPlainTextEdit()
        self.raw.setReadOnly(True)
        self.raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        self.issues = QPlainTextEdit()
        self.issues.setReadOnly(True)
        self.details.addTab(self.fields, "Parsed")
        self.details.addTab(self.raw, "Raw")
        self.details.addTab(self.issues, "Validation")
        self.view_tools = MessageViewTools(self.details, self.fields, default_columns=(1, 2, 3))
        table_columns(self.frames)
        lower_layout.addWidget(self.details, 1)
        splitter.addWidget(lower)
        splitter.setSizes([220, 520])
        layout.addWidget(splitter, 1)
        self.splitter = splitter

        self.load_button.clicked.connect(self._load)
        self.decode_button.clicked.connect(self.decode)
        self.repair_button.clicked.connect(self.repair_selected)
        self.frames.currentCellChanged.connect(lambda *_args: self._show_selected())

    def set_reveal(self, reveal: bool) -> None:
        current = self.input.toPlainText()
        if current != self._input_display:
            self._input_source = current
            self._input_display = current
        self._show_sensitive = bool(reveal)
        self._show_selected()
        self._show_input()

    def set_dictionary(self, _dictionary) -> None:
        if self.input.toPlainText().strip():
            self.decode()

    def decode(self) -> None:
        service = OfflineDecoder(self._dictionary_provider())
        try:
            current = self.input.toPlainText()
            source = self._input_source if current == self._input_display else current
            self._frames = service.decode_text(source)
            self._input_source = source
            self._input_display = current
            self._show_input()
        except (TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Offline Decoder", str(exc))
            return
        self.frames.setRowCount(0)
        for index, frame in enumerate(self._frames, start=1):
            row = self.frames.rowCount()
            self.frames.insertRow(row)
            status = frame.framing_error or ("Validation warnings" if frame.issues else "Parsed")
            values = [str(index), frame.message.msg_type, str(len(frame.message.fields)), str(len(frame.raw)), status]
            for column, value in enumerate(values):
                self.frames.setItem(row, column, QTableWidgetItem(value))
        self.repair_button.setEnabled(bool(self._frames))
        if self._frames:
            self.frames.selectRow(0)
            self._show_selected()
        else:
            self.fields.setRowCount(0)
            self.raw.clear()
            self.issues.setPlainText("No input frames found.")

    def _show_input(self):
        if self.input.toPlainText() != self._input_display:
            return  # Do not overwrite an unprocessed, user-edited input draft.
        self._input_display = self._input_source if self._show_sensitive else self._policy_provider().redact_text(self._input_source)
        blocker = QSignalBlocker(self.input)
        self.input.setPlainText(self._input_display)
        del blocker

    def repair_selected(self) -> None:
        frame = self._selected_frame()
        if frame is None:
            return
        try:
            repaired = OfflineDecoder(self._dictionary_provider()).repair(frame)
        except (TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Cannot repair framing", str(exc))
            return
        self.input.setPlainText(raw_to_editor_text(repaired))
        self.decode()

    def _selected_frame(self) -> DecodedFrame | None:
        row = self.frames.currentRow()
        return self._frames[row] if 0 <= row < len(self._frames) else None

    def _show_selected(self) -> None:
        frame = self._selected_frame()
        if frame is None:
            return
        policy = self._policy_provider()
        reveal = self._show_sensitive
        raw = frame.raw if reveal else policy.redact(frame.raw, self._dictionary_provider())
        message = frame.message
        self.fields.setRowCount(0)
        for index, field in enumerate(message.fields):
            row = self.fields.rowCount()
            self.fields.insertRow(row)
            definition = self._dictionary_provider().field(field.tag)
            value = decode_value(field.value, message.encoding)
            if field.tag in policy.secret_tags and not reveal:
                value = "<REDACTED>"
            for column, item_text in enumerate(
                [str(index), field.tag, definition.name if definition else "", value]
            ):
                self.fields.setItem(row, column, QTableWidgetItem(item_text))
        self.raw.setPlainText(raw_to_editor_text(raw))
        issues = "\n".join(frame.issues) if frame.issues else "No issues detected."
        if not reveal:
            for field in message.fields:
                if field.tag in policy.secret_tags and field.value:
                    issues = issues.replace(decode_value(field.value, message.encoding), "<REDACTED>")
            issues = policy.redact_text(issues)
        self.issues.setPlainText(issues)

    def _load(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Open FIX text/raw file", "", "All files (*)")
        if not path:
            return
        try:
            payload = Path(path).read_bytes()
            if len(payload) > 8 * 1024 * 1024:
                raise ValueError("Decoder files are limited to 8 MiB")
            self.input.setPlainText(payload.decode("utf-8", errors="replace"))
            self.decode()
        except (OSError, ValueError) as exc:
            QMessageBox.warning(self, "Offline Decoder", str(exc))


__all__ = ["DecoderPanel"]
