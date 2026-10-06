from __future__ import annotations

from collections.abc import Callable

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QApplication,
    QHBoxLayout,
    QHeaderView,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...fix.fields import FixField
from ...fix.parser import decode_value, editor_text_to_raw, encode_value, parse_message, raw_to_editor_text
from ...fix.serializer import serialize_structured
from ...project.redaction import SecretRedactionPolicy
from ...session.injection import InjectionMode
from .message_analysis import MessageValidationWidget
from .message_view import MessageViewTools, TableEmptyState
from .table_copy import TableCopySupport


class MessageEditorWidget(QWidget):
    """One ordered field/raw editor shared by every Sender mode."""

    def __init__(
        self,
        dictionary_provider: Callable[[], object],
        secret_policy_provider: Callable[[], SecretRedactionPolicy],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self._dictionary_provider = dictionary_provider
        self._policy_provider = secret_policy_provider
        self._working_raw = b""
        self._mode = InjectionMode.BUSINESS_REPLAY
        self._reveal = False
        self._populating = False
        self._editor_index = 0
        layout = QVBoxLayout(self)
        self.tabs = QTabWidget()

        structured_page = QWidget()
        structured_layout = QVBoxLayout(structured_page)
        self.fields = QTableWidget(0, 6)
        self.fields.setProperty("displayRole", "message")
        self.fields.setHorizontalHeaderLabels(["Wire", "Tag", "Name", "Value", "Meaning", "Type"])
        self.fields.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.fields.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.fields.verticalHeader().setVisible(False)
        self.fields.horizontalHeader().setStretchLastSection(False)
        self.fields.horizontalHeader().setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        for column, width in ((1, 80), (2, 220), (4, 230), (5, 110)):
            self.fields.setColumnWidth(column, width)
        structured_layout.addWidget(self.fields, 1)
        buttons = QHBoxLayout()
        self.add_field = QPushButton("Add field")
        self.remove_field = QPushButton("Remove field")
        self.add_field.clicked.connect(self._add_field)
        self.remove_field.clicked.connect(self._remove_field)
        self.fields.itemChanged.connect(self._structured_item_changed)
        buttons.addWidget(self.add_field)
        buttons.addWidget(self.remove_field)
        buttons.addStretch(1)
        structured_layout.addLayout(buttons)

        raw_page = QWidget()
        raw_layout = QVBoxLayout(raw_page)
        self.raw = QPlainTextEdit()
        self.raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        raw_layout.addWidget(self.raw)
        self.tabs.addTab(structured_page, "Parsed")
        self.tabs.addTab(raw_page, "Raw")
        self.validation = MessageValidationWidget()
        self.tabs.addTab(self.validation, "Validation")
        self.view_tools = MessageViewTools(self.tabs, self.fields, default_columns=(1, 2, 3, 4))
        self.empty_state = TableEmptyState(self.fields, "No message loaded.")
        self.copy_support = TableCopySupport(self)
        self.copy_support.install_field_menu(self.fields, tag_column=1, value_column=3)
        self.tabs.currentChanged.connect(self._tab_changed)
        layout.addWidget(self.tabs)

    def set_raw(self, raw: bytes) -> None:
        self._working_raw = bytes(raw)
        self._populate_structured()
        self._populate_raw()
        self._apply_mode()

    def set_mode(self, mode: InjectionMode | str) -> None:
        self._sync_current_editor()
        self._mode = mode if isinstance(mode, InjectionMode) else InjectionMode(str(mode))
        self._apply_mode()

    def set_reveal(self, reveal: bool) -> None:
        self.commit_presentation_draft()
        self._reveal = bool(reveal)
        self._populate_structured()
        self._populate_raw()
        self._apply_mode()
        visible = self._working_raw if self._reveal else self._policy_provider().redact(self._working_raw, self._dictionary_provider())
        self.validation.set_message(visible, self._dictionary_provider())

    def commit_presentation_draft(self) -> None:
        """Commit visible edits without repairing framing during a privacy change."""
        self._commit_active_field_editor()
        if self._mode is not InjectionMode.BUSINESS_REPLAY and self._editor_index == 1 and not self.has_hidden_secret():
            text = self.raw.toPlainText()
            if text != raw_to_editor_text(self._working_raw):
                self._working_raw = editor_text_to_raw(text)

    def has_hidden_secret(self) -> bool:
        policy = self._policy_provider()
        message = parse_message(self._working_raw, self._dictionary_provider())
        return not self._reveal and any(field.tag in policy.secret_tags for field in message.fields)

    def outbound_raw(self, *, repair_raw: bool = True) -> bytes:
        self._commit_active_field_editor()
        if self._mode is InjectionMode.EXACT_RAW:
            if self.has_hidden_secret():
                raise ValueError("Disable masking in Settings → Privacy before exact raw replay")
            self._working_raw = editor_text_to_raw(self.raw.toPlainText())
            return self._working_raw
        if self._mode is InjectionMode.BUSINESS_REPLAY:
            return self._working_raw
        if self._editor_index == 1:
            if self.has_hidden_secret():
                raise ValueError("Disable masking in Settings → Privacy before editing raw FIX")
            parsed = parse_message(editor_text_to_raw(self.raw.toPlainText()), self._dictionary_provider())
            self._working_raw = serialize_structured(parsed.fields) if repair_raw else parsed.raw
        else:
            self._working_raw = self._structured_raw(repair=repair_raw)
        return self._working_raw

    def _structured_raw(self, *, repair: bool = True) -> bytes:
        original = parse_message(self._working_raw, self._dictionary_provider())
        policy = self._policy_provider()
        fields: list[FixField] = []
        for row in range(self.fields.rowCount()):
            tag_item = self.fields.item(row, 1)
            value_item = self.fields.item(row, 3)
            if tag_item is None or value_item is None:
                continue
            tag = tag_item.text().strip()
            if not tag:
                continue
            if tag in policy.secret_tags and not self._reveal:
                original_value = value_item.data(Qt.ItemDataRole.UserRole)
                if not isinstance(original_value, (bytes, bytearray)):
                    raise ValueError(f"Cannot recover redacted tag {tag}")
                value = bytes(original_value)
            else:
                original_value = value_item.data(Qt.ItemDataRole.UserRole)
                original_text = value_item.data(int(Qt.ItemDataRole.UserRole) + 1)
                value = (
                    bytes(original_value)
                    if isinstance(original_value, (bytes, bytearray))
                    and value_item.text() == original_text
                    else encode_value(value_item.text(), original.encoding)
                )
            fields.append(FixField(tag, value))
        if repair:
            return serialize_structured(fields)
        return b"".join(
            field.tag.encode("ascii") + b"=" + bytes(field.value) + b"\x01"
            for field in fields
        )

    def _populate_structured(self) -> None:
        self._populating = True
        try:
            message = parse_message(self._working_raw, self._dictionary_provider())
            policy = self._policy_provider()
            self.fields.setRowCount(0)
            for wire_index, field in enumerate(message.fields):
                row = self.fields.rowCount()
                self.fields.insertRow(row)
                definition = self._dictionary_provider().field(field.tag)
                value = decode_value(field.value, message.encoding)
                display = "<REDACTED>" if field.tag in policy.secret_tags and not self._reveal else value
                for column, text in enumerate(
                    [str(wire_index), field.tag, definition.name if definition else "", display,
                     definition.enums.get(value, "") if definition and display == value else "",
                     definition.field_type if definition else ""]
                ):
                    item = QTableWidgetItem(text)
                    if column == 3:
                        item.setData(Qt.ItemDataRole.UserRole, bytes(field.value))
                        item.setData(int(Qt.ItemDataRole.UserRole) + 1, display)
                    self.fields.setItem(row, column, item)
        finally:
            self._populating = False

    def _populate_raw(self) -> None:
        policy = self._policy_provider()
        display = self._working_raw if self._reveal else policy.redact(
            self._working_raw, self._dictionary_provider()
        )
        self.raw.setPlainText(raw_to_editor_text(display))

    def _sync_current_editor(self) -> None:
        if not self._working_raw or self._mode is InjectionMode.BUSINESS_REPLAY:
            return
        self._commit_active_field_editor()
        try:
            if self._editor_index == 0:
                self._working_raw = self._structured_raw()
            elif not self.has_hidden_secret():
                raw = editor_text_to_raw(self.raw.toPlainText())
                self._working_raw = raw if self._mode is InjectionMode.EXACT_RAW else serialize_structured(
                    parse_message(raw, self._dictionary_provider()).fields
                )
        except (TypeError, ValueError):
            # Keep the current editor text; outbound_raw reports the actionable error.
            return

    def _tab_changed(self, index: int) -> None:
        if self._populating:
            return
        if index >= 2:
            # Inspection must not commit, normalize or replace an unfinished raw
            # draft. Sending still uses the last active editing surface.
            raw = editor_text_to_raw(self.raw.toPlainText()) if self._editor_index == 1 else self._working_raw
            visible = raw if self._reveal else self._policy_provider().redact(raw, self._dictionary_provider())
            self.validation.set_message(visible, self._dictionary_provider())
            return
        if index == self._editor_index:
            return
        self._editor_index = index
        if index == 1:
            try:
                if self._mode is InjectionMode.CLONE_EDIT:
                    self._working_raw = self._structured_raw()
            except (TypeError, ValueError):
                return
            self._populate_raw()
        elif self._mode is not InjectionMode.BUSINESS_REPLAY and not self.has_hidden_secret():
            try:
                raw = editor_text_to_raw(self.raw.toPlainText())
                self._working_raw = raw if self._mode is InjectionMode.EXACT_RAW else serialize_structured(
                    parse_message(raw, self._dictionary_provider()).fields
                )
                self._populate_structured()
            except (TypeError, ValueError):
                return
        self._apply_mode()

    def _apply_mode(self) -> None:
        clone = self._mode is InjectionMode.CLONE_EDIT
        exact = self._mode is InjectionMode.EXACT_RAW
        self.tabs.setTabEnabled(0, not exact)
        if exact:
            self.tabs.setCurrentIndex(1)
        self.fields.setEditTriggers(
            QAbstractItemView.EditTrigger.DoubleClicked | QAbstractItemView.EditTrigger.EditKeyPressed
            if clone
            else QAbstractItemView.EditTrigger.NoEditTriggers
        )
        for row in range(self.fields.rowCount()):
            for column in range(self.fields.columnCount()):
                item = self.fields.item(row, column)
                if item is None:
                    continue
                editable = clone and column in {1, 3}
                tag_item = self.fields.item(row, 1)
                if tag_item and tag_item.text() in self._policy_provider().secret_tags and not self._reveal:
                    editable = False
                flags = item.flags()
                item.setFlags((flags | Qt.ItemFlag.ItemIsEditable) if editable else (flags & ~Qt.ItemFlag.ItemIsEditable))
        self.add_field.setEnabled(clone)
        self.remove_field.setEnabled(clone)
        raw_editable = exact or clone
        if self.has_hidden_secret():
            raw_editable = False
        self.raw.setReadOnly(not raw_editable)

    def _add_field(self) -> None:
        if self._mode is not InjectionMode.CLONE_EDIT:
            return
        row = self.fields.currentRow()
        insert_at = self.fields.rowCount() if row < 0 else row + 1
        if self.fields.rowCount() and insert_at >= self.fields.rowCount():
            last = self.fields.item(self.fields.rowCount() - 1, 1)
            if last and last.text() == "10":
                insert_at = self.fields.rowCount() - 1
        self._populating = True
        try:
            self.fields.insertRow(insert_at)
            for column, value in enumerate([str(insert_at), "", "", "", "", ""]):
                self.fields.setItem(insert_at, column, QTableWidgetItem(value))
        finally:
            self._populating = False
        self._renumber_rows()
        self._apply_mode()
        self.fields.setCurrentCell(insert_at, 1)
        self._store_structured_raw()

    def _remove_field(self) -> None:
        if self._mode is not InjectionMode.CLONE_EDIT:
            return
        row = self.fields.currentRow()
        if row < 0:
            return
        tag = self.fields.item(row, 1).text() if self.fields.item(row, 1) else ""
        if tag in {"8", "9", "10"}:
            QMessageBox.information(self, "Clone/Edit", "Structural fields 8, 9, and 10 are retained in safe mode.")
            return
        self.fields.removeRow(row)
        self._renumber_rows()
        self._store_structured_raw()

    def _commit_active_field_editor(self) -> None:
        editor = QApplication.focusWidget()
        if editor is not None and self.fields.isAncestorOf(editor):
            # The delegate keeps active text outside QTableWidgetItem until it
            # receives commitData. Serialization must see that latest value.
            self.fields.commitData(editor)

    def _structured_item_changed(self, item: QTableWidgetItem) -> None:
        if self._populating or self._mode is not InjectionMode.CLONE_EDIT:
            return
        if item.column() in {1, 3}:
            tag = self.fields.item(item.row(), 1).text().strip()
            definition = self._dictionary_provider().field(tag)
            value = self.fields.item(item.row(), 3).text()
            secret = tag in self._policy_provider().secret_tags and not self._reveal
            self._populating = True
            try:
                for column, text in (
                    (2, definition.name if definition else ""),
                    (4, definition.enums.get(value, "") if definition and not secret else ""),
                    (5, definition.field_type if definition else ""),
                ):
                    cell = self.fields.item(item.row(), column)
                    if cell is not None:
                        cell.setText(text)
            finally:
                self._populating = False
            self._store_structured_raw()

    def _store_structured_raw(self) -> None:
        try:
            self._working_raw = self._structured_raw()
        except (TypeError, ValueError):
            # Retain incomplete input in the table until it becomes a valid
            # ordered FIX field list; outbound_raw reports final errors.
            return
        self._populate_raw()

    def _renumber_rows(self) -> None:
        self._populating = True
        try:
            for row in range(self.fields.rowCount()):
                item = self.fields.item(row, 0)
                if item is not None:
                    item.setText(str(row))
        finally:
            self._populating = False


__all__ = ["MessageEditorWidget"]
