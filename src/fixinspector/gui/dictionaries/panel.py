from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QAbstractItemView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...fix.dictionary import FixDictionary
from ..widgets.presentation import table_columns


class DictionaryBrowserPanel(QWidget):
    """Searchable, read-only projection of loaded FIX dictionaries."""

    def __init__(self, dictionary: FixDictionary | None = None, parent=None) -> None:
        super().__init__(parent)
        self.dictionary = dictionary or FixDictionary()
        layout = QVBoxLayout(self)
        toolbar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search tag, field/message name, type, enum, group…")
        self.summary = QLabel()
        toolbar.addWidget(self.search, 1)
        toolbar.addWidget(self.summary)
        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Vertical)
        self.tabs = QTabWidget()
        self.fields = QTableWidget(0, 6)
        self.fields.setHorizontalHeaderLabels(["Tag", "Name", "Type", "Enums", "Custom", "Used by"])
        self.messages = QTableWidget(0, 6)
        self.messages.setHorizontalHeaderLabels(["MsgType", "Name", "Category", "Required", "Groups", "Fields"])
        for table in (self.fields, self.messages):
            table.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
            table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)
            table.setSortingEnabled(True)
            table.horizontalHeader().setStretchLastSection(True)
            table.verticalHeader().setVisible(False)
        self.tabs.addTab(self.fields, "Fields")
        self.tabs.addTab(self.messages, "Messages")
        splitter.addWidget(self.tabs)
        self.details = QPlainTextEdit()
        self.details.setReadOnly(True)
        splitter.addWidget(self.details)
        splitter.setSizes([560, 220])
        layout.addWidget(splitter, 1)

        self.search.textChanged.connect(self._filter)
        self.fields.itemSelectionChanged.connect(self._field_selected)
        self.messages.itemSelectionChanged.connect(self._message_selected)
        self.refresh(self.dictionary)
        table_columns(self.fields)
        table_columns(self.messages)

    def refresh(self, dictionary: FixDictionary) -> None:
        self.dictionary = dictionary
        self.fields.setSortingEnabled(False)
        self.fields.setRowCount(0)
        for definition in sorted(dictionary.fields_by_tag.values(), key=lambda item: int(item.tag)):
            row = self.fields.rowCount()
            self.fields.insertRow(row)
            usages = dictionary.messages_using_tag(definition.tag)
            enums = "; ".join(f"{value}={meaning}" for value, meaning in definition.enums.items())
            try:
                custom = "Y" if int(definition.tag) >= 5000 else ""
            except ValueError:
                custom = "Y"
            values = [
                definition.tag,
                definition.name,
                definition.field_type,
                enums,
                custom,
                ", ".join(f"{item.msg_type}/{item.name}" for item in usages),
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setToolTip(value)
                self.fields.setItem(row, column, cell)
        self.fields.setSortingEnabled(True)

        self.messages.setSortingEnabled(False)
        self.messages.setRowCount(0)
        for definition in sorted(dictionary.messages.values(), key=lambda item: item.msg_type):
            row = self.messages.rowCount()
            self.messages.insertRow(row)
            groups = "; ".join(
                f"{group.count_tag}/{group.name} delimiter={group.delimiter_tag or '?'}"
                for group in definition.groups
            )
            values = [
                definition.msg_type,
                definition.name,
                definition.category,
                ", ".join(sorted(definition.required_tags, key=lambda value: int(value))),
                groups,
                str(len(definition.tag_paths)),
            ]
            for column, value in enumerate(values):
                cell = QTableWidgetItem(value)
                cell.setToolTip(value)
                self.messages.setItem(row, column, cell)
        self.messages.setSortingEnabled(True)
        def groups(items):
            return sum(1 + groups(item.nested_groups) for item in items)
        count = sum(groups(message.groups) for message in dictionary.messages.values())
        self.summary.setText(f"{len(dictionary.fields_by_tag)} fields · {len(dictionary.messages)} messages · {count} repeating groups")
        self._filter(self.search.text())

    def _filter(self, text: str) -> None:
        needle = text.strip().casefold()
        for table in (self.fields, self.messages):
            for row in range(table.rowCount()):
                visible = not needle or any(
                    needle in (table.item(row, column).text() if table.item(row, column) else "").casefold()
                    for column in range(table.columnCount())
                )
                table.setRowHidden(row, not visible)

    def _field_selected(self) -> None:
        row = self.fields.currentRow()
        tag_item = self.fields.item(row, 0) if row >= 0 else None
        definition = self.dictionary.field(tag_item.text()) if tag_item else None
        if definition is None:
            return
        usage = self.dictionary.messages_using_tag(definition.tag)
        try:
            custom = int(definition.tag) >= 5000
        except ValueError:
            custom = True
        lines = [
            f"{definition.tag} - {definition.name}",
            f"Type: {definition.field_type}",
            f"Custom/vendor: {'yes' if custom else 'no'}",
            "",
            "Enums:",
        ]
        lines.extend(f"  {value} = {meaning}" for value, meaning in definition.enums.items())
        if not definition.enums:
            lines.append("  (none)")
        lines.extend(["", "Messages / paths:"])
        for message in usage:
            path = " / ".join(message.tag_paths.get(definition.tag, [])) or "top level"
            lines.append(f"  {message.msg_type} {message.name}: {path}")
        self.details.setPlainText("\n".join(lines))

    def _message_selected(self) -> None:
        row = self.messages.currentRow()
        item = self.messages.item(row, 0) if row >= 0 else None
        definition = self.dictionary.message(item.text()) if item else None
        if definition is None:
            return
        required = ", ".join(sorted(definition.required_tags, key=lambda value: int(value))) or "(none)"
        lines = [
            f"{definition.msg_type} - {definition.name}",
            f"Category: {definition.category}",
            f"Required tags: {required}",
            "",
            "Repeating groups:",
        ]
        for group in definition.groups:
            members = ", ".join(group.member_tags) or "(unknown)"
            lines.append(
                f"  {group.count_tag} {group.name}; delimiter {group.delimiter_tag or '?'}; members {members}"
            )
        if not definition.groups:
            lines.append("  (none)")
        self.details.setPlainText("\n".join(lines))


__all__ = ["DictionaryBrowserPanel"]
