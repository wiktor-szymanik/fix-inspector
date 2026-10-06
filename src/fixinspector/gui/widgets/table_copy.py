from __future__ import annotations

from collections.abc import Callable, Iterable

from PySide6.QtCore import QObject, QPoint, Qt
from PySide6.QtGui import QKeySequence, QShortcut
from PySide6.QtWidgets import QApplication, QMenu, QTableWidget

from ...fix.parser import decode_value, parse_message, raw_to_editor_text


class TableCopySupport(QObject):
    """Reusable cell selection, Ctrl+C, and FIX-aware context menus."""

    def __init__(self, parent=None) -> None:
        super().__init__(parent)
        self._shortcuts: list[QShortcut] = []

    def install_basic_copy(self, table: QTableWidget) -> None:
        shortcut = QShortcut(QKeySequence.StandardKey.Copy, table)
        shortcut.setContext(Qt.ShortcutContext.WidgetWithChildrenShortcut)
        shortcut.activated.connect(lambda current=table: self.copy_selected_cells(current))
        self._shortcuts.append(shortcut)

    def install_field_menu(self, table: QTableWidget, *, tag_column: int = 0, value_column: int = 2) -> None:
        self.install_basic_copy(table)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(
            lambda position, current=table: self._show_field_menu(current, position, tag_column, value_column)
        )

    def install_message_menu(
        self,
        table: QTableWidget,
        record_for_row: Callable[[int], object | None],
        display_raw: Callable[[object], bytes],
        dictionary: Callable[[], object],
        extra_actions: Callable[[object], Iterable[tuple[str, Callable[[], None], bool]]] | None = None,
    ) -> None:
        self.install_basic_copy(table)
        table.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        table.customContextMenuRequested.connect(
            lambda position, current=table: self._show_message_menu(
                current,
                position,
                record_for_row,
                display_raw,
                dictionary,
                extra_actions,
            )
        )

    @staticmethod
    def copy_selected_cells(table: QTableWidget) -> None:
        indexes = sorted(table.selectedIndexes(), key=lambda index: (index.row(), index.column()))
        if not indexes:
            current = table.currentItem()
            if current is None:
                return
            QApplication.clipboard().setText(current.text())
            return
        rows: dict[int, dict[int, str]] = {}
        for index in indexes:
            rows.setdefault(index.row(), {})[index.column()] = index.data() or ""
        minimum_column = min(index.column() for index in indexes)
        maximum_column = max(index.column() for index in indexes)
        lines = [
            "\t".join(rows[row].get(column, "") for column in range(minimum_column, maximum_column + 1))
            for row in sorted(rows)
        ]
        QApplication.clipboard().setText("\n".join(lines))

    def _show_field_menu(self, table: QTableWidget, position: QPoint, tag_column=0, value_column=2) -> None:
        item = table.itemAt(position)
        if item is not None:
            table.setCurrentItem(item)
        row = table.currentRow()
        menu = QMenu(table)
        menu.addAction("Copy selected", lambda: self.copy_selected_cells(table))
        if row >= 0:
            tag_item = table.item(row, tag_column)
            value_item = table.item(row, value_column)
            tag = tag_item.text() if tag_item else ""
            value = value_item.text() if value_item else ""
            menu.addSeparator()
            menu.addAction("Copy value", lambda: QApplication.clipboard().setText(value))
            menu.addAction("Copy tag", lambda: QApplication.clipboard().setText(tag))
            menu.addAction("Copy tag=value", lambda: QApplication.clipboard().setText(f"{tag}={value}"))
        menu.exec(table.viewport().mapToGlobal(position))

    def _show_message_menu(
        self,
        table: QTableWidget,
        position: QPoint,
        record_for_row: Callable[[int], object | None],
        display_raw: Callable[[object], bytes],
        dictionary: Callable[[], object],
        extra_actions: Callable[[object], Iterable[tuple[str, Callable[[], None], bool]]] | None,
    ) -> None:
        item = table.itemAt(position)
        if item is not None:
            table.setCurrentItem(item)
        row = table.currentRow()
        record = record_for_row(row) if row >= 0 else None
        menu = QMenu(table)
        menu.addAction("Copy selected", lambda: self.copy_selected_cells(table))
        if record is not None:
            raw = display_raw(record)
            menu.addSeparator()
            menu.addAction("Copy raw", lambda: QApplication.clipboard().setText(raw_to_editor_text(raw)))
            menu.addAction(
                "Copy readable",
                lambda: QApplication.clipboard().setText(self._readable(raw, dictionary())),
            )
            if extra_actions is not None:
                menu.addSeparator()
                for label, callback, enabled in extra_actions(record):
                    action = menu.addAction(label, lambda _checked=False, action=callback: action())
                    action.setEnabled(enabled)
        menu.exec(table.viewport().mapToGlobal(position))

    @staticmethod
    def _readable(raw: bytes, dictionary) -> str:
        message = parse_message(raw, dictionary)
        lines: list[str] = []
        for field in message.fields:
            definition = dictionary.field(field.tag) if dictionary else None
            name = f" {definition.name}" if definition else ""
            value = decode_value(field.value, message.encoding)
            lines.append(f"{field.tag}{name}={value}")
        if not lines:
            return raw_to_editor_text(raw)
        return "\n".join(lines)
