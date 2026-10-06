"""Reusable presentation adapters; logical field indices and wire order stay intact."""

from PySide6.QtCore import Qt
from PySide6.QtWidgets import QHBoxLayout, QLabel, QMenu, QToolButton, QWidget


class MessageViewTools(QWidget):
    """Columns and optional analysis pages for an existing lossless message view."""

    def __init__(self, tabs, table, *, default_columns=(0, 1, 2, 3), extra_tabs=()):
        super().__init__(tabs)
        self.tabs = tabs
        self.table = table
        self.default_columns = tuple(default_columns)
        layout = QHBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(8)
        self.columns = QToolButton()
        self.columns.setText("Columns")
        self.columns.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.column_menu = QMenu(self.columns)
        self.columns.setMenu(self.column_menu)
        self.column_actions = []
        for column in range(table.columnCount()):
            item = table.horizontalHeaderItem(column)
            action = self.column_menu.addAction(item.text() if item else str(column))
            action.setCheckable(True)
            action.toggled.connect(lambda checked, c=column: table.setColumnHidden(c, not checked))
            self.column_actions.append(action)
        self.column_menu.aboutToShow.connect(self.sync_columns)
        layout.addWidget(self.columns)
        self.reset_columns()
        self.more = QToolButton()
        self.more.setText("More")
        self.more.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.more_menu = QMenu(self.more)
        self.more.setMenu(self.more_menu)
        self.extra_actions = {}
        for index in extra_tabs:
            name = tabs.tabText(index)
            tabs.setTabVisible(index, False)
            action = self.more_menu.addAction(name)
            action.setCheckable(True)
            self.extra_actions[index] = action
            action.toggled.connect(lambda checked, i=index: self._show_extra(i, checked))
        self.more.setVisible(bool(extra_tabs))
        layout.addWidget(self.more)
        tabs.setCornerWidget(self, Qt.Corner.TopRightCorner)

    def show_tab(self, index):
        if index in self.extra_actions:
            self.extra_actions[index].setChecked(True)
        self.tabs.setCurrentIndex(index)

    def _show_extra(self, index, checked):
        self.tabs.setTabVisible(index, checked)
        if checked:
            self.tabs.setCurrentIndex(index)

    def sync_columns(self):
        for column, action in enumerate(self.column_actions):
            action.setChecked(not self.table.isColumnHidden(column))

    def reset_columns(self):
        for column in range(self.table.columnCount()):
            self.table.setColumnHidden(column, column not in self.default_columns)
        self.sync_columns()


class TableEmptyState(QLabel):
    """An empty-table overlay that retains the table, model and selection bindings."""

    def __init__(self, table, text: str):
        super().__init__(text, table.viewport())
        from PySide6.QtCore import QEvent
        self._resize_event = QEvent.Type.Resize
        self.table = table
        self.setProperty("role", "empty")
        self.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.setWordWrap(True)
        self.setAttribute(Qt.WidgetAttribute.WA_TransparentForMouseEvents)
        table.viewport().installEventFilter(self)
        for signal in (table.model().rowsInserted, table.model().rowsRemoved, table.model().modelReset):
            signal.connect(self.refresh)
        self.refresh()

    def refresh(self, *_):
        self.setGeometry(self.table.viewport().rect())
        self.setVisible(self.table.model().rowCount() == 0)
        self.raise_()

    def eventFilter(self, watched, event):
        if event.type() == self._resize_event:
            self.setGeometry(self.table.viewport().rect())
        return False
