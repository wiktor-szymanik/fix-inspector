"""Small presentation helpers; none owns message or protocol state."""
from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtWidgets import QMenu, QToolButton, QVBoxLayout, QWidget

class Disclosure(QWidget):
    def __init__(self, title, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(0, 0, 0, 0)
        self.toggle = QToolButton()
        self.toggle.setText(title)
        self.toggle.setToolTip("Show or hide " + title.lower())
        self.toggle.setCheckable(True)
        self.body = QWidget()
        self.body_layout = QVBoxLayout(self.body)
        self.body_layout.setContentsMargins(0, 0, 0, 0)
        layout.addWidget(self.toggle)
        layout.addWidget(self.body)
        self.toggle.toggled.connect(self.body.setVisible)
        self.body.hide()


def table_columns(table, *, hidden=()):
    """Header column choices, keeping every logical/model index intact."""
    menu = QMenu(table)
    for column in range(table.columnCount()):
        action = menu.addAction(table.horizontalHeaderItem(column).text())
        action.setCheckable(True)
        action.toggled.connect(lambda checked, c=column: table.setColumnHidden(c, not checked))
        if column in hidden:
            table.setColumnHidden(column, True)
    def show(point):
        for column, action in enumerate(menu.actions()):
            blocker = QSignalBlocker(action)
            action.setChecked(not table.isColumnHidden(column))
            del blocker
        menu.exec(table.horizontalHeader().mapToGlobal(point))
    table.horizontalHeader().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
    table.horizontalHeader().customContextMenuRequested.connect(show)
    table.horizontalHeader().setToolTip("Right-click to choose columns; drag borders to resize")
    return menu
