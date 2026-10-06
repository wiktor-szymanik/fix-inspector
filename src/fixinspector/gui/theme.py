"""Shared desktop design tokens. Protocol/traffic semantics do not live here."""

BLUE = "#2563a6"
BLUE_LIGHT = "#edf4fc"
GREEN = "#18794e"
AMBER = "#946200"
RED = "#b42318"
MUTED = "#667085"
SPACE = 8

STYLESHEET = """
QWidget { font-size: 10pt; color: #243247; }
QMainWindow, QDialog { background: #f6f8fb; }
QTabWidget::pane { border: 1px solid #d6dce5; background: white; }
QTabBar::tab { padding: 8px 16px; background: #f6f8fb; border-bottom: 2px solid transparent; }
QTabBar::tab:selected { color: #2563a6; background: #edf4fc; border-bottom-color: #2563a6; font-weight: 600; }
QTabWidget#workspaceTabs > QTabBar::tab { padding: 12px 24px; }
QTabWidget#proxyTabs > QTabBar::tab { padding: 8px 16px; }
QPushButton, QToolButton { padding: 6px 12px; border: 1px solid #c7d0dc; border-radius: 4px; background: #ffffff; }
QPushButton:hover, QToolButton:hover { border-color: #2563a6; background: #edf4fc; }
QPushButton[role="primary"], QPushButton#forwardButton, QPushButton#interceptToggle:checked {
    background: #2563a6; color: white; border-color: #2563a6; font-weight: 600;
}
QPushButton[role="danger"], QPushButton#dropButton { color: #b42318; border-color: #dcb1ae; }
QPushButton:disabled, QToolButton:disabled { color: #8993a2; background: #f2f4f7; border-color: #e1e5ec; }
QPushButton#forwardButton:disabled, QPushButton#dropButton:disabled, QPushButton[role="primary"]:disabled {
    color: #8993a2; background: #f2f4f7; border-color: #e1e5ec;
}
QGroupBox { font-weight: 600; border: 1px solid #d6dce5; border-radius: 4px; margin-top: 16px; padding: 8px; }
QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
QLabel[role="section"] { font-weight: 600; }
QLabel[role="muted"], QLabel#mutedLabel { color: #667085; }
QLabel[role="success"] { color: #18794e; }
QLabel[role="warning"], QLabel#deadlineLabel { color: #946200; }
QLabel[role="danger"] { color: #b42318; }
QLabel[role="badge"] { color: #2563a6; background: #edf4fc; padding: 4px 8px; border-radius: 4px; }
QLabel[role="empty"] { color: #667085; padding: 24px; }
QTableView, QTreeView, QListWidget, QPlainTextEdit, QTextBrowser {
    background: white; border: 1px solid #d6dce5; gridline-color: #edf0f5;
    selection-background-color: #d4e5fa; selection-color: #163963;
}
QHeaderView::section { background: #f6f8fb; border: 0; border-bottom: 1px solid #d6dce5; padding: 8px; font-weight: 600; }
QTableView::item:hover { background: #edf4fc; }
QLineEdit, QSpinBox, QDoubleSpinBox, QComboBox { padding: 4px; border: 1px solid #c7d0dc; border-radius: 3px; background: white; }
QLineEdit:focus, QPlainTextEdit:focus, QComboBox:focus { border-color: #2563a6; }
QToolTip { color: #243247; background: #f6f8fb; border: 1px solid #c7d0dc; padding: 8px; }
QMenu { background: white; border: 1px solid #d6dce5; }
QMenu::item { padding: 6px 24px; }
QMenu::item:selected { background: #edf4fc; color: #2563a6; }
QStatusBar { background: #f6f8fb; }
"""


def role(widget, value: str) -> None:
    if widget.property("role") == value:
        return
    widget.setProperty("role", value)
    widget.style().unpolish(widget)
    widget.style().polish(widget)


def contextual_hint(label, text: str, detail: str | None = None) -> None:
    """Retain help on demand instead of allocating permanent paragraph space."""
    label.setToolTip(detail or label.text())
    label.setText(text)
    role(label, "muted")
