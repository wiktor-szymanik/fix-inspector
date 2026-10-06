"""Unified Rules surface; fixed engine tiers and event triggers remain explicit."""

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QDialog, QHBoxLayout, QLabel, QMenu, QMessageBox, QPushButton, QTableWidget,
    QTableWidgetItem, QTabWidget, QToolButton, QVBoxLayout, QWidget,
)

from .rules_adapter import RulesAdapter
from .rule_editor import RuleEditor
from ..proxy_behaviour.panel import ProxyBehaviourPanel
from ..theme import role
from ..widgets.message_view import TableEmptyState
from ..widgets.flow_layout import FlowLayout


class QueueJournalPanel(ProxyBehaviourPanel):
    """Reuse the established queue actions without constructing legacy policy UI."""

    def __init__(self, engine, policy_provider, parent):
        QWidget.__init__(self, parent)
        self.engine = engine
        self.controller = engine.proxy_behaviour
        self.secret_tags = lambda: policy_provider().secret_tags
        QVBoxLayout(self).addWidget(self._build_queue_journal())

    def refresh(self):
        self._refresh_queue(self.engine.pending_records())
        self._refresh_events(self.controller.snapshot().events)


class RulesPanel(QWidget):
    state_changed = Signal()

    def __init__(self, engine, policy_provider, parent=None):
        super().__init__(parent)
        self.engine = engine
        self.adapter = RulesAdapter(engine, policy_provider)
        self._rows = []
        self._rendered_rows = None
        self._updating = False
        layout = QVBoxLayout(self)
        actions = FlowLayout()
        self.add = QPushButton("+ Add rule")
        role(self.add, "primary")
        self.add.clicked.connect(self.add_rule)
        actions.addWidget(self.add)
        presets = QToolButton()
        presets.setText("Presets")
        presets.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        menu = QMenu(presets)
        for label, preset in (("Clean", "Clean"), ("Server latency · 5 s", "Server response delay"),
                              ("Drop server application traffic", "Ambiguous application delivery"),
                              ("Drop client application traffic", "Client request blackhole")):
            menu.addAction(label, lambda _checked=False, name=preset: self.apply_preset(name))
        presets.setMenu(menu)
        actions.addWidget(presets)
        self.reset_button = QPushButton("Reset proxy behaviour")
        self.reset_button.clicked.connect(self.reset)
        actions.addWidget(self.reset_button)
        precedence = QLabel("Precedence ⓘ")
        precedence.setToolTip("1 Global Drop/Pause → 2 one-shot → 3 first matching ordered rule → 4 category default → 5 direction delay → NORMAL. Disconnect triggers are independent. Only tier 3 is reorderable.")
        actions.addWidget(precedence)
        actions.addStretch(1)
        layout.addLayout(actions)
        self.tabs = QTabWidget()
        page = QWidget()
        page_layout = QVBoxLayout(page)
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(["Order", "Enabled", "Direction", "Match", "Action", "Summary"])
        self.table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.table.verticalHeader().hide()
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setColumnWidth(2, 190)
        self.table.setColumnWidth(3, 290)
        self.table.itemChanged.connect(self._checked)
        self.table.cellDoubleClicked.connect(lambda *_: self.edit_rule())
        page_layout.addWidget(self.table, 1)
        self.empty = TableEmptyState(self.table, "No active overrides or saved rules.\nNormal forwarding policy.")
        buttons = FlowLayout()
        for label, callback in (("Edit", self.edit_rule), ("Remove / disable", self.remove),
                                ("Move up", lambda: self.move(-1)), ("Move down", lambda: self.move(1))):
            button = QPushButton(label)
            button.clicked.connect(callback)
            buttons.addWidget(button)
        buttons.addStretch(1)
        page_layout.addLayout(buttons)
        self.tabs.addTab(page, "Rules")
        # Retain only the existing queue/journal operations, not the mirrored
        # policy panels. No second independent queue implementation is introduced.
        self.legacy = QueueJournalPanel(engine, policy_provider, self)
        self.tabs.addTab(self.legacy, "Queue / journal")
        self.legacy.state_changed.connect(self._changed)
        layout.addWidget(self.tabs)
        self.refresh()

    def selected(self):
        index = self.table.currentRow()
        return self._rows[index] if 0 <= index < len(self._rows) else None

    def _changed(self):
        self._rendered_rows = None
        self.state_changed.emit()
        self.refresh()

    def refresh(self):
        rows = self.adapter.rows()
        if rows != self._rendered_rows:
            selected = self.selected()
            self._updating = True
            self.table.setRowCount(len(rows))
            for index, row in enumerate(rows):
                values = [row.priority, "", self.adapter.direction_text(row), row.match, row.action.title(), row.summary]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    item.setToolTip(value)
                    if column == 1:
                        if row.key[0] != "disconnect":
                            item.setFlags(item.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                            item.setCheckState(Qt.CheckState.Checked if row.enabled else Qt.CheckState.Unchecked)
                        else:
                            item.setText("Armed")
                            item.setToolTip("Independent event trigger. Individual cancellation is not supported by the engine; use Reset.")
                    self.table.setItem(index, column, item)
                if selected and selected.key == row.key:
                    self.table.selectRow(index)
            self._rows = rows
            self._rendered_rows = rows
            self._updating = False
        self.legacy._refresh_queue(self.engine.pending_records())
        self.legacy._refresh_events(self.adapter.controller.snapshot().events)

    def _edit(self, row=None):
        if row and not row.editable:
            QMessageBox.information(self, "Disconnect trigger", "The engine has no individual trigger editor. Use Reset proxy behaviour to clear triggers.")
            return
        dialog = RuleEditor(self.adapter, self, row)
        while dialog.exec() == QDialog.DialogCode.Accepted:
            try:
                self.adapter.apply(dialog.values(), row=row)
            except ValueError as exc:
                QMessageBox.warning(self, "Rule", str(exc))
                continue
            self._changed()
            break

    def add_rule(self):
        self._edit()

    def edit_rule(self):
        row = self.selected()
        if row:
            self._edit(row)

    def _checked(self, item):
        if not self._updating and item.column() == 1 and item.row() < len(self._rows):
            self.adapter.set_enabled(self._rows[item.row()], item.checkState() == Qt.CheckState.Checked)
            self._changed()

    def remove(self):
        row = self.selected()
        if row:
            try:
                self.adapter.disable_or_delete(row, delete=True)
                self._changed()
            except ValueError as exc:
                QMessageBox.information(self, "Rule", str(exc))

    def move(self, offset):
        row = self.selected()
        if row:
            try:
                self.adapter.move(row, offset)
                self._changed()
            except ValueError as exc:
                QMessageBox.information(self, "Fixed precedence", str(exc))

    def reset(self):
        # Reuse existing confirmation and engine reset, including its explicit
        # held-queue discard contract. This is not silently converted to Forward.
        self.legacy._reset()
        self.refresh()

    def apply_preset(self, name):
        if name == "Clean":
            self.reset()
        else:
            self.adapter.controller.apply_preset(name)
            self._changed()
