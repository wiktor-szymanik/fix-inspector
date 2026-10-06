"""Proxy-specific composition; controller ownership and wire actions are unchanged."""

from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QHeaderView, QLabel, QMenu, QPushButton, QToolButton, QVBoxLayout, QWidget,
)

from ..history.filters import HistoryFilters
from ..theme import role
from ..widgets.flow_layout import FlowLayout


class ProxyWorkspace:
    def __init__(self, window, shell):
        self.window = window
        self.shell = shell
        self.page = QWidget()
        layout = QVBoxLayout(self.page)
        self.header = FlowLayout()
        self.proxy = QLabel()
        self.session = QLabel()
        self.queue = QLabel()
        self.error = QLabel()
        self.error.setWordWrap(True)
        role(self.error, "danger")
        old_control_box = window.start_button.parentWidget()
        for control in (self.proxy, self.session, self.queue, window.start_button, window.stop_button):
            self.header.addWidget(control)
        old_control_box.hide()
        layout.addLayout(self.header)
        layout.addWidget(self.error)
        selected_workspace = window.workspace_tabs.currentIndex()
        window.workspace_tabs.removeTab(0)
        layout.addWidget(shell.proxy_tabs)
        window.workspace_tabs.insertTab(0, self.page, "Proxy")
        window.workspace_tabs.setCurrentIndex(selected_workspace)
        shell.proxy_tabs.show()
        self._intercept()
        history_page = shell.pages["History"].widget()
        self.filters = HistoryFilters(window, history_page)
        self._columns()
        self._scope()
        shell.history_tools.extra_actions[3].setChecked(False)
        # Diff joins the More menu; existing tab index stays valid in projects.
        index = 4
        window.history_inspector.setTabVisible(index, False)
        action = shell.history_tools.more_menu.addAction("Diff")
        action.setCheckable(True)
        action.toggled.connect(lambda checked: shell.history_tools._show_extra(index, checked))
        shell.history_tools.extra_actions[index] = action
        self.refresh()

    def _intercept(self):
        w = self.window
        w.intercept_splitter.setOrientation(Qt.Orientation.Horizontal)
        w.intercept_splitter.setSizes([560, 1120])
        w.intercept_splitter.setStretchFactor(0, 1)
        w.intercept_splitter.setStretchFactor(1, 2)
        old_tabs = w.intercept_editor_tabs
        box = old_tabs.parentWidget()
        layout = box.layout()
        index = layout.indexOf(old_tabs)
        old_tabs.removeTab(old_tabs.indexOf(w.proxy_shared_editor))
        old_tabs.hide()
        layout.insertWidget(index, w.proxy_shared_editor, 1)
        w.proxy_shared_editor.show()
        toolbar = self.shell.pages["Intercept"].widget().layout().itemAt(0).layout()
        toolbar.insertWidget(3, w.revert_button)
        w.revert_button.show()
        w.structured_mode.hide()
        w.raw_mode.hide()
        w.intercept_policy_label.hide()
        w.intercept_proxy_label.hide()
        for label in w._queue_box.findChildren(QLabel, options=Qt.FindChildOption.FindDirectChildrenOnly):
            label.hide()
        w._queue_box.setToolTip("FIX message ordering is preserved. Messages behind a held message remain queued. Resolve HELD before QUEUED.")
        w.intercept_master.setToolTip("Enable or disable interception using Proxy Settings scope")
        w.proxy_behaviour_status.hide()  # Rules tab + shared status replace the long policy sentence.
        w._refresh_intercept_details()

    def _columns(self):
        w = self.window
        # Interactive widths stay stable across font changes and are persisted.
        w.history.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        if not w._as_bool(w._settings().value("ui/proxy_phase2_columns", False)):
            for column, width in enumerate((70, 170, 190, 65, 230, 80, 115, 190, 140, 170, 130, 140, 130, 110)):
                if column < w.history.columnCount():
                    w.history.setColumnWidth(column, width)
        self.columns = QToolButton()
        self.columns.setText("Columns")
        self.columns.setPopupMode(QToolButton.ToolButtonPopupMode.InstantPopup)
        self.column_menu = QMenu(self.columns)
        self.columns.setMenu(self.column_menu)
        self._column_actions = []
        for column in range(w.history.columnCount()):
            action = self.column_menu.addAction(w.history.horizontalHeaderItem(column).text())
            action.setCheckable(True)
            action.toggled.connect(lambda checked, c=column: w.history.setColumnHidden(c, not checked))
            self._column_actions.append(action)
        self.column_menu.aboutToShow.connect(self._sync_columns)
        self.shell.pages["History"].widget().layout().itemAt(0).layout().addWidget(self.columns)
        w.history.horizontalHeader().setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        w.history.horizontalHeader().customContextMenuRequested.connect(self._header_menu)
        if not w._as_bool(w._settings().value("ui/proxy_phase2_columns", False)):
            self.reset_columns()
        self._sync_columns()

    def reset_columns(self):
        w = self.window
        for column in range(w.history.columnCount()):
            w.history.setColumnHidden(column, column not in {1, 2, 3, 4, 5, 6, 7, 9})
        for column in range(w.held_table.columnCount()):
            w.held_table.setColumnHidden(column, column not in {2, 4, 6})

    def _sync_columns(self):
        for column, action in enumerate(self._column_actions):
            action.setChecked(not self.window.history.isColumnHidden(column))

    def _header_menu(self, point):
        self._sync_columns()
        self.column_menu.exec(self.window.history.horizontalHeader().mapToGlobal(point))

    def _scope(self):
        w = self.window
        self._policy_controls = (w.intercept_c2s_policy, w.intercept_s2c_policy,
                                 w.intercept_c2s_admin_policy, w.intercept_s2c_admin_policy)
        self.scope = QComboBox()
        self.scope.addItems(["Application messages", "Session/Admin", "All", "Custom"])
        self.directions = QComboBox()
        self.directions.addItems(["Client → Server", "Server → Client", "Both", "Custom"])
        form = w.intercept_c2s_policy.parentWidget().layout()
        form.addWidget(QLabel("Intercept direction"), 4, 0)
        form.addWidget(self.directions, 4, 1)
        form.addWidget(QLabel("Intercept scope"), 4, 2)
        form.addWidget(self.scope, 4, 3)
        self._sync_scope()
        self.scope.currentIndexChanged.connect(self._apply_scope)
        self.directions.currentIndexChanged.connect(self._apply_scope)
        for control in self._policy_controls:
            control.toggled.connect(self._sync_scope)

    def _sync_scope(self, *_):
        app_c, app_s, admin_c, admin_s = [control.isChecked() for control in self._policy_controls]
        left, right = (app_c, admin_c), (app_s, admin_s)
        direction = 2 if left == right and any(left) else 0 if any(left) and not any(right) else 1 if any(right) and not any(left) else 3
        pair = left if any(left) else right
        scope = 2 if all(pair) else 0 if pair == (True, False) else 1 if pair == (False, True) else 3
        if direction == 3:
            scope = 3
        blockers = [QSignalBlocker(self.scope), QSignalBlocker(self.directions)]
        self.scope.setCurrentIndex(scope)
        self.directions.setCurrentIndex(direction)
        del blockers
        self._custom_visibility()

    def _custom_visibility(self):
        custom = self.scope.currentIndex() == 3 or self.directions.currentIndex() == 3
        for control in self._policy_controls:
            control.setVisible(custom)

    def _apply_scope(self):
        self._custom_visibility()
        scope, direction = self.scope.currentIndex(), self.directions.currentIndex()
        if 3 in (scope, direction):
            return
        blockers = [QSignalBlocker(control) for control in self._policy_controls]
        flags = (direction in {0, 2} and scope in {0, 2}, direction in {1, 2} and scope in {0, 2},
                 direction in {0, 2} and scope in {1, 2}, direction in {1, 2} and scope in {1, 2})
        for control, checked in zip(self._policy_controls, flags):
            control.setChecked(checked)
        del blockers
        self.window._update_intercept()
        self.window._save_settings()

    def refresh(self):
        w = self.window
        snapshot = w.engine.diagnostics()
        running = snapshot.listener_state.startswith("Listening ")
        error = bool(snapshot.last_transport_error)
        self.proxy.setText("Proxy ● Running" if running else "Proxy ● " + snapshot.listener_state)
        role(self.proxy, "danger" if error else "success" if running else "muted")
        active = bool(snapshot.client_session_id and snapshot.upstream_state.startswith("Connected "))
        self.session.setText("FIX session ● Observed" if active else "FIX session ● Inactive")
        role(self.session, "success" if active else "muted")
        self.queue.setText(f"Held {snapshot.held_count} · Queued {snapshot.queued_count}")
        text = w.secret_policy.redact_text(snapshot.last_transport_error)
        self.error.setText(text[:180])
        self.error.setToolTip(text)
        self.error.setVisible(bool(text))
        w.intercept_master.setText("Intercept ON" if w.intercept_master.isChecked() else "Intercept OFF")
        w._queue_box.setTitle("Intercept queue")
        record = w.records.get(w.selected_intercept_record_id or -1)
        if record:
            w.intercept_message_title.setText(f"{w.dictionary.message_name(record.msg_type)} [{record.msg_type}] · Seq {record.sequence_number or '-'} · {record.status}")
        else:
            w.intercept_message_title.setText("No intercepted message selected")

    def close(self):
        self.filters.dialog.close()
