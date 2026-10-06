"""Desktop navigation and UI composition over unchanged product controllers."""

from pathlib import Path

from PySide6.QtCore import Qt, QSignalBlocker
from PySide6.QtGui import QKeySequence
from PySide6.QtWidgets import (
    QDialog, QDialogButtonBox, QFormLayout, QGroupBox, QHBoxLayout, QLabel,
    QMessageBox, QPushButton, QScrollArea, QTabWidget, QTextBrowser,
    QToolButton, QVBoxLayout, QWidget,
)

from .. import __version__
from .diagnostics.troubleshooting import TroubleshootingDialog
from .settings.presentation import scrollable
from .theme import contextual_hint, role
from .widgets.message_view import MessageViewTools, TableEmptyState


def content(page):
    return page.widget() if isinstance(page, QScrollArea) else page


class WorkspaceShell:
    """Owns presentation only. Existing controls are moved, never recreated.

    Legacy project tab integers retain their historical meaning through the
    explicit route map; neither the SQLite schema nor controller state changes.
    """

    LEGACY_ROUTES = ("Intercept", "History", "Settings", "Sender", "Composer", "Fuzzer", "Decoder", "Dictionaries", "Troubleshooting")

    def __init__(self, window):
        self.window = window
        self.pages = {}
        tabs = window.workspace_tabs
        selected = tabs.currentIndex()
        while tabs.count():
            self.pages[tabs.tabText(0)] = tabs.widget(0)
            tabs.removeTab(0)
        self.proxy_tabs = QTabWidget()
        self.proxy_tabs.setObjectName("proxyTabs")
        self.proxy_tabs.addTab(self.pages["Intercept"], "Intercept")
        self.proxy_tabs.addTab(self.pages["History"], "History")
        # Move the Rules adapter with its existing scroll container intact.
        rules = QWidget()
        rules_layout = QVBoxLayout(rules)
        behaviour_page = window.configuration_sections.widget(1)
        window.configuration_sections.removeTab(1)
        rules_layout.addWidget(behaviour_page)
        behaviour_page.show()
        self.proxy_tabs.addTab(scrollable(rules), "Rules")
        self.proxy_tabs.addTab(self.pages["Configuration"], "Settings")
        tabs.addTab(self.proxy_tabs, "Proxy")
        for name in ("Sender", "Composer", "Fuzzer", "Decoder", "Dictionaries"):
            tabs.addTab(self.pages[name], name)

        self._settings_dialog()
        self.troubleshooting = TroubleshootingDialog(window, self.pages["Diagnostics"])
        self._menus()
        self._message_views()
        self._compact_proxy()
        self._status()
        self.restore_legacy_index(selected, show_dialog=False)
        self.refresh()

    def _settings_dialog(self):
        w = self.window
        self.settings = QDialog(w)
        self.settings.setWindowTitle("Settings - FIX Inspector")
        self.settings.resize(800, 620)
        outer = QVBoxLayout(self.settings)
        self.settings_tabs = QTabWidget()
        outer.addWidget(self.settings_tabs, 1)
        general = QWidget()
        general_form = QFormLayout(general)
        general_form.addRow(w.config_hide_heartbeats)
        general_form.addRow(w.config_hide_admin)
        self.settings_tabs.addTab(scrollable(general), "General")
        # PresentationController created this panel using the old construction
        # path; retain its signals/state and remove just its old tab wrapper.
        display = w.configuration_sections.widget(1)
        w.configuration_sections.removeTab(1)
        self.settings_tabs.addTab(display, "Display")
        privacy = QWidget()
        privacy_layout = QFormLayout(privacy)
        privacy_layout.addRow(w.mask_sensitive_fields)
        privacy_layout.addRow(QLabel("Sensitive field values are masked throughout the application."))
        privacy_layout.addRow("Always sensitive", QLabel("553"))
        privacy_layout.addRow("Additional sensitive tags", w.additional_secret_tags)
        privacy_layout.addRow(w.secret_policy_error)
        privacy_layout.addRow(w.apply_secret_tags)
        self.settings_tabs.addTab(scrollable(privacy), "Privacy")
        advanced = QWidget()
        advanced_form = QFormLayout(advanced)
        advanced_form.addRow("In-memory History limit", w.history_limit)
        self.settings_tabs.addTab(scrollable(advanced), "Advanced")
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        buttons.rejected.connect(self.settings.close)
        self.settings.finished.connect(lambda _: w._save_settings())
        outer.addWidget(buttons)

        general_proxy = content(w.configuration_sections.widget(0))
        # Remove the emptied History / secrets group, not any of its controls.
        for box in general_proxy.findChildren(QGroupBox):
            if box.title() == "History and secrets":
                box.hide()
        # Dictionary loading belongs next to browsing. Move the existing group.
        dictionary_box = w.transport_dict.parentWidget()
        w.dictionary_browser.layout().insertWidget(0, dictionary_box)
        w.configuration_sections.tabBar().hide()
        self.settings_button = QToolButton()
        self.settings_button.setText("Settings")
        self.settings_button.setToolTip("Global display, privacy and application preferences")
        self.settings_button.clicked.connect(self.show_settings)
        w.workspace_tabs.setCornerWidget(self.settings_button, Qt.Corner.TopRightCorner)

    def show_settings(self, *_):
        self.settings.show()
        self.settings.raise_()
        self.settings.activateWindow()

    def show_troubleshooting(self, *_):
        self.window._refresh_diagnostics()
        self.troubleshooting.show()
        self.troubleshooting.raise_()

    def navigate(self, route: str):
        w = self.window
        if route in ("Intercept", "History", "Rules", "Settings"):
            w.workspace_tabs.setCurrentIndex(0)
            self.proxy_tabs.setCurrentIndex(("Intercept", "History", "Rules", "Settings").index(route))
        elif route == "Troubleshooting":
            self.show_troubleshooting()
        elif route in self.pages:
            w.workspace_tabs.setCurrentWidget(self.pages[route])

    def legacy_index(self) -> int:
        tabs = self.window.workspace_tabs
        route = tabs.tabText(tabs.currentIndex())
        if route == "Proxy":
            route = self.proxy_tabs.tabText(self.proxy_tabs.currentIndex())
        if route == "Rules":
            route = "Settings"
        return self.LEGACY_ROUTES.index(route) if route in self.LEGACY_ROUTES else 0

    def restore_legacy_index(self, index, *, show_dialog=True):
        if 0 <= index < len(self.LEGACY_ROUTES):
            route = self.LEGACY_ROUTES[index]
            self.navigate(route if show_dialog or route != "Troubleshooting" else "Intercept")

    def _menus(self):
        w = self.window
        old = {action.text(): action.menu() for action in w.menuBar().actions() if action.menu()}
        project_actions = list(old["Project"].actions())
        exports = old["Export"]
        w.menuBar().clear()
        file_menu = w.menuBar().addMenu("File")
        for action in project_actions:
            file_menu.addAction(action)
        file_menu.addSeparator()
        exports.setTitle("Export…")
        file_menu.addMenu(exports)
        file_menu.addSeparator()
        quit_action = file_menu.addAction("Exit")
        quit_action.setShortcut(QKeySequence.StandardKey.Quit)
        quit_action.triggered.connect(w.close)
        view = w.menuBar().addMenu("View")
        self.presentation_action = view.addAction("Presentation mode")
        self.presentation_action.setCheckable(True)
        self.presentation_action.toggled.connect(w.presentation_controller.set_presentation)
        view.addAction("Reset layout", self.reset_layout)
        view.addAction("Settings…", self.show_settings)
        help_menu = w.menuBar().addMenu("Help")
        help_menu.addAction("Documentation", self.show_documentation)
        help_menu.addAction("Keyboard shortcuts", self.show_shortcuts)
        help_menu.addAction("Troubleshooting…", self.show_troubleshooting)
        help_menu.addAction("About FIX Inspector", self.show_about)

    def _message_views(self):
        w = self.window
        self.history_tools = MessageViewTools(w.history_inspector, w.history_fields, extra_tabs=(3, 5, 6))
        self.intercept_tools = MessageViewTools(w.intercept_editor_tabs, w.intercept_fields)
        if w._as_bool(w._settings().value("ui/viewer_columns_initialized", False)):
            for key, attribute in w._HEADER_SETTINGS.items():
                saved = w._settings().value(key)
                if saved is not None:
                    getattr(w, attribute).horizontalHeader().restoreState(saved)
        w.intercept_editor_tabs.setTabText(0, "Parsed")
        w.intercept_editor_tabs.setTabText(3, "Editor")
        w.intercept_editor_tabs.setTabToolTip(3, "Shared ordered-field editor used by Sender, Composer and Fuzzer")
        self.history_empty = TableEmptyState(w.history, "No FIX messages captured yet.\nStart the proxy and send traffic through the configured listener.")
        self.intercept_empty = TableEmptyState(w.held_table, "No intercepted messages.")
        self.history_fields_empty = TableEmptyState(w.history_fields, "Select a captured message to inspect its fields.")
        self.intercept_fields_empty = TableEmptyState(w.intercept_fields, "Select an intercepted message to inspect or edit it.")
        self.composer_empty = TableEmptyState(w.composer_panel.messages, "No application message types.\nLoad a FIX dictionary in Dictionaries.")
        self.fuzzer_empty = TableEmptyState(w.fuzzer_panel.results, "No test cases.\nLoad a baseline and preview a finite plan.")
        w.repeater_panel.empty.setText("No message loaded.\nOpen a message from History or Intercept in Sender.")
        role(w.repeater_panel.empty, "empty")
        # Existing legacy field tables already use Tag / Name / Value / Meaning.
        for table in (w.history_fields, w.intercept_fields):
            table.setProperty("displayRole", "message")

    def _compact_proxy(self):
        w = self.window
        intercept = content(self.pages["Intercept"])
        toolbar = intercept.layout().itemAt(0).layout()
        toolbar.insertWidget(1, w.forward_button)
        toolbar.insertWidget(2, w.drop_button)
        # Wrap secondary controls onto a second compact row at large UI scales.
        secondary = QHBoxLayout()
        for control in (w.intercept_policy_label, w.proxy_behaviour_status):
            toolbar.removeWidget(control)
            secondary.addWidget(control)
        secondary.addStretch(1)
        intercept.layout().insertLayout(1, secondary)
        w.intercept_policy_label.setWordWrap(True)
        for button in intercept.findChildren(QPushButton):
            if button.text() == "Configuration…":
                button.setText("Proxy settings")
                button.clicked.disconnect()
                button.clicked.connect(lambda: self.navigate("Settings"))
        w.intercept_policy_label.setToolTip("Configure interception directions and timeout in Proxy → Settings")
        w.proxy_behaviour_status.setToolTip("Open Proxy → Rules (existing Proxy Behaviour controls)")
        for label in w._queue_box.findChildren(QLabel):
            if "QUEUED traffic" in label.text():
                contextual_hint(label, "Ordering preserved ⓘ", "FIX message ordering is preserved. Messages behind a held message remain queued.")
        # Static legends remain available as tooltips, not permanent paragraphs.
        for page in (intercept, content(self.pages["History"])):
            for label in page.findChildren(QLabel):
                if label.text().startswith(("Blue =", "Traffic:", "Field legend:", "Raw FIX view.")):
                    contextual_hint(label, "Message colors ⓘ" if "Raw FIX" not in label.text() else "Raw mode ⓘ")
        history_layout = content(self.pages["History"]).layout()
        filter_row = history_layout.itemAt(0).layout()
        filter_options = QHBoxLayout()
        for control in (w.direction_filter, w.bookmarks_only, w.hide_heartbeats, w.hide_admin):
            filter_row.removeWidget(control)
            filter_options.addWidget(control)
        filter_options.addStretch(1)
        history_layout.insertLayout(1, filter_options)
        for button in (w.forward_button, w.start_button):
            role(button, "primary")
        # Leave the stored clear operation unchanged; only the user-facing
        # entry asks before deleting local evidence.
        for button in content(self.pages["History"]).findChildren(QPushButton):
            if button.text() == "Clear":
                button.setText("Clear history")
                button.clicked.disconnect()
                button.clicked.connect(self.confirm_clear_history)

    def confirm_clear_history(self):
        w = self.window
        if w.records and QMessageBox.question(
            w, "Clear History", "Delete captured History, including records in the open project?",
            QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
            QMessageBox.StandardButton.Cancel,
        ) != QMessageBox.StandardButton.Yes:
            return
        w._clear_history()

    def _status(self):
        w = self.window
        # Keep legacy labels alive for existing callbacks, but show only four
        # concise indicators. Detailed values remain in Troubleshooting.
        for label in w.presentation_controller._status_labels:
            label.hide()
        layout = w.presentation_controller.status_scroll.widget().layout()
        self.proxy_status = QLabel()
        self.session_status = QPushButton()
        self.session_status.clicked.connect(self.show_troubleshooting)
        self.upstream_status = QLabel()
        self.queue_status = QLabel()
        for control in (self.proxy_status, self.session_status, self.upstream_status, self.queue_status):
            layout.insertWidget(layout.count() - 1, control)

    def refresh(self):
        w = self.window
        snapshot = w.engine.diagnostics()
        running = snapshot.listener_state.startswith("Listening ")
        connected = snapshot.upstream_state.startswith("Connected ")
        observed = bool(snapshot.client_session_id or snapshot.server_session_id)
        self.proxy_status.setText("● Proxy running" if running else "● Proxy stopped")
        role(self.proxy_status, "success" if running else "muted")
        self.session_status.setText("FIX session observed" if observed and connected else "FIX session not active")
        self.session_status.setToolTip(w.session_state_label.text())
        transport = "Plain TCP" if w.upstream_transport.currentData() == "plain_tcp" else "TLS"
        warning = transport == "TLS" and not w.verify_tls.isChecked()
        self.upstream_status.setText(f"Upstream: {w.upstream_host.text() or 'not configured'}:{w.upstream_port.text()} · {transport}" + (" · verification disabled" if warning else ""))
        role(self.upstream_status, "warning" if warning else "muted")
        self.queue_status.setText(f"Held: {snapshot.held_count} · Queued: {snapshot.queued_count}")
        self.queue_status.setToolTip(w.queue_state_label.text())
        message = w.status_label.text()
        if message != getattr(self, "_last_status", "Ready"):
            self._last_status = message
            w.statusBar().showMessage(w.secret_policy.redact_text(message), 5000)
        blocker = QSignalBlocker(self.presentation_action)
        self.presentation_action.setChecked(w.presentation_controller.presentation)
        del blocker

    def reset_layout(self):
        w = self.window
        for attribute in w._HEADER_SETTINGS.values():
            table = getattr(w, attribute)
            header = table.horizontalHeader()
            for column in range(table.columnCount()):
                header.moveSection(header.visualIndex(column), column)
                table.setColumnWidth(column, 205 if column == 1 else 150)
        self.history_tools.reset_columns()
        self.intercept_tools.reset_columns()
        w.history_splitter.setSizes([490, 330])
        w.intercept_splitter.setSizes([230, 620])
        if hasattr(w, "proxy_workspace"):
            w.proxy_workspace.reset_columns()
            w.intercept_splitter.setSizes([560, 1120])
        self.navigate("Intercept")
        w._save_settings()

    def show_documentation(self):
        dialog = QDialog(self.window)
        dialog.setWindowTitle("FIX Inspector documentation")
        dialog.resize(900, 700)
        layout = QVBoxLayout(dialog)
        browser = QTextBrowser()
        browser.setOpenExternalLinks(False)
        root = Path(__file__).resolve().parents[3] / "docs"
        guide = root / "USER_GUIDE.md"
        browser.setMarkdown(guide.read_text(encoding="utf-8") if guide.is_file() else "See docs/USER_GUIDE.md in the release package.")
        layout.addWidget(browser)
        self.documentation_dialog = dialog
        dialog.show()

    def show_shortcuts(self):
        QMessageBox.information(self.window, "Keyboard shortcuts", "Ctrl+N / Ctrl+O / Ctrl+S: project\nCtrl+I: intercept on/off\nCtrl+Enter: forward\nCtrl+Shift+D: drop\nCtrl+L: History search\nCtrl+F: search Proxy History, Composer or Dictionaries\nCtrl+R: send current Sender item (existing send confirmations apply)\nCtrl+C: copy\nCtrl+Plus / Minus / 0: UI scale\nCtrl+wheel: message font over message content; UI scale elsewhere")

    def show_about(self):
        QMessageBox.about(self.window, "About FIX Inspector", f"FIX Inspector\nVersion {__version__}\n\nSecurity testing and inspection toolkit for FIX protocol traffic.\n\nLocal projects · No telemetry · Offline runtime")

    def close(self):
        for dialog in (self.settings, self.troubleshooting, getattr(self, "documentation_dialog", None)):
            if dialog is not None:
                dialog.close()
