"""Product workspace over the modular transport/FIX/session backend."""

from __future__ import annotations

import difflib
import logging
import json
from pathlib import Path
import time

from PySide6.QtCore import Qt, QTimer
from PySide6.QtGui import QAction, QBrush, QColor, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QInputDialog,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTreeWidget,
    QTreeWidgetItem,
    QVBoxLayout,
    QWidget,
)

from .. import __version__
from .._legacy_v03 import gui as _v03_gui
from ..app_logging import configure_logging, current_log_path, update_logging_policy
from ..correlation import CorrelationEngine
from ..composer import ComposerController
from ..fix.dictionary import FixDictionary
from ..fix.fields import FixField
from ..fix.framing import SOH_SYMBOL
from ..fix.groups import project_groups
from ..fix.parser import (
    decode_value,
    editor_text_to_raw,
    encode_value,
    parse_message,
    raw_to_editor_text,
)
from ..fix.serializer import serialize_structured
from ..fix.validation import validate_message
from ..fuzzer import FuzzerController, eligible_outcome_records
from ..history import (
    FilterSyntaxError,
    HistoryDocument,
    HistoryRetentionPolicy,
    compile_filter,
    matches_text,
)
from ..project import ProjectDatabase, SecretRedactionPolicy, write_export
from ..project.redaction import redact_sensitive
from ..project.settings import decode_bytes, encode_bytes
from ..presentation import display_direction, display_direction_text, display_status, internal_direction
from ..records import TrafficRecord
from ..repeater import IsolatedRepeaterConnection, RepeaterController
from ..session.injection import (
    AutoUpdatePolicy,
    InjectionMode,
    InjectionRequest,
    apply_auto_updates,
)
from ..transport.connection import ProxyConfig, ProxyEngine
from ..transport.upstream import PLAIN_TCP_VERIFICATION
from .diagnostics import DiagnosticsPanel
from .decoder import DecoderPanel
from .dictionaries import DictionaryBrowserPanel
from .composer import ComposerPanel
from .fuzzer import FuzzerPanel
from .repeater import RepeaterPanel
from .proxy.rules_panel import RulesPanel
from .proxy.endpoints import ProxyEndpointsPanel
from .settings.presentation import PresentationController
from .theme import STYLESHEET, role
from .workspace import WorkspaceShell
from .proxy.workspace import ProxyWorkspace
from .product import ProductPresentation
from .widgets import MessageDiffWidget, MessageEditorWidget, MessageValidationWidget, TableCopySupport

LOGGER = logging.getLogger(__name__)

# The reference UI is retained as a visual shell during Stage 1. Replace every
# backend global it uses so live operation goes through the modular product
# packages. The retained compatibility shell only shares the product version label.
_v03_gui.FixDictionary = FixDictionary
_v03_gui.FixField = FixField
_v03_gui.TrafficRecord = TrafficRecord
_v03_gui.ProxyConfig = ProxyConfig
_v03_gui.ProxyEngine = ProxyEngine
_v03_gui.SOH_SYMBOL = SOH_SYMBOL
_v03_gui.decode_value = decode_value
_v03_gui.editor_text_to_raw = editor_text_to_raw
_v03_gui.encode_value = encode_value
_v03_gui.parse_message = parse_message
_v03_gui.raw_to_editor_text = raw_to_editor_text
_v03_gui.redact_sensitive = redact_sensitive
_v03_gui.serialize_structured = serialize_structured
_v03_gui.validate_message = validate_message


class MainWindow(_v03_gui.MainWindow):
    HISTORY_COLUMNS = [
        "#", "Time", "Direction", "Type", "Message", "Seq", "Account", "ClOrdID",
        "OrderID", "State", "★", "Note", "Source", "Fault",
    ]
    HELD_COLUMNS = ["#", "Direction", "Type", "Message", "Seq", "Account", "State"]
    SESSION_ADMIN_ROW_COLORS = {
        "0": "#eeeeee",
        "A": "#e5ebfa",
        "1": "#e8edf2",
        "2": "#ebe5f7",
        "3": "#f9dddd",
        "4": "#e2e9f8",
        "5": "#faead2",
    }
    _HEADER_SETTINGS = {
        "ui/history_header": "history",
        "ui/held_header": "held_table",
        "ui/intercept_fields_header": "intercept_fields",
        "ui/history_fields_header": "history_fields",
    }

    def __init__(self) -> None:
        super().__init__()
        settings = self._settings()
        # Only an explicit new global preference may disclose values. Ignore
        # legacy per-workspace flags and malformed settings (masked fallback).
        self._show_sensitive = str(settings.value("security/mask_sensitive_fields", True)).lower() == "false"
        if not settings.contains("proxy/verify_tls"):
            self.verify_tls.setChecked(True)
        try:
            self.secret_policy = SecretRedactionPolicy.from_text(
                str(settings.value("security/additional_secret_tags", ""))
            )
        except ValueError:
            self.secret_policy = SecretRedactionPolicy()
        configure_logging(self.secret_policy)
        self.project_database: ProjectDatabase | None = None
        self.project_path: Path | None = None
        self._loading_project = False
        self._history_documents: dict[int, HistoryDocument] = {}
        self._evicted_record_count = 0
        self.correlation = CorrelationEngine(self.dictionary)
        self.setWindowTitle(f"FIX Inspector {__version__}")
        self._copy_support = TableCopySupport(self)
        self._stage1_shortcuts: list[QShortcut] = []
        self._install_resizable_proxy_layout()
        self._install_shared_proxy_editor()
        self._install_selection_and_copy()
        self._install_shortcuts()
        self._install_legends()
        self._install_tls_warning()
        self._install_stage2_history()
        self._install_stage2_configuration()
        self._install_session_admin_controls()
        self._install_proxy_behaviour()
        self._install_project_actions()
        self._install_repeater()
        self._install_composer()
        self._install_fuzzer()
        self._install_decoder()
        self._install_dictionary_browser()
        self._install_diagnostics()
        self._restore_stage1_settings()
        self._update_intercept()
        self._refresh_diagnostics()
        self.presentation_controller = PresentationController(self)
        self.shell = WorkspaceShell(self)
        self.proxy_workspace = ProxyWorkspace(self, self.shell)
        self.product_presentation = ProductPresentation(self)
        self._refresh_secret_views()

    def _apply_styles(self) -> None:
        self.setStyleSheet(STYLESHEET)

    def _navigate(self, route: str) -> None:
        if hasattr(self, "shell"):
            self.shell.navigate(route)
        else:
            legacy = {"Intercept": 0, "History": 1, "Settings": 2}
            self.workspace_tabs.setCurrentIndex(legacy.get(route, 0))

    def _workspace_index(self) -> int:
        return self.shell.legacy_index() if hasattr(self, "shell") else self.workspace_tabs.currentIndex()

    def _restore_workspace_index(self, index: int) -> None:
        if hasattr(self, "shell"):
            self.shell.restore_legacy_index(index)
        else:
            self.workspace_tabs.setCurrentIndex(index)

    # ----------------------------------------------------------- Stage 1 setup

    def _build_configuration_tab(self) -> QWidget:
        page = super()._build_configuration_tab()
        old_endpoints = self.listen_host.parentWidget()
        self.proxy_endpoints = ProxyEndpointsPanel(page)
        page.layout().replaceWidget(old_endpoints, self.proxy_endpoints)
        old_endpoints.hide()
        old_endpoints.deleteLater()
        for attribute in (
            "listen_host", "listen_port", "upstream_host", "upstream_port",
            "upstream_transport", "upstream_sni", "verify_tls", "ca_file",
            "ca_browse", "route_summary",
        ):
            setattr(self, attribute, getattr(self.proxy_endpoints, attribute))
        self.ca_browse.clicked.connect(self._browse_ca)
        self.transport_dict.parentWidget().setTitle("FIX dictionaries")
        self.intercept_c2s_policy.parentWidget().setTitle("Interception and session controls")
        self.config_hide_admin.parentWidget().setTitle("History and secrets")
        self.dictionary_state.setToolTip(
            "XML dictionaries are optional metadata. Proxy forwarding works without them."
        )
        return page

    def _restore_settings(self) -> None:
        # Restore before the base class, whose intercept signals can save settings.
        transport = str(self._settings().value("proxy/upstream_transport", "tls"))
        index = self.upstream_transport.findData(transport)
        self.upstream_transport.setCurrentIndex(index if index >= 0 else 1)
        super()._restore_settings()

    def _set_proxy_running(self, running: bool) -> None:
        super()._set_proxy_running(running)
        self.proxy_endpoints.set_running(running)
        if hasattr(self, "tls_warning"):
            self._update_tls_warning()

    def _browse_dict(self, target: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select FIX XML dictionary", "", "XML files (*.xml);;All files (*)"
        )
        if path:
            target.setText(path)

    def _install_resizable_proxy_layout(self) -> None:
        self._queue_box = self.held_table.parentWidget()
        self._queue_box.setTitle("Intercept / ordered queue")
        self._queue_box.setMaximumHeight(16_777_215)
        self.held_table.setMaximumHeight(16_777_215)
        self.intercept_splitter.insertWidget(0, self._queue_box)
        self.intercept_splitter.setCollapsible(0, False)
        self.intercept_splitter.setCollapsible(1, False)
        self.intercept_splitter.setSizes([230, 620])
        help_labels = self._queue_box.findChildren(QLabel)
        if help_labels:
            help_labels[0].setText(
                "HELD needs a decision. QUEUED traffic cannot overtake it, including session/admin messages. "
                "Queued application messages are promoted to HELD in wire order."
            )

    def _install_selection_and_copy(self) -> None:
        for table in (self.history, self.history_fields, self.intercept_fields):
            table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
            table.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.held_table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.held_table.setSelectionMode(QAbstractItemView.SelectionMode.SingleSelection)

        self._copy_support.install_message_menu(
            self.history,
            lambda row: self._record_for_table_row(self.history, row),
            self._display_raw,
            lambda: self.dictionary,
            self._history_context_actions,
        )
        self._copy_support.install_message_menu(
            self.held_table,
            lambda row: self._record_for_table_row(self.held_table, row),
            self._display_raw,
            lambda: self.dictionary,
            self._message_context_actions,
        )
        self._copy_support.install_field_menu(self.history_fields)
        self._copy_support.install_field_menu(self.intercept_fields)

    def _install_shared_proxy_editor(self) -> None:
        self.proxy_shared_editor = MessageEditorWidget(
            lambda: self.dictionary,
            lambda: self.secret_policy,
        )
        self.intercept_editor_tabs.addTab(self.proxy_shared_editor, "Shared editor")
        legacy_validation = self.intercept_validation
        validation_layout = legacy_validation.parentWidget().layout()
        validation_index = validation_layout.indexOf(legacy_validation)
        self.intercept_validation = MessageValidationWidget()
        validation_layout.insertWidget(validation_index, self.intercept_validation)
        legacy_validation.hide()

    def _install_shortcuts(self) -> None:
        shortcuts = [
            ("Ctrl+I", self.intercept_master.toggle),
            ("Ctrl+Return", self._forward_current),
            ("Ctrl+Enter", self._forward_current),
            ("Ctrl+Shift+D", self._drop_current),
            ("Ctrl+L", self._focus_history_filter),
        ]
        for sequence, callback in shortcuts:
            shortcut = QShortcut(QKeySequence(sequence), self)
            shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
            shortcut.activated.connect(callback)
            self._stage1_shortcuts.append(shortcut)

    def _install_legends(self) -> None:
        field_legend = QLabel(
            "Field legend: gray = FIX structure · yellow = identifier · purple = custom/vendor · "
            "red = configured secret (tag 553 is mandatory). Status text always accompanies color."
        )
        field_legend.setObjectName("mutedLabel")
        field_legend.setWordWrap(True)
        self.intercept_fields.parentWidget().layout().addWidget(field_legend)
        for label in self.workspace_tabs.widget(1).findChildren(QLabel):
            if label.text().casefold().startswith("blue = client"):
                label.setText(
                    "Traffic: blue Client → Server · green Server → Client · pale blue HELD · "
                    "gray QUEUED · purple AUTO-FWD · "
                    "red DROPPED/DISCONNECTED · orange MODIFIED. Session: gray Heartbeat · "
                    "blue-violet Logon/Resend/SequenceReset · amber Logout · light red Reject. "
                    "Field colors are shown in Proxy."
                )
                label.setWordWrap(True)

    def _install_tls_warning(self) -> None:
        self.tls_warning = QLabel()
        self.tls_warning.setWordWrap(True)
        connection_box = self.verify_tls.parentWidget()
        connection_box.layout().addWidget(self.tls_warning, 8, 0, 1, 4)
        self.verify_tls.toggled.connect(self._update_tls_warning)
        self.ca_file.textChanged.connect(self._update_tls_warning)
        self.upstream_transport.currentIndexChanged.connect(self._update_tls_warning)
        self._update_tls_warning()

    def _install_diagnostics(self) -> None:
        self.diagnostics_panel = DiagnosticsPanel()
        self.workspace_tabs.addTab(self.diagnostics_panel, "Diagnostics")
        self.tls_state_label = QLabel()
        self.queue_state_label = QLabel("Held 0 / queued 0")
        self.statusBar().addPermanentWidget(self.tls_state_label)
        self.statusBar().addPermanentWidget(self.queue_state_label)
        self._ui_timer.timeout.connect(self._refresh_diagnostics)

    def _install_repeater(self) -> None:
        self.repeater_controller = RepeaterController(
            self.engine.queue_injection,
            dictionary=self.dictionary,
        )
        self.repeater_panel = RepeaterPanel(
            lambda: self.dictionary,
            lambda: self.secret_policy,
            self._repeater_related_rows,
        )
        self.repeater_panel.queue_requested.connect(self._queue_repeater)
        self.repeater_panel.new_connection_requested.connect(self._send_repeater_new_connection)
        self.repeater_panel.close_connection_requested.connect(self._close_repeater_connection)
        self.repeater_panel.navigate_history.connect(self._navigate_history_record)
        self.repeater_panel.fuzzer_requested.connect(
            lambda raw, title, source_id: self._create_fuzzer_campaign(
                "Sender", source_id, raw, title
            )
        )
        self.repeater_panel.injection_event.connect(self._on_injection_event)
        self.repeater_controller.add_listener(self.repeater_panel.apply_event)
        self.engine.set_injection_listener(self.repeater_panel.injection_event.emit)
        self._repeater_connections: dict[str, IsolatedRepeaterConnection] = {}
        self.workspace_tabs.addTab(self.repeater_panel, "Sender")

    def _install_composer(self) -> None:
        self.composer_controller = ComposerController(self.dictionary, self.engine.queue_injection)
        self.composer_panel = ComposerPanel(
            self.composer_controller,
            lambda: self.dictionary,
            lambda: self.secret_policy,
        )
        self.composer_panel.queue_requested.connect(self._queue_composer)
        self.composer_panel.state_changed.connect(self._persist_workspace_state)
        self.composer_panel.fuzzer_requested.connect(
            lambda raw, title, source_id: self._create_fuzzer_campaign(
                "Composer", source_id, raw, title
            )
        )
        self.composer_controller.add_listener(self.composer_panel.apply_event)
        self.workspace_tabs.addTab(self.composer_panel, "Composer")

    def _install_fuzzer(self) -> None:
        self.fuzzer_controller = FuzzerController(
            self.dictionary,
            self.engine.queue_injection,
            self.engine.cancel_injection,
            self._fuzzer_outcome_records,
        )
        self.fuzzer_panel = FuzzerPanel(
            self.fuzzer_controller,
            lambda: self.dictionary,
            lambda: self.secret_policy,
            self._interesting_history_values,
        )
        self.fuzzer_panel.navigate_history.connect(self._navigate_history_record)
        self.fuzzer_panel.state_changed.connect(self._persist_workspace_state)
        self.fuzzer_panel.result_requested.connect(self._send_result_to_tool)
        self.fuzzer_controller.add_listener(self.fuzzer_panel.apply_campaign)
        self.workspace_tabs.addTab(self.fuzzer_panel, "Fuzzer")

    def _install_decoder(self) -> None:
        self.decoder_panel = DecoderPanel(
            lambda: self.dictionary,
            lambda: self.secret_policy,
        )
        self._copy_support.install_basic_copy(self.decoder_panel.frames)
        self._copy_support.install_basic_copy(self.decoder_panel.fields)
        self.workspace_tabs.addTab(self.decoder_panel, "Decoder")

    # ----------------------------------------------------------- Stage 2 setup

    def _install_stage2_history(self) -> None:
        self.filter_edit.setPlaceholderText(
            "Search all fields, or enable Expression (example: msgtype=D AND tag.54=1)"
        )
        history_page = self.workspace_tabs.widget(1)
        page_layout = history_page.layout()
        filter_layout = page_layout.itemAt(0).layout()
        self.advanced_filter = QCheckBox("Expression")
        self.advanced_filter.setToolTip(
            "Operators: = != > >= < <= ~ !~; AND, OR, NOT, parentheses. "
            "Properties include direction, msgtype, status, seq, account, clordid, orderid and tag.N."
        )
        self.direction_filter = QComboBox()
        self.direction_filter.addItem("All directions", "")
        self.direction_filter.addItem("Client → Server", "C→S")
        self.direction_filter.addItem("Server → Client", "S→C")
        self.bookmarks_only = QCheckBox("Bookmarks")
        filter_layout.insertWidget(1, self.advanced_filter)
        filter_layout.insertWidget(2, self.direction_filter)
        filter_layout.insertWidget(3, self.bookmarks_only)
        self.filter_error = QLabel()
        role(self.filter_error, "danger")
        self.filter_error.setWordWrap(True)
        self.filter_error.hide()
        page_layout.insertWidget(1, self.filter_error)

        self._filter_timer = QTimer(self)
        self._filter_timer.setSingleShot(True)
        self._filter_timer.setInterval(120)
        self._filter_timer.timeout.connect(self._run_history_filter)
        self.advanced_filter.toggled.connect(self._apply_history_filter)
        self.direction_filter.currentIndexChanged.connect(self._apply_history_filter)
        self.bookmarks_only.toggled.connect(self._apply_history_filter)

        inspector = self.history_fields.parentWidget()
        while inspector is not None and not isinstance(inspector, QTabWidget):
            inspector = inspector.parentWidget()
        self.history_inspector = inspector
        if self.history_inspector is None:
            raise RuntimeError("History inspector tab widget was not found")

        group_page = QWidget()
        group_layout = QVBoxLayout(group_page)
        self.history_groups = QTreeWidget()
        self.history_groups.setHeaderLabels(["Group / instance", "Wire field", "Value", "Status"])
        self.history_groups.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        group_layout.addWidget(self.history_groups)
        self.history_inspector.addTab(group_page, "Groups")

        diff_page = QWidget()
        diff_layout = QVBoxLayout(diff_page)
        self.history_diff = MessageDiffWidget()
        diff_layout.addWidget(self.history_diff)
        self.history_inspector.addTab(diff_page, "Diff")

        related_page = QWidget()
        related_layout = QVBoxLayout(related_page)
        self.history_related = QTableWidget(0, 7)
        self.history_related.setHorizontalHeaderLabels(
            ["Score", "#", "Direction", "Type", "Message", "Seq", "Evidence"]
        )
        self.history_related.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.history_related.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.history_related.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.history_related.horizontalHeader().setStretchLastSection(True)
        self.history_related.verticalHeader().setVisible(False)
        self.history_related.cellDoubleClicked.connect(self._select_related_record)
        related_layout.addWidget(self.history_related)
        self._copy_support.install_basic_copy(self.history_related)
        self.history_inspector.addTab(related_page, "Related")

        notes_page = QWidget()
        notes_layout = QVBoxLayout(notes_page)
        note_toolbar = QHBoxLayout()
        self.bookmark_button = QPushButton("☆ Bookmark")
        self.bookmark_button.clicked.connect(self._toggle_selected_bookmark)
        self.save_note_button = QPushButton("Save note")
        self.save_note_button.clicked.connect(self._save_selected_note)
        note_toolbar.addWidget(self.bookmark_button)
        note_toolbar.addStretch(1)
        note_toolbar.addWidget(self.save_note_button)
        self.history_note = QPlainTextEdit()
        self.history_note.setPlaceholderText("Per-message analyst note (stored in the project)")
        notes_layout.addLayout(note_toolbar)
        notes_layout.addWidget(self.history_note, 1)
        self.history_inspector.addTab(notes_page, "Notes")
        self._apply_history_filter()

    def _install_stage2_configuration(self) -> None:
        box = self.config_hide_admin.parentWidget()
        layout = box.layout()
        self.additional_secret_tags = QLineEdit(",".join(sorted(self.secret_policy.additional_tags)))
        self.additional_secret_tags.setPlaceholderText("Example: 554, 925")
        self.additional_secret_tags.setToolTip(
            "Comma-separated additional secret tags. Tag 553 is always secret and cannot be removed."
        )
        self.mask_sensitive_fields = QCheckBox("Mask sensitive FIX fields")
        self.mask_sensitive_fields.setChecked(not self._show_sensitive)
        self.secret_policy_error = QLabel()
        self.secret_policy_error.setWordWrap(True)
        role(self.secret_policy_error, "danger")
        self.secret_policy_error.hide()
        self.apply_secret_tags = QPushButton("Apply")
        self.apply_secret_tags.clicked.connect(self._apply_secret_policy)
        layout.addWidget(QLabel("Additional secret tags (553 always included)"), 2, 0)
        layout.addWidget(self.additional_secret_tags, 2, 1)
        layout.addWidget(self.apply_secret_tags, 2, 2)
        self.history_limit = QSpinBox()
        self.history_limit.setRange(100, 1_000_000)
        self.history_limit.setSingleStep(1_000)
        try:
            configured_limit = int(self._settings().value("history/live_limit", 10_000))
        except (TypeError, ValueError):
            configured_limit = 10_000
        self.history_limit.setValue(max(100, min(1_000_000, configured_limit)))
        self.history_limit.setSuffix(" live records")
        self.history_limit.setToolTip(
            "Bounds the in-memory/UI History and correlation indexes. When a project is open, "
            "evicted records remain in SQLite and are not deleted by Save."
        )
        self.history_limit.valueChanged.connect(self._history_limit_changed)
        layout.addWidget(QLabel("In-memory History limit"), 3, 0)
        layout.addWidget(self.history_limit, 3, 1, 1, 2)

    def _install_session_admin_controls(self) -> None:
        """Add independent display and opt-in admin interception controls."""
        self.hide_admin.setText("Hide other session/admin")
        self.hide_admin.setToolTip(
            "Hide Logon, TestRequest, ResendRequest, Reject, SequenceReset and Logout. "
            "Heartbeat has its own independent filter."
        )
        self.hide_heartbeats = QCheckBox("Hide Heartbeats")
        self.hide_heartbeats.setChecked(True)
        self.hide_heartbeats.setToolTip("Hide only Heartbeat messages (35=0).")
        history_layout = self.workspace_tabs.widget(1).layout().itemAt(0).layout()
        history_layout.insertWidget(max(0, history_layout.indexOf(self.hide_admin)), self.hide_heartbeats)
        self.hide_heartbeats.toggled.connect(self._apply_history_filter)

        self.config_hide_admin.setText("Hide other session/admin in History by default")
        self.config_hide_heartbeats = QCheckBox("Hide Heartbeats in History by default")
        self.config_hide_heartbeats.setChecked(True)
        self.config_hide_heartbeats.toggled.connect(self._config_hide_heartbeats_changed)
        display_layout = self.config_hide_admin.parentWidget().layout()
        display_layout.addWidget(self.config_hide_heartbeats, 0, 2)

        self.intercept_c2s_policy.setText("Hold Client → Server application/business messages")
        self.intercept_s2c_policy.setText("Hold Server → Client application/business messages")
        self.intercept_c2s_admin_policy = QCheckBox(
            "Also hold Client → Server session/admin messages"
        )
        self.intercept_s2c_admin_policy = QCheckBox(
            "Also hold Server → Client session/admin messages"
        )
        self.intercept_c2s_admin_policy.setChecked(False)
        self.intercept_s2c_admin_policy.setChecked(False)
        for checkbox in (self.intercept_c2s_admin_policy, self.intercept_s2c_admin_policy):
            checkbox.setToolTip(
                "Explicit opt-in. Session/admin traffic remains automatically forwarded by default."
            )
            checkbox.toggled.connect(self._update_intercept)
        intercept_layout = self.intercept_c2s_policy.parentWidget().layout()
        intercept_layout.addWidget(self.intercept_c2s_admin_policy, 3, 0, 1, 2)
        intercept_layout.addWidget(self.intercept_s2c_admin_policy, 3, 2, 1, 2)
        self.intercept_policy_label.setText("Policy: Client → Server application messages")

    def _config_hide_heartbeats_changed(self, checked: bool) -> None:
        if self.hide_heartbeats.isChecked() != checked:
            self.hide_heartbeats.setChecked(checked)
        self._apply_history_filter()

    def _update_intercept(self) -> None:
        if not hasattr(self, "intercept_master"):
            return
        if not hasattr(self, "intercept_c2s_admin_policy"):
            super()._update_intercept()
            return
        master = self.intercept_master.isChecked()
        self.engine.set_intercept(
            master and self.intercept_c2s_policy.isChecked(),
            master and self.intercept_s2c_policy.isChecked(),
            self.hold_timeout.value(),
            c2s_admin=master and self.intercept_c2s_admin_policy.isChecked(),
            s2c_admin=master and self.intercept_s2c_admin_policy.isChecked(),
        )
        self._update_policy_label()

    def _update_policy_label(self) -> None:
        if not hasattr(self, "intercept_c2s_admin_policy"):
            super()._update_policy_label()
            return
        policies: list[str] = []
        if self.intercept_c2s_policy.isChecked():
            policies.append("Client → Server application")
        if self.intercept_s2c_policy.isChecked():
            policies.append("Server → Client application")
        if self.intercept_c2s_admin_policy.isChecked():
            policies.append("Client → Server session/admin")
        if self.intercept_s2c_admin_policy.isChecked():
            policies.append("Server → Client session/admin")
        timeout = self.hold_timeout.value()
        timeout_text = "unlimited hold" if timeout == 0 else f"{timeout}s safety timeout"
        self.intercept_policy_label.setText(
            f"Policy: {' + '.join(policies) if policies else 'none'} messages • {timeout_text}"
        )

    def _install_proxy_behaviour(self) -> None:
        """Turn Configuration into General/Proxy Behaviour subsections."""
        configuration_page = self.workspace_tabs.widget(2)
        outer = configuration_page.layout()
        existing_widgets = []
        while outer.count():
            item = outer.takeAt(0)
            widget = item.widget()
            if widget is not None:
                existing_widgets.append(widget)

        general_page = QWidget()
        general_layout = QVBoxLayout(general_page)
        for widget in existing_widgets:
            general_layout.addWidget(widget)
        general_layout.addStretch(1)

        self.engine.proxy_behaviour.set_secret_tags(self.secret_policy.secret_tags)
        self.proxy_behaviour_panel = RulesPanel(
            self.engine,
            lambda: self.secret_policy,
        )
        self.proxy_behaviour_panel.state_changed.connect(self._proxy_behaviour_changed)
        self.configuration_sections = QTabWidget()
        self.configuration_sections.addTab(general_page, "General")
        self.configuration_sections.addTab(self.proxy_behaviour_panel, "Proxy Behaviour")
        outer.addWidget(self.configuration_sections)

        proxy_page = self.workspace_tabs.widget(0)
        toolbar = proxy_page.layout().itemAt(0).layout()
        self.proxy_behaviour_status = QPushButton("Client → Server NORMAL | Server → Client NORMAL")
        self.proxy_behaviour_status.setToolTip(
            "Current message-layer fault policy. Click to open Configuration → Proxy Behaviour."
        )
        self.proxy_behaviour_status.clicked.connect(self._show_proxy_behaviour)
        toolbar.insertWidget(2, self.proxy_behaviour_status)

    def _show_proxy_behaviour(self) -> None:
        if hasattr(self, "shell"):
            self.shell.navigate("Rules")
        else:
            self.workspace_tabs.setCurrentIndex(2)
            self.configuration_sections.setCurrentIndex(1)

    def _proxy_behaviour_changed(self) -> None:
        self._persist_workspace_state()
        self._refresh_diagnostics()

    def _install_dictionary_browser(self) -> None:
        self.dictionary_browser = DictionaryBrowserPanel(self.dictionary)
        self.workspace_tabs.addTab(self.dictionary_browser, "Dictionaries")
        self._copy_support.install_basic_copy(self.dictionary_browser.fields)
        self._copy_support.install_basic_copy(self.dictionary_browser.messages)

    def _install_project_actions(self) -> None:
        project_menu = self.menuBar().addMenu("Project")
        actions = [
            ("New project…", QKeySequence.StandardKey.New, self._new_project),
            ("Open project…", QKeySequence.StandardKey.Open, self._open_project),
            ("Save project", QKeySequence.StandardKey.Save, self._save_project),
            ("Save project as…", QKeySequence.StandardKey.SaveAs, self._save_project_as),
            ("Close project", None, self._close_project),
        ]
        for label, shortcut, callback in actions:
            action = QAction(label, self)
            if shortcut is not None:
                action.setShortcut(shortcut)
            action.triggered.connect(callback)
            project_menu.addAction(action)
        export_menu = self.menuBar().addMenu("Export")
        for label, kind in (
            ("Selected as readable text…", "readable"),
            ("Selected as raw FIX…", "raw"),
            ("Selected as JSON…", "json"),
            ("Selected as Markdown…", "markdown"),
        ):
            action = QAction(label, self)
            action.triggered.connect(lambda _checked=False, current=kind: self._export_selected(current))
            export_menu.addAction(action)
        self.project_state_label = QLabel("Project: unsaved")
        self.statusBar().addPermanentWidget(self.project_state_label)

    # ----------------------------------------------------------- queue records

    def _on_record(self, record: TrafficRecord) -> None:
        super()._on_record(record)
        if getattr(self, "_observed_heartbeat", None):
            self.session_info.setText(f"Observed HeartBtInt: {self._observed_heartbeat}s")
            self.session_info.setToolTip("Holding sequence N delays later traffic. Configure the external client's heartbeat interval to suit manual inspection.")
        self._history_documents[record.record_id] = HistoryDocument.from_record(record, self.dictionary)
        self.correlation.add(record)
        self._persist_record(record)
        if record.status == "QUEUED":
            self._add_held_record(record)
        if hasattr(self, "repeater_panel"):
            self.repeater_panel.refresh_correlated()
        self._enforce_history_limit()
        self._refresh_diagnostics()

    def _add_held_record(self, record: TrafficRecord) -> None:
        super()._add_held_record(record)
        self._style_queue_row(record.record_id)

    def _on_record_status(self, record_id: int, status: str) -> None:
        super()._on_record_status(record_id, status)
        record = self.records.get(record_id)
        if record is not None:
            self._history_documents[record_id] = HistoryDocument.from_record(record, self.dictionary)
            self.correlation.add(record)
            self._persist_record(record)
        if status == "HELD" and record is not None:
            if record_id not in self.held_row_for_record:
                self._add_held_record(record)
            self._held_started[record_id] = time.monotonic()
            row = self.held_row_for_record.get(record_id)
            if row is not None:
                for column, value in enumerate(self._held_summary(record)):
                    item = self.held_table.item(row, column)
                    if item:
                        item.setText(value)
                self._style_queue_row(record_id)
            self.selected_intercept_record_id = record_id
            self._navigate("Intercept")
            self._select_held_record(record_id)
            self._refresh_intercept_details()
            self.status_label.setText(f"#{record_id} promoted from QUEUED to HELD in wire order")
        self._enforce_history_limit()
        self._refresh_diagnostics()

    def _history_limit_changed(self, _value: int) -> None:
        self._settings().setValue("history/live_limit", self.history_limit.value())
        self._enforce_history_limit()
        self._refresh_diagnostics()

    def _enforce_history_limit(self) -> None:
        if not hasattr(self, "history_limit"):
            return
        policy = HistoryRetentionPolicy(self.history_limit.value())
        for record_id in policy.eviction_ids(self.records):
            row = self.history_row_for_record.pop(record_id, None)
            if row is not None:
                self.history.removeRow(row)
                for current_id, current_row in tuple(self.history_row_for_record.items()):
                    if current_row > row:
                        self.history_row_for_record[current_id] = current_row - 1
            self.records.pop(record_id, None)
            self._history_documents.pop(record_id, None)
            self.correlation.remove(record_id)
            if self.selected_history_record_id == record_id:
                self.selected_history_record_id = None
            self._evicted_record_count += 1
        if self.selected_history_record_id is None and self.history.rowCount() == 0:
            self._refresh_history_details()

    def _style_queue_row(self, record_id: int) -> None:
        row = self.held_row_for_record.get(record_id)
        record = self.records.get(record_id)
        if row is None or record is None:
            return
        color = QColor("#e9edf2") if record.status == "QUEUED" else QColor("#edf4fc")
        for column in range(self.held_table.columnCount()):
            item = self.held_table.item(row, column)
            if item:
                item.setBackground(QBrush(color))

    def _history_color(self, record: TrafficRecord) -> QColor:
        if record.status in {"INJECTED", "RECOVERY-REPLAY"}:
            return QColor("#d9f2e6")
        if record.status == "EXACT-RAW-REPLAY":
            return QColor("#ffd7d7")
        if record.status == "QUEUED":
            return QColor("#e9edf2")
        if record.status == "DISCONNECTED":
            return QColor("#ffd7d7")
        if record.status in {"DROPPED", "DISCONNECT_TRIGGER"}:
            return QColor("#ffd7d7")
        if record.status in {"PAUSED", "HELD", "DELAYED"}:
            return QColor("#edf4fc")
        if record.status in {"DUPLICATED", "FAULT-INJECTED DUPLICATE", "RELEASED_FROM_QUEUE"}:
            return QColor("#e7ddff")
        admin_color = self.SESSION_ADMIN_ROW_COLORS.get(record.msg_type)
        if admin_color:
            return QColor(admin_color)
        return super()._history_color(record)

    def _record_summary(self, record: TrafficRecord) -> list[str]:
        values = super()._record_summary(record)
        values[2] = display_direction(record.direction)
        if not self._reveal_state() and hasattr(self, "secret_policy"):
            for column, tag in ((3, "35"), (4, "35"), (5, "34"), (6, "1"), (7, "11"), (8, "37")):
                if tag in self.secret_policy.secret_tags and values[column]:
                    values[column] = "<REDACTED>"
        note = self.secret_policy.redact_text(record.note) if hasattr(self, "secret_policy") else record.note
        return values + [
            "★" if record.bookmarked else "",
            note.replace("\n", " ")[:120],
            "SENDER" if record.source == "REPEATER" else record.source,
            " / ".join(
                part
                for part in (
                    record.fault_action,
                    self.secret_policy.redact_text(record.fault_rule),
                    display_direction_text(self.secret_policy.redact_text(record.fault_reason)),
                    f"duplicate of #{record.duplicate_of_record_id}"
                    if record.duplicate_of_record_id is not None
                    else "",
                )
                if part
            ),
        ]

    def _field_color(self, tag: str) -> QColor | None:
        policy = getattr(self, "secret_policy", SecretRedactionPolicy())
        if str(tag) in policy.secret_tags:
            return QColor("#ffd9d9")
        return super()._field_color(tag)

    # ----------------------------------------------------------- History model

    def _apply_history_filter(self) -> None:
        if not hasattr(self, "_history_documents"):
            super()._apply_history_filter()
            return
        timer = getattr(self, "_filter_timer", None)
        if timer is None:
            self._run_history_filter()
        else:
            timer.start()

    def _run_history_filter(self) -> None:
        if not hasattr(self, "advanced_filter"):
            return
        expression = self.filter_edit.text().strip()
        predicate = None
        if self.advanced_filter.isChecked() and expression:
            try:
                predicate = compile_filter(expression)
            except FilterSyntaxError as exc:
                self.filter_error.setText(f"Filter expression: {exc}")
                self.filter_error.show()
                return
        self.filter_error.clear()
        self.filter_error.hide()
        direction = str(self.direction_filter.currentData() or "")
        for record_id, row in self.history_row_for_record.items():
            record = self.records.get(record_id)
            if record is None:
                continue
            document = self._history_documents.get(record_id)
            if document is None:
                document = HistoryDocument.from_record(record, self.dictionary)
                self._history_documents[record_id] = document
            hidden = self.hide_heartbeats.isChecked() and record.msg_type == "0"
            hidden = hidden or (
                self.hide_admin.isChecked()
                and record.msg_type != "0"
                and self.dictionary.is_admin(record.msg_type)
            )
            hidden = hidden or (bool(direction) and record.direction != direction)
            hidden = hidden or (self.bookmarks_only.isChecked() and not record.bookmarked)
            if not hidden and expression:
                hidden = not (predicate(document) if predicate is not None else matches_text(document, expression))
            if not hidden and hasattr(self, "proxy_workspace"):
                hidden = not self.proxy_workspace.filters.accepts(document)
            self.history.setRowHidden(row, hidden)

    def _populate_field_table(self, table: QTableWidget, record: TrafficRecord, editable: bool) -> None:
        super()._populate_field_table(table, record, editable)
        message = parse_message(record.raw, self.dictionary)
        projection = project_groups(message, self.dictionary)
        reveal = self._reveal_state()
        policy = getattr(self, "secret_policy", SecretRedactionPolicy())
        for row, projected in enumerate(projection.fields):
            if row >= table.rowCount():
                break
            group_item = table.item(row, 6)
            if group_item is not None and projected.group_path:
                group_item.setText(projected.group_path)
                group_item.setToolTip(projected.group_path)
            if projected.field.tag in policy.secret_tags and not reveal:
                value_item = table.item(row, 2)
                if value_item is not None:
                    value_item.setText("<REDACTED>")
                    value_item.setToolTip("<REDACTED>")
                    value_item.setFlags(value_item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                meaning = table.item(row, 3)
                if meaning is not None:
                    meaning.setText("")
                    meaning.setToolTip("")

    def _refresh_history_details(self) -> None:
        super()._refresh_history_details()
        if not hasattr(self, "history_groups"):
            return
        record = self.records.get(self.selected_history_record_id or -1)
        self.history_groups.clear()
        self.history_diff.clear()
        self.history_related.setRowCount(0)
        if record is None:
            self.history_note.clear()
            self.history_note.setEnabled(False)
            self.bookmark_button.setText("☆ Bookmark")
            return
        self.history_note.setEnabled(True)
        self.history_note.setPlainText(record.note)
        self.bookmark_button.setText("★ Bookmarked" if record.bookmarked else "☆ Bookmark")
        self.history_raw.setPlainText(raw_to_editor_text(self._display_raw(record)))
        self._refresh_group_view(record)
        self._refresh_diff_view(record)
        self._refresh_related_view(record)

    def _refresh_group_view(self, record: TrafficRecord) -> None:
        message = parse_message(self._display_raw(record), self.dictionary)
        projection = project_groups(message, self.dictionary)
        if not projection.groups:
            QTreeWidgetItem(self.history_groups, ["No repeating groups defined/observed", "", "", ""])
            return
        for group in projection.groups:
            status = group.issue or f"declared {group.declared_count}"
            root = QTreeWidgetItem(
                self.history_groups,
                [f"{group.definition.count_tag} {group.definition.name}", "", "", status],
            )
            for instance in group.instances:
                instance_item = QTreeWidgetItem(root, [f"Instance {instance.instance_number}", "", "", ""])
                for index in instance.field_indexes:
                    field = message.fields[index]
                    definition = self.dictionary.field(field.tag)
                    name = definition.name if definition else ""
                    value = decode_value(field.value, message.encoding)
                    QTreeWidgetItem(instance_item, ["", f"{field.tag} {name}", value, f"wire index {index}"])
            root.setExpanded(True)

    def _refresh_diff_view(self, record: TrafficRecord) -> None:
        if record.effective_raw is None:
            self.history_diff.setPlainText("No effective modification. The original wire message is active.")
            return
        visible = lambda raw: raw if self._reveal_state() else self.secret_policy.redact(raw, self.dictionary)
        original = parse_message(visible(record.original_raw), self.dictionary)
        effective = parse_message(visible(record.effective_raw), self.dictionary)

        def lines(message) -> list[str]:
            occurrences: dict[str, int] = {}
            result: list[str] = []
            for field in message.fields:
                occurrences[field.tag] = occurrences.get(field.tag, 0) + 1
                value = decode_value(field.value, message.encoding)
                result.append(f"{field.tag}[{occurrences[field.tag]}]={value}")
            return result

        difference = list(
            difflib.unified_diff(
                lines(original), lines(effective), fromfile="original", tofile="effective", lineterm=""
            )
        )
        self.history_diff.setPlainText("\n".join(difference) if difference else "No field-level differences.")

    def _refresh_related_view(self, record: TrafficRecord) -> None:
        for link in self.correlation.related(record.record_id):
            related = self.correlation.record(link.target_id)
            if related is None:
                continue
            row = self.history_related.rowCount()
            self.history_related.insertRow(row)
            values = [
                str(link.score),
                str(related.record_id),
                display_direction(related.direction),
                related.msg_type,
                self.dictionary.message_name(related.msg_type),
                str(related.sequence_number or ""),
                "; ".join(link.reasons),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 1:
                    item.setData(Qt.ItemDataRole.UserRole, related.record_id)
                self.history_related.setItem(row, column, item)

    def _select_related_record(self, row: int, _column: int) -> None:
        item = self.history_related.item(row, 1)
        record_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        history_row = self.history_row_for_record.get(int(record_id)) if record_id is not None else None
        if history_row is not None:
            self.history.selectRow(history_row)
            self.history.scrollToItem(self.history.item(history_row, 0))

    def _save_selected_note(self) -> None:
        record = self.records.get(self.selected_history_record_id or -1)
        if record is None:
            return
        record.note = self.history_note.toPlainText()
        self._refresh_record_row(record)
        self._history_documents[record.record_id] = HistoryDocument.from_record(record, self.dictionary)
        self._persist_record(record)
        self.status_label.setText(f"Saved note for #{record.record_id}")

    def _toggle_selected_bookmark(self) -> None:
        record = self.records.get(self.selected_history_record_id or -1)
        if record is None:
            return
        record.bookmarked = not record.bookmarked
        self._refresh_record_row(record)
        self._history_documents[record.record_id] = HistoryDocument.from_record(record, self.dictionary)
        self._persist_record(record)
        self.bookmark_button.setText("★ Bookmarked" if record.bookmarked else "☆ Bookmark")
        self._apply_history_filter()

    def _refresh_record_row(self, record: TrafficRecord) -> None:
        row = self.history_row_for_record.get(record.record_id)
        if row is None:
            return
        for column, value in enumerate(self._record_summary(record)):
            item = self.history.item(row, column)
            if item is None:
                item = QTableWidgetItem()
                self.history.setItem(row, column, item)
            item.setText(value)
        self._style_history_row(row, record)

    def _history_context_actions(self, record: object):
        return self._message_context_actions(record) + [
            ("Export selected…", lambda: self._export_selected("choose"), True),
        ]

    def _message_context_actions(self, record: object):
        current = record if isinstance(record, TrafficRecord) else None
        if current is None:
            return []
        bookmark_label = "Remove bookmark" if current.bookmarked else "Add bookmark"
        return [
            (bookmark_label, lambda rid=current.record_id: self._toggle_bookmark(rid), True),
            ("Edit note…", lambda rid=current.record_id: self._edit_note(rid), True),
            (
                "Open in Sender",
                lambda rid=current.record_id: self._send_to_repeater(rid),
                True,
            ),
            (
                "Send to Fuzzer",
                lambda rid=current.record_id: self._send_to_fuzzer(rid),
                not self.dictionary.is_admin(current.msg_type),
            ),
            ("Send to Composer", lambda: self._send_to_composer(current.record_id),
             not self.dictionary.is_admin(current.msg_type) and current.msg_type in self.dictionary.messages),
            ("Send to Decoder", lambda: self._send_to_decoder(current.record_id), True),
        ]

    def _send_to_composer(self, record_id: int) -> None:
        record = self.records.get(record_id)
        if record is None or self.dictionary.is_admin(record.msg_type) or record.msg_type not in self.dictionary.messages:
            return
        panel = self.composer_panel
        try:
            panel.form = panel.controller.build_form(record.msg_type)
            panel.form.apply_raw(record.raw)
            panel._populate_form()
        except (KeyError, ValueError) as exc:
            QMessageBox.warning(self, "Send to Composer", self.secret_policy.redact_text(str(exc)))
            return
        # Preserve the full captured draft (including duplicate/custom fields).
        # Form regeneration remains an explicit existing Composer operation.
        panel._baseline_raw = record.raw
        panel.editor.set_raw(record.raw)
        panel.workbench.setCurrentIndex(1)
        panel.refresh_analysis(record.raw)
        self._navigate("Composer")

    def _send_to_decoder(self, record_id: int) -> None:
        record = self.records.get(record_id)
        if record is None:
            return
        # The Decoder input is a plain editor, so never paste hidden secrets.
        self.decoder_panel.input.setPlainText(raw_to_editor_text(self._display_raw(record)))
        self.decoder_panel.decode()
        self._navigate("Decoder")

    def _send_result_to_tool(self, destination: str, raw: bytes, title: str) -> None:
        if destination == "Sender":
            # A draft item, not a synthetic captured History event.
            record = TrafficRecord(0, "C→S", bytes(raw), source="FUZZER")
            item = self.repeater_controller.create_from_record(record)
            item.title = title
            item.source_record_id = 0  # existing persisted sentinel for no captured History source
            self.repeater_panel.add_item(item)
            self._navigate("Sender")
        elif destination == "Decoder":
            visible = raw if self._reveal_state() else self.secret_policy.redact(raw, self.dictionary)
            self.decoder_panel.input.setPlainText(raw_to_editor_text(visible))
            self.decoder_panel.decode()
            self._navigate("Decoder")

    def _send_to_repeater(self, record_id: int) -> None:
        record = self.records.get(record_id)
        if record is None:
            return
        try:
            item = self.repeater_controller.create_from_record(record)
        except ValueError as exc:
            QMessageBox.warning(self, "Open in Sender", str(exc))
            return
        self.repeater_panel.add_item(item)
        self._navigate("Sender")
        self.status_label.setText(f"Created {item.item_id} from History #{record_id}")

    def _queue_repeater(
        self,
        item_id: str,
        raw: bytes,
        mode: InjectionMode,
        auto_update: AutoUpdatePolicy,
    ) -> None:
        if not self._proxy_running:
            QMessageBox.warning(
                self,
                "Sender",
                "Start the proxy and establish an active external FIX session before queuing a replay.",
            )
            return
        if mode is InjectionMode.EXACT_RAW:
            answer = QMessageBox.critical(
                self,
                "Confirm session-destructive replay",
                "Send the captured raw bytes immediately? This bypasses safe-slot sequencing and can "
                "damage the active FIX session.",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        try:
            request = self.repeater_controller.queue(item_id, raw, mode, auto_update)
        except (KeyError, TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Sender", str(exc))
            return
        self.status_label.setText(display_status(request.status.value))
        self._refresh_diagnostics()

    def _send_repeater_new_connection(
        self, item_id: str, raw: bytes, auto_update: AutoUpdatePolicy
    ) -> None:
        existing = self._repeater_connections.get(item_id)
        if existing is not None and existing.running:
            QMessageBox.information(
                self,
                "Send on new connection",
                "Close this item's existing test connection before opening another one.",
            )
            return
        try:
            config = self._current_proxy_config()
            outbound = apply_auto_updates(
                raw,
                auto_update,
                sequence_number=1,
                dictionary=self.dictionary,
            )
            connection = IsolatedRepeaterConnection(
                config,
                dictionary=self.dictionary,
                next_record_id=self.engine.next_record_id,
                on_record=lambda record, key=item_id: (
                    self.repeater_panel.connection_record.emit(key, record),
                    self.bridge.record_received.emit(record),
                ),
                on_status=lambda text, key=item_id: self.repeater_panel.connection_status.emit(
                    key, text
                ),
            )
            self._repeater_connections[item_id] = connection
            connection.send_logon(outbound)
        except (OSError, RuntimeError, TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Send on new connection", str(exc))

    def _close_repeater_connection(self, item_id: str) -> None:
        connection = self._repeater_connections.get(item_id)
        if connection is not None:
            connection.close()
        self.repeater_panel.connection_status.emit(item_id, "Isolated Sender connection closed")

    def _current_proxy_config(self) -> ProxyConfig:
        return ProxyConfig(
            listen_host=self.listen_host.text().strip(),
            listen_port=int(self.listen_port.text()),
            upstream_host=self.upstream_host.text().strip(),
            upstream_port=int(self.upstream_port.text()),
            upstream_sni=self.upstream_sni.text().strip(),
            verify_upstream=self.verify_tls.isChecked(),
            ca_file=self.ca_file.text().strip(),
            upstream_transport=str(self.upstream_transport.currentData()),
        )

    def _on_injection_event(self, request: InjectionRequest) -> None:
        self.repeater_controller.handle_injection_event(request)
        self.composer_controller.handle_injection_event(request)
        self.fuzzer_controller.handle_injection_event(request)
        self._refresh_diagnostics()

    def _queue_composer(self, raw: bytes, template_id: str) -> None:
        if not self._proxy_running:
            QMessageBox.warning(
                self,
                "Composer",
                "Start the proxy and establish an active external FIX session before queuing a message.",
            )
            return
        request = self.composer_controller.queue(raw, template_id=template_id)
        self.status_label.setText(display_status(request.status.value))
        self._refresh_diagnostics()

    def _persist_workspace_state(self) -> None:
        if self.project_database is None or self._loading_project:
            self.status_label.setText("Workspace state is in memory; save it by creating or saving a project")
            return
        try:
            self.project_database.save_states(self._capture_project_states())
        except RuntimeError as exc:
            self.status_label.setText(str(exc))

    def _send_to_fuzzer(self, record_id: int) -> None:
        record = self.records.get(record_id)
        if record is None:
            return
        self._create_fuzzer_campaign(
            "History",
            f"#{record_id}",
            record.raw,
            f"History #{record_id} · {record.msg_type} / {self.dictionary.message_name(record.msg_type)}",
        )

    def _create_fuzzer_campaign(self, source_kind: str, source_id: str, raw: bytes, title: str) -> None:
        try:
            campaign = self.fuzzer_controller.create_campaign(source_kind, source_id, raw, title)
        except ValueError as exc:
            QMessageBox.warning(self, "Fuzzer baseline", str(exc))
            return
        self.fuzzer_panel.add_campaign(campaign)
        self._navigate("Fuzzer")
        self.status_label.setText(
            f"Created finite low-rate campaign {campaign.campaign_id} from {source_kind} {source_id}"
        )

    def _fuzzer_outcome_records(self, record_id: int) -> list[TrafficRecord]:
        related: list[TrafficRecord] = []
        for link in self.correlation.related(record_id):
            record = self.records.get(link.target_id)
            if record is not None:
                related.append(record)
        # Related History may legitimately contain an older baseline or a
        # sibling request. Those are context, not a campaign outcome.
        return eligible_outcome_records(record_id, related)

    def _interesting_history_values(self, tag: str) -> tuple[bytes, ...]:
        key = str(tag)
        if not key or key in self.secret_policy.secret_tags:
            return ()
        values: list[bytes] = []
        seen: set[bytes] = set()
        for record in self.records.values():
            for value in parse_message(record.raw, self.dictionary).values(key):
                current = bytes(value)
                if current in seen:
                    continue
                seen.add(current)
                values.append(current)
                if len(values) >= 50:
                    return tuple(values)
        return tuple(values)

    def _navigate_history_record(self, record_id: int) -> None:
        row = self.history_row_for_record.get(record_id)
        if row is None:
            return
        self._navigate("History")
        self.history.selectRow(row)
        self.selected_history_record_id = record_id
        self._refresh_history_details()

    def _repeater_related_rows(self, record_id: int) -> list[tuple[int, int, str, str, str, str]]:
        rows: list[tuple[int, int, str, str, str, str]] = []
        for link in self.correlation.related(record_id):
            record = self.records.get(link.target_id)
            if record is None:
                continue
            rows.append(
                (
                    link.score,
                    record.record_id,
                    record.direction,
                    record.msg_type,
                    str(record.sequence_number or ""),
                    ", ".join(link.reasons),
                )
            )
        return rows

    def _toggle_bookmark(self, record_id: int) -> None:
        self.selected_history_record_id = record_id
        self._toggle_selected_bookmark()

    def _edit_note(self, record_id: int) -> None:
        record = self.records.get(record_id)
        if record is None:
            return
        text, accepted = QInputDialog.getMultiLineText(self, f"Note for #{record_id}", "Analyst note", record.note)
        if accepted:
            record.note = text
            self._refresh_record_row(record)
            self._history_documents[record.record_id] = HistoryDocument.from_record(record, self.dictionary)
            self._persist_record(record)
            if self.selected_history_record_id == record_id:
                self.history_note.setPlainText(text)

    # ----------------------------------------------------------- secret policy

    def _apply_secret_policy(self) -> None:
        try:
            policy = SecretRedactionPolicy.from_text(self.additional_secret_tags.text())
        except ValueError as exc:
            self.secret_policy_error.setText(str(exc))
            self.secret_policy_error.show()
            return
        self.secret_policy_error.clear()
        self.secret_policy_error.hide()
        from .widgets import MessageEditorWidget
        editors = self.findChildren(MessageEditorWidget)
        for editor in editors:
            editor.commit_presentation_draft()
        self.secret_policy = policy
        self._show_sensitive = not self.mask_sensitive_fields.isChecked()
        # Reproject with the new tag set before another editor synchronization.
        for editor in editors:
            editor.set_raw(editor._working_raw)
        update_logging_policy(policy)
        self.engine.proxy_behaviour.set_secret_tags(policy.secret_tags)
        self.additional_secret_tags.setText(",".join(sorted(policy.additional_tags, key=int)))
        self._refresh_secret_views()
        if self.project_database is not None:
            self.project_database.policy = policy
            try:
                self.project_database.reapply_redaction_policy()
                self.project_database.save_records(self.records.values())
                self.project_database.save_states(self._capture_project_states())
            except RuntimeError as exc:
                QMessageBox.critical(self, "Secret policy", str(exc))
                return
        settings = self._settings()
        settings.setValue("security/additional_secret_tags", self.additional_secret_tags.text())
        settings.setValue("security/mask_sensitive_fields", not self._show_sensitive)
        settings.sync()
        self._history_documents = {
            record_id: HistoryDocument.from_record(record, self.dictionary)
            for record_id, record in self.records.items()
        }
        self.status_label.setText(
            "Secret policy applied: " + ", ".join(sorted(policy.secret_tags, key=int))
        )

    def _refresh_secret_views(self) -> None:
        self._refresh_history_details()
        for record_id, row in self.history_row_for_record.items():
            record = self.records.get(record_id)
            if record is not None:
                for column, value in enumerate(self._record_summary(record)):
                    item = self.history.item(row, column)
                    if item is not None:
                        item.setText(value)
        # Refresh legacy inspection surfaces without reloading the shared
        # editable draft from the original held record.
        super()._refresh_intercept_details()
        record = self.records.get(self.selected_intercept_record_id or -1)
        if record is not None:
            self.intercept_raw.setPlainText(raw_to_editor_text(self._display_raw(record)))
        self.proxy_shared_editor.set_reveal(self._show_sensitive)
        for panel in (self.repeater_panel, self.composer_panel, self.fuzzer_panel, self.decoder_panel):
            panel.set_reveal(self._show_sensitive)

    def _refresh_intercept_details(self) -> None:
        super()._refresh_intercept_details()
        if hasattr(self, "proxy_shared_editor"):
            record = self.records.get(self.selected_intercept_record_id or -1)
            self.proxy_shared_editor.set_reveal(self._reveal_state())
            if record is not None:
                self.proxy_shared_editor.set_raw(record.raw)
                self.proxy_shared_editor.set_mode(
                    InjectionMode.CLONE_EDIT if record.status == "HELD" else InjectionMode.BUSINESS_REPLAY
                )
            else:
                self.proxy_shared_editor.set_raw(b"")
                self.proxy_shared_editor.set_mode(InjectionMode.BUSINESS_REPLAY)
        if not hasattr(self, "secret_policy") or self._reveal_state():
            return
        record = self.records.get(self.selected_intercept_record_id or -1)
        if record is not None:
            self.intercept_raw.setPlainText(raw_to_editor_text(self.secret_policy.redact(record.raw, self.dictionary)))
            self._refresh_intercept_editability()

    def _refresh_intercept_editability(self) -> None:
        super()._refresh_intercept_editability()
        if not hasattr(self, "secret_policy") or self._reveal_state():
            return
        record = self.records.get(self.selected_intercept_record_id or -1)
        if record is None:
            return
        message = parse_message(record.raw, self.dictionary)
        contains_secret = any(field.tag in self.secret_policy.secret_tags for field in message.fields)
        for row in range(self.intercept_fields.rowCount()):
            tag_item = self.intercept_fields.item(row, 0)
            if tag_item is None or tag_item.text() not in self.secret_policy.secret_tags:
                continue
            for column in range(self.intercept_fields.columnCount()):
                item = self.intercept_fields.item(row, column)
                if item is not None:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
        if contains_secret and self.raw_mode.isChecked():
            self.intercept_raw.setReadOnly(True)

    def _current_structured_raw(self) -> bytes:
        record = self.records.get(self.selected_intercept_record_id or -1)
        if not record:
            raise ValueError("No intercepted message selected")
        original = parse_message(record.raw, self.dictionary)
        fields: list[FixField] = []
        policy = getattr(self, "secret_policy", SecretRedactionPolicy())
        for row in range(self.intercept_fields.rowCount()):
            tag_item = self.intercept_fields.item(row, 0)
            value_item = self.intercept_fields.item(row, 2)
            if not tag_item or not value_item:
                continue
            tag = tag_item.text().strip()
            if not tag:
                continue
            if tag in policy.secret_tags and not self._reveal_state():
                value = value_item.data(Qt.ItemDataRole.UserRole)
                if not isinstance(value, (bytes, bytearray)):
                    raise ValueError(f"Cannot recover redacted secret tag {tag}")
                value_bytes = bytes(value)
            else:
                value_bytes = encode_value(value_item.text(), original.encoding)
            fields.append(FixField(tag=tag, value=value_bytes))
        return serialize_structured(fields)

    def _forward_current(self) -> None:
        record = self.records.get(self.selected_intercept_record_id or -1)
        if not record or record.status != "HELD":
            return
        if hasattr(self, "proxy_workspace") or self.intercept_editor_tabs.currentWidget() is self.proxy_shared_editor:
            try:
                outbound = self.proxy_shared_editor.outbound_raw(
                    repair_raw=self.proxy_shared_editor._editor_index == 0
                )
            except (TypeError, ValueError) as exc:
                QMessageBox.critical(self, "Cannot forward", str(exc))
                return
            original_raw = record.raw
            record.modified = outbound != original_raw
            record.raw = outbound
            self.engine.resolve_intercept(record.record_id, "forward", outbound)
            self.status_label.setText(f"Forward requested for #{record.record_id}")
            return
        message = parse_message(record.raw, self.dictionary)
        has_hidden_secret = (
            not self._reveal_state()
            and any(field.tag in self.secret_policy.secret_tags for field in message.fields)
        )
        if self.raw_mode.isChecked() and has_hidden_secret:
            QMessageBox.critical(
                self,
                "Cannot forward",
                "Disable masking in Settings → Privacy before forwarding from the redacted raw editor.",
            )
            return
        super()._forward_current()

    # ------------------------------------------------------------ diagnostics

    def _on_proxy_status(self, text: str) -> None:
        visible_text = display_direction_text(text)
        super()._on_proxy_status(visible_text)
        LOGGER.info("Proxy status: %s", visible_text)
        if text.startswith("Listener error"):
            self._set_proxy_running(False)
        self._refresh_diagnostics()

    def _refresh_diagnostics(self) -> None:
        if not hasattr(self, "diagnostics_panel"):
            return
        snapshot = self.engine.diagnostics()
        field_count = len(self.dictionary.fields_by_tag)
        message_count = len(self.dictionary.messages)
        self.diagnostics_panel.update_state(snapshot, field_count, message_count)
        durable_count = self.project_database.record_count() if self.project_database is not None else None
        self.diagnostics_panel.update_runtime(
            live_count=len(self.records),
            live_limit=self.history_limit.value() if hasattr(self, "history_limit") else 10_000,
            evicted_count=self._evicted_record_count,
            durable_count=durable_count,
            log_path=current_log_path(),
        )
        self.queue_state_label.setText(f"Held {snapshot.held_count} / queued {snapshot.queued_count}")
        if snapshot.paused_client_sequence is None:
            self._queue_box.setTitle(
                f"Intercept / ordered queue - held {snapshot.held_count}, queued {snapshot.queued_count}"
            )
        else:
            self._queue_box.setTitle(
                f"Client → Server paused at SeqNum {snapshot.paused_client_sequence} - "
                f"{snapshot.client_queued_count} subsequent message(s) queued"
            )
        plain_tcp = snapshot.tls_verification == PLAIN_TCP_VERIFICATION
        self.tls_state_label.setText(
            "Upstream: Plain TCP" if plain_tcp else f"TLS: {snapshot.tls_verification}"
        )
        role(self.tls_state_label, "muted" if plain_tcp else
             "warning" if snapshot.tls_verification.startswith("DISABLED") else "success")
        if hasattr(self, "fuzzer_controller"):
            self.fuzzer_controller.set_connected(snapshot.upstream_state.startswith("Connected "))
            self.fuzzer_controller.tick()
        if hasattr(self, "proxy_behaviour_panel"):
            self.proxy_behaviour_panel.refresh()
            behaviour_text = display_direction_text(
                self.engine.proxy_behaviour.status_text(snapshot.held_count + snapshot.queued_count)
            )
            self.proxy_behaviour_status.setText(behaviour_text)
            behaviour = self.engine.proxy_behaviour.snapshot()
            active = any(
                (
                    state.global_mode.value != "NORMAL"
                    or state.application_mode.value != "NORMAL"
                    or state.admin_mode.value != "NORMAL"
                    or state.delay_enabled
                )
                for state in (behaviour.client_to_server, behaviour.server_to_client)
            ) or bool(behaviour.active_rule_count or behaviour.one_shots or behaviour.disconnect_triggers)
            role(self.proxy_behaviour_status, "danger" if active else "secondary")
        if hasattr(self, "shell"):
            self.shell.refresh()
        if hasattr(self, "proxy_workspace"):
            self.proxy_workspace.refresh()

    def _update_tls_warning(self) -> None:
        transport = str(self.upstream_transport.currentData())
        if transport == "plain_tcp":
            self.tls_warning.setText("Plain TCP - upstream traffic is not encrypted.")
            role(self.tls_warning, "muted")
        elif self.verify_tls.isChecked():
            ca = self.ca_file.text().strip()
            trust = f"custom CA {Path(ca).name}" if ca else "system trust store"
            self.tls_warning.setText(f"TLS certificate and hostname verification enabled using {trust}.")
            role(self.tls_warning, "success")
        else:
            self.tls_warning.setText(
                "WARNING: upstream TLS certificate verification is DISABLED. "
                "This is a testing-only mode and does not authenticate the server."
            )
            role(self.tls_warning, "warning")
        self.engine.set_tls_preview(
            self.verify_tls.isChecked(), self.ca_file.text().strip(), transport=transport
        )
        self._refresh_diagnostics()

    def _start_proxy(self) -> None:
        try:
            config = self._current_proxy_config()
            config.validate_endpoints()
        except (ValueError, OSError) as exc:
            QMessageBox.critical(self, "Proxy configuration", str(exc))
            return
        if config.upstream_transport == "tls" and not config.verify_upstream:
            answer = QMessageBox.warning(
                self,
                "Testing-only TLS mode",
                "Upstream certificate verification is DISABLED. The server will not be authenticated. "
                "Use this only for an authorized test harness. Start anyway?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        try:
            self._update_intercept()
            self._save_settings()
            self.engine.start(config)
            self._set_proxy_running(True)
        except Exception as exc:  # noqa: BLE001 - report transport startup failures
            QMessageBox.critical(self, "Proxy error", str(exc))

    # ------------------------------------------------------------- persistence

    def _persist_record(self, record: TrafficRecord) -> None:
        if self.project_database is None or self._loading_project:
            return
        try:
            self.project_database.save_record(record)
        except RuntimeError as exc:
            self.status_label.setText(str(exc))

    def _capture_project_states(self) -> dict[str, object]:
        headers = {
            name: encode_bytes(bytes(getattr(self, attribute).horizontalHeader().saveState()))
            for name, attribute in self._HEADER_SETTINGS.items()
        }
        return {
            "history_filter": {
                "text": self.proxy_workspace.filters.persistable_text(self.filter_edit.text()) if hasattr(self, "proxy_workspace") else self.filter_edit.text(),
                "advanced": self.advanced_filter.isChecked(),
                "direction": str(self.direction_filter.currentData() or ""),
                "bookmarks_only": self.bookmarks_only.isChecked(),
                "hide_admin": self.hide_admin.isChecked(),
                "hide_heartbeats": self.hide_heartbeats.isChecked(),
                "controls": self.proxy_workspace.filters.persistence_state() if hasattr(self, "proxy_workspace") else None,
            },
            "dictionary": {
                "transport": self.transport_dict.text().strip(),
                "application": self.app_dict.text().strip(),
            },
            "security": {"secret_tags": sorted(self.secret_policy.secret_tags, key=int)},
            "retention": {"max_live_records": self.history_limit.value()},
            "repeater": {
                "items": self.repeater_controller.to_state(
                    lambda raw: self.secret_policy.redact(raw, self.dictionary)
                )
            },
            "composer": self.composer_controller.to_state(
                lambda raw: self.secret_policy.redact(raw, self.dictionary),
                self.secret_policy.redact_text,
            ),
            "fuzzer": self.fuzzer_controller.to_state(
                lambda raw: self.secret_policy.redact(raw, self.dictionary),
                self.secret_policy.redact_text,
            ),
            "proxy_behaviour": self.engine.proxy_behaviour.to_state(
                self.secret_policy.secret_tags
            ),
            "ui_layout": {
                "geometry": encode_bytes(bytes(self.saveGeometry())),
                "history_splitter": encode_bytes(bytes(self.history_splitter.saveState())),
                "intercept_splitter": encode_bytes(bytes(self.intercept_splitter.saveState())),
                "headers": headers,
                "workspace_tab": self._workspace_index(),
                "inspector_tab": self.history_inspector.currentIndex(),
            },
        }

    def _restore_project_states(self, states: dict[str, object]) -> None:
        security = states.get("security", {})
        if isinstance(security, dict):
            tags = security.get("secret_tags", ["553"])
            if isinstance(tags, list):
                try:
                    self.secret_policy = SecretRedactionPolicy(self.secret_policy.additional_tags | frozenset(str(tag) for tag in tags))
                    self.additional_secret_tags.setText(
                        ",".join(sorted(self.secret_policy.additional_tags, key=int))
                    )
                except ValueError:
                    pass  # Invalid legacy project metadata cannot weaken the global policy.
        if self.project_database is not None:
            self.project_database.policy = self.secret_policy
        update_logging_policy(self.secret_policy)

        self.engine.proxy_behaviour.set_secret_tags(self.secret_policy.secret_tags)
        self.engine.proxy_behaviour.restore_state(states.get("proxy_behaviour", {}))
        if hasattr(self, "proxy_behaviour_panel"):
            self.proxy_behaviour_panel.refresh()

        retention = states.get("retention", {})
        if isinstance(retention, dict):
            try:
                self.history_limit.setValue(int(retention.get("max_live_records", 10_000)))
            except (TypeError, ValueError):
                self.history_limit.setValue(10_000)

        repeater_state = states.get("repeater", {})
        if isinstance(repeater_state, dict):
            self.repeater_controller.restore_state(repeater_state.get("items", []))
            self.repeater_panel.restore_items(self.repeater_controller.items())
            greatest_injection_id = max(
                (
                    run.injection_id
                    for item in self.repeater_controller.items()
                    for run in item.runs
                ),
                default=0,
            )
            self.engine.injection.reserve_ids_through(greatest_injection_id)

        self.composer_controller.restore_state(states.get("composer", {}))
        self.composer_panel.refresh_templates()
        self.fuzzer_controller.restore_state(states.get("fuzzer", []))
        self.fuzzer_panel.restore_campaigns(self.fuzzer_controller.campaigns())
        greatest_fuzzer_injection_id = max(
            (
                case.injection_id or 0
                for campaign in self.fuzzer_controller.campaigns()
                for case in campaign.cases
            ),
            default=0,
        )
        self.engine.injection.reserve_ids_through(
            max(greatest_injection_id if isinstance(repeater_state, dict) else 0, greatest_fuzzer_injection_id)
        )

        dictionary_state = states.get("dictionary", {})
        if isinstance(dictionary_state, dict):
            self.transport_dict.setText(str(dictionary_state.get("transport", "")))
            self.app_dict.setText(str(dictionary_state.get("application", "")))
            paths = [
                path
                for path in (self.transport_dict.text().strip(), self.app_dict.text().strip())
                if path and Path(path).is_file()
            ]
            if paths:
                try:
                    self.dictionary = FixDictionary.from_files(*paths)
                    self._loaded_dictionary_paths = (self.transport_dict.text().strip(), self.app_dict.text().strip())
                    self.engine.set_dictionary(self.dictionary)
                    self.repeater_controller.dictionary = self.dictionary
                    self.composer_controller.set_dictionary(self.dictionary)
                    self.fuzzer_controller.set_dictionary(self.dictionary)
                    self.composer_panel.refresh_messages()
                    self.fuzzer_panel.refresh_current()
                    self.dictionary_browser.refresh(self.dictionary)
                    if self.project_database is not None:
                        self.project_database.dictionary = self.dictionary
                    self.dictionary_state.setText(
                        f"Loaded {len(self.dictionary.fields_by_tag)} fields / "
                        f"{len(self.dictionary.messages)} messages"
                    )
                except Exception as exc:  # noqa: BLE001
                    self.dictionary_state.setText(f"Project dictionary could not be loaded: {exc}")

        history = states.get("history_filter", {})
        if isinstance(history, dict):
            if hasattr(self, "proxy_workspace"):
                self.proxy_workspace.filters._syncing = True
            self.filter_edit.setText(str(history.get("text", "")))
            self.advanced_filter.setChecked(bool(history.get("advanced", False)))
            direction = internal_direction(history.get("direction", ""))
            index = self.direction_filter.findData(direction)
            self.direction_filter.setCurrentIndex(max(0, index))
            self.bookmarks_only.setChecked(bool(history.get("bookmarks_only", False)))
            self.hide_admin.setChecked(bool(history.get("hide_admin", True)))
            self.hide_heartbeats.setChecked(bool(history.get("hide_heartbeats", True)))
            self.config_hide_admin.setChecked(self.hide_admin.isChecked())
            self.config_hide_heartbeats.setChecked(self.hide_heartbeats.isChecked())
            if hasattr(self, "proxy_workspace"):
                self.proxy_workspace.filters.restore(history.get("controls"))

        layout = states.get("ui_layout", {})
        if isinstance(layout, dict):
            try:
                if layout.get("geometry"):
                    self.restoreGeometry(decode_bytes(str(layout["geometry"])))
                if layout.get("history_splitter"):
                    self.history_splitter.restoreState(decode_bytes(str(layout["history_splitter"])))
                if layout.get("intercept_splitter"):
                    self.intercept_splitter.restoreState(decode_bytes(str(layout["intercept_splitter"])))
                headers = layout.get("headers", {})
                if isinstance(headers, dict):
                    for name, attribute in self._HEADER_SETTINGS.items():
                        if name in headers:
                            getattr(self, attribute).horizontalHeader().restoreState(
                                decode_bytes(str(headers[name]))
                            )
                self._restore_workspace_index(int(layout.get("workspace_tab", 1)))
                if hasattr(self, "proxy_workspace"):
                    self.intercept_splitter.setOrientation(Qt.Orientation.Horizontal)
                inspector_index = int(layout.get("inspector_tab", 0))
                if hasattr(self, "shell"):
                    self.shell.history_tools.show_tab(inspector_index)
                else:
                    self.history_inspector.setCurrentIndex(inspector_index)
            except (ValueError, TypeError):
                self.status_label.setText("Some saved project layout state could not be restored")
        if hasattr(self, "product_presentation"):
            self.product_presentation.dictionaries.refresh()
        self._refresh_secret_views()

    def _new_project(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "New FIX Inspector project", "", "FIX Inspector project (*.fixproj);;All files (*)"
        )
        if not path:
            return
        if not Path(path).suffix:
            path += ".fixproj"
        self._attach_project(Path(path), load=False)

    def _open_project(self) -> None:
        if self._proxy_running or self.held_row_for_record:
            QMessageBox.warning(
                self,
                "Open project",
                "Stop the proxy and resolve the ordered intercept queue before opening a project.",
            )
            return
        if self.records and self.project_database is None:
            answer = QMessageBox.question(
                self,
                "Open project",
                "Opening a project replaces the current unsaved in-memory History. Continue?",
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        path, _ = QFileDialog.getOpenFileName(
            self, "Open FIX Inspector project", "", "FIX Inspector project (*.fixproj);;All files (*)"
        )
        if path:
            self._attach_project(Path(path), load=True)

    def _attach_project(self, path: Path, *, load: bool) -> None:
        if self.project_database is not None:
            try:
                self.project_database.save_records(self.records.values())
                self.project_database.save_states(self._capture_project_states())
            except RuntimeError:
                pass
            self.project_database.close()
        database: ProjectDatabase | None = None
        try:
            database = ProjectDatabase(path, policy=self.secret_policy, dictionary=self.dictionary)
            self.project_database = database
            self.project_path = path
            opened_status = f"{'Opened' if load else 'Created'} project {path.name}"
            if load:
                states = database.load_states()
                self._restore_project_states(states)
                records = database.load_records(limit=self.history_limit.value())
                self._load_project_records(records)
                durable_count = database.record_count()
                if durable_count > len(records):
                    opened_status = (
                        f"Opened {path.name}; showing newest {len(records):,} of "
                        f"{durable_count:,} durable record(s)"
                    )
            else:
                database.replace_records(self.records.values())
                database.save_states(self._capture_project_states())
            self.project_state_label.setText(f"Project: {path.name}")
            self.setWindowTitle(f"FIX Inspector {__version__} - {path.name}")
            self.status_label.setText(opened_status)
        except (OSError, RuntimeError) as exc:
            if database is not None:
                database.close()
            self.project_database = None
            self.project_path = None
            QMessageBox.critical(self, "Project error", str(exc))

    def _load_project_records(self, records: list[TrafficRecord]) -> None:
        self._loading_project = True
        try:
            self._reset_history_views()
            for record in records:
                self.records[record.record_id] = record
                row = self.history.rowCount()
                self.history.insertRow(row)
                self.history_row_for_record[record.record_id] = row
                for column, value in enumerate(self._record_summary(record)):
                    item = QTableWidgetItem(value)
                    if column == 0:
                        item.setData(Qt.ItemDataRole.UserRole, record.record_id)
                    self.history.setItem(row, column, item)
                self._style_history_row(row, record)
                self._history_documents[record.record_id] = HistoryDocument.from_record(record, self.dictionary)
            self.correlation.rebuild(records)
            self.engine.reserve_record_ids_through(max((record.record_id for record in records), default=0))
        finally:
            self._loading_project = False
        self._run_history_filter()
        if records:
            self.history.selectRow(0)

    def _save_project(self) -> None:
        if self.project_database is None:
            self._save_project_as()
            return
        try:
            self.project_database.policy = self.secret_policy
            self.project_database.dictionary = self.dictionary
            self.project_database.save_records(self.records.values())
            self.project_database.save_states(self._capture_project_states())
            self.status_label.setText(f"Saved project {self.project_path.name if self.project_path else ''}")
        except RuntimeError as exc:
            QMessageBox.critical(self, "Project save error", str(exc))

    def _save_project_as(self) -> None:
        path, _ = QFileDialog.getSaveFileName(
            self, "Save FIX Inspector project as", "", "FIX Inspector project (*.fixproj);;All files (*)"
        )
        if not path:
            return
        if not Path(path).suffix:
            path += ".fixproj"
        target = Path(path)
        if self.project_database is None:
            self._attach_project(target, load=False)
            return
        original_path = self.project_path
        original_database = self.project_database
        try:
            original_database.save_records(self.records.values())
            original_database.save_states(self._capture_project_states())
            original_database.backup_to(target)
            original_database.close()
            self.project_database = None
            replacement = ProjectDatabase(
                target, policy=self.secret_policy, dictionary=self.dictionary
            )
            self.project_database = replacement
            self.project_path = target
            self.project_state_label.setText(f"Project: {target.name}")
            self.setWindowTitle(f"FIX Inspector {__version__} - {target.name}")
            self.status_label.setText(f"Saved complete project copy as {target.name}")
        except (OSError, RuntimeError) as exc:
            # Save As must not leave the window pointing at a closed database.
            # If switching to the copy fails after backup, reopen the original.
            if self.project_database is None and original_path is not None:
                try:
                    self.project_database = ProjectDatabase(
                        original_path,
                        policy=self.secret_policy,
                        dictionary=self.dictionary,
                    )
                    self.project_path = original_path
                except (OSError, RuntimeError):
                    self.project_path = None
            QMessageBox.critical(self, "Project save-as error", str(exc))

    def _close_project(self) -> None:
        if self.project_database is None:
            return
        self._save_project()
        self.project_database.close()
        self.project_database = None
        self.project_path = None
        self.project_state_label.setText("Project: unsaved")
        self.setWindowTitle(f"FIX Inspector {__version__}")
        self.status_label.setText("Project closed; in-memory history retained")

    def _selected_history_records(self) -> list[TrafficRecord]:
        rows = sorted({index.row() for index in self.history.selectedIndexes()})
        if not rows and self.history.currentRow() >= 0:
            rows = [self.history.currentRow()]
        result: list[TrafficRecord] = []
        for row in rows:
            record = self._record_for_table_row(self.history, row)
            if isinstance(record, TrafficRecord):
                result.append(record)
        return result

    def _export_selected(self, kind: str) -> None:
        records = self._selected_history_records()
        if not records:
            QMessageBox.information(self, "Export", "Select one or more History rows first.")
            return
        if kind == "choose":
            labels = ["Readable text", "Raw FIX", "JSON", "Markdown"]
            selected, accepted = QInputDialog.getItem(self, "Export selected", "Format", labels, 0, False)
            if not accepted:
                return
            kind = {"Readable text": "readable", "Raw FIX": "raw", "JSON": "json", "Markdown": "markdown"}[selected]
        extension = {"readable": "txt", "raw": "fix", "json": "json", "markdown": "md"}[kind]
        path, _ = QFileDialog.getSaveFileName(
            self,
            "Export selected traffic (secrets redacted)",
            f"fix-traffic.{extension}",
            f"{extension.upper()} files (*.{extension});;All files (*)",
        )
        if not path:
            return
        try:
            write_export(path, records, kind, dictionary=self.dictionary, policy=self.secret_policy)
            self.status_label.setText(f"Exported {len(records)} record(s), configured secrets redacted")
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "Export error", str(exc))

    def _reset_history_views(self) -> None:
        self.history.setRowCount(0)
        self.held_table.setRowCount(0)
        self.records.clear()
        self.history_row_for_record.clear()
        self.held_row_for_record.clear()
        self._held_started.clear()
        self._history_documents.clear()
        self.correlation.clear()
        self.selected_history_record_id = None
        self.selected_intercept_record_id = None
        self._refresh_history_details()
        self._refresh_intercept_details()

    def _clear_history(self) -> None:
        if self.held_row_for_record:
            QMessageBox.warning(self, "History", "Resolve held/queued messages before clearing history.")
            return
        self._reset_history_views()
        if self.project_database is not None:
            try:
                self.project_database.replace_records([])
            except RuntimeError as exc:
                self.status_label.setText(str(exc))

    def _load_dictionaries(self) -> bool:
        paths = (self.transport_dict.text().strip(), self.app_dict.text().strip())
        try:
            dictionary = FixDictionary.from_files(*(path for path in paths if path))
        except Exception as exc:  # same parser; fail-soft inline UI error
            self.dictionary_state.setText("Dictionary not loaded: " + self.secret_policy.redact_text(str(exc)))
            role(self.dictionary_state, "danger")
            return False
        self.dictionary = dictionary
        self.engine.set_dictionary(dictionary)
        self._loaded_dictionary_paths = paths
        self.dictionary_state.setText(f"Loaded {len(dictionary.fields_by_tag)} fields / {len(dictionary.messages)} messages" if any(paths) else "No dictionary loaded - forwarding remains available")
        role(self.dictionary_state, "muted")
        self.status_label.setText("Dictionaries loaded" if any(paths) else "Dictionaries removed")
        self._save_settings()
        self._rebuild_history_rows()
        self._refresh_history_details()
        self._refresh_intercept_details()
        if not hasattr(self, "dictionary_browser"):
            return True
        self.dictionary_browser.refresh(self.dictionary)
        self.correlation.dictionary = self.dictionary
        if hasattr(self, "repeater_controller"):
            self.repeater_controller.dictionary = self.dictionary
        if hasattr(self, "composer_controller"):
            self.composer_controller.set_dictionary(self.dictionary)
            self.composer_panel.refresh_messages()
        if hasattr(self, "fuzzer_controller"):
            self.fuzzer_controller.set_dictionary(self.dictionary)
            self.fuzzer_panel.refresh_current()
        if hasattr(self, "decoder_panel"):
            self.decoder_panel.set_dictionary(self.dictionary)
        self.correlation.rebuild(self.records.values())
        self._history_documents = {
            record_id: HistoryDocument.from_record(record, self.dictionary)
            for record_id, record in self.records.items()
        }
        if self.project_database is not None:
            self.project_database.dictionary = self.dictionary
        if hasattr(self, "product_presentation"):
            self.product_presentation.dictionaries.refresh()
        return True

    def _restore_stage1_settings(self) -> None:
        settings = self._settings()
        splitter_state = settings.value("ui/intercept_splitter")
        if splitter_state is not None:
            self.intercept_splitter.restoreState(splitter_state)
        for key, attribute in self._HEADER_SETTINGS.items():
            state = settings.value(key)
            if state is not None:
                getattr(self, attribute).horizontalHeader().restoreState(state)
        try:
            self.workspace_tabs.setCurrentIndex(int(settings.value("ui/current_tab", 0)))
        except (TypeError, ValueError):
            pass
        self.filter_edit.setText(str(settings.value("history/filter", "")))
        self.advanced_filter.setChecked(self._as_bool(settings.value("history/advanced", False)))
        direction = internal_direction(settings.value("history/direction", ""))
        self.direction_filter.setCurrentIndex(max(0, self.direction_filter.findData(direction)))
        self.bookmarks_only.setChecked(self._as_bool(settings.value("history/bookmarks_only", False)))
        hide_heartbeats = self._as_bool(settings.value("traffic/hide_heartbeats", True), True)
        self.hide_heartbeats.setChecked(hide_heartbeats)
        self.config_hide_heartbeats.setChecked(hide_heartbeats)
        self.intercept_c2s_admin_policy.setChecked(
            self._as_bool(settings.value("traffic/policy_c2s_admin", False), False)
        )
        self.intercept_s2c_admin_policy.setChecked(
            self._as_bool(settings.value("traffic/policy_s2c_admin", False), False)
        )

    def _save_settings(self) -> None:
        super()._save_settings()
        if hasattr(self, "presentation_controller"):
            self.presentation_controller.save()
        if not hasattr(self, "history"):
            return
        settings = self._settings()
        settings.setValue("proxy/upstream_transport", self.upstream_transport.currentData())
        if hasattr(self, "shell"):
            settings.setValue("ui/current_tab", self._workspace_index())
            settings.setValue("ui/viewer_columns_initialized", True)
        if hasattr(self, "proxy_workspace"):
            settings.setValue("ui/proxy_phase2_columns", True)
            settings.setValue("ui/history_filter_controls", json.dumps(self.proxy_workspace.filters.persistence_state()))
        settings.setValue("ui/intercept_splitter", self.intercept_splitter.saveState())
        for key, attribute in self._HEADER_SETTINGS.items():
            settings.setValue(key, getattr(self, attribute).horizontalHeader().saveState())
        if hasattr(self, "advanced_filter"):
            settings.setValue("history/filter", self.proxy_workspace.filters.persistable_text(self.filter_edit.text()) if hasattr(self, "proxy_workspace") else self.filter_edit.text())
            settings.setValue("history/advanced", self.advanced_filter.isChecked())
            settings.setValue("history/direction", str(self.direction_filter.currentData() or ""))
            settings.setValue("history/bookmarks_only", self.bookmarks_only.isChecked())
            settings.setValue(
                "security/additional_secret_tags",
                ",".join(sorted(self.secret_policy.additional_tags, key=int)),
            )
            settings.setValue("history/live_limit", self.history_limit.value())
            settings.setValue("security/mask_sensitive_fields", not self._show_sensitive)
            settings.setValue("traffic/hide_heartbeats", self.hide_heartbeats.isChecked())
            settings.setValue(
                "traffic/policy_c2s_admin", self.intercept_c2s_admin_policy.isChecked()
            )
            settings.setValue(
                "traffic/policy_s2c_admin", self.intercept_s2c_admin_policy.isChecked()
            )
        settings.sync()

    def closeEvent(self, event) -> None:  # noqa: N802
        if hasattr(self, "proxy_workspace"):
            self.proxy_workspace.close()
        if hasattr(self, "shell"):
            self.shell.close()
        if hasattr(self, "presentation_controller"):
            self.presentation_controller.detach()
        for connection in tuple(getattr(self, "_repeater_connections", {}).values()):
            connection.close()
        if self.project_database is not None:
            try:
                self.project_database.save_records(self.records.values())
                self.project_database.save_states(self._capture_project_states())
            except RuntimeError:
                pass
            self.project_database.close()
            self.project_database = None
        super().closeEvent(event)

    # --------------------------------------------------------------- utilities

    def _record_for_table_row(self, table: QTableWidget, row: int):
        if row < 0:
            return None
        item = table.item(row, 0)
        if item is None:
            return None
        record_id = item.data(Qt.ItemDataRole.UserRole)
        return self.records.get(int(record_id)) if record_id is not None else None

    def _display_raw(self, record: TrafficRecord) -> bytes:
        policy = getattr(self, "secret_policy", SecretRedactionPolicy())
        return record.raw if self._reveal_state() else policy.redact(record.raw, self.dictionary)

    def _focus_history_filter(self) -> None:
        self._navigate("History")
        target = self.proxy_workspace.filters.search if hasattr(self, "proxy_workspace") else self.filter_edit
        target.setFocus()
        target.selectAll()


__all__ = ["MainWindow"]
