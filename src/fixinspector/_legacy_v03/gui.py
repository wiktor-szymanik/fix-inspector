from __future__ import annotations

import time
from pathlib import Path

from .. import __version__

from PySide6.QtCore import QObject, Qt, Signal, QSettings, QTimer, QStandardPaths
from PySide6.QtGui import QAction, QBrush, QColor, QFont
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPushButton,
    QPlainTextEdit,
    QRadioButton,
    QSplitter,
    QSpinBox,
    QStatusBar,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from .codec import (
    SOH_SYMBOL,
    decode_value,
    editor_text_to_raw,
    encode_value,
    parse_message,
    raw_to_editor_text,
    redact_sensitive,
    serialize_structured,
)
from .dictionary import FixDictionary
from .model import FixField, TrafficRecord
from .proxy import ProxyConfig, ProxyEngine
from .rules import validate_message


class Bridge(QObject):
    record_received = Signal(object)
    record_status = Signal(int, str)
    proxy_status = Signal(str)


class MainWindow(QMainWindow):
    """Burp-inspired FIX intercepting proxy UI.

    QuickFIX/J remains the session engine. This GUI is deliberately focused on
    observing, holding, editing and forwarding complete FIX messages.
    """

    HISTORY_COLUMNS = ["#", "Time", "Direction", "Type", "Message", "Seq", "Account", "ClOrdID", "OrderID", "State"]
    HELD_COLUMNS = ["#", "Direction", "Type", "Message", "Seq", "Account", "State"]
    FIELD_COLUMNS = ["Tag", "Name", "Value", "Meaning", "Type", "Req", "Group / Component"]

    ADMIN_TYPES = {"A", "0", "1", "2", "3", "4", "5"}

    def __init__(self) -> None:
        super().__init__()
        self.setWindowTitle(f"FIX Inspector {__version__}")
        self.resize(1500, 930)

        self.dictionary = FixDictionary()
        self.bridge = Bridge()
        self.engine = ProxyEngine(
            dictionary=self.dictionary,
            on_record=self.bridge.record_received.emit,
            on_record_status=self.bridge.record_status.emit,
            on_status=self.bridge.proxy_status.emit,
        )

        self.records: dict[int, TrafficRecord] = {}
        self.history_row_for_record: dict[int, int] = {}
        self.held_row_for_record: dict[int, int] = {}
        self._held_started: dict[int, float] = {}

        self.selected_history_record_id: int | None = None
        self.selected_intercept_record_id: int | None = None
        self._populating_intercept_fields = False
        self._show_sensitive = False
        self._observed_heartbeat: str | None = None
        self._proxy_running = False

        self.bridge.record_received.connect(self._on_record)
        self.bridge.record_status.connect(self._on_record_status)
        self.bridge.proxy_status.connect(self._on_proxy_status)

        config_root = Path(QStandardPaths.writableLocation(QStandardPaths.StandardLocation.AppConfigLocation))
        if not str(config_root):
            config_root = Path.home() / ".fix-inspector"
        config_root.mkdir(parents=True, exist_ok=True)
        self._settings_path = config_root / "fix_inspector.ini"

        # One-time migration when upgrading in-place from 0.2, which stored
        # settings next to the application.
        legacy_settings = Path(__file__).resolve().parent.parent / "fix_inspector.ini"
        if not self._settings_path.exists() and legacy_settings.is_file():
            try:
                self._settings_path.write_bytes(legacy_settings.read_bytes())
            except OSError:
                pass

        self._build_ui()
        self._apply_styles()
        self._restore_settings()
        self._autoload_dictionaries()
        self._set_proxy_running(False)

        self._ui_timer = QTimer(self)
        self._ui_timer.setInterval(250)
        self._ui_timer.timeout.connect(self._update_hold_countdown)
        self._ui_timer.start()

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        root = QWidget()
        root_layout = QVBoxLayout(root)
        root_layout.setContentsMargins(8, 8, 8, 4)

        self.workspace_tabs = QTabWidget()
        self.workspace_tabs.setObjectName("workspaceTabs")
        self.workspace_tabs.addTab(self._build_intercept_tab(), "Intercept")
        self.workspace_tabs.addTab(self._build_history_tab(), "History")
        self.workspace_tabs.addTab(self._build_configuration_tab(), "Configuration")
        root_layout.addWidget(self.workspace_tabs, 1)

        self.setCentralWidget(root)
        self.setStatusBar(QStatusBar())
        self.status_label = QLabel("Ready")
        self.proxy_state_label = QLabel("Proxy: stopped")
        self.session_state_label = QLabel("FIX session: not observed")
        self.statusBar().addWidget(self.status_label, 1)
        self.statusBar().addPermanentWidget(self.session_state_label)
        self.statusBar().addPermanentWidget(self.proxy_state_label)

        clear_action = QAction("Clear history", self)
        clear_action.triggered.connect(self._clear_history)
        self.menuBar().addAction(clear_action)

    def _build_intercept_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)

        toolbar = QHBoxLayout()
        self.intercept_master = QPushButton("Intercept is OFF")
        self.intercept_master.setObjectName("interceptToggle")
        self.intercept_master.setCheckable(True)
        self.intercept_master.setMinimumWidth(165)
        self.intercept_master.toggled.connect(self._intercept_master_toggled)

        self.intercept_policy_label = QLabel("Policy: Client → Server application messages")
        self.intercept_policy_label.setToolTip(
            "The master switch enables/disables interception. Direction policy and timeout are configured in Configuration."
        )

        self.intercept_proxy_label = QLabel("Proxy stopped")
        self.intercept_proxy_label.setObjectName("connectionBadge")


        configure_button = QPushButton("Configuration…")
        configure_button.clicked.connect(lambda: self.workspace_tabs.setCurrentIndex(2))

        toolbar.addWidget(self.intercept_master)
        toolbar.addWidget(self.intercept_policy_label)
        toolbar.addStretch(1)
        toolbar.addWidget(self.intercept_proxy_label)
        toolbar.addWidget(configure_button)
        layout.addLayout(toolbar)

        queue_box = QGroupBox("Intercept queue")
        queue_layout = QVBoxLayout(queue_box)
        queue_help = QLabel(
            "Only HELD messages appear here. Resolved messages remain available in History. "
            "Session/admin messages are normally forwarded automatically."
        )
        queue_help.setWordWrap(True)
        queue_help.setObjectName("mutedLabel")
        queue_layout.addWidget(queue_help)

        self.held_table = QTableWidget(0, len(self.HELD_COLUMNS))
        self.held_table.setHorizontalHeaderLabels(self.HELD_COLUMNS)
        self._configure_table(self.held_table)
        self.held_table.setMaximumHeight(190)
        held_header = self.held_table.horizontalHeader()
        held_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        held_header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        held_header.setSectionResizeMode(1, QHeaderView.ResizeMode.ResizeToContents)
        held_header.setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        held_header.setSectionResizeMode(3, QHeaderView.ResizeMode.Stretch)
        held_header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        held_header.setSectionResizeMode(6, QHeaderView.ResizeMode.ResizeToContents)
        self.held_table.setColumnWidth(5, 120)
        self.held_table.itemSelectionChanged.connect(self._intercept_selection_changed)
        queue_layout.addWidget(self.held_table)
        layout.addWidget(queue_box)

        self.intercept_splitter = QSplitter(Qt.Orientation.Vertical)

        editor_box = QGroupBox("Message editor")
        editor_layout = QVBoxLayout(editor_box)

        meta = QHBoxLayout()
        self.intercept_message_title = QLabel("No message intercepted")
        title_font = QFont()
        title_font.setBold(True)
        title_font.setPointSize(11)
        self.intercept_message_title.setFont(title_font)
        self.intercept_deadline_label = QLabel("")
        self.intercept_deadline_label.setObjectName("deadlineLabel")
        meta.addWidget(self.intercept_message_title)
        meta.addStretch(1)
        meta.addWidget(self.intercept_deadline_label)
        editor_layout.addLayout(meta)

        mode_row = QHBoxLayout()
        self.structured_mode = QRadioButton("Structured")
        self.raw_mode = QRadioButton("Raw")
        self.structured_mode.setChecked(True)
        self.structured_mode.setToolTip("Edit tag values; BodyLength (9) and CheckSum (10) are recalculated automatically.")
        self.raw_mode.setToolTip("Edit raw bytes; tag 9/10 are not repaired. Useful for parser/protocol tests.")
        self.structured_mode.toggled.connect(self._refresh_intercept_editability)
        self.raw_mode.toggled.connect(self._refresh_intercept_editability)
        mode_row.addWidget(self.structured_mode)
        mode_row.addWidget(self.raw_mode)
        mode_row.addStretch(1)
        editor_layout.addLayout(mode_row)

        self.intercept_editor_tabs = QTabWidget()

        structured_tab = QWidget()
        structured_layout = QVBoxLayout(structured_tab)
        self.intercept_fields = QTableWidget(0, len(self.FIELD_COLUMNS))
        self.intercept_fields.setHorizontalHeaderLabels(self.FIELD_COLUMNS)
        self._configure_field_table(self.intercept_fields)
        self.intercept_fields.itemChanged.connect(self._intercept_field_changed)
        structured_layout.addWidget(self.intercept_fields, 1)

        field_actions = QHBoxLayout()
        self.add_field_button = QPushButton("Add field")
        self.remove_field_button = QPushButton("Remove field")
        self.revert_button = QPushButton("Revert edits")
        self.validate_button = QPushButton("Validate")
        self.add_field_button.clicked.connect(self._add_field)
        self.remove_field_button.clicked.connect(self._remove_field)
        self.revert_button.clicked.connect(self._revert_intercept)
        self.validate_button.clicked.connect(self._validate_intercept)
        field_actions.addWidget(self.add_field_button)
        field_actions.addWidget(self.remove_field_button)
        field_actions.addWidget(self.revert_button)
        field_actions.addWidget(self.validate_button)
        field_actions.addStretch(1)
        structured_layout.addLayout(field_actions)

        raw_tab = QWidget()
        raw_layout = QVBoxLayout(raw_tab)
        raw_note = QLabel(f"Raw FIX view. {SOH_SYMBOL} represents byte 0x01. Raw mode intentionally does not repair BodyLength/CheckSum.")
        raw_note.setObjectName("mutedLabel")
        raw_layout.addWidget(raw_note)
        self.intercept_raw = QPlainTextEdit()
        self.intercept_raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        raw_layout.addWidget(self.intercept_raw)

        validation_tab = QWidget()
        validation_layout = QVBoxLayout(validation_tab)
        self.intercept_validation = QPlainTextEdit()
        self.intercept_validation.setReadOnly(True)
        validation_layout.addWidget(self.intercept_validation)

        self.intercept_editor_tabs.addTab(structured_tab, "Fields")
        self.intercept_editor_tabs.addTab(raw_tab, "Raw")
        self.intercept_editor_tabs.addTab(validation_tab, "Validation")
        editor_layout.addWidget(self.intercept_editor_tabs, 1)

        action_row = QHBoxLayout()
        self.forward_button = QPushButton("Forward")
        self.forward_button.setObjectName("forwardButton")
        self.drop_button = QPushButton("Drop")
        self.drop_button.setObjectName("dropButton")
        self.forward_button.clicked.connect(self._forward_current)
        self.drop_button.clicked.connect(self._drop_current)
        action_row.addStretch(1)
        action_row.addWidget(self.forward_button)
        action_row.addWidget(self.drop_button)
        editor_layout.addLayout(action_row)

        self.intercept_splitter.addWidget(editor_box)
        self.intercept_splitter.setSizes([650])
        layout.addWidget(self.intercept_splitter, 1)
        return page

    def _build_history_tab(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        layout.setContentsMargins(8, 8, 8, 8)

        filter_row = QHBoxLayout()
        self.filter_edit = QLineEdit()
        self.filter_edit.setPlaceholderText("Filter: MsgType, Account, ClOrdID, OrderID, field value…")
        self.filter_edit.textChanged.connect(self._apply_history_filter)
        self.hide_admin = QCheckBox("Hide session/admin")
        self.hide_admin.setChecked(True)
        self.hide_admin.setToolTip("Display-only filter for A, 0, 1, 2, 3, 4, 5. Traffic is still forwarded and retained.")
        self.hide_admin.toggled.connect(self._apply_history_filter)
        clear_button = QPushButton("Clear")
        clear_button.clicked.connect(self._clear_history)
        filter_row.addWidget(self.filter_edit, 1)
        filter_row.addWidget(self.hide_admin)
        filter_row.addWidget(clear_button)
        layout.addLayout(filter_row)

        self.history_splitter = QSplitter(Qt.Orientation.Vertical)

        self.history = QTableWidget(0, len(self.HISTORY_COLUMNS))
        self.history.setHorizontalHeaderLabels(self.HISTORY_COLUMNS)
        self._configure_table(self.history)
        history_header = self.history.horizontalHeader()
        history_header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        for index in (0, 1, 2, 3, 5, 9):
            history_header.setSectionResizeMode(index, QHeaderView.ResizeMode.ResizeToContents)
        history_header.setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
        self.history.setColumnWidth(6, 115)
        self.history.setColumnWidth(7, 190)
        self.history.setColumnWidth(8, 140)
        self.history.itemSelectionChanged.connect(self._history_selection_changed)
        self.history_splitter.addWidget(self.history)

        inspector = QTabWidget()
        parsed_page = QWidget()
        parsed_layout = QVBoxLayout(parsed_page)
        self.history_fields = QTableWidget(0, len(self.FIELD_COLUMNS))
        self.history_fields.setHorizontalHeaderLabels(self.FIELD_COLUMNS)
        self._configure_field_table(self.history_fields)
        self.history_fields.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        parsed_layout.addWidget(self.history_fields)

        raw_page = QWidget()
        raw_layout = QVBoxLayout(raw_page)
        self.history_raw = QPlainTextEdit()
        self.history_raw.setReadOnly(True)
        self.history_raw.setLineWrapMode(QPlainTextEdit.LineWrapMode.NoWrap)
        raw_layout.addWidget(self.history_raw)

        validation_page = QWidget()
        validation_layout = QVBoxLayout(validation_page)
        self.history_validation = QPlainTextEdit()
        self.history_validation.setReadOnly(True)
        validation_layout.addWidget(self.history_validation)

        inspector.addTab(parsed_page, "Parsed")
        inspector.addTab(raw_page, "Raw")
        inspector.addTab(validation_page, "Validation")
        self.history_splitter.addWidget(inspector)
        self.history_splitter.setSizes([490, 330])
        layout.addWidget(self.history_splitter, 1)

        legend = QLabel(
            "Blue = Client → Server   •   Green = Server → Client   •   Yellow = HELD   •   Purple = AUTO-FWD   •   Red = DROPPED"
        )
        legend.setObjectName("mutedLabel")
        layout.addWidget(legend)
        return page

    def _build_configuration_tab(self) -> QWidget:
        page = QWidget()
        outer = QVBoxLayout(page)
        outer.setContentsMargins(12, 12, 12, 12)

        status_box = QGroupBox("Proxy control")
        status_layout = QGridLayout(status_box)
        self.config_proxy_state = QLabel("Stopped")
        self.config_proxy_state.setObjectName("connectionBadge")
        self.start_button = QPushButton("Start proxy")
        self.stop_button = QPushButton("Stop proxy")
        self.start_button.clicked.connect(self._start_proxy)
        self.stop_button.clicked.connect(self._stop_proxy)
        status_layout.addWidget(QLabel("Status"), 0, 0)
        status_layout.addWidget(self.config_proxy_state, 0, 1)
        status_layout.addWidget(self.start_button, 0, 3)
        status_layout.addWidget(self.stop_button, 0, 4)
        outer.addWidget(status_box)

        connection_box = QGroupBox("Listener and upstream TLS")
        connection_layout = QGridLayout(connection_box)
        self.listen_host = QLineEdit("127.0.0.1")
        self.listen_port = QLineEdit("4582")
        self.upstream_host = QLineEdit("")
        self.upstream_port = QLineEdit("4581")
        self.upstream_sni = QLineEdit("")
        self.verify_tls = QCheckBox("Verify upstream certificate")
        self.ca_file = QLineEdit("")
        ca_browse = QPushButton("Browse…")
        ca_browse.clicked.connect(self._browse_ca)
        connection_layout.addWidget(QLabel("Listen host"), 0, 0)
        connection_layout.addWidget(self.listen_host, 0, 1)
        connection_layout.addWidget(QLabel("Listen port"), 0, 2)
        connection_layout.addWidget(self.listen_port, 0, 3)
        connection_layout.addWidget(QLabel("Upstream host"), 1, 0)
        connection_layout.addWidget(self.upstream_host, 1, 1)
        connection_layout.addWidget(QLabel("Upstream port"), 1, 2)
        connection_layout.addWidget(self.upstream_port, 1, 3)
        connection_layout.addWidget(QLabel("SNI / hostname"), 2, 0)
        connection_layout.addWidget(self.upstream_sni, 2, 1)
        connection_layout.addWidget(self.verify_tls, 2, 2, 1, 2)
        connection_layout.addWidget(QLabel("CA file"), 3, 0)
        connection_layout.addWidget(self.ca_file, 3, 1, 1, 2)
        connection_layout.addWidget(ca_browse, 3, 3)
        note = QLabel(
            "Current lab topology: Java client → plaintext FIX on localhost → FIX Inspector → TLS 1.3 → upstream API. "
            "Use the unmodified Java build separately when assessing the official client's TLS validation."
        )
        note.setWordWrap(True)
        note.setObjectName("mutedLabel")
        connection_layout.addWidget(note, 4, 0, 1, 4)
        outer.addWidget(connection_box)

        dict_box = QGroupBox("QuickFIX/J dictionaries")
        dict_layout = QGridLayout(dict_box)
        self.transport_dict = QLineEdit("")
        self.app_dict = QLineEdit("")
        transport_browse = QPushButton("FIXT11.xml…")
        app_browse = QPushButton("FIX50.xml…")
        load_dicts = QPushButton("Load dictionaries")
        transport_browse.clicked.connect(lambda: self._browse_dict(self.transport_dict))
        app_browse.clicked.connect(lambda: self._browse_dict(self.app_dict))
        load_dicts.clicked.connect(self._load_dictionaries)
        self.dictionary_state = QLabel("No dictionary loaded")
        self.dictionary_state.setObjectName("mutedLabel")
        dict_layout.addWidget(QLabel("Transport"), 0, 0)
        dict_layout.addWidget(self.transport_dict, 0, 1)
        dict_layout.addWidget(transport_browse, 0, 2)
        dict_layout.addWidget(QLabel("Application"), 1, 0)
        dict_layout.addWidget(self.app_dict, 1, 1)
        dict_layout.addWidget(app_browse, 1, 2)
        dict_layout.addWidget(load_dicts, 0, 3, 2, 1)
        dict_layout.addWidget(self.dictionary_state, 2, 0, 1, 4)
        outer.addWidget(dict_box)

        intercept_box = QGroupBox("Interception policy and session safety")
        intercept_layout = QGridLayout(intercept_box)
        self.intercept_c2s_policy = QCheckBox("Hold Client → Server application/business messages")
        self.intercept_s2c_policy = QCheckBox("Hold Server → Client application/business messages")
        self.intercept_c2s_policy.setChecked(True)
        self.intercept_s2c_policy.setChecked(False)
        self.intercept_c2s_policy.toggled.connect(self._update_intercept)
        self.intercept_s2c_policy.toggled.connect(self._update_intercept)
        self.hold_timeout = QSpinBox()
        self.hold_timeout.setRange(0, 600)
        self.hold_timeout.setValue(7)
        self.hold_timeout.setSuffix(" s")
        self.hold_timeout.setSpecialValueText("Unlimited")
        self.hold_timeout.valueChanged.connect(self._update_intercept)
        self.hold_timeout.setToolTip(
            "FIX uses an ordered MsgSeqNum stream. Holding message N also delays later N+1 traffic. "
            "0 disables the safety timeout; only use that deliberately."
        )
        self.session_info = QLabel("Observed HeartBtInt: not seen yet")
        self.session_info.setObjectName("mutedLabel")
        self.session_info.setWordWrap(True)
        intercept_layout.addWidget(self.intercept_c2s_policy, 0, 0, 1, 2)
        intercept_layout.addWidget(self.intercept_s2c_policy, 0, 2, 1, 2)
        intercept_layout.addWidget(QLabel("Auto-forward HELD after"), 1, 0)
        intercept_layout.addWidget(self.hold_timeout, 1, 1)
        intercept_layout.addWidget(self.session_info, 2, 0, 1, 4)
        outer.addWidget(intercept_box)

        ui_box = QGroupBox("History / display defaults")
        ui_layout = QGridLayout(ui_box)
        self.config_hide_admin = QCheckBox("Hide session/admin traffic in History by default")
        self.config_hide_admin.setChecked(True)
        self.config_hide_admin.toggled.connect(self._config_hide_admin_changed)
        security_note = QLabel("Sensitive field display is controlled in Settings → Privacy.")
        security_note.setWordWrap(True)
        security_note.setObjectName("mutedLabel")
        ui_layout.addWidget(self.config_hide_admin, 0, 0, 1, 2)
        ui_layout.addWidget(security_note, 1, 0, 1, 3)
        outer.addWidget(ui_box)

        outer.addStretch(1)
        return page

    def _configure_table(self, table: QTableWidget) -> None:
        table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        table.setAlternatingRowColors(False)
        table.setWordWrap(False)
        table.setTextElideMode(Qt.TextElideMode.ElideRight)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.verticalHeader().setVisible(False)
        table.horizontalHeader().setMinimumSectionSize(45)

    def _configure_field_table(self, table: QTableWidget) -> None:
        table.setWordWrap(False)
        table.setTextElideMode(Qt.TextElideMode.ElideRight)
        table.setHorizontalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.setVerticalScrollMode(QAbstractItemView.ScrollMode.ScrollPerPixel)
        table.verticalHeader().setVisible(False)
        header = table.horizontalHeader()
        header.setMinimumSectionSize(55)
        header.setStretchLastSection(False)
        header.setSectionResizeMode(QHeaderView.ResizeMode.Interactive)
        header.setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeMode.Stretch)
        header.setSectionResizeMode(4, QHeaderView.ResizeMode.ResizeToContents)
        header.setSectionResizeMode(5, QHeaderView.ResizeMode.ResizeToContents)
        table.setColumnWidth(1, 205)
        table.setColumnWidth(3, 220)
        table.setColumnWidth(6, 250)

    def _apply_styles(self) -> None:
        self.setStyleSheet(
            """
            QMainWindow, QWidget { font-size: 10pt; }
            QTabWidget#workspaceTabs > QTabBar::tab {
                padding: 10px 24px;
                min-width: 105px;
            }
            QTabWidget#workspaceTabs > QTabBar::tab:selected {
                border-bottom: 3px solid #e8891b;
                font-weight: 600;
            }
            QGroupBox {
                font-weight: 600;
                margin-top: 8px;
                padding-top: 8px;
            }
            QGroupBox::title { subcontrol-origin: margin; left: 8px; padding: 0 4px; }
            QPushButton { padding: 6px 12px; }
            QPushButton#interceptToggle { font-weight: 700; padding: 8px 18px; }
            QPushButton#interceptToggle:checked {
                background: #e8891b;
                color: white;
                border: 1px solid #c56e0e;
            }
            QPushButton#forwardButton {
                background: #e8891b;
                color: white;
                font-weight: 700;
                padding: 8px 20px;
            }
            QPushButton#dropButton {
                font-weight: 700;
                padding: 8px 20px;
            }
            QLabel#mutedLabel { color: #6b6b6b; }
            QLabel#deadlineLabel { color: #a85a00; font-weight: 600; }
            QLabel#connectionBadge { font-weight: 600; padding: 2px 7px; }
            QTableWidget { gridline-color: #d7d7d7; }
            QHeaderView::section { padding: 5px; font-weight: 600; }
            """
        )

    # -------------------------------------------------------------- settings

    def _settings(self) -> QSettings:
        return QSettings(str(self._settings_path), QSettings.Format.IniFormat)

    @staticmethod
    def _as_bool(value, default: bool = False) -> bool:
        if value is None:
            return default
        if isinstance(value, bool):
            return value
        return str(value).strip().lower() in {"1", "true", "yes", "on"}

    def _restore_settings(self) -> None:
        settings = self._settings()
        self.listen_host.setText(str(settings.value("proxy/listen_host", "127.0.0.1")))
        self.listen_port.setText(str(settings.value("proxy/listen_port", "4582")))
        self.upstream_host.setText(str(settings.value("proxy/upstream_host", "")))
        self.upstream_port.setText(str(settings.value("proxy/upstream_port", "4581")))
        self.upstream_sni.setText(str(settings.value("proxy/upstream_sni", "")))
        self.verify_tls.setChecked(self._as_bool(settings.value("proxy/verify_tls", False)))
        self.ca_file.setText(str(settings.value("proxy/ca_file", "")))
        self.transport_dict.setText(str(settings.value("dictionary/transport", "")))
        self.app_dict.setText(str(settings.value("dictionary/application", "")))

        old_c2s = self._as_bool(settings.value("traffic/intercept_c2s", False))
        old_s2c = self._as_bool(settings.value("traffic/intercept_s2c", False))
        self.intercept_c2s_policy.setChecked(self._as_bool(settings.value("traffic/policy_c2s", old_c2s or not old_s2c), True))
        self.intercept_s2c_policy.setChecked(self._as_bool(settings.value("traffic/policy_s2c", old_s2c), False))
        master_default = old_c2s or old_s2c
        self.intercept_master.setChecked(self._as_bool(settings.value("traffic/intercept_master", master_default)))

        hide_admin = self._as_bool(settings.value("traffic/hide_admin", True), True)
        self.hide_admin.setChecked(hide_admin)
        self.config_hide_admin.setChecked(hide_admin)
        try:
            self.hold_timeout.setValue(int(settings.value("traffic/hold_timeout", 7)))
        except (TypeError, ValueError):
            self.hold_timeout.setValue(7)


        geometry = settings.value("ui/geometry")
        if geometry is not None:
            self.restoreGeometry(geometry)
        history_splitter = settings.value("ui/history_splitter")
        if history_splitter is not None:
            self.history_splitter.restoreState(history_splitter)
        try:
            self.workspace_tabs.setCurrentIndex(int(settings.value("ui/current_tab", 0)))
        except (TypeError, ValueError):
            pass

        self._update_intercept()
        self._update_policy_label()

    def _save_settings(self) -> None:
        settings = self._settings()
        settings.setValue("proxy/listen_host", self.listen_host.text().strip())
        settings.setValue("proxy/listen_port", self.listen_port.text().strip())
        settings.setValue("proxy/upstream_host", self.upstream_host.text().strip())
        settings.setValue("proxy/upstream_port", self.upstream_port.text().strip())
        settings.setValue("proxy/upstream_sni", self.upstream_sni.text().strip())
        settings.setValue("proxy/verify_tls", self.verify_tls.isChecked())
        settings.setValue("proxy/ca_file", self.ca_file.text().strip())
        settings.setValue("dictionary/transport", self.transport_dict.text().strip())
        settings.setValue("dictionary/application", self.app_dict.text().strip())
        settings.setValue("traffic/intercept_master", self.intercept_master.isChecked())
        settings.setValue("traffic/policy_c2s", self.intercept_c2s_policy.isChecked())
        settings.setValue("traffic/policy_s2c", self.intercept_s2c_policy.isChecked())
        settings.setValue("traffic/hide_admin", self.hide_admin.isChecked())
        settings.setValue("traffic/hold_timeout", self.hold_timeout.value())
        settings.setValue("ui/geometry", self.saveGeometry())
        settings.setValue("ui/history_splitter", self.history_splitter.saveState())
        settings.setValue("ui/current_tab", self.workspace_tabs.currentIndex())
        settings.sync()

    # -------------------------------------------------------------- browse/io

    def _browse_ca(self) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select CA certificate", "", "Certificates (*.pem *.crt *.cer);;All files (*)")
        if path:
            self.ca_file.setText(path)

    def _browse_dict(self, target: QLineEdit) -> None:
        path, _ = QFileDialog.getOpenFileName(self, "Select QuickFIX/J XML dictionary", "", "XML files (*.xml);;All files (*)")
        if path:
            target.setText(path)

    def _autoload_dictionaries(self) -> None:
        paths = [p for p in (self.transport_dict.text().strip(), self.app_dict.text().strip()) if p and Path(p).is_file()]
        if not paths:
            return
        try:
            dictionary = FixDictionary.from_files(*paths)
        except Exception as exc:  # noqa: BLE001
            self.dictionary_state.setText(f"Saved dictionary could not be loaded: {exc}")
            return
        self.dictionary = dictionary
        self.engine.set_dictionary(dictionary)
        self.dictionary_state.setText(f"Loaded {len(dictionary.fields_by_tag)} fields / {len(dictionary.messages)} messages")

    def _load_dictionaries(self) -> None:
        paths = [p for p in (self.transport_dict.text().strip(), self.app_dict.text().strip()) if p]
        if not paths:
            QMessageBox.warning(self, "Dictionary", "Choose at least one XML dictionary.")
            return
        try:
            dictionary = FixDictionary.from_files(*paths)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Dictionary error", str(exc))
            return
        self.dictionary = dictionary
        self.engine.set_dictionary(dictionary)
        self.dictionary_state.setText(f"Loaded {len(dictionary.fields_by_tag)} fields / {len(dictionary.messages)} messages")
        self.status_label.setText("Dictionaries loaded")
        self._save_settings()
        self._rebuild_history_rows()
        self._refresh_history_details()
        self._refresh_intercept_details()

    # --------------------------------------------------------------- proxy ctl

    def _start_proxy(self) -> None:
        try:
            config = ProxyConfig(
                listen_host=self.listen_host.text().strip() or "127.0.0.1",
                listen_port=int(self.listen_port.text()),
                upstream_host=self.upstream_host.text().strip(),
                upstream_port=int(self.upstream_port.text()),
                upstream_sni=self.upstream_sni.text().strip(),
                verify_upstream=self.verify_tls.isChecked(),
                ca_file=self.ca_file.text().strip(),
            )
            self._update_intercept()
            self._save_settings()
            self.engine.start(config)
            self._set_proxy_running(True)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Proxy error", str(exc))

    def _stop_proxy(self) -> None:
        self.engine.stop()
        self._set_proxy_running(False)

    def closeEvent(self, event) -> None:  # noqa: N802
        self._save_settings()
        self.engine.stop()
        super().closeEvent(event)

    def _set_proxy_running(self, running: bool) -> None:
        self._proxy_running = running
        self.start_button.setEnabled(not running)
        self.stop_button.setEnabled(running)
        for widget in (
            self.listen_host,
            self.listen_port,
            self.upstream_host,
            self.upstream_port,
            self.upstream_sni,
            self.verify_tls,
            self.ca_file,
        ):
            widget.setEnabled(not running)
        state = "Running" if running else "Stopped"
        self.config_proxy_state.setText(state)
        self.intercept_proxy_label.setText(f"Proxy {state.lower()}")
        self.proxy_state_label.setText(f"Proxy: {state.lower()}")

    def _intercept_master_toggled(self, checked: bool) -> None:
        self.intercept_master.setText("Intercept is ON" if checked else "Intercept is OFF")
        self._update_intercept()
        self._save_settings()

    def _update_intercept(self) -> None:
        if not hasattr(self, "intercept_master"):
            return
        master = self.intercept_master.isChecked()
        c2s = master and self.intercept_c2s_policy.isChecked()
        s2c = master and self.intercept_s2c_policy.isChecked()
        self.engine.set_intercept(c2s, s2c, self.hold_timeout.value())
        self._update_policy_label()

    def _update_policy_label(self) -> None:
        if not hasattr(self, "intercept_c2s_policy"):
            return
        directions = []
        if self.intercept_c2s_policy.isChecked():
            directions.append("Client → Server")
        if self.intercept_s2c_policy.isChecked():
            directions.append("Server → Client")
        direction = " + ".join(directions) if directions else "none"
        timeout = self.hold_timeout.value()
        timeout_text = "unlimited hold" if timeout == 0 else f"{timeout}s safety timeout"
        self.intercept_policy_label.setText(f"Policy: {direction} application messages • {timeout_text}")

    def _on_proxy_status(self, text: str) -> None:
        self.status_label.setText(text)
        self.intercept_proxy_label.setText(text)
        if text == "Stopped":
            self._set_proxy_running(False)
        elif text.startswith("Listening") or text.startswith("Client connected") or text.startswith("TLS connected"):
            self._set_proxy_running(True)

    # ----------------------------------------------------------- shared display

    def _reveal_state(self) -> bool:
        return self._show_sensitive

    def _config_hide_admin_changed(self, checked: bool) -> None:
        if self.hide_admin.isChecked() != checked:
            self.hide_admin.setChecked(checked)
        self._apply_history_filter()

    def _record_summary(self, record: TrafficRecord) -> list[str]:
        message = parse_message(record.raw, self.dictionary)

        def val(tag: str) -> str:
            raw = message.first(tag)
            return decode_value(raw, message.encoding) if raw is not None else ""

        state = record.status
        if record.modified and state == "FORWARDED":
            state = "MODIFIED"
        return [
            str(record.record_id),
            record.timestamp.astimezone().strftime("%H:%M:%S.%f")[:-3],
            record.direction,
            message.msg_type,
            self.dictionary.message_name(message.msg_type),
            val("34"),
            val("1"),
            val("11"),
            val("37"),
            state,
        ]

    def _held_summary(self, record: TrafficRecord) -> list[str]:
        full = self._record_summary(record)
        return [full[0], full[2], full[3], full[4], full[5], full[6], full[9]]

    def _history_color(self, record: TrafficRecord) -> QColor:
        state = "MODIFIED" if record.modified and record.status == "FORWARDED" else record.status
        if state == "HELD":
            return QColor("#fff0b8")
        if state == "DROPPED":
            return QColor("#ffd7d7")
        if state == "AUTO-FWD":
            return QColor("#eadcff")
        if state == "MODIFIED":
            return QColor("#ffe0b8")
        if self.dictionary.is_admin(record.msg_type):
            return QColor("#eeeeee")
        if record.direction == "C→S":
            return QColor("#e6f1ff")
        return QColor("#e8f7ec")

    def _style_history_row(self, row: int, record: TrafficRecord) -> None:
        brush = QBrush(self._history_color(record))
        for column in range(self.history.columnCount()):
            item = self.history.item(row, column)
            if item:
                item.setBackground(brush)
                if item.text():
                    item.setToolTip(item.text())

    def _field_color(self, tag: str) -> QColor | None:
        if tag == "553":
            return QColor("#ffd9d9")
        if tag in {"8", "9", "35", "10"}:
            return QColor("#e7edf5")
        if tag in {"1", "11", "37", "41", "48", "55", "710"}:
            return QColor("#fff4cc")
        try:
            if int(tag) >= 10000:
                return QColor("#f1e8ff")
        except ValueError:
            pass
        return None

    def _populate_field_table(self, table: QTableWidget, record: TrafficRecord, editable: bool) -> None:
        message = parse_message(record.raw, self.dictionary)
        msg_def = self.dictionary.message(message.msg_type)
        required = msg_def.required_tags if msg_def else set()
        reveal = self._reveal_state()
        table.setRowCount(0)

        for field in message.fields:
            row = table.rowCount()
            table.insertRow(row)
            definition = self.dictionary.field(field.tag)
            name = definition.name if definition else ""
            field_type = definition.field_type if definition else ""
            text = decode_value(field.value, message.encoding)
            display_value = text if reveal or field.tag != "553" else "<REDACTED>"
            meaning = definition.enums.get(text, "") if definition else ""
            group = self.dictionary.group_path(message.msg_type, field.tag)
            values = [field.tag, name, display_value, meaning, field_type, "Y" if field.tag in required else "", group]
            color = self._field_color(field.tag)

            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 2:
                    item.setData(Qt.ItemDataRole.UserRole, field.value)
                if color is not None:
                    item.setBackground(QBrush(color))
                tooltip = [f"Tag {field.tag}"]
                if name:
                    tooltip.append(name)
                if field_type:
                    tooltip.append(f"Type: {field_type}")
                if meaning:
                    tooltip.append(f"Meaning: {meaning}")
                if group:
                    tooltip.append(f"Group/component: {group}")
                if field.tag == "553":
                    tooltip.append("Sensitive: Username/API key")
                item.setToolTip("\n".join(tooltip))
                flags = item.flags()
                can_edit = editable and column == 2 and (field.tag != "553" or reveal)
                item.setFlags((flags | Qt.ItemFlag.ItemIsEditable) if can_edit else (flags & ~Qt.ItemFlag.ItemIsEditable))
                table.setItem(row, column, item)

    # ------------------------------------------------------------- record flow

    def _on_record(self, record: TrafficRecord) -> None:
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
        self._apply_history_filter()

        if record.direction == "C→S" and record.msg_type == "A" and record.source == "CLIENT":
            message = parse_message(record.raw, self.dictionary)
            heartbeat = message.first("108")
            if heartbeat is not None:
                hb = decode_value(heartbeat, message.encoding)
                self._observed_heartbeat = hb
                text = (
                    f"Observed HeartBtInt: {hb}s. Holding MsgSeqNum N delays later N+1 traffic; "
                    "for comfortable manual editing consider a larger HeartBtInt in the experimental Java client."
                )
                self.session_info.setText(text)
                self.session_state_label.setText(f"HeartBtInt: {hb}s")

        if record.status == "HELD":
            self._add_held_record(record)
            self._held_started[record.record_id] = time.monotonic()
            self.selected_intercept_record_id = record.record_id
            self.workspace_tabs.setCurrentIndex(0)
            self._select_held_record(record.record_id)
            self._refresh_intercept_details()
            timeout = self.hold_timeout.value()
            timeout_text = "no auto-forward" if timeout == 0 else f"auto-forward in {timeout}s"
            self.status_label.setText(f"HELD #{record.record_id} {record.direction} {self.dictionary.message_name(record.msg_type)} - {timeout_text}")

    def _add_held_record(self, record: TrafficRecord) -> None:
        row = self.held_table.rowCount()
        self.held_table.insertRow(row)
        self.held_row_for_record[record.record_id] = row
        for column, value in enumerate(self._held_summary(record)):
            item = QTableWidgetItem(value)
            if column == 0:
                item.setData(Qt.ItemDataRole.UserRole, record.record_id)
            item.setBackground(QBrush(QColor("#fff0b8")))
            self.held_table.setItem(row, column, item)

    def _select_held_record(self, record_id: int) -> None:
        row = self.held_row_for_record.get(record_id)
        if row is not None:
            self.held_table.selectRow(row)

    def _remove_held_record(self, record_id: int) -> None:
        row = self.held_row_for_record.get(record_id)
        if row is None:
            return
        self.held_table.removeRow(row)
        self.held_row_for_record.pop(record_id, None)
        # QTableWidget row indexes shift after removal.
        for rid, old_row in list(self.held_row_for_record.items()):
            if old_row > row:
                self.held_row_for_record[rid] = old_row - 1

    def _on_record_status(self, record_id: int, status: str) -> None:
        record = self.records.get(record_id)
        if record:
            record.status = status

        row = self.history_row_for_record.get(record_id)
        if row is not None and record:
            for column, value in enumerate(self._record_summary(record)):
                item = self.history.item(row, column)
                if item:
                    item.setText(value)
            self._style_history_row(row, record)

        if status != "HELD":
            self._held_started.pop(record_id, None)
            self._remove_held_record(record_id)
            if self.selected_intercept_record_id == record_id:
                self.selected_intercept_record_id = None
                self._refresh_intercept_details()

        if status == "AUTO-FWD":
            self.status_label.setText(f"#{record_id} auto-forwarded after hold timeout")
        elif status == "DROPPED":
            self.status_label.setText(f"#{record_id} dropped")
        elif status == "FORWARDED":
            self.status_label.setText(f"#{record_id} forwarded")
        self._apply_history_filter()

    # --------------------------------------------------------------- intercept

    def _intercept_selection_changed(self) -> None:
        selected = self.held_table.selectedItems()
        if not selected:
            if self.selected_intercept_record_id not in self.held_row_for_record:
                self.selected_intercept_record_id = None
            self._refresh_intercept_details()
            return
        row = selected[0].row()
        item = self.held_table.item(row, 0)
        self.selected_intercept_record_id = int(item.data(Qt.ItemDataRole.UserRole))
        self._refresh_intercept_details()

    def _refresh_intercept_details(self) -> None:
        record = self.records.get(self.selected_intercept_record_id or -1)
        self._populating_intercept_fields = True
        self.intercept_fields.setRowCount(0)
        self.intercept_raw.clear()
        self.intercept_validation.clear()

        if not record:
            self.intercept_message_title.setText("No message intercepted")
            self.intercept_deadline_label.setText("")
            self._populating_intercept_fields = False
            self._refresh_intercept_editability()
            return

        message = parse_message(record.raw, self.dictionary)
        self.intercept_message_title.setText(
            f"#{record.record_id}  {record.direction}  {message.msg_type} / {self.dictionary.message_name(message.msg_type)}  "
            f"Seq={self._value(message, '34') or '-'}  Account={self._value(message, '1') or '-'}"
        )
        self._populate_field_table(self.intercept_fields, record, editable=record.status == "HELD" and self.structured_mode.isChecked())
        raw_for_display = record.raw if self._reveal_state() else redact_sensitive(record.raw, self.dictionary)
        self.intercept_raw.setPlainText(raw_to_editor_text(raw_for_display))
        self._populating_intercept_fields = False
        self._refresh_intercept_editability()
        self._validate_intercept()
        self._update_hold_countdown()

    def _refresh_intercept_editability(self) -> None:
        record = self.records.get(self.selected_intercept_record_id or -1)
        held = bool(record and record.status == "HELD")
        structured = self.structured_mode.isChecked()
        reveal = self._reveal_state()
        contains_secret = bool(record and b"553=" in record.raw)

        for row in range(self.intercept_fields.rowCount()):
            tag_item = self.intercept_fields.item(row, 0)
            for column in range(self.intercept_fields.columnCount()):
                item = self.intercept_fields.item(row, column)
                if not item:
                    continue
                editable = held and structured and column == 2
                if tag_item and tag_item.text() == "553" and not reveal:
                    editable = False
                flags = item.flags()
                item.setFlags((flags | Qt.ItemFlag.ItemIsEditable) if editable else (flags & ~Qt.ItemFlag.ItemIsEditable))

        raw_editable = held and self.raw_mode.isChecked() and (reveal or not contains_secret)
        self.intercept_raw.setReadOnly(not raw_editable)
        self.add_field_button.setEnabled(held and structured)
        self.remove_field_button.setEnabled(held and structured)
        self.revert_button.setEnabled(held)
        self.validate_button.setEnabled(bool(record))
        self.forward_button.setEnabled(held)
        self.drop_button.setEnabled(held)

        # Keep editor tabs aligned with mode without hiding either view.
        if self.raw_mode.isChecked():
            self.intercept_editor_tabs.setCurrentIndex(1)
        elif self.intercept_editor_tabs.currentIndex() == 1:
            self.intercept_editor_tabs.setCurrentIndex(0)


    def _intercept_field_changed(self, item: QTableWidgetItem) -> None:
        if self._populating_intercept_fields:
            return
        record = self.records.get(self.selected_intercept_record_id or -1)
        if not record or record.status != "HELD":
            return

        # If a newly added tag is entered, enrich its descriptive columns from
        # the loaded QuickFIX/J dictionary. Values remain fully user-controlled.
        if item.column() == 0:
            tag = item.text().strip()
            definition = self.dictionary.field(tag)
            message = parse_message(record.raw, self.dictionary)
            if definition:
                self._populating_intercept_fields = True
                try:
                    row = item.row()
                    self.intercept_fields.item(row, 1).setText(definition.name)
                    self.intercept_fields.item(row, 4).setText(definition.field_type)
                    self.intercept_fields.item(row, 6).setText(self.dictionary.group_path(message.msg_type, tag))
                    color = self._field_color(tag)
                    if color is not None:
                        for col in range(self.intercept_fields.columnCount()):
                            cell = self.intercept_fields.item(row, col)
                            if cell:
                                cell.setBackground(QBrush(color))
                finally:
                    self._populating_intercept_fields = False
        self._validate_intercept()

    def _current_structured_raw(self) -> bytes:
        record = self.records.get(self.selected_intercept_record_id or -1)
        if not record:
            raise ValueError("No intercepted message selected")
        original = parse_message(record.raw, self.dictionary)
        fields: list[FixField] = []
        for row in range(self.intercept_fields.rowCount()):
            tag_item = self.intercept_fields.item(row, 0)
            value_item = self.intercept_fields.item(row, 2)
            if not tag_item or not value_item:
                continue
            tag = tag_item.text().strip()
            if not tag:
                continue
            if tag == "553" and not self._reveal_state():
                value = value_item.data(Qt.ItemDataRole.UserRole)
                if not isinstance(value, (bytes, bytearray)):
                    raise ValueError("Cannot recover redacted tag 553")
                value_bytes = bytes(value)
            else:
                value_bytes = encode_value(value_item.text(), original.encoding)
            fields.append(FixField(tag=tag, value=value_bytes))
        return serialize_structured(fields)

    def _forward_current(self) -> None:
        record = self.records.get(self.selected_intercept_record_id or -1)
        if not record or record.status != "HELD":
            return
        original_raw = record.raw
        try:
            if self.raw_mode.isChecked():
                if b"553=" in record.raw and not self._reveal_state():
                    raise ValueError("Disable masking in Settings → Privacy before forwarding from the redacted raw view")
                outbound = editor_text_to_raw(self.intercept_raw.toPlainText())
            else:
                outbound = self._current_structured_raw()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Cannot forward", str(exc))
            return

        record.modified = outbound != original_raw
        record.raw = outbound
        self.engine.resolve_intercept(record.record_id, "forward", outbound)
        self.status_label.setText(f"Forward requested for #{record.record_id}")

    def _drop_current(self) -> None:
        record = self.records.get(self.selected_intercept_record_id or -1)
        if not record or record.status != "HELD":
            return
        answer = QMessageBox.question(
            self,
            "Drop FIX message",
            "Dropping a FIX message creates a MsgSeqNum gap and may trigger ResendRequest/session recovery. Drop it anyway?",
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.engine.resolve_intercept(record.record_id, "drop")

    def _revert_intercept(self) -> None:
        # Edits live in widgets until Forward. Re-populating restores the original held raw message.
        self._refresh_intercept_details()

    def _add_field(self) -> None:
        record = self.records.get(self.selected_intercept_record_id or -1)
        if not record or record.status != "HELD" or not self.structured_mode.isChecked():
            return
        row = self.intercept_fields.currentRow()
        if row < 0:
            row = self.intercept_fields.rowCount() - 1
        insert_at = max(0, row + 1)
        if self.intercept_fields.rowCount() and insert_at >= self.intercept_fields.rowCount():
            last_tag = self.intercept_fields.item(self.intercept_fields.rowCount() - 1, 0).text()
            if last_tag == "10":
                insert_at = self.intercept_fields.rowCount() - 1
        self.intercept_fields.insertRow(insert_at)
        for column, value in enumerate(["", "", "", "", "", "", ""]):
            item = QTableWidgetItem(value)
            item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
            self.intercept_fields.setItem(insert_at, column, item)
        self.intercept_fields.item(insert_at, 0).setFlags(self.intercept_fields.item(insert_at, 0).flags() | Qt.ItemFlag.ItemIsEditable)
        self.intercept_fields.item(insert_at, 2).setFlags(self.intercept_fields.item(insert_at, 2).flags() | Qt.ItemFlag.ItemIsEditable)
        self.intercept_fields.setCurrentCell(insert_at, 0)

    def _remove_field(self) -> None:
        row = self.intercept_fields.currentRow()
        if row < 0:
            return
        tag_item = self.intercept_fields.item(row, 0)
        tag = tag_item.text() if tag_item else ""
        if tag in {"8", "9", "10"}:
            QMessageBox.information(self, "Structured mode", "Use Raw mode to remove or corrupt structural fields 8, 9 or 10.")
            return
        self.intercept_fields.removeRow(row)

    def _validate_intercept(self) -> None:
        record = self.records.get(self.selected_intercept_record_id or -1)
        if not record:
            self.intercept_validation.clear()
            return
        try:
            if record.status == "HELD" and self.structured_mode.isChecked():
                raw = self._current_structured_raw()
            elif record.status == "HELD" and self.raw_mode.isChecked() and (self._reveal_state() or b"553=" not in record.raw):
                raw = editor_text_to_raw(self.intercept_raw.toPlainText())
            else:
                raw = record.raw
            message = parse_message(raw, self.dictionary)
            issues = validate_message(message, self.dictionary)
        except Exception as exc:  # noqa: BLE001
            self.intercept_validation.setPlainText(f"ERROR: {exc}")
            return
        if not issues:
            self.intercept_validation.setPlainText("No dictionary/business-rule warnings.")
        else:
            self.intercept_validation.setPlainText("\n".join(f"[{i.level}] {i.text}" for i in issues))

    def _update_hold_countdown(self) -> None:
        record_id = self.selected_intercept_record_id
        if record_id is None or record_id not in self._held_started:
            self.intercept_deadline_label.setText("")
            return
        timeout = self.hold_timeout.value()
        if timeout == 0:
            self.intercept_deadline_label.setText("HELD • auto-forward disabled")
            return
        elapsed = time.monotonic() - self._held_started[record_id]
        remaining = max(0.0, timeout - elapsed)
        self.intercept_deadline_label.setText(f"HELD • auto-forward in ~{remaining:0.1f}s")

    # ---------------------------------------------------------------- history

    def _history_selection_changed(self) -> None:
        selected = self.history.selectedItems()
        if not selected:
            self.selected_history_record_id = None
            self._refresh_history_details()
            return
        row = selected[0].row()
        item = self.history.item(row, 0)
        self.selected_history_record_id = int(item.data(Qt.ItemDataRole.UserRole))
        self._refresh_history_details()

    def _refresh_history_details(self) -> None:
        record = self.records.get(self.selected_history_record_id or -1)
        self.history_fields.setRowCount(0)
        self.history_raw.clear()
        self.history_validation.clear()
        if not record:
            return

        self._populate_field_table(self.history_fields, record, editable=False)
        raw_for_display = record.raw if self._reveal_state() else redact_sensitive(record.raw, self.dictionary)
        self.history_raw.setPlainText(raw_to_editor_text(raw_for_display))
        try:
            message = parse_message(record.raw, self.dictionary)
            issues = validate_message(message, self.dictionary)
            if issues:
                self.history_validation.setPlainText("\n".join(f"[{i.level}] {i.text}" for i in issues))
            else:
                self.history_validation.setPlainText("No dictionary/business-rule warnings.")
        except Exception as exc:  # noqa: BLE001
            self.history_validation.setPlainText(f"ERROR: {exc}")

    def _apply_history_filter(self) -> None:
        query = self.filter_edit.text().strip().lower()
        hide_admin = self.hide_admin.isChecked()
        for record_id, row in self.history_row_for_record.items():
            record = self.records.get(record_id)
            if not record:
                continue
            message = parse_message(record.raw, self.dictionary)
            hidden = hide_admin and self.dictionary.is_admin(message.msg_type)
            if query and not hidden:
                summary = " ".join(self._record_summary(record)).lower()
                raw_text = raw_to_editor_text(redact_sensitive(record.raw, self.dictionary)).lower()
                hidden = query not in summary and query not in raw_text
            self.history.setRowHidden(row, hidden)

    def _rebuild_history_rows(self) -> None:
        for record_id, row in self.history_row_for_record.items():
            record = self.records.get(record_id)
            if not record:
                continue
            for column, value in enumerate(self._record_summary(record)):
                item = self.history.item(row, column)
                if item:
                    item.setText(value)
            self._style_history_row(row, record)
        for record_id, row in self.held_row_for_record.items():
            record = self.records.get(record_id)
            if not record:
                continue
            for column, value in enumerate(self._held_summary(record)):
                item = self.held_table.item(row, column)
                if item:
                    item.setText(value)
        self._apply_history_filter()

    def _clear_history(self) -> None:
        held = [r for r in self.records.values() if r.status == "HELD"]
        if held:
            QMessageBox.warning(self, "History", "Resolve held messages before clearing history.")
            return
        self.history.setRowCount(0)
        self.held_table.setRowCount(0)
        self.records.clear()
        self.history_row_for_record.clear()
        self.held_row_for_record.clear()
        self._held_started.clear()
        self.selected_history_record_id = None
        self.selected_intercept_record_id = None
        self._refresh_history_details()
        self._refresh_intercept_details()

    # ---------------------------------------------------------------- helpers

    @staticmethod
    def _value(message, tag: str) -> str:
        raw = message.first(tag)
        return decode_value(raw, message.encoding) if raw is not None else ""
