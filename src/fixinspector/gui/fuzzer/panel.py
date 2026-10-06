from __future__ import annotations

from ..theme import contextual_hint, role
from ..widgets.flow_layout import FlowLayout
from ..widgets.presentation import Disclosure, table_columns

from collections.abc import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtGui import QColor, QBrush
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFormLayout,
    QGroupBox,
    QHeaderView,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPlainTextEdit,
    QPushButton,
    QSpinBox,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from ...fix.parser import parse_message, raw_to_editor_text
from ...fuzzer import (
    DESTRUCTIVE_KINDS,
    FIELD_KINDS,
    CampaignStatus,
    FuzzerCampaign,
    FuzzerController,
    MAX_CAMPAIGN_CASES,
    MutationKind,
    MutationSafety,
    MutationSpec,
)
from ...session.injection import InjectionMode, SESSION_HEADER_TAGS
from ...presentation import display_status
from ..widgets import MessageEditorWidget


class FuzzerPanel(QWidget):
    navigate_history = Signal(int)
    state_changed = Signal()
    result_requested = Signal(str, bytes, str)

    def __init__(
        self,
        controller: FuzzerController,
        dictionary_provider: Callable[[], object],
        secret_policy_provider: Callable[[], object],
        history_values_provider: Callable[[str], tuple[bytes, ...]],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self._dictionary_provider = dictionary_provider
        self._secret_policy_provider = secret_policy_provider
        self._history_values_provider = history_values_provider
        self._loading = False
        layout = QVBoxLayout(self)

        toolbar = FlowLayout()
        self.campaigns = QComboBox()
        self.campaigns.setMinimumWidth(330)
        self._show_sensitive = False
        self._private_tester_draft = None
        self.status = QLabel("Create a campaign from History, Sender, or Composer")
        self.status.setWordWrap(True)
        toolbar.addWidget(QLabel("Campaign"))
        toolbar.addWidget(self.campaigns)
        toolbar.addStretch(1)
        toolbar.addWidget(self.status)
        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        splitter.setProperty("stackAtLargeScale", True)
        splitter.addWidget(self._build_baseline_pane(dictionary_provider, secret_policy_provider))
        splitter.addWidget(self._build_planner_pane())
        splitter.addWidget(self._build_results_pane())
        splitter.setSizes([360, 470, 700])
        layout.addWidget(splitter, 1)
        # Keep planning/execution actions together above the scrollable work
        # area. Signals still target the existing campaign controller methods.
        for button in (self.generate, self.start, self.pause, self.resume, self.stop):
            toolbar.addWidget(button)
        self.mutations.horizontalHeader().setSectionResizeMode(0, QHeaderView.ResizeMode.ResizeToContents)
        self.mutations.horizontalHeader().setSectionResizeMode(1, QHeaderView.ResizeMode.Stretch)
        self.mutations.horizontalHeader().setSectionResizeMode(2, QHeaderView.ResizeMode.ResizeToContents)
        self.result_view = MessageEditorWidget(dictionary_provider, secret_policy_provider)
        self.result_view.set_mode(InjectionMode.BUSINESS_REPLAY)
        self.result_view.setToolTip("Selected case payload before session-field handling. Double-click a result for sent/correlated traffic in History.")
        self.results.parentWidget().layout().addWidget(self.result_view, 1)
        self.results.itemSelectionChanged.connect(self._show_result)
        self.results.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.results.customContextMenuRequested.connect(self._result_menu)
        table_columns(self.results, hidden=(7, 8, 9))

        self.campaigns.currentIndexChanged.connect(self._campaign_selected)
        self.destructive.toggled.connect(self._destructive_toggled)
        self.generate.clicked.connect(self._generate_plan)
        self.start.clicked.connect(self._start)
        self.pause.clicked.connect(self._pause)
        self.resume.clicked.connect(self._resume)
        self.stop.clicked.connect(self._stop)
        self.results.cellDoubleClicked.connect(self._result_double_clicked)
        self.results.itemChanged.connect(self._result_item_changed)
        self._populate_mutations()
        self.mutations.itemChanged.connect(self._mutation_item_changed)
        self._update_selected_mutations_preview()
        self._update_controls(None)

    def _build_baseline_pane(self, dictionary_provider, secret_policy_provider) -> QWidget:
        pane = QGroupBox("Base message")
        layout = QVBoxLayout(pane)
        self.source = QLabel("No baseline selected")
        self.source.setWordWrap(True)
        layout.addWidget(self.source)
        self.baseline = MessageEditorWidget(dictionary_provider, secret_policy_provider)
        self.baseline.set_mode(InjectionMode.BUSINESS_REPLAY)
        layout.addWidget(self.baseline, 1)
        return pane

    def _build_planner_pane(self) -> QWidget:
        pane = QGroupBox("Mutation configuration")
        layout = QVBoxLayout(pane)
        form = QFormLayout()
        self.target_tag = QComboBox()
        self.target_tag.setMinimumWidth(240)
        self.unknown_tag = QLineEdit("9999")
        self.case_limit = QSpinBox()
        self.case_limit.setRange(1, MAX_CAMPAIGN_CASES)
        self.case_limit.setValue(10)
        self.interval = QDoubleSpinBox()
        self.interval.setRange(0.25, 60.0)
        self.interval.setValue(1.0)
        self.interval.setSingleStep(0.25)
        self.interval.setSuffix(" s")
        self.outcome_window = QDoubleSpinBox()
        self.outcome_window.setRange(0.25, 60.0)
        self.outcome_window.setValue(1.0)
        self.outcome_window.setSingleStep(0.25)
        self.outcome_window.setSuffix(" s")
        form.addRow("Target field", self.target_tag)
        form.addRow("Finite case limit", self.case_limit)
        form.addRow("Minimum case interval", self.interval)
        layout.addLayout(form)

        self.mutations = QTableWidget(0, 3)
        self.mutations.setHorizontalHeaderLabels(["Use", "Mutation", "Class"])
        self.mutations.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.mutations.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.mutations.horizontalHeader().setStretchLastSection(True)
        self.mutations.verticalHeader().setVisible(False)
        layout.addWidget(self.mutations, 1)
        self.selected_mutations_preview = QLabel("Selected mutations: none")
        self.selected_mutations_preview.setWordWrap(True)
        role(self.selected_mutations_preview, "badge")
        layout.addWidget(self.selected_mutations_preview)

        self.tester_values = QPlainTextEdit()
        self.tester_values.setPlaceholderText("Tester-supplied values, one finite value per line")
        self.tester_values.setMaximumHeight(100)
        self.advanced = Disclosure("Advanced options")
        self.advanced.body_layout.addWidget(QLabel("Unknown tag"))
        self.advanced.body_layout.addWidget(self.unknown_tag)
        self.advanced.body_layout.addWidget(QLabel("Correlation window"))
        self.advanced.body_layout.addWidget(self.outcome_window)
        self.advanced.body_layout.addWidget(self.tester_values)
        layout.addWidget(self.advanced)

        self.destructive = QCheckBox("Enable session-destructive cases")
        layout.addWidget(self.destructive)
        self.destructive_legend = QLabel("Red rows indicate session-destructive mutations.")
        self.destructive_legend.setWordWrap(True)
        self.destructive_legend.setToolTip("These mutations may intentionally invalidate FIX framing or session state.")
        role(self.destructive_legend, "muted")
        layout.addWidget(self.destructive_legend)
        self.generate = QPushButton("Generate finite plan")
        layout.addWidget(self.generate)
        return pane

    def _build_results_pane(self) -> QWidget:
        pane = QGroupBox("Results")
        pane.setToolTip("Sequential execution and correlated outcomes")
        layout = QVBoxLayout(pane)
        controls = QHBoxLayout()
        self.start = QPushButton("Start")
        role(self.start, "primary")
        self.pause = QPushButton("Pause")
        self.resume = QPushButton("Resume")
        self.stop = QPushButton("Stop")
        for button in (self.start, self.pause, self.resume, self.stop):
            controls.addWidget(button)
        controls.addStretch(1)
        layout.addLayout(controls)
        self.results = QTableWidget(0, 10)
        self.results.setHorizontalHeaderLabels(
            ["Case", "Mutation", "Class", "Status", "Seq", "Sent #", "Outcome", "Correlated", "Session", "Notes"]
        )
        self.results.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        self.results.setSelectionMode(QAbstractItemView.SelectionMode.ExtendedSelection)
        self.results.horizontalHeader().setStretchLastSection(True)
        self.results.verticalHeader().setVisible(False)
        layout.addWidget(self.results, 1)
        return pane

    def _populate_mutations(self) -> None:
        self.mutations.setRowCount(0)
        for kind in MutationKind:
            row = self.mutations.rowCount()
            self.mutations.insertRow(row)
            use = QTableWidgetItem()
            use.setFlags(use.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            use.setCheckState(Qt.CheckState.Unchecked)
            # QVariant converts str-backed Enum objects to plain str. Store a
            # stable internal identifier and normalize it at the UI boundary.
            use.setData(Qt.ItemDataRole.UserRole, kind.name)
            self.mutations.setItem(row, 0, use)
            self.mutations.setItem(row, 1, QTableWidgetItem(kind.value))
            safety = (
                MutationSafety.SESSION_DESTRUCTIVE
                if kind in DESTRUCTIVE_KINDS
                else MutationSafety.SAFE_SESSION
            )
            safety_item = QTableWidgetItem(safety.value)
            self.mutations.setItem(row, 2, safety_item)
            if safety is MutationSafety.SESSION_DESTRUCTIVE:
                for column in range(3):
                    self.mutations.item(row, column).setBackground(QBrush(QColor("#ffd7d7")))
        self._update_destructive_rows()

    def add_campaign(self, campaign: FuzzerCampaign) -> None:
        index = self.campaigns.findData(campaign.campaign_id)
        if index < 0:
            self.campaigns.addItem(campaign.title, campaign.campaign_id)
            index = self.campaigns.count() - 1
        else:
            self.campaigns.setItemText(index, campaign.title)
        self.campaigns.setCurrentIndex(index)
        self._show_campaign(campaign)

    def restore_campaigns(self, campaigns: tuple[FuzzerCampaign, ...]) -> None:
        self.campaigns.clear()
        for campaign in campaigns:
            self.campaigns.addItem(campaign.title, campaign.campaign_id)
        if campaigns:
            self.campaigns.setCurrentIndex(0)
            self._show_campaign(campaigns[0])
        else:
            self._show_campaign(None)

    def refresh_current(self) -> None:
        self._show_campaign(self.controller.campaign(self.current_campaign_id()))

    def apply_campaign(self, campaign: FuzzerCampaign) -> None:
        index = self.campaigns.findData(campaign.campaign_id)
        if index < 0:
            self.campaigns.addItem(campaign.title, campaign.campaign_id)
            index = self.campaigns.count() - 1
        if self.current_campaign_id() == campaign.campaign_id:
            self._show_campaign(campaign)
        self.state_changed.emit()

    def current_campaign_id(self) -> str:
        return str(self.campaigns.currentData() or "")

    def selected_mutation_kinds(self) -> tuple[MutationKind, ...]:
        selected: list[MutationKind] = []
        for row in range(self.mutations.rowCount()):
            use = self.mutations.item(row, 0)
            if use is None or use.checkState() != Qt.CheckState.Checked:
                continue
            kind = self._mutation_kind(use)
            if kind is not None:
                selected.append(kind)
        return tuple(selected)

    def _campaign_selected(self) -> None:
        self._show_campaign(self.controller.campaign(self.current_campaign_id()))

    def _show_campaign(self, campaign: FuzzerCampaign | None) -> None:
        self._loading = True
        try:
            self.result_view.set_raw(b"")
            if campaign is None:
                self.source.setText("No baseline selected")
                self.status.setText("Create a campaign from History, Sender, or Composer")
                self.results.setRowCount(0)
                self.target_tag.clear()
                self._update_controls(None)
                return
            self.source.setText(
                f"{'Sender' if campaign.source_kind == 'Repeater' else campaign.source_kind} {campaign.source_id} · {campaign.title}\n"
                "Baseline is read-only; every case is generated as a separate ordered field list."
            )
            self.baseline.set_raw(campaign.baseline_raw)
            self.baseline.set_reveal(self._show_sensitive)
            self._populate_targets(campaign)
            self.case_limit.setValue(campaign.case_limit)
            self.interval.setValue(campaign.interval_seconds)
            self.outcome_window.setValue(campaign.outcome_window_seconds)
            self.destructive.setChecked(campaign.destructive_opt_in)
            self.status.setText(
                f"{display_status(campaign.status.value)} · {campaign.completed_count}/{len(campaign.cases)} case(s) finished"
            )
            self._populate_results(campaign)
            self._update_controls(campaign)
        finally:
            self._loading = False

    def _populate_targets(self, campaign: FuzzerCampaign) -> None:
        previous = str(self.target_tag.currentData() or "")
        self.target_tag.clear()
        message = parse_message(campaign.baseline_raw, self._dictionary_provider())
        secrets = self._secret_policy_provider().secret_tags
        seen: set[str] = set()
        for field in message.fields:
            if field.tag in seen or field.tag in SESSION_HEADER_TAGS:
                continue
            if field.tag in secrets and not self._show_sensitive:
                continue
            seen.add(field.tag)
            definition = self._dictionary_provider().field(field.tag)
            label = f"{field.tag} · {definition.name if definition else 'Unknown'}"
            self.target_tag.addItem(label, field.tag)
        if previous:
            self.target_tag.setCurrentIndex(max(0, self.target_tag.findData(previous)))

    def _populate_results(self, campaign: FuzzerCampaign) -> None:
        selected = self.results.currentItem()
        selected_id = selected.data(Qt.ItemDataRole.UserRole) if selected else None
        self.results.setRowCount(0)
        for case in campaign.cases:
            row = self.results.rowCount()
            self.results.insertRow(row)
            values = [
                str(case.case_id),
                display_status(case.description),
                case.safety.value,
                display_status(case.status.value),
                str(case.sequence_number or ""),
                str(case.sent_record_id or ""),
                " ".join(value for value in (case.outcome_classification, case.outcome_summary) if value),
                ", ".join(str(value) for value in case.correlated_record_ids),
                case.session_state,
                case.notes,
            ]
            policy = self._secret_policy_provider()
            secret_values = [field.value.decode("utf-8", errors="replace")
                             for field in parse_message(case.raw, self._dictionary_provider()).fields
                             if field.tag in policy.secret_tags and field.value] if not self._show_sensitive else []
            for column, value in enumerate(values):
                if not self._show_sensitive:
                    value = policy.redact_text(value)
                    for secret in secret_values:
                        value = value.replace(secret, "<REDACTED>")
                item = QTableWidgetItem(value)
                item.setData(Qt.ItemDataRole.UserRole, case.case_id)
                if column != 9:
                    item.setFlags(item.flags() & ~Qt.ItemFlag.ItemIsEditable)
                if case.safety is MutationSafety.SESSION_DESTRUCTIVE:
                    item.setBackground(QBrush(QColor("#ffd7d7")))
                self.results.setItem(row, column, item)
        if campaign.cases:
            row = next((index for index, case in enumerate(campaign.cases) if case.case_id == selected_id), 0)
            self.results.setCurrentCell(row, 0)
            self._show_result()

    def _generate_plan(self) -> None:
        campaign = self.controller.campaign(self.current_campaign_id())
        if campaign is None:
            QMessageBox.information(self, "Fuzzer", "Create a baseline campaign first.")
            return
        tag = str(self.target_tag.currentData() or "")
        tester_values = tuple(
            line.encode("utf-8")
            for line in self.tester_values.toPlainText().splitlines()
            if line != ""
        )
        history_values = self._history_values_provider(tag)
        selected_kinds = self.selected_mutation_kinds()
        specs: list[MutationSpec] = []
        for kind in selected_kinds:
            values: tuple[bytes, ...] = ()
            if kind is MutationKind.TESTER_VALUES:
                values = tester_values
            elif kind in {MutationKind.HISTORY_VALUES, MutationKind.REUSE_BUSINESS_ID}:
                values = history_values
            specs.append(
                MutationSpec(
                    kind,
                    tag if kind in FIELD_KINDS else "",
                    values,
                    self.unknown_tag.text().strip() or "9999",
                )
            )
        if not specs:
            QMessageBox.information(self, "Fuzzer plan", "Select at least one mutation.")
            return
        try:
            self.controller.plan(
                campaign.campaign_id,
                specs,
                case_limit=self.case_limit.value(),
                interval_seconds=self.interval.value(),
                outcome_window_seconds=self.outcome_window.value(),
                destructive_opt_in=self.destructive.isChecked(),
            )
        except (KeyError, RuntimeError, TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Fuzzer plan", str(exc))
            return
        self._show_campaign(campaign)

    def _start(self) -> None:
        campaign_id = self.current_campaign_id()
        if not campaign_id:
            return
        try:
            self.controller.start(campaign_id)
            self.controller.tick()
        except (KeyError, RuntimeError, ValueError) as exc:
            QMessageBox.warning(self, "Start Fuzzer", str(exc))

    def _pause(self) -> None:
        if self.current_campaign_id():
            self.controller.pause(self.current_campaign_id())

    def _resume(self) -> None:
        self._start()

    def _stop(self) -> None:
        if not self.current_campaign_id():
            return
        answer = QMessageBox.question(
            self,
            "Stop finite campaign",
            "Stop this campaign and cancel its one waiting injection, if any? Completed results are retained.",
        )
        if answer == QMessageBox.StandardButton.Yes:
            self.controller.stop(self.current_campaign_id())

    def _destructive_toggled(self, checked: bool) -> None:
        if self._loading:
            self._update_destructive_rows()
            return
        campaign = self.controller.campaign(self.current_campaign_id())
        if campaign is not None:
            campaign.destructive_opt_in = checked
        self._update_destructive_rows()

    def _update_destructive_rows(self) -> None:
        enabled = self.destructive.isChecked()
        for row in range(self.mutations.rowCount()):
            use = self.mutations.item(row, 0)
            kind = self._mutation_kind(use)
            if kind not in DESTRUCTIVE_KINDS:
                continue
            if not enabled:
                use.setCheckState(Qt.CheckState.Unchecked)
            for column in range(self.mutations.columnCount()):
                item = self.mutations.item(row, column)
                if item is None:
                    continue
                flags = item.flags()
                item.setFlags((flags | Qt.ItemFlag.ItemIsEnabled) if enabled else (flags & ~Qt.ItemFlag.ItemIsEnabled))
        self._update_selected_mutations_preview()

    @staticmethod
    def _mutation_kind(item: QTableWidgetItem | None) -> MutationKind | None:
        if item is None:
            return None
        value = item.data(Qt.ItemDataRole.UserRole)
        if isinstance(value, MutationKind):
            return value
        identifier = str(value or "")
        try:
            return MutationKind[identifier]
        except KeyError:
            try:
                return MutationKind(identifier)
            except ValueError:
                return None

    def _mutation_item_changed(self, item: QTableWidgetItem) -> None:
        if item.column() == 0:
            self._update_selected_mutations_preview()

    def _update_selected_mutations_preview(self) -> None:
        if not hasattr(self, "selected_mutations_preview"):
            return
        selected = self.selected_mutation_kinds()
        text = "Selected mutations: none" if not selected else "Selected mutations:\n" + "\n".join(
            f"- {kind.name}" for kind in selected
        )
        self.selected_mutations_preview.setText(text)

    def set_reveal(self, reveal: bool) -> None:
        self._show_sensitive = bool(reveal)
        self.baseline.set_reveal(reveal)
        self.result_view.set_reveal(reveal)
        selected_tag = str(self.target_tag.currentData() or "")
        if not reveal and selected_tag in self._secret_policy_provider().secret_tags:
            self._private_tester_draft = (self.current_campaign_id(), selected_tag, self.tester_values.toPlainText())
            self.tester_values.clear()
        campaign = self.controller.campaign(self.current_campaign_id())
        if campaign is not None:
            self._populate_targets(campaign)
            was_loading = self._loading
            self._loading = True
            try:
                self._populate_results(campaign)
            finally:
                self._loading = was_loading
        if reveal and self._private_tester_draft is not None:
            campaign_id, tag, text = self._private_tester_draft
            if campaign_id == self.current_campaign_id() and not self.tester_values.toPlainText() and self.target_tag.findData(tag) >= 0:
                self.target_tag.setCurrentIndex(self.target_tag.findData(tag))
                self.tester_values.setPlainText(text)
            self._private_tester_draft = None

    def _selected_case(self):
        campaign = self.controller.campaign(self.current_campaign_id())
        row = self.results.currentRow()
        return campaign.cases[row] if campaign and 0 <= row < len(campaign.cases) else None

    def _show_result(self):
        case = self._selected_case()
        if hasattr(self, "result_view"):
            self.result_view.set_raw(case.raw if case else b"")
            self.result_view.set_reveal(self._show_sensitive)

    def _result_menu(self, point):
        from PySide6.QtWidgets import QApplication, QMenu
        item = self.results.itemAt(point)
        if item:
            self.results.setCurrentItem(item)
        case = self._selected_case()
        if case is None:
            return
        menu = QMenu(self.results)
        for destination in ("Sender", "Decoder"):
            menu.addAction("Send to " + destination, lambda _checked=False, target=destination:
                           self.result_requested.emit(target, case.raw, f"Fuzzer case {case.case_id}"))
        raw = case.raw if self._show_sensitive else self._secret_policy_provider().redact(case.raw, self._dictionary_provider())
        menu.addAction("Copy raw", lambda: QApplication.clipboard().setText(raw_to_editor_text(raw)))
        menu.exec(self.results.viewport().mapToGlobal(point))

    def _result_double_clicked(self, row: int, _column: int) -> None:
        campaign = self.controller.campaign(self.current_campaign_id())
        if campaign is None or not 0 <= row < len(campaign.cases):
            return
        case = campaign.cases[row]
        record_id = case.sent_record_id or next(iter(case.correlated_record_ids), None)
        if record_id is not None:
            self.navigate_history.emit(record_id)

    def _result_item_changed(self, item: QTableWidgetItem) -> None:
        if self._loading or item.column() != 9:
            return
        campaign = self.controller.campaign(self.current_campaign_id())
        if campaign is None:
            return
        case_id = item.data(Qt.ItemDataRole.UserRole)
        case = next((value for value in campaign.cases if value.case_id == case_id), None)
        if case is not None:
            case.notes = item.text()
            self.state_changed.emit()

    def _update_controls(self, campaign: FuzzerCampaign | None) -> None:
        active = bool(
            campaign
            and campaign.status
            in {CampaignStatus.RUNNING, CampaignStatus.WAITING_SLOT, CampaignStatus.WAITING_OUTCOME}
        )
        paused = bool(
            campaign
            and campaign.status in {CampaignStatus.PAUSED_USER, CampaignStatus.PAUSED_DISCONNECTED}
        )
        self.generate.setEnabled(bool(campaign) and not active)
        self.start.setEnabled(bool(campaign and campaign.cases) and not active)
        self.pause.setEnabled(active)
        self.resume.setEnabled(paused)
        self.stop.setEnabled(active or paused)


__all__ = ["FuzzerPanel"]
