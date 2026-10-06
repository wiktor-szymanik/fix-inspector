"""Qt configuration surface for the message-layer proxy behaviour service."""

from __future__ import annotations

from ..theme import contextual_hint, role

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QDialogButtonBox,
    QFormLayout,
    QGridLayout,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...intercept.proxy_behaviour import (
    MAX_DELAY_MS,
    MAX_DUPLICATE_COPIES,
    MAX_ONE_SHOT_MESSAGES,
    DisconnectEvent,
    DisconnectSide,
    FaultAction,
    FaultRule,
    MessageCategory,
    TagCondition,
)
from ...presentation import display_direction, display_direction_text


class RuleDialog(QDialog):
    def __init__(
        self,
        parent=None,
        rule: FaultRule | None = None,
        secret_tags=(),
    ) -> None:
        super().__init__(parent)
        self._secret_tags = {str(tag) for tag in secret_tags} | {"553"}
        self._original_secret_values: dict[str, list[str]] = {}
        self.setWindowTitle("Proxy Behaviour rule")
        self.setMinimumWidth(520)
        layout = QFormLayout(self)
        self.name = QLineEdit(rule.name if rule else "New fault rule")
        self.direction = QComboBox()
        self.direction.addItem("Client → Server", "C→S")
        self.direction.addItem("Server → Client", "S→C")
        self.direction.addItem("ANY", "ANY")
        self.category = QComboBox()
        self.category.addItems(["ANY", "APPLICATION", "ADMIN"])
        self.msg_type = QLineEdit(rule.msg_type if rule else "")
        self.msg_type.setPlaceholderText("Example: 8, D, AP; blank = any")
        self.conditions = QLineEdit()
        self.conditions.setPlaceholderText("11=AMBIG-RETRY-003, 150=F (AND)")
        self.action = QComboBox()
        self.action.addItems([item.value for item in FaultAction])
        self.delay = QSpinBox()
        self.delay.setRange(0, MAX_DELAY_MS)
        self.delay.setSuffix(" ms")
        self.jitter = QSpinBox()
        self.jitter.setRange(0, MAX_DELAY_MS)
        self.jitter.setSuffix(" ms")
        self.copies = QSpinBox()
        self.copies.setRange(1, MAX_DUPLICATE_COPIES)
        self.enabled = QCheckBox("Enabled")
        self.enabled.setChecked(True)
        if rule is not None:
            self.direction.setCurrentIndex(max(0, self.direction.findData(rule.direction)))
            self.category.setCurrentText(rule.category.value)
            displayed_conditions = []
            for item in rule.conditions:
                if item.tag in self._secret_tags:
                    self._original_secret_values.setdefault(item.tag, []).append(item.value)
                    displayed_conditions.append(f"{item.tag}=<REDACTED>")
                else:
                    displayed_conditions.append(f"{item.tag}={item.value}")
            self.conditions.setText(", ".join(displayed_conditions))
            self.action.setCurrentText(rule.action.value)
            self.delay.setValue(rule.delay_ms)
            self.jitter.setValue(rule.jitter_ms)
            self.copies.setValue(rule.duplicate_copies)
            self.enabled.setChecked(rule.enabled)
        layout.addRow("Name", self.name)
        layout.addRow("Direction", self.direction)
        layout.addRow("Category", self.category)
        layout.addRow("MsgType", self.msg_type)
        layout.addRow("Tag=value conditions", self.conditions)
        layout.addRow("Action", self.action)
        layout.addRow("Delay", self.delay)
        layout.addRow("Jitter (+/-)", self.jitter)
        layout.addRow("Extra duplicate copies", self.copies)
        layout.addRow("State", self.enabled)
        note = QLabel("Conditions are exact and combined with AND. Duplicate tag occurrences are retained; any occurrence may satisfy a condition.")
        note.setWordWrap(True)
        layout.addRow(note)
        buttons = QDialogButtonBox(
            QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel
        )
        buttons.accepted.connect(self.accept)
        buttons.rejected.connect(self.reject)
        layout.addRow(buttons)

    def values(self) -> dict[str, object]:
        conditions: list[TagCondition] = []
        preserved_secret_values = {
            tag: list(values) for tag, values in self._original_secret_values.items()
        }
        for part in self.conditions.text().split(","):
            text = part.strip()
            if not text:
                continue
            if "=" not in text:
                raise ValueError(f"Condition must use tag=value: {text}")
            tag, value = text.split("=", 1)
            normalized_tag = tag.strip()
            if (
                normalized_tag in self._secret_tags
                and value == "<REDACTED>"
                and preserved_secret_values.get(normalized_tag)
            ):
                value = preserved_secret_values[normalized_tag].pop(0)
            conditions.append(TagCondition(normalized_tag, value))
        return {
            "name": self.name.text().strip(),
            "direction": str(self.direction.currentData()),
            "category": self.category.currentText(),
            "msg_type": self.msg_type.text().strip(),
            "conditions": conditions,
            "action": self.action.currentText(),
            "delay_ms": self.delay.value(),
            "jitter_ms": self.jitter.value(),
            "duplicate_copies": self.copies.value(),
            "enabled": self.enabled.isChecked(),
        }


class ProxyBehaviourPanel(QWidget):
    state_changed = Signal()

    def __init__(self, engine, secret_tags, parent=None) -> None:
        super().__init__(parent)
        self.engine = engine
        self.controller = engine.proxy_behaviour
        self.secret_tags = secret_tags
        self._syncing = False
        self._direction_widgets: dict[str, dict[str, object]] = {}

        root = QVBoxLayout(self)
        top = QHBoxLayout()
        self.status = QLabel()
        self.status.setWordWrap(True)
        role(self.status, "section")
        self.preset = QComboBox()
        self.preset.addItems(
            [
                "Clean",
                "Ambiguous application delivery",
                "Server response delay",
                "Client request blackhole",
            ]
        )
        apply_preset = QPushButton("Apply preset")
        apply_preset.clicked.connect(self._apply_preset)
        reset = QPushButton("RESET PROXY BEHAVIOUR")
        role(reset, "danger")
        reset.clicked.connect(self._reset)
        top.addWidget(self.status, 1)
        top.addWidget(self.preset)
        top.addWidget(apply_preset)
        top.addWidget(reset)
        root.addLayout(top)

        precedence = QLabel(
            "Precedence: global DROP/PAUSE → one-shot → first matching enabled rule → "
            "application/admin default → directional delay → NORMAL. "
            "Faults are OFF at startup; project rules restore disabled."
        )
        precedence.setWordWrap(True)
        precedence.setObjectName("mutedLabel")
        contextual_hint(precedence, "Rule precedence ⓘ")
        root.addWidget(precedence)

        tabs = QTabWidget()
        directions = QWidget()
        direction_layout = QHBoxLayout(directions)
        for direction, title in (("C→S", "Client → Server"), ("S→C", "Server → Client")):
            direction_layout.addWidget(self._build_direction(direction, title), 1)
        tabs.addTab(directions, "Directions / one-shots")
        tabs.addTab(self._build_rules(), "Ordered FIX-aware rules")
        tabs.addTab(self._build_queue_journal(), "Paused queue / event journal")
        root.addWidget(tabs, 1)
        self.refresh()

    def _build_direction(self, direction: str, title: str) -> QGroupBox:
        box = QGroupBox(title)
        layout = QGridLayout(box)
        global_mode = QComboBox()
        global_mode.addItems(["NORMAL", "DROP", "PAUSE"])
        application = QComboBox()
        application.addItems(["NORMAL", "DROP", "PAUSE"])
        admin = QComboBox()
        admin.addItems(["NORMAL", "DROP", "PAUSE"])
        delay_enabled = QCheckBox("Enable direction delay")
        delay = QSpinBox()
        delay.setRange(0, MAX_DELAY_MS)
        delay.setSuffix(" ms")
        jitter = QSpinBox()
        jitter.setRange(0, MAX_DELAY_MS)
        jitter.setSuffix(" ms")
        delay_category = QComboBox()
        delay_category.addItems(["APPLICATION", "ADMIN", "ANY"])
        for widget in (global_mode, application, admin, delay_enabled, delay, jitter, delay_category):
            if isinstance(widget, QComboBox):
                widget.currentIndexChanged.connect(lambda _index, d=direction: self._direction_changed(d))
            elif isinstance(widget, QCheckBox):
                widget.toggled.connect(lambda _checked, d=direction: self._direction_changed(d))
            else:
                widget.valueChanged.connect(lambda _value, d=direction: self._direction_changed(d))

        shot_action = QComboBox()
        shot_action.addItems(["DROP", "PAUSE", "DELAY", "DUPLICATE"])
        shot_count = QSpinBox()
        shot_count.setRange(1, MAX_ONE_SHOT_MESSAGES)
        shot_delay = QSpinBox()
        shot_delay.setRange(0, MAX_DELAY_MS)
        shot_delay.setSuffix(" ms")
        shot_jitter = QSpinBox()
        shot_jitter.setRange(0, MAX_DELAY_MS)
        shot_jitter.setSuffix(" ms jitter")
        shot_copies = QSpinBox()
        shot_copies.setRange(1, MAX_DUPLICATE_COPIES)
        arm_shot = QPushButton("Arm next N")
        arm_shot.clicked.connect(lambda _checked=False, d=direction: self._arm_one_shot(d))
        clear_shot = QPushButton("Clear one-shot")
        clear_shot.clicked.connect(lambda _checked=False, d=direction: self._clear_one_shot(d))
        shot_state = QLabel("Not armed")

        disconnect_side = QComboBox()
        disconnect_side.addItems(["CLIENT", "SERVER", "BOTH"])
        disconnect_event = QComboBox()
        disconnect_event.addItems(["FORWARDED", "DROPPED", "RECEIVED"])
        arm_disconnect = QPushButton("Arm disconnect after next")
        arm_disconnect.clicked.connect(
            lambda _checked=False, d=direction: self._arm_disconnect(d)
        )

        row = 0
        layout.addWidget(QLabel("Global mode (Drop/Pause all)"), row, 0)
        layout.addWidget(global_mode, row, 1)
        row += 1
        layout.addWidget(QLabel("Application messages"), row, 0)
        layout.addWidget(application, row, 1)
        row += 1
        layout.addWidget(QLabel("Administrative messages"), row, 0)
        layout.addWidget(admin, row, 1)
        row += 1
        layout.addWidget(delay_enabled, row, 0, 1, 2)
        row += 1
        layout.addWidget(QLabel("Delay / jitter (+/-)"), row, 0)
        delay_row = QHBoxLayout()
        delay_row.addWidget(delay)
        delay_row.addWidget(jitter)
        delay_row.addWidget(delay_category)
        layout.addLayout(delay_row, row, 1)
        row += 1
        layout.addWidget(QLabel("One-shot action / messages"), row, 0)
        shot_row = QHBoxLayout()
        shot_row.addWidget(shot_action)
        shot_row.addWidget(shot_count)
        layout.addLayout(shot_row, row, 1)
        row += 1
        layout.addWidget(QLabel("One-shot delay / jitter / extra copies"), row, 0)
        shot_parameter_row = QHBoxLayout()
        shot_parameter_row.addWidget(shot_delay)
        shot_parameter_row.addWidget(shot_jitter)
        shot_parameter_row.addWidget(shot_copies)
        layout.addLayout(shot_parameter_row, row, 1)
        row += 1
        shot_buttons = QHBoxLayout()
        shot_buttons.addWidget(arm_shot)
        shot_buttons.addWidget(clear_shot)
        layout.addLayout(shot_buttons, row, 0, 1, 2)
        row += 1
        layout.addWidget(shot_state, row, 0, 1, 2)
        row += 1
        layout.addWidget(QLabel("Disconnect side / after"), row, 0)
        disconnect_row = QHBoxLayout()
        disconnect_row.addWidget(disconnect_side)
        disconnect_row.addWidget(disconnect_event)
        layout.addLayout(disconnect_row, row, 1)
        row += 1
        layout.addWidget(arm_disconnect, row, 0, 1, 2)

        self._direction_widgets[direction] = {
            "global": global_mode,
            "application": application,
            "admin": admin,
            "delay_enabled": delay_enabled,
            "delay": delay,
            "jitter": jitter,
            "delay_category": delay_category,
            "shot_action": shot_action,
            "shot_count": shot_count,
            "shot_delay": shot_delay,
            "shot_jitter": shot_jitter,
            "shot_copies": shot_copies,
            "shot_state": shot_state,
            "disconnect_side": disconnect_side,
            "disconnect_event": disconnect_event,
        }
        return box

    def _build_rules(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        self.rule_table = QTableWidget(0, 8)
        self.rule_table.setHorizontalHeaderLabels(
            ["On", "Name", "Direction", "Category", "MsgType", "Conditions (AND)", "Action", "Parameter"]
        )
        self.rule_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.rule_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.rule_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.rule_table.verticalHeader().setVisible(False)
        self.rule_table.horizontalHeader().setStretchLastSection(True)
        self.rule_table.itemChanged.connect(self._rule_check_changed)
        self.rule_table.cellDoubleClicked.connect(lambda _row, _column: self._edit_rule())
        layout.addWidget(self.rule_table, 1)
        buttons = QHBoxLayout()
        for label, callback in (
            ("Add", self._add_rule),
            ("Edit", self._edit_rule),
            ("Delete", self._delete_rule),
            ("Move up", lambda: self._move_rule(-1)),
            ("Move down", lambda: self._move_rule(1)),
        ):
            button = QPushButton(label)
            button.clicked.connect(callback)
            buttons.addWidget(button)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        return page

    def _build_queue_journal(self) -> QWidget:
        page = QWidget()
        layout = QVBoxLayout(page)
        manual = QHBoxLayout()
        for label, callback in (
            ("Disconnect client side", lambda: self._disconnect("CLIENT")),
            ("Disconnect server side", lambda: self._disconnect("SERVER")),
            ("Disconnect both", lambda: self._disconnect("BOTH")),
        ):
            button = QPushButton(label)
            button.clicked.connect(callback)
            manual.addWidget(button)
        manual.addStretch(1)
        layout.addLayout(manual)
        self.queue_table = QTableWidget(0, 6)
        self.queue_table.setHorizontalHeaderLabels(["#", "Direction", "MsgType", "Seq", "State", "Fault"])
        self.queue_table.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.queue_table.setSelectionMode(QTableWidget.SelectionMode.SingleSelection)
        self.queue_table.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.queue_table.verticalHeader().setVisible(False)
        self.queue_table.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.queue_table, 1)
        queue_buttons = QHBoxLayout()
        for label, callback in (
            ("Forward selected", lambda: self._resolve_selected("forward")),
            ("Drop selected", lambda: self._resolve_selected("drop")),
            ("Forward all", lambda: self._resolve_all("forward")),
            ("Drop all", lambda: self._resolve_all("drop")),
        ):
            button = QPushButton(label)
            button.clicked.connect(callback)
            queue_buttons.addWidget(button)
        queue_buttons.addStretch(1)
        layout.addLayout(queue_buttons)
        layout.addWidget(QLabel("Fault-injection event journal (metadata only; no raw FIX or tag values)"))
        self.events = QTableWidget(0, 5)
        self.events.setHorizontalHeaderLabels(["Time", "Direction", "Kind", "Record", "Event"])
        self.events.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.events.verticalHeader().setVisible(False)
        self.events.horizontalHeader().setStretchLastSection(True)
        layout.addWidget(self.events, 1)
        return page

    def _direction_changed(self, direction: str) -> None:
        if self._syncing:
            return
        widgets = self._direction_widgets[direction]
        self.controller.set_global_mode(direction, widgets["global"].currentText())
        self.controller.set_category_mode(direction, "APPLICATION", widgets["application"].currentText())
        self.controller.set_category_mode(direction, "ADMIN", widgets["admin"].currentText())
        self.controller.set_delay(
            direction,
            enabled=widgets["delay_enabled"].isChecked(),
            delay_ms=widgets["delay"].value(),
            jitter_ms=widgets["jitter"].value(),
            category=widgets["delay_category"].currentText(),
        )
        self.state_changed.emit()
        self.refresh()

    def _arm_one_shot(self, direction: str) -> None:
        widgets = self._direction_widgets[direction]
        self.controller.arm_one_shot(
            direction,
            widgets["shot_action"].currentText(),
            widgets["shot_count"].value(),
            delay_ms=widgets["shot_delay"].value(),
            jitter_ms=widgets["shot_jitter"].value(),
            duplicate_copies=widgets["shot_copies"].value(),
        )
        self.controller.record_event(kind="ARM", direction=direction, summary=f"{direction} one-shot armed")
        self.state_changed.emit()
        self.refresh()

    def _clear_one_shot(self, direction: str) -> None:
        self.controller.clear_one_shot(direction)
        self.state_changed.emit()
        self.refresh()

    def _arm_disconnect(self, direction: str) -> None:
        widgets = self._direction_widgets[direction]
        trigger = self.controller.arm_disconnect(
            widgets["disconnect_side"].currentText(),
            direction,
            widgets["disconnect_event"].currentText(),
        )
        self.controller.record_event(
            kind="ARM",
            direction=direction,
            summary=(
                f"Disconnect {trigger.side.value.lower()} after next {direction} "
                f"message {trigger.event.value.lower()}"
            ),
        )
        self.state_changed.emit()
        self.refresh()

    def _disconnect(self, side: str) -> None:
        self.engine.disconnect(side)
        self.refresh()

    def _apply_preset(self) -> None:
        if self.preset.currentText() == "Clean":
            self._reset()
            return
        self.controller.apply_preset(self.preset.currentText())
        self.state_changed.emit()
        self.refresh()

    def _reset(self) -> None:
        pending = self.engine.pending_records()
        if pending:
            answer = QMessageBox.warning(
                self,
                "Reset Proxy Behaviour",
                f"Reset will discard {len(pending)} held/queued message(s). Continue?",
                QMessageBox.StandardButton.Yes | QMessageBox.StandardButton.Cancel,
                QMessageBox.StandardButton.Cancel,
            )
            if answer != QMessageBox.StandardButton.Yes:
                return
        self.engine.reset_proxy_behaviour()
        self.state_changed.emit()
        self.refresh()

    def _add_rule(self) -> None:
        dialog = RuleDialog(self, secret_tags=self.secret_tags())
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.controller.add_rule(**dialog.values())
        except ValueError as exc:
            QMessageBox.critical(self, "Invalid rule", str(exc))
            return
        self.state_changed.emit()
        self.refresh()

    def _selected_rule(self) -> FaultRule | None:
        row = self.rule_table.currentRow()
        if row < 0:
            return None
        item = self.rule_table.item(row, 0)
        rule_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        return next((rule for rule in self.controller.rules() if rule.rule_id == rule_id), None)

    def _edit_rule(self) -> None:
        rule = self._selected_rule()
        if rule is None:
            return
        dialog = RuleDialog(self, rule, self.secret_tags())
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return
        try:
            self.controller.update_rule(rule.rule_id, **dialog.values())
        except ValueError as exc:
            QMessageBox.critical(self, "Invalid rule", str(exc))
            return
        self.state_changed.emit()
        self.refresh()

    def _delete_rule(self) -> None:
        rule = self._selected_rule()
        if rule is not None:
            self.controller.delete_rule(rule.rule_id)
            self.state_changed.emit()
            self.refresh()

    def _move_rule(self, offset: int) -> None:
        rule = self._selected_rule()
        if rule is not None:
            self.controller.move_rule(rule.rule_id, offset)
            self.state_changed.emit()
            self.refresh()

    def _rule_check_changed(self, item: QTableWidgetItem) -> None:
        if self._syncing or item.column() != 0:
            return
        rule_id = item.data(Qt.ItemDataRole.UserRole)
        if rule_id is not None:
            self.controller.set_rule_enabled(
                int(rule_id), item.checkState() == Qt.CheckState.Checked
            )
            self.state_changed.emit()
            self.refresh()

    def _resolve_selected(self, action: str) -> None:
        row = self.queue_table.currentRow()
        if row < 0:
            return
        item = self.queue_table.item(row, 0)
        record_id = item.data(Qt.ItemDataRole.UserRole) if item else None
        record = next((record for record in self.engine.pending_records() if record.record_id == record_id), None)
        if record is None:
            return
        if record.status != "HELD":
            QMessageBox.information(self, "Ordered queue", "Resolve the HELD head before a later QUEUED message.")
            return
        self.engine.resolve_intercept(record.record_id, action)

    def _resolve_all(self, action: str) -> None:
        directions = {record.direction for record in self.engine.pending_records()}
        for direction in directions:
            self.engine.resolve_all_intercept(direction, action)

    def refresh(self) -> None:
        snapshot = self.controller.snapshot()
        pending = self.engine.pending_records()
        self.status.setText(display_direction_text(self.controller.status_text(len(pending))))
        active = any(
            (
                state.global_mode is not FaultAction.NORMAL
                or state.application_mode is not FaultAction.NORMAL
                or state.admin_mode is not FaultAction.NORMAL
                or state.delay_enabled
            )
            for state in (snapshot.client_to_server, snapshot.server_to_client)
        ) or bool(
            snapshot.active_rule_count
            or snapshot.one_shots
            or snapshot.disconnect_triggers
        )
        role(self.status, "warning" if active else "success")
        self._syncing = True
        try:
            for direction, state in (("C→S", snapshot.client_to_server), ("S→C", snapshot.server_to_client)):
                widgets = self._direction_widgets[direction]
                widgets["global"].setCurrentText(state.global_mode.value)
                widgets["application"].setCurrentText(state.application_mode.value)
                widgets["admin"].setCurrentText(state.admin_mode.value)
                widgets["delay_enabled"].setChecked(state.delay_enabled)
                widgets["delay"].setValue(state.delay_ms)
                widgets["jitter"].setValue(state.jitter_ms)
                widgets["delay_category"].setCurrentText(state.delay_category.value)
                shot = snapshot.one_shots.get(direction)
                widgets["shot_state"].setText(
                    "Not armed"
                    if shot is None
                    else f"Armed: {shot.action.value}, {shot.remaining} message(s) remaining"
                )
            self._refresh_rules(snapshot.rules)
            self._refresh_queue(pending)
            self._refresh_events(snapshot.events)
        finally:
            self._syncing = False

    def _refresh_rules(self, rules: tuple[FaultRule, ...]) -> None:
        selected_id = self._selected_rule().rule_id if self._selected_rule() else None
        self.rule_table.setRowCount(len(rules))
        secrets = set(self.secret_tags()) | {"553"}
        for row, rule in enumerate(rules):
            enabled = QTableWidgetItem("")
            enabled.setFlags(enabled.flags() | Qt.ItemFlag.ItemIsUserCheckable)
            enabled.setCheckState(Qt.CheckState.Checked if rule.enabled else Qt.CheckState.Unchecked)
            enabled.setData(Qt.ItemDataRole.UserRole, rule.rule_id)
            self.rule_table.setItem(row, 0, enabled)
            conditions = ", ".join(
                f"{condition.tag}={'<REDACTED>' if condition.tag in secrets else condition.value}"
                for condition in rule.conditions
            )
            parameter = (
                f"{rule.delay_ms}ms +/-{rule.jitter_ms}"
                if rule.action is FaultAction.DELAY
                else f"{rule.duplicate_copies} extra"
                if rule.action is FaultAction.DUPLICATE
                else ""
            )
            for column, value in enumerate(
                [rule.name, display_direction(rule.direction), rule.category.value, rule.msg_type or "ANY", conditions, rule.action.value, parameter],
                start=1,
            ):
                self.rule_table.setItem(row, column, QTableWidgetItem(value))
            if rule.rule_id == selected_id:
                self.rule_table.selectRow(row)

    def _refresh_queue(self, records) -> None:
        selected = None
        if self.queue_table.currentRow() >= 0 and self.queue_table.item(self.queue_table.currentRow(), 0):
            selected = self.queue_table.item(self.queue_table.currentRow(), 0).data(Qt.ItemDataRole.UserRole)
        self.queue_table.setRowCount(len(records))
        for row, record in enumerate(records):
            values = [record.record_id, display_direction(record.direction), record.msg_type, record.sequence_number or "", record.status, record.fault_action]
            for column, value in enumerate(values):
                item = QTableWidgetItem(str(value))
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, record.record_id)
                self.queue_table.setItem(row, column, item)
            if record.record_id == selected:
                self.queue_table.selectRow(row)

    def _refresh_events(self, events) -> None:
        latest = list(events[-250:])
        self.events.setRowCount(len(latest))
        for row, event in enumerate(latest):
            values = [
                event.timestamp.astimezone().strftime("%H:%M:%S.%f")[:-3],
                display_direction(event.direction),
                event.kind,
                event.record_id or "",
                display_direction_text(event.summary),
            ]
            for column, value in enumerate(values):
                self.events.setItem(row, column, QTableWidgetItem(str(value)))
        if latest:
            self.events.scrollToBottom()


__all__ = ["ProxyBehaviourPanel", "RuleDialog"]
