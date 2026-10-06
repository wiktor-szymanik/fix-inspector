"""Action-aware form mapping only to capabilities present in the existing core."""

from PySide6.QtWidgets import QComboBox, QLabel, QSpinBox

from ...intercept.proxy_behaviour import MAX_ONE_SHOT_MESSAGES
from ..proxy_behaviour.panel import RuleDialog


class RuleEditor(RuleDialog):
    def __init__(self, adapter, parent=None, row=None):
        self.adapter = adapter
        self.row = row
        rule = next((r for r in adapter.controller.rules() if row and row.key == ("rule", r.rule_id)), None)
        super().__init__(parent, rule, adapter.policy_provider().secret_tags)
        self.setWindowTitle("Edit rule" if row else "Add rule")
        self.form = self.layout()
        self.direction.setItemText(2, "Both")
        self.kind = QComboBox()
        for text, key in (("Ordered rule", "rule"), ("Next N messages", "once"),
                          ("Global override", "global"), ("Category default", "category"),
                          ("Directional delay", "delay"), ("Disconnect after event", "disconnect"),
                          ("Disconnect now", "disconnect_now")):
            self.kind.addItem(text, key)
        self.form.insertRow(0, "Applicability", self.kind)
        self.match = QComboBox()
        self.match.addItems(["All messages", "Application", "Session/Admin", "MsgType", "Tag conditions (AND)", "Combined match"])
        self.form.insertRow(3, "Match", self.match)
        self.count = QSpinBox()
        self.count.setRange(1, MAX_ONE_SHOT_MESSAGES)
        self.side = QComboBox()
        self.side.addItems(["CLIENT", "SERVER", "BOTH"])
        self.event = QComboBox()
        self.event.addItems(["RECEIVED", "FORWARDED", "DROPPED"])
        self.form.insertRow(self.form.rowCount() - 2, "Message count", self.count)
        self.form.insertRow(self.form.rowCount() - 2, "Disconnect side", self.side)
        self.form.insertRow(self.form.rowCount() - 2, "After event", self.event)
        self.note = QLabel("Matching / precedence ⓘ")
        self.note.setToolTip("Ordered rules support MsgType, category and exact tag=value conditions combined with AND. Any duplicate occurrence may match. Boolean/range expressions are not supported by the rule engine. Next N applies to all messages in the selected direction, not a filtered subset. Disconnect triggers run independently after the chosen event.")
        # Retain original help as tooltip without an extra explanatory paragraph.
        for label in self.findChildren(QLabel):
            if label.text().startswith("Conditions are exact"):
                label.hide()
        self.form.insertRow(self.form.rowCount() - 1, self.note)
        if rule:
            count = bool(rule.msg_type) + bool(rule.conditions) + (rule.category.value != "ANY")
            self.match.setCurrentIndex(5 if count > 1 else 4 if rule.conditions else 3 if rule.msg_type else
                                       1 if rule.category.value == "APPLICATION" else 2 if rule.category.value == "ADMIN" else 0)
        if row:
            self.kind.setCurrentIndex(self.kind.findData(row.key[0]))
            self.kind.setEnabled(False)
            self.direction.setCurrentIndex(max(0, self.direction.findData(row.direction)))
            if row.key[0] != "rule":
                self._restore_non_rule(row)
        self.kind.currentIndexChanged.connect(self._update_fields)
        self.match.currentIndexChanged.connect(self._update_fields)
        self.action.currentIndexChanged.connect(self._update_parameters)
        self._update_fields()

    def _restore_non_rule(self, row):
        self.direction.setEnabled(False)
        self.action.setCurrentText(row.action)
        state = self.adapter.controller.direction(row.direction)
        kind = row.key[0]
        if kind == "category":
            self.category.setCurrentText(row.key[2])
            self.category.setEnabled(False)
        if kind == "delay":
            self.delay.setValue(state.delay_ms)
            self.jitter.setValue(state.jitter_ms)
            self.category.setCurrentText(state.delay_category.value)
        if kind == "once":
            shot = self.adapter.controller.snapshot().one_shots.get(row.direction)
            if shot:
                self.count.setValue(shot.remaining)
                self.delay.setValue(shot.delay_ms)
                self.jitter.setValue(shot.jitter_ms)
                self.copies.setValue(shot.duplicate_copies)

    def _visible(self, control, visible):
        self.form.setRowVisible(control, visible)

    def _update_fields(self):
        kind = self.kind.currentData()
        ordered = kind == "rule"
        self._visible(self.name, ordered)
        self._visible(self.match, ordered)
        self._visible(self.enabled, ordered)
        self._visible(self.category, kind in {"category", "delay"} or ordered and self.match.currentIndex() == 5)
        self._visible(self.msg_type, ordered and self.match.currentIndex() in {3, 5})
        self._visible(self.conditions, ordered and self.match.currentIndex() in {4, 5})
        self._visible(self.count, kind in {"once", "disconnect"})
        self._visible(self.side, kind in {"disconnect", "disconnect_now"})
        self._visible(self.event, kind == "disconnect")
        self._visible(self.direction, kind != "disconnect_now")
        self._visible(self.action, kind not in {"disconnect", "disconnect_now", "delay"})
        allowed = ["NORMAL", "DROP", "PAUSE", "DELAY", "DUPLICATE"] if ordered else ["DROP", "PAUSE", "DELAY", "DUPLICATE"] if kind == "once" else ["NORMAL", "DROP", "PAUSE"]
        previous = self.action.currentText()
        self.action.blockSignals(True)
        self.action.clear()
        self.action.addItems(allowed)
        self.action.setCurrentText(previous if previous in allowed else allowed[0])
        self.action.blockSignals(False)
        self._update_parameters()

    def _update_parameters(self):
        delay = self.kind.currentData() == "delay" or self.kind.currentData() in {"rule", "once"} and self.action.currentText() == "DELAY"
        self._visible(self.delay, delay)
        self._visible(self.jitter, delay)
        self._visible(self.copies, self.kind.currentData() in {"rule", "once"} and self.action.currentText() == "DUPLICATE")

    def values(self):
        kind = self.kind.currentData()
        direction = str(self.direction.currentData())
        base = {"kind": kind, "direction": direction}
        if kind == "rule":
            selected = self.match.currentIndex()
            saved_conditions = self.conditions.text()
            if selected not in {4, 5}:
                self.conditions.clear()
            try:
                values = super().values()
            finally:
                self.conditions.setText(saved_conditions)
            if selected != 5:
                values["category"] = "APPLICATION" if selected == 1 else "ADMIN" if selected == 2 else "ANY"
            if selected not in {3, 5}:
                values["msg_type"] = ""
            if selected not in {4, 5}:
                values["conditions"] = []
            return {**values, "kind": kind}
        if kind == "once":
            return {**base, "action": self.action.currentText(), "count": self.count.value(),
                    "delay_ms": self.delay.value(), "jitter_ms": self.jitter.value(), "duplicate_copies": self.copies.value()}
        if kind in {"disconnect", "disconnect_now"}:
            values = {**base, "side": self.side.currentText()}
            if kind == "disconnect":
                values.update(event=self.event.currentText(), count=self.count.value())
            return values
        if kind == "delay":
            return {**base, "enabled": True, "delay_ms": self.delay.value(), "jitter_ms": self.jitter.value(), "category": self.category.currentText()}
        if kind == "category":
            if self.category.currentText() == "ANY":
                raise ValueError("Category default requires Application or Session/Admin, not ANY.")
            return {**base, "action": self.action.currentText(), "category": self.category.currentText()}
        return {**base, "action": self.action.currentText()}
