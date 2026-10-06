"""History filter presentation over the existing expression compiler and records."""

from datetime import datetime
import json
import re

from PySide6.QtCore import QSignalBlocker, Qt
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QDialog, QDialogButtonBox, QFormLayout, QLabel,
    QLineEdit, QPushButton, QTabWidget, QToolButton, QVBoxLayout, QWidget,
)

from ...history import compile_filter, FilterSyntaxError
from ..settings.presentation import scrollable
from ..theme import role
from ..widgets.flow_layout import FlowLayout


def quoted(text):
    return json.dumps(text, ensure_ascii=False)


class HistoryFilters:
    def __init__(self, window, page):
        self.window = window
        self._syncing = False
        self.extra = {}
        self.dialog = QDialog(window)
        self.dialog.setWindowTitle("History filters")
        self.dialog.resize(660, 620)
        layout = QVBoxLayout(self.dialog)
        tabs = QTabWidget()
        layout.addWidget(tabs, 1)
        general = QWidget()
        form = QFormLayout(general)
        self.category = QComboBox()
        self.category.addItems(["All messages", "Application", "Session/Admin"])
        self.state = QLineEdit()
        self.source = QComboBox()
        self.source.addItems(["All sources", "Proxy", "Sender", "Composer", "Fuzzer"])
        self.modified = QCheckBox("Modified")
        self.faulted = QCheckBox("Faulted")
        self.dropped = QCheckBox("Dropped")
        # Move existing controls with their signal bindings/persistence intact.
        for title, control in (("Direction", window.direction_filter), ("Category", self.category),
                               ("State", self.state), ("Source", self.source),
                               ("", window.bookmarks_only), ("", self.modified), ("", self.faulted),
                               ("", self.dropped), ("", window.hide_heartbeats), ("", window.hide_admin)):
            form.addRow(title, control)
        tabs.addTab(scrollable(general), "Traffic")
        fields_page = QWidget()
        fields_form = QFormLayout(fields_page)
        self.fields = {}
        for key, title in (("msgtype", "MsgType"), ("account", "Account"), ("clordid", "ClOrdID"),
                           ("orderid", "OrderID"), ("seq_from", "Sequence from"), ("seq_to", "Sequence to"),
                           ("time_from", "Time from (ISO 8601)"), ("time_to", "Time to (ISO 8601)")):
            control = QLineEdit()
            fields_form.addRow(title, control)
            self.fields[key] = control
        tabs.addTab(scrollable(fields_page), "Fields / range")
        advanced_page = QWidget()
        advanced_form = QFormLayout(advanced_page)
        self.expression = QLineEdit()
        self.expression.setPlaceholderText('tag.54=1 AND tag.44>100')
        self.expression.setToolTip("Existing History expressions: AND / OR / NOT, comparisons, parentheses, arbitrary tag.N")
        advanced_form.addRow("Advanced tag expression", self.expression)
        tabs.addTab(scrollable(advanced_page), "Advanced")
        self.error = QLabel()
        self.error.setWordWrap(True)
        role(self.error, "danger")
        layout.addWidget(self.error)
        clear = QPushButton("Clear filters")
        clear.clicked.connect(self.clear_filters)
        layout.addWidget(clear)
        close = QDialogButtonBox(QDialogButtonBox.StandardButton.Close)
        close.rejected.connect(self.dialog.close)
        layout.addWidget(close)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search messages…")
        self.button = QPushButton("Filter")
        self.button.clicked.connect(self.show)
        self.chip_widget = QWidget()
        self.chips = FlowLayout(self.chip_widget)
        outer = page.layout()
        top = outer.itemAt(0).layout()
        top.removeWidget(window.filter_edit)
        top.removeWidget(window.advanced_filter)
        window.filter_edit.hide()
        window.advanced_filter.hide()
        # Legacy editor is only a compatibility bridge for saved expressions.
        top.insertWidget(0, self.search, 1)
        top.insertWidget(1, self.button)
        outer.insertWidget(1, self.chip_widget)
        try:
            saved = json.loads(str(window._settings().value("ui/history_filter_controls", "null")))
        except (TypeError, ValueError):
            saved = None
        self.restore(saved)
        for control in [self.search, self.expression, self.state, *self.fields.values()]:
            control.textChanged.connect(self.changed)
        for control in (self.category, self.source):
            control.currentIndexChanged.connect(self.changed)
        for control in (self.modified, self.faulted, self.dropped, window.bookmarks_only,
                        window.hide_heartbeats, window.hide_admin):
            control.toggled.connect(self.changed)
        window.direction_filter.currentIndexChanged.connect(self.changed)
        self.changed()

    def show(self):
        self.dialog.show()
        self.dialog.raise_()

    def state_values(self):
        return {"search": self.search.text(), "expression": self.expression.text(),
                "category": self.category.currentIndex(), "source": self.source.currentIndex(),
                "state": self.state.text(), "modified": self.modified.isChecked(),
                "faulted": self.faulted.isChecked(), "dropped": self.dropped.isChecked(),
                **{key: widget.text() for key, widget in self.fields.items()}}

    def persistence_state(self):
        # Direct legacy/project updates remain authoritative, not overwritten by
        # stale controls that have not been touched in the new toolbar.
        if self.window.filter_edit.text() != getattr(self, "_compiled_expression", ""):
            return None
        values = self.state_values()
        for key, value in values.items():
            if isinstance(value, str):
                values[key] = self.persistable_text(value)
        for name, tag in (("account", "1"), ("clordid", "11"), ("orderid", "37"), ("msgtype", "35")):
            if tag in self.window.secret_policy.secret_tags:
                values[name] = ""
        return values

    def references_secret(self, text):
        from ...history.filtering import _resolve_tag
        operands = re.findall(r"([\w.\[\]:]+)\s*[=!<>~]", text)
        return any(_resolve_tag(name.casefold()) in self.window.secret_policy.secret_tags for name in operands)

    def persistable_text(self, text):
        # A secret-tag predicate remains usable in this session, but its operand
        # must not become a second plaintext credential store in INI/projects.
        return "" if self.references_secret(text) else self.window.secret_policy.redact_text(text)

    def restore(self, saved):
        w = self.window
        self._syncing = True
        saved = saved if isinstance(saved, dict) else {
            "expression" if w.advanced_filter.isChecked() else "search": w.filter_edit.text()
        }
        self.search.setText(str(saved.get("search", "")))
        self.expression.setText(str(saved.get("expression", "")))
        self.state.setText(str(saved.get("state", "")))
        for name, control in self.fields.items():
            control.setText(str(saved.get(name, "")))
        for name, control in (("category", self.category), ("source", self.source)):
            try:
                control.setCurrentIndex(max(0, min(control.count()-1, int(saved.get(name, 0)))))
            except (TypeError, ValueError):
                control.setCurrentIndex(0)
        for name, control in (("modified", self.modified), ("faulted", self.faulted), ("dropped", self.dropped)):
            control.setChecked(bool(saved.get(name, False)))
        self._syncing = False
        self.changed()

    def changed(self, *_):
        if self._syncing:
            return
        w = self.window
        parts = []
        values = self.state_values()
        if values["expression"].strip():
            parts.append(f'({values["expression"]})')
        for name in ("msgtype", "account", "clordid", "orderid"):
            if values[name].strip():
                parts.append(f"{name}={quoted(values[name].strip())}")
        if values["state"].strip():
            parts.append(f"status={quoted(values['state'].strip())}")
        for name in ("modified", "dropped"):
            if values[name]:
                parts.append("modified=true" if name == "modified" else "status=DROPPED")
        if values["source"]:
            source = "REPEATER" if self.source.currentText() == "Sender" else self.source.currentText().upper()
            parts.append('(source=CLIENT OR source=SERVER)' if source == "PROXY" else f"source={source}")
        try:
            for name, operator in (("seq_from", ">="), ("seq_to", "<=")):
                if values[name].strip():
                    parts.append(f"seq{operator}{int(values[name])}")
            if values["seq_from"] and values["seq_to"] and int(values["seq_from"]) > int(values["seq_to"]):
                raise ValueError("Sequence from must not exceed sequence to")
            time_from = self._time(values["time_from"])
            time_to = self._time(values["time_to"])
            if time_from is not None and time_to is not None and time_from > time_to:
                raise ValueError("Time from must not exceed time to")
            expression = " AND ".join(parts)
            if len(parts) == 1 and values["expression"].strip():
                expression = values["expression"]
            if expression:
                compile_filter(expression)
        except (ValueError, FilterSyntaxError) as exc:
            error = "Invalid secret-tag filter expression" if self.references_secret(str(exc)) else str(exc)
            self.error.setText(error)
            w.filter_error.setText(error)
            w.filter_error.show()
            return  # Keep the last valid predicate/rows while typing.
        self.error.clear()
        self.extra = values
        self.time_from, self.time_to = time_from, time_to
        self._compiled_expression = expression
        self._search_text = values["search"].strip()
        blockers = [QSignalBlocker(w.filter_edit), QSignalBlocker(w.advanced_filter)]
        w.filter_edit.setText(expression)
        w.advanced_filter.setChecked(bool(expression))
        del blockers
        w._apply_history_filter()
        self._refresh_chips(values)

    @staticmethod
    def _time(value):
        return datetime.fromisoformat(value.strip()).timestamp() if value.strip() else None

    def accepts(self, document):
        from ...history import matches_text
        record = document.record
        category = self.extra.get("category", 0)
        admin = self.window.dictionary.is_admin(record.msg_type)
        if category == 1 and admin or category == 2 and not admin:
            return False
        if self.extra.get("faulted") and record.fault_action in {"", "NORMAL", None}:
            return False
        timestamp = record.timestamp.timestamp()
        if getattr(self, "time_from", None) is not None and timestamp < self.time_from:
            return False
        if getattr(self, "time_to", None) is not None and timestamp > self.time_to:
            return False
        return matches_text(document, getattr(self, "_search_text", ""))

    def _refresh_chips(self, values):
        while self.chips.count():
            item = self.chips.takeAt(0)
            if item.widget():
                item.widget().deleteLater()
        chips = []
        w = self.window
        for control, text in ((w.hide_heartbeats, "Hide Heartbeats"), (w.hide_admin, "Hide other session/admin"),
                              (w.bookmarks_only, "Bookmarked"), (self.modified, "Modified"),
                              (self.faulted, "Faulted"), (self.dropped, "Dropped")):
            if control.isChecked():
                chips.append((text, lambda c=control: c.setChecked(False)))
        for control in (w.direction_filter, self.category, self.source):
            if control.currentIndex() > 0:
                chips.append((control.currentText(), lambda c=control: c.setCurrentIndex(0)))
        for name, control in [("State", self.state), ("Advanced", self.expression), *self.fields.items()]:
            if control.text().strip():
                # Expressions/values may contain secrets; use existing policy.
                label = f"{name}: secret-tag filter (not saved)" if self.references_secret(control.text()) else w.secret_policy.redact_text(f"{name}: {control.text()}")
                chips.append((label, control.clear))
        for text, callback in chips:
            button = QToolButton()
            button.setText(text[:70] + ("…" if len(text) > 70 else "") + " ×")
            button.setToolTip(text)
            button.clicked.connect(lambda _checked=False, action=callback: action())
            self.chips.addWidget(button)
        self.button.setText(f"Filter ({len(chips)})" if chips else "Filter")
        self.chip_widget.setVisible(bool(chips))

    def clear_filters(self):
        w = self.window
        self._syncing = True
        for control in (self.expression, self.state, *self.fields.values()):
            control.clear()
        for control in (w.hide_heartbeats, w.hide_admin, w.bookmarks_only, self.modified, self.faulted, self.dropped):
            control.setChecked(False)
        for control in (w.direction_filter, self.category, self.source):
            control.setCurrentIndex(0)
        self._syncing = False
        self.changed()
