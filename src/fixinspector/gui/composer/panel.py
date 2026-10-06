from __future__ import annotations

from ..theme import contextual_hint, role
from ..widgets.flow_layout import FlowLayout
from ..widgets.presentation import table_columns

from collections.abc import Callable

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QFileDialog,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMessageBox,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QVBoxLayout,
    QWidget,
)

from ...composer import BusinessSecurityOverlay, ComposerController, ComposerField, ComposerForm, ComposerGroup
from ...session.injection import InjectionMode, InjectionRequest
from ...presentation import display_status
from ..widgets import MessageDiffWidget, MessageEditorWidget, MessageValidationWidget


class GroupEditor(QWidget):
    changed = Signal()

    def __init__(self, group: ComposerGroup, secret_tags=frozenset(), reveal: bool = False, parent=None) -> None:
        super().__init__(parent)
        self.group = group
        self._secret_tags = frozenset(secret_tags)
        self._reveal = reveal
        layout = QVBoxLayout(self)
        help_text = QLabel(
            f"{group.definition.name} ({group.definition.count_tag}); each row is one wire-order instance. "
            "Nested groups remain available in the shared raw/structured editor."
        )
        help_text.setWordWrap(True)
        contextual_hint(help_text, "Repeating group ⓘ")
        layout.addWidget(help_text)
        columns = [
            tag
            for tag in group.definition.direct_member_tags
            if tag not in {nested.count_tag for nested in group.definition.nested_groups}
        ]
        self._columns = columns
        self.table = QTableWidget(0, len(columns))
        self.table.setProperty("displayRole", "message")
        self.table.setHorizontalHeaderLabels(
            [
                f"{group.dictionary.field(tag).name if group.dictionary.field(tag) else tag} ({tag})"
                + (" *" if tag in group.definition.required_member_tags else "")
                for tag in columns
            ]
        )
        self.table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.table.horizontalHeader().setStretchLastSection(True)
        for column in range(len(columns)):
            self.table.setColumnWidth(column, 220)
        layout.addWidget(self.table, 1)
        buttons = QHBoxLayout()
        add = QPushButton("Add instance")
        remove = QPushButton("Remove instance")
        add.clicked.connect(self.add_instance)
        remove.clicked.connect(self.remove_instance)
        buttons.addWidget(add)
        buttons.addWidget(remove)
        buttons.addStretch(1)
        layout.addLayout(buttons)
        for instance in tuple(group.instances):
            self._append_instance_row(instance)
        if group.definition.required and not group.instances:
            self.add_instance()

    def add_instance(self) -> None:
        instance = self.group.add_instance()
        self._append_instance_row(instance)
        self.changed.emit()

    def _append_instance_row(self, instance) -> None:
        row = self.table.rowCount()
        self.table.insertRow(row)
        for column, tag in enumerate(self._columns):
            field = instance.fields[tag]
            editor = _value_editor(field, secret=field.tag in self._secret_tags, reveal=self._reveal)
            editor.currentTextChanged.connect(
                lambda value, current=field: self._field_changed(current, value)
            )
            self.table.setCellWidget(row, column, editor)
        self.table.setCurrentCell(row, 0)

    def remove_instance(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            row = self.table.rowCount() - 1
        if row < 0:
            return
        self.group.remove_instance(row)
        self.table.removeRow(row)
        self.changed.emit()

    def _field_changed(self, field: ComposerField, value: str) -> None:
        field.value = value
        field.enabled = True
        self.changed.emit()


class ComposerPanel(QWidget):
    queue_requested = Signal(bytes, str)
    state_changed = Signal()
    fuzzer_requested = Signal(bytes, str, str)

    def __init__(
        self,
        controller: ComposerController,
        dictionary_provider: Callable[[], object],
        secret_policy_provider: Callable[[], object],
        parent=None,
    ) -> None:
        super().__init__(parent)
        self.controller = controller
        self._dictionary_provider = dictionary_provider
        self._secret_policy_provider = secret_policy_provider
        self.form: ComposerForm | None = None
        self._baseline_raw = b""
        self._loading = False
        layout = QVBoxLayout(self)

        toolbar = FlowLayout()
        self.template_name = QLineEdit()
        self.template_name.setPlaceholderText("Template name")
        self.templates = QComboBox()
        self.templates.setMinimumWidth(210)
        save_template = QPushButton("Save template")
        load_template = QPushButton("Load")
        delete_template = QPushButton("Delete")
        overlay = QPushButton("Load hints overlay…")
        self._show_sensitive = False
        self.status = QLabel("Select an application MsgType")
        self.status.setWordWrap(True)
        self.queue_button = QPushButton("Queue message")
        self.queue_button.setToolTip("Wait for a safe active-session slot")
        role(self.queue_button, "primary")
        self.fuzzer_button = QPushButton("Create Fuzzer campaign")
        toolbar.addWidget(self.template_name)
        toolbar.addWidget(self.templates)
        toolbar.addWidget(save_template)
        toolbar.addWidget(load_template)
        toolbar.addWidget(delete_template)
        toolbar.addWidget(overlay)
        toolbar.addStretch(1)
        toolbar.addWidget(self.status)
        toolbar.addWidget(self.fuzzer_button)
        toolbar.addWidget(self.queue_button)
        managed = QLabel("Session fields: Managed ⓘ")
        managed.setToolTip("Composer uses the existing managed active-session injection. For Framing only or Manual, send a captured result to Sender.")
        role(managed, "muted")
        toolbar.addWidget(managed)
        layout.addLayout(toolbar)

        splitter = QSplitter(Qt.Orientation.Horizontal)
        message_page = QWidget()
        message_layout = QVBoxLayout(message_page)
        self.search = QLineEdit()
        self.search.setPlaceholderText("Search application message name or MsgType")
        self.messages = QTableWidget(0, 2)
        self.messages.setHorizontalHeaderLabels(["MsgType", "Message"])
        self.messages.setEditTriggers(QAbstractItemView.EditTrigger.NoEditTriggers)
        self.messages.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectRows)
        self.messages.horizontalHeader().setStretchLastSection(True)
        message_layout.addWidget(self.search)
        message_layout.addWidget(self.messages, 1)
        splitter.addWidget(message_page)

        self.workbench = QTabWidget()
        form_page = QWidget()
        form_layout = QVBoxLayout(form_page)
        self.message_hint = QLabel()
        self.message_hint.setWordWrap(True)
        self.message_hint.setObjectName("mutedLabel")
        form_layout.addWidget(self.message_hint)
        required_label = QLabel("Required fields")
        role(required_label, "section")
        form_layout.addWidget(required_label)
        self.required = self._field_table()
        form_layout.addWidget(self.required, 1)
        optional_label = QLabel("Optional fields - enable only fields to place on the wire")
        role(optional_label, "section")
        form_layout.addWidget(optional_label)
        self.optional = self._field_table()
        form_layout.addWidget(self.optional, 1)
        self.group_tabs = QTabWidget()
        form_layout.addWidget(self.group_tabs, 1)
        self.workbench.addTab(form_page, "Fields")

        self.editor = MessageEditorWidget(dictionary_provider, secret_policy_provider)
        self.workbench.addTab(self.editor, "Message")
        self.diff = MessageDiffWidget()
        self.validation = MessageValidationWidget()
        self.workbench.addTab(self.diff, "Diff")
        self.workbench.addTab(self.validation, "Validation")
        splitter.addWidget(self.workbench)
        splitter.setSizes([260, 1000])
        layout.addWidget(splitter, 1)

        self.search.textChanged.connect(self.refresh_messages)
        self.messages.cellDoubleClicked.connect(lambda row, _column: self._select_row(row))
        self.messages.itemSelectionChanged.connect(self._selected_message_changed)
        self.optional.itemChanged.connect(self._optional_checked)
        self.workbench.currentChanged.connect(lambda _index: self.refresh_analysis())
        save_template.clicked.connect(self.save_template)
        load_template.clicked.connect(self.load_template)
        delete_template.clicked.connect(self.delete_template)
        overlay.clicked.connect(self.load_overlay)
        self.queue_button.clicked.connect(self._queue)
        self.fuzzer_button.clicked.connect(self._create_fuzzer)
        self.refresh_messages()
        self.refresh_templates()
        for table in (self.messages, self.required, self.optional):
            table_columns(table)
        for table in (self.required, self.optional):
            table.horizontalHeader().setStretchLastSection(False)
            table.horizontalHeader().setSectionResizeMode(4, QHeaderView.ResizeMode.Stretch)
            for column, width in ((0, 100), (1, 80), (2, 200), (3, 110), (5, 240)):
                table.setColumnWidth(column, width)

    @staticmethod
    def _field_table() -> QTableWidget:
        table = QTableWidget(0, 6)
        table.setProperty("displayRole", "message")
        table.setHorizontalHeaderLabels(["Use", "Tag", "Name", "Type", "Value", "Hint / security"])
        table.setSelectionBehavior(QAbstractItemView.SelectionBehavior.SelectItems)
        table.horizontalHeader().setStretchLastSection(True)
        table.verticalHeader().setVisible(False)
        return table

    def refresh_messages(self) -> None:
        query = self.search.text().strip().casefold()
        self.messages.setRowCount(0)
        dictionary = self._dictionary_provider()
        values = sorted(dictionary.messages.values(), key=lambda item: (item.name.casefold(), item.msg_type))
        for definition in values:
            if dictionary.is_admin(definition.msg_type):
                continue
            if query and query not in definition.msg_type.casefold() and query not in definition.name.casefold():
                continue
            row = self.messages.rowCount()
            self.messages.insertRow(row)
            tag = QTableWidgetItem(definition.msg_type)
            tag.setData(Qt.ItemDataRole.UserRole, definition.msg_type)
            self.messages.setItem(row, 0, tag)
            self.messages.setItem(row, 1, QTableWidgetItem(definition.name))

    def _selected_message_changed(self) -> None:
        row = self.messages.currentRow()
        if row >= 0:
            self._select_row(row)

    def _select_row(self, row: int) -> None:
        item = self.messages.item(row, 0)
        if item is None:
            return
        msg_type = str(item.data(Qt.ItemDataRole.UserRole) or item.text())
        try:
            self.form = self.controller.build_form(msg_type)
        except (KeyError, ValueError) as exc:
            QMessageBox.warning(self, "Composer", str(exc))
            return
        self._populate_form()

    def _populate_form(self) -> None:
        if self.form is None:
            return
        self._loading = True
        try:
            self.message_hint.setText(
                f"{self.form.msg_type} / {self.form.message_name}"
                + (f" - {self.form.message_hint}" if self.form.message_hint else "")
            )
            self._populate_field_rows(self.required, self.form.required_fields, required=True)
            self._populate_field_rows(self.optional, self.form.optional_fields, required=False)
            while self.group_tabs.count():
                self.group_tabs.removeTab(0)
            for group in self.form.groups:
                editor = GroupEditor(
                    group,
                    self._secret_policy_provider().secret_tags,
                    self._show_sensitive,
                )
                editor.changed.connect(self._form_changed)
                self.group_tabs.addTab(editor, f"{group.definition.name} ({group.definition.count_tag})")
            self.group_tabs.setVisible(bool(self.form.groups))
        finally:
            self._loading = False
        self._baseline_raw = self.form.to_raw()
        self.editor.set_raw(self._baseline_raw)
        self.editor.set_mode(InjectionMode.CLONE_EDIT)
        self.status.setText("Form generated - session headers will be replaced from the active slot")
        self.refresh_analysis()

    def _populate_field_rows(self, table: QTableWidget, fields: list[ComposerField], *, required: bool) -> None:
        table.setRowCount(0)
        for field in fields:
            row = table.rowCount()
            table.insertRow(row)
            use = QTableWidgetItem("Required" if required else "")
            use.setData(Qt.ItemDataRole.UserRole, field.tag)
            if not required:
                use.setFlags(use.flags() | Qt.ItemFlag.ItemIsUserCheckable)
                use.setCheckState(Qt.CheckState.Checked if field.enabled else Qt.CheckState.Unchecked)
            table.setItem(row, 0, use)
            table.setItem(row, 1, QTableWidgetItem(field.tag))
            table.setItem(row, 2, QTableWidgetItem(field.name))
            table.setItem(row, 3, QTableWidgetItem(field.field_type))
            editor = _value_editor(
                field,
                secret=field.tag in self._secret_policy_provider().secret_tags,
                reveal=self._show_sensitive,
            )
            editor.currentTextChanged.connect(
                lambda value, current=field: self._value_changed(current, value)
            )
            table.setCellWidget(row, 4, editor)
            hint = " · ".join(value for value in (field.hint, field.security_hint) if value)
            table.setItem(row, 5, QTableWidgetItem(hint))

    def _value_changed(self, field: ComposerField, value: str) -> None:
        field.value = value
        self._form_changed()

    def _optional_checked(self, item: QTableWidgetItem) -> None:
        if self._loading or item.column() != 0 or self.form is None:
            return
        tag = str(item.data(Qt.ItemDataRole.UserRole) or "")
        field = self.form.field(tag)
        if field is not None:
            field.enabled = item.checkState() == Qt.CheckState.Checked
            self._form_changed()

    def _form_changed(self) -> None:
        if self._loading or self.form is None:
            return
        raw = self.form.to_raw()
        self.editor.set_raw(raw)
        self.refresh_analysis(raw)

    def set_reveal(self, reveal: bool) -> None:
        self._show_sensitive = bool(reveal)
        self.editor.set_reveal(reveal)
        for group in self.findChildren(GroupEditor):
            group._reveal = bool(reveal)
            group._secret_tags = self._secret_policy_provider().secret_tags
        for editor in self.findChildren(QComboBox):
            tag = editor.property("fixTag")
            if tag is not None and editor.lineEdit() is not None:
                secret = str(tag) in self._secret_policy_provider().secret_tags
                editor.setProperty("secret", secret)
                editor.lineEdit().setEchoMode(
                    QLineEdit.EchoMode.Password if secret and not reveal else QLineEdit.EchoMode.Normal
                )
        self.refresh_analysis(self.editor._working_raw)

    def current_raw(self) -> bytes:
        if self.form is None:
            raise ValueError("Select an application MsgType first")
        return self.editor.outbound_raw()

    def refresh_analysis(self, raw: bytes | None = None) -> None:
        if self.form is None:
            return
        try:
            current = raw if raw is not None else self.editor.outbound_raw()
        except (TypeError, ValueError) as exc:
            self.validation.setPlainText(str(exc))
            return
        policy = self._secret_policy_provider()
        dictionary = self._dictionary_provider()
        visible = lambda raw: raw if self._show_sensitive else policy.redact(raw, dictionary)
        self.diff.set_messages(visible(self._baseline_raw), visible(current))
        issues = self.form.validation_issues()
        if not self._show_sensitive:
            issues = [policy.redact_text(issue) for issue in issues]
        self.validation.set_message(visible(current), dictionary, issues)

    def _queue(self) -> None:
        try:
            raw = self.current_raw()
        except (TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Composer", str(exc))
            return
        template_id = str(self.templates.currentData() or "")
        self.queue_requested.emit(raw, template_id)

    def _create_fuzzer(self) -> None:
        try:
            raw = self.current_raw()
        except (TypeError, ValueError) as exc:
            QMessageBox.critical(self, "Fuzzer baseline", str(exc))
            return
        template_id = str(self.templates.currentData() or "draft")
        title = self.template_name.text().strip() or (
            f"Composer {self.form.msg_type} / {self.form.message_name}" if self.form else "Composer draft"
        )
        self.fuzzer_requested.emit(raw, title, template_id)

    def apply_event(self, request: InjectionRequest) -> None:
        self.status.setText(display_status(request.status.value) + (f" - {request.detail}" if request.detail else ""))
        role(self.status, "success" if "Injected" in request.status.value else "muted")

    def save_template(self) -> None:
        try:
            raw = self.current_raw()
            if self.form is None:
                raise ValueError("Select a MsgType first")
            selected_id = str(self.templates.currentData() or "")
            template = self.controller.save_template(
                self.template_name.text(), self.form.msg_type, raw, selected_id
            )
        except (TypeError, ValueError) as exc:
            QMessageBox.warning(self, "Composer template", str(exc))
            return
        self.refresh_templates(template.template_id)
        self.status.setText(f"Saved project template {template.name}")
        self.state_changed.emit()

    def load_template(self) -> None:
        template = self.controller.template(str(self.templates.currentData() or ""))
        if template is None:
            return
        self._select_msg_type(template.msg_type)
        if self.form is not None:
            try:
                self.form.apply_raw(template.raw)
                self._populate_form()
            except ValueError as exc:
                QMessageBox.warning(self, "Composer template", str(exc))
                return
        self.editor.set_raw(template.raw)
        self.template_name.setText(template.name)
        self.refresh_analysis(template.raw)
        self.status.setText(f"Loaded project template {template.name}")

    def delete_template(self) -> None:
        template_id = str(self.templates.currentData() or "")
        if template_id:
            self.controller.delete_template(template_id)
            self.refresh_templates()
            self.state_changed.emit()

    def refresh_templates(self, selected_id: str = "") -> None:
        self.templates.clear()
        self.templates.addItem("No saved template", "")
        for item in self.controller.templates():
            self.templates.addItem(f"{item.name} [{item.msg_type}]", item.template_id)
        if selected_id:
            self.templates.setCurrentIndex(max(0, self.templates.findData(selected_id)))

    def _select_msg_type(self, msg_type: str) -> None:
        self.search.clear()
        self.refresh_messages()
        for row in range(self.messages.rowCount()):
            if self.messages.item(row, 0).text() == msg_type:
                self.messages.selectRow(row)
                self._select_row(row)
                return

    def load_overlay(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self,
            "Load Composer business/security hints",
            "",
            "JSON overlay (*.json);;All files (*)",
        )
        if not path:
            return
        try:
            overlay = BusinessSecurityOverlay.load(path)
        except (OSError, ValueError) as exc:
            QMessageBox.critical(self, "Composer overlay", str(exc))
            return
        self.controller.set_overlay(overlay)
        if self.form is not None:
            self._select_msg_type(self.form.msg_type)
        self.status.setText(f"Loaded hints overlay {path}")
        self.state_changed.emit()


def _value_editor(field: ComposerField, *, secret: bool = False, reveal: bool = False) -> QComboBox:
    editor = QComboBox()
    editor.setEditable(True)
    editor.addItem("")
    for value, description in field.enum_options.items():
        editor.addItem(value)
        index = editor.count() - 1
        editor.setItemData(index, description, Qt.ItemDataRole.ToolTipRole)
    editor.setCurrentText(field.value)
    editor.setProperty("secret", secret)
    editor.setProperty("fixTag", field.tag)
    if secret and editor.lineEdit() is not None:
        editor.lineEdit().setEchoMode(
            QLineEdit.EchoMode.Normal if reveal else QLineEdit.EchoMode.Password
        )
    editor.setToolTip(
        "Dictionary enum values are suggestions. Type any arbitrary invalid value for negative/security testing."
    )
    return editor


__all__ = ["ComposerPanel", "GroupEditor"]
