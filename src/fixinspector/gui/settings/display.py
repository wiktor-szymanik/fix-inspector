"""Local, persistent display preferences. No protocol or message dependencies."""

from dataclasses import dataclass, replace

from PySide6.QtCore import QSignalBlocker, Signal
from PySide6.QtWidgets import (
    QCheckBox, QComboBox, QFormLayout, QGroupBox, QLabel, QSpinBox, QVBoxLayout, QWidget,
)
from ..theme import contextual_hint

SCALE_STEPS = (100, 110, 125, 150, 175, 200)


@dataclass(frozen=True)
class DisplaySettings:
    # The existing application stylesheet uses 10 pt for all these widgets.
    interface_scale: int = 100
    message_font_size: int = 10
    table_font_size: int = 10

    @classmethod
    def load(cls, settings):
        defaults = cls()
        values = {}
        for name, low, high in (
            ("interface_scale", 100, 200), ("message_font_size", 8, 32),
            ("table_font_size", 8, 24),
        ):
            try:
                value = int(settings.value(f"display/{name}", getattr(defaults, name)))
            except (ValueError, TypeError):
                value = getattr(defaults, name)
            if not low <= value <= high or (name == "interface_scale" and value not in SCALE_STEPS):
                value = getattr(defaults, name)
            values[name] = value
        return cls(**values)

    def save(self, settings) -> None:
        for name in ("interface_scale", "message_font_size", "table_font_size"):
            settings.setValue(f"display/{name}", getattr(self, name))
        settings.sync()

    def zoom(self, direction: int):
        index = max(0, min(len(SCALE_STEPS) - 1, SCALE_STEPS.index(self.interface_scale) + direction))
        return replace(self, interface_scale=SCALE_STEPS[index])


PRESENTATION_PRESET = DisplaySettings(150, 18, 15)


class DisplaySettingsPanel(QWidget):
    preferences_changed = Signal(object)
    presentation_changed = Signal(bool)

    def __init__(self, parent=None):
        super().__init__(parent)
        layout = QVBoxLayout(self)
        box = QGroupBox("Display and presentation")
        form = QFormLayout(box)
        self.interface_scale = QComboBox()
        for scale in SCALE_STEPS:
            self.interface_scale.addItem(f"{scale}%", scale)
        self.message_font_size = QSpinBox()
        self.message_font_size.setRange(8, 32)
        self.message_font_size.setSuffix(" pt")
        self.table_font_size = QSpinBox()
        self.table_font_size.setRange(8, 24)
        self.table_font_size.setSuffix(" pt")
        self.presentation = QCheckBox("Enable presentation mode")
        form.addRow("Interface scale", self.interface_scale)
        form.addRow("Message font size", self.message_font_size)
        form.addRow("Table font size", self.table_font_size)
        form.addRow(self.presentation)
        help_text = QLabel(
            "Changes apply immediately. Font sizes are base points at 100%; interface scale "
            "also scales message and table text. Presentation mode is temporary and restores "
            "your normal settings when disabled.\n"
            "Ctrl+Plus / Ctrl+Minus: interface scale. Ctrl+0: 100%. "
            "Ctrl+wheel over message content: message font; elsewhere: interface scale. "
            "No FIX content is changed."
        )
        help_text.setWordWrap(True)
        contextual_hint(help_text, "Display shortcuts and scaling ⓘ")
        form.addRow(help_text)
        layout.addWidget(box)
        layout.addStretch(1)
        self.interface_scale.currentIndexChanged.connect(self._edited)
        self.message_font_size.valueChanged.connect(self._edited)
        self.table_font_size.valueChanged.connect(self._edited)
        self.presentation.toggled.connect(self.presentation_changed)

    def show_settings(self, value: DisplaySettings, presentation: bool) -> None:
        controls = (self.interface_scale, self.message_font_size, self.table_font_size, self.presentation)
        blockers = [QSignalBlocker(control) for control in controls]
        self.interface_scale.setCurrentIndex(self.interface_scale.findData(value.interface_scale))
        self.message_font_size.setValue(value.message_font_size)
        self.table_font_size.setValue(value.table_font_size)
        self.presentation.setChecked(presentation)
        del blockers

    def _edited(self) -> None:
        self.preferences_changed.emit(DisplaySettings(
            int(self.interface_scale.currentData()), self.message_font_size.value(),
            self.table_font_size.value(),
        ))
