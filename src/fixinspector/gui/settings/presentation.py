"""Font/widget scaling only: never reads, reloads, or commits message contents."""

from dataclasses import replace
import re
from shiboken6 import isValid

from PySide6.QtCore import QEvent, QObject, Qt
from PySide6.QtGui import QFontDatabase, QKeySequence, QShortcut
from PySide6.QtWidgets import (
    QApplication, QFrame, QHBoxLayout, QLabel, QListWidget, QPlainTextEdit, QScrollArea,
    QSplitter, QStyle, QTableView, QTabWidget, QTreeView, QWidget,
)

from .display import DisplaySettings, DisplaySettingsPanel, PRESENTATION_PRESET


def scrollable(page: QWidget) -> QScrollArea:
    area = QScrollArea()
    area.setFrameShape(QFrame.Shape.NoFrame)
    area.setWidgetResizable(True)
    area.setWidget(page)
    return area


class PresentationController(QObject):
    def __init__(self, window):
        super().__init__(window)
        self.window = window
        self.normal = DisplaySettings.load(window._settings())
        self.effective = self.normal
        self.presentation = False
        self._base_style = window.styleSheet()
        self._indicator_width = window.style().pixelMetric(QStyle.PixelMetric.PM_IndicatorWidth)
        self._indicator_height = window.style().pixelMetric(QStyle.PixelMetric.PM_IndicatorHeight)
        self._wheel_remainder = 0
        self._wheel_target = None
        self.panel = DisplaySettingsPanel()
        window.configuration_sections.addTab(scrollable(self.panel), "Display")
        self.panel.preferences_changed.connect(self.set_preferences)
        self.panel.presentation_changed.connect(self.set_presentation)
        self.indicator = QLabel()
        self.indicator.setToolTip("Display-only zoom; FIX bytes are unchanged")
        window.statusBar().addPermanentWidget(self.indicator)
        # The permanent status labels otherwise force a >1920px minimum width
        # at large fonts. Preserve every label in a horizontally scrollable row.
        status_content = QWidget()
        status_layout = QHBoxLayout(status_content)
        status_layout.setContentsMargins(0, 0, 0, 0)
        status_layout.setSpacing(10)
        self._status_labels = window.statusBar().findChildren(
            QLabel, options=Qt.FindChildOption.FindDirectChildrenOnly
        )
        for label in self._status_labels:
            window.statusBar().removeWidget(label)
            status_layout.addWidget(label)
            label.show()
        status_layout.addStretch(1)
        self.status_scroll = scrollable(status_content)
        self.status_scroll.setVerticalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        window.statusBar().addWidget(self.status_scroll, 1)
        self.shortcuts = []
        # Ctrl+= is the unshifted form of Ctrl+Plus on common keyboards.
        for sequence, callback in (
            ("Ctrl++", lambda: self.zoom(1)), ("Ctrl+=", lambda: self.zoom(1)),
            ("Ctrl+-", lambda: self.zoom(-1)), ("Ctrl+0", self.reset_scale),
        ):
            shortcut = QShortcut(QKeySequence(sequence), window)
            shortcut.setContext(Qt.ShortcutContext.WindowShortcut)
            shortcut.activated.connect(callback)
            self.shortcuts.append(shortcut)
        # Wrap existing pages, without rebuilding controls or changing tab indices.
        for tabs in (window.configuration_sections, window.workspace_tabs):
            selected = tabs.currentIndex()
            for index in range(tabs.count()):
                page = tabs.widget(index)
                if isinstance(page, QScrollArea):
                    continue
                title = tabs.tabText(index)
                tabs.removeTab(index)
                tabs.insertTab(index, scrollable(page), title)
            tabs.setCurrentIndex(selected)
        for tabs in window.findChildren(QTabWidget):
            tabs.setUsesScrollButtons(True)
        # Field viewers differ from message-list tables.
        for widget in (window.history_fields, window.history_groups):
            widget.setProperty("displayRole", "message")
        window.history_note.setProperty("displayRole", "interface")
        self._application = QApplication.instance()
        self._application.installEventFilter(self)
        self._installed = True
        self._application.aboutToQuit.connect(self.detach)
        window.destroyed.connect(self.detach)
        self.apply()

    def detach(self) -> None:
        """Remove the global filter before Qt destroys the owning window."""
        if self._installed:
            self._installed = False
            if isValid(self._application):
                self._application.removeEventFilter(self)

    def set_preferences(self, settings: DisplaySettings) -> None:
        if settings == self.effective:
            return
        self.effective = settings
        if not self.presentation:
            self.normal = settings
            self.save()
        self.apply()

    def set_presentation(self, enabled: bool) -> None:
        if self.presentation == enabled:
            return
        self.presentation = enabled
        self.effective = PRESENTATION_PRESET if enabled else self.normal
        self.apply()

    def zoom(self, direction: int) -> None:
        self.set_preferences(self.effective.zoom(direction))

    def reset_scale(self) -> None:
        self.set_preferences(replace(self.effective, interface_scale=100))

    def save(self) -> None:
        # Presentation adjustments are intentionally never persisted.
        self.normal.save(self.window._settings())

    def apply(self) -> None:
        value = self.effective
        factor = value.interface_scale / 100
        style = re.sub(
            r"(\d+(?:\.\d+)?)(px|pt)",
            lambda match: f"{float(match[1]) * factor:g}{match[2]}", self._base_style,
        )
        family = QFontDatabase.systemFont(QFontDatabase.SystemFont.FixedFont).family()
        family = family.replace("'", "\\'")
        table_pt = value.table_font_size * factor
        message_pt = value.message_font_size * factor
        style += f"""
            QCheckBox::indicator, QRadioButton::indicator {{
                width: {self._indicator_width * factor:g}px;
                height: {self._indicator_height * factor:g}px;
            }}
            QTableView, QTableView *, QTreeView, QTreeView *, QListWidget, QListWidget * {{
                font-size: {table_pt:g}pt;
            }}
            QPlainTextEdit, QWidget[displayRole="message"], QWidget[displayRole="message"] * {{
                font-family: '{family}'; font-size: {message_pt:g}pt;
            }}
            QPlainTextEdit[displayRole="interface"] {{ font-size: {10 * factor:g}pt; }}
            QTreeView::item, QListWidget::item {{ padding-top: {2 * factor:g}px; padding-bottom: {2 * factor:g}px; }}
        """
        self.window.setStyleSheet(style)
        for widget in self.window.findChildren(QWidget):
            self._size_content(widget)
        self.panel.show_settings(value, self.presentation)
        self.indicator.setText(f"UI: {value.interface_scale}% | Message font: {message_pt:g} pt")
        self.status_scroll.setFixedHeight(
            max(label.fontMetrics().height() for label in self._status_labels)
            + self.status_scroll.style().pixelMetric(QStyle.PixelMetric.PM_ScrollBarExtent) + 8
        )

    def _size_content(self, widget) -> None:
        factor = self.effective.interface_scale / 100
        if isinstance(widget, QSplitter) and widget.property("stackAtLargeScale"):
            orientation = Qt.Orientation.Vertical if factor >= 1.5 else Qt.Orientation.Horizontal
            if widget.orientation() != orientation:
                widget.setOrientation(orientation)
        if isinstance(widget, QTableView):
            widget.ensurePolished()
            header = widget.verticalHeader()
            if widget.property("displayBaseRow") is None:
                widget.setProperty("displayBaseRow", header.defaultSectionSize())
            height = max(round(widget.property("displayBaseRow") * factor),
                         widget.fontMetrics().height() + round(14 * factor))
            header.setDefaultSectionSize(height)
            header.setMinimumSectionSize(height)
        if isinstance(widget, (QTableView, QTreeView, QListWidget, QPlainTextEdit)):
            if widget.property("displayBaseMinHeight") is None:
                widget.setProperty("displayBaseMinHeight", widget.minimumHeight())
            # Keep a usable viewport inside the scrollable page, even at 200%.
            content_height = widget.fontMetrics().lineSpacing() * 3 + 8
            if isinstance(widget, QTableView):
                content_height = (
                    widget.verticalHeader().defaultSectionSize() * 2
                    + widget.horizontalHeader().sizeHint().height() + 4
                )
            widget.setMinimumHeight(max(round(widget.property("displayBaseMinHeight") * factor),
                                        round(70 * factor), content_height))

    def eventFilter(self, watched, event):  # noqa: N802 - Qt API
        if event.type() not in (QEvent.Type.Show, QEvent.Type.Wheel):
            return False
        if not self._installed or not isValid(self.window) or not isinstance(watched, QWidget):
            return False
        if not self.window.isAncestorOf(watched):
            return False
        if event.type() == QEvent.Type.Show:
            self._size_content(watched)
        elif event.type() == QEvent.Type.Wheel and event.modifiers() & Qt.KeyboardModifier.ControlModifier:
            target = watched
            message = False
            while target is not None and target is not self.window:
                if target.property("displayRole") == "message" or (
                    isinstance(target, QPlainTextEdit) and target.property("displayRole") != "interface"
                ):
                    message = True
                    break
                target = target.parentWidget()
            if self._wheel_target != message:
                self._wheel_remainder = 0
                self._wheel_target = message
            self._wheel_remainder += event.angleDelta().y()
            steps = int(self._wheel_remainder / 120)
            self._wheel_remainder -= steps * 120
            if steps:
                if message:
                    self.set_preferences(replace(
                        self.effective, message_font_size=max(8, min(32, self.effective.message_font_size + steps))
                    ))
                else:
                    self.zoom(steps)
            event.accept()
            return True
        return False
