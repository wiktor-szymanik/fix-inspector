from __future__ import annotations

from contextlib import ExitStack
from dataclasses import replace
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class DisplaySettingsTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication
        cls.application = QApplication.instance() or QApplication([])
        # Qt's offscreen plugin on Windows has an empty font database. Load only
        # already-installed Windows fonts into this test process for visual QA.
        from PySide6.QtGui import QFont, QFontDatabase
        if os.name == "nt" and not QFontDatabase.families():
            fonts = Path(os.environ.get("WINDIR", "C:/Windows")) / "Fonts"
            for name in ("segoeui.ttf", "segoeuib.ttf", "consola.ttf", "seguisym.ttf"):
                QFontDatabase.addApplicationFont(str(fonts / name))
            cls.application.setFont(QFont("Segoe UI", 10))

    def setUp(self):
        from PySide6.QtCore import QSettings
        from fixinspector.gui import main_window
        self.stack = ExitStack()
        self.addCleanup(self.stack.close)
        self.directory = Path(self.stack.enter_context(tempfile.TemporaryDirectory(dir=Path.cwd())))
        self.settings = QSettings(str(self.directory / "display.ini"), QSettings.Format.IniFormat)
        self.stack.enter_context(patch.object(main_window.MainWindow, "_settings", return_value=self.settings))
        self.stack.enter_context(patch.object(main_window._v03_gui.QStandardPaths, "writableLocation", return_value=str(self.directory)))
        self.stack.enter_context(patch.object(main_window, "configure_logging", return_value=None))
        self.windows = []
        self.addCleanup(self._close)

    def _close(self):
        for window in self.windows:
            window.close()
            window.deleteLater()
        self.application.processEvents()

    def window(self):
        from fixinspector.gui.main_window import MainWindow
        window = MainWindow()
        self.windows.append(window)
        window.resize(1800, 960)
        window.show()
        self.application.processEvents()
        return window

    def test_defaults_and_invalid_saved_values_fall_back_to_existing_sizes(self):
        from fixinspector.gui.settings.display import DisplaySettings
        self.assertEqual(DisplaySettings(100, 10, 10), DisplaySettings.load(self.settings))
        for key, value in (("interface_scale", 123), ("message_font_size", "bad"), ("table_font_size", 100)):
            self.settings.setValue(f"display/{key}", value)
        window = self.window()
        self.assertEqual(DisplaySettings(), window.presentation_controller.normal)
        self.assertEqual(10, window.history.font().pointSizeF())
        self.assertEqual(10, window.history_raw.font().pointSizeF())

    def test_message_fonts_update_without_content_changes_or_serializer_calls(self):
        from PySide6.QtTest import QSignalSpy
        from fixinspector.gui.widgets.message_editor import MessageEditorWidget
        from fixinspector.session.injection import InjectionMode
        from tests.support import fix_message
        window = self.window()
        editor = window.findChildren(MessageEditorWidget)[0]
        raw = fix_message("A", 7, [("553", b"hidden-secret"), ("10001", b"one"), ("10001", b"two")])
        editor.set_raw(raw)
        editor.set_mode(InjectionMode.CLONE_EDIT)
        before_raw = editor.raw.toPlainText()
        before_fields = [[editor.fields.item(row, col).text() for col in range(4)] for row in range(editor.fields.rowCount())]
        spy = QSignalSpy(editor.raw.textChanged)
        with patch("fixinspector.gui.widgets.message_editor.serialize_structured") as serializer:
            window.presentation_controller.panel.message_font_size.setValue(20)
            self.application.processEvents()
            serializer.assert_not_called()
        self.assertEqual(20, editor.raw.font().pointSizeF())
        self.assertEqual(20, editor.fields.font().pointSizeF())
        self.assertEqual(0, spy.count())
        self.assertEqual(raw, editor._working_raw)
        self.assertEqual(before_raw, editor.raw.toPlainText())
        self.assertNotIn("hidden-secret", before_raw)
        self.assertEqual(before_fields, [[editor.fields.item(row, col).text() for col in range(4)] for row in range(editor.fields.rowCount())])

    def test_history_font_rows_selection_columns_and_records_preserved(self):
        from fixinspector.records import TrafficRecord
        from tests.support import fix_message
        window = self.window()
        raw = fix_message("D", 8, [("11", b"display-test")])
        window._on_record(TrafficRecord(700, "C→S", raw, msg_type="D"))
        window.history.setColumnWidth(4, 231)
        window.history.setCurrentCell(0, 4)
        original_height = window.history.rowHeight(0)
        window.presentation_controller.panel.table_font_size.setValue(16)
        self.application.processEvents()
        self.assertEqual(16, window.history.font().pointSizeF())
        self.assertEqual(16, window.history.horizontalHeader().font().pointSizeF())
        self.assertGreater(window.history.rowHeight(0), original_height)
        self.assertGreater(window.history.rowHeight(0), window.history.fontMetrics().height())
        self.assertEqual(231, window.history.columnWidth(4))
        self.assertEqual((0, 4), (window.history.currentRow(), window.history.currentColumn()))
        self.assertEqual(raw, window.records[700].raw)
        self.assertEqual(1, window.history.rowCount())

    def test_presentation_restores_normal_values_and_never_persists_preset(self):
        from fixinspector.gui.settings.display import DisplaySettings, PRESENTATION_PRESET
        window = self.window()
        controller = window.presentation_controller
        normal = DisplaySettings(110, 13, 11)
        controller.set_preferences(normal)
        controller.panel.presentation.setChecked(True)
        self.assertEqual(PRESENTATION_PRESET, controller.effective)
        controller.zoom(1)
        self.assertEqual(normal, DisplaySettings.load(self.settings))
        controller.panel.presentation.setChecked(False)
        self.assertEqual(normal, controller.effective)
        controller.set_presentation(True)
        window._save_settings()
        restored = self.window().presentation_controller
        self.assertEqual(normal, restored.effective)
        self.assertFalse(restored.presentation)

    def test_shortcuts_and_wheel_are_display_only(self):
        from PySide6.QtCore import QPoint, QPointF, Qt
        from PySide6.QtGui import QWheelEvent
        from PySide6.QtTest import QTest
        window = self.window()
        window.activateWindow()
        window.history_raw.setPlainText("8=FIX.4.4␁9=bad␁35=A␁10=999␁")
        self.application.processEvents()
        QTest.keyClick(window, Qt.Key.Key_Equal, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(110, window.presentation_controller.effective.interface_scale)
        QTest.keyClick(window, Qt.Key.Key_Minus, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(100, window.presentation_controller.effective.interface_scale)
        QTest.keyClick(window, Qt.Key.Key_Plus, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(110, window.presentation_controller.effective.interface_scale)
        QTest.keyClick(window, Qt.Key.Key_0, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(100, window.presentation_controller.effective.interface_scale)
        wheel = QWheelEvent(QPointF(5, 5), QPointF(5, 5), QPoint(), QPoint(0, 120),
                            Qt.MouseButton.NoButton, Qt.KeyboardModifier.ControlModifier,
                            Qt.ScrollPhase.NoScrollPhase, False)
        self.application.sendEvent(window.history_raw.viewport(), wheel)
        self.assertEqual(11, window.presentation_controller.effective.message_font_size)
        self.assertEqual("8=FIX.4.4␁9=bad␁35=A␁10=999␁", window.history_raw.toPlainText())
        controller = window.presentation_controller
        for _ in range(10):
            controller.zoom(1)
        self.assertEqual(200, controller.effective.interface_scale)
        for _ in range(10):
            controller.zoom(-1)
        self.assertEqual(100, controller.effective.interface_scale)

    def test_late_created_field_table_and_dialog_inherit_current_scale(self):
        from PySide6.QtWidgets import QInputDialog, QTableWidget
        window = self.window()
        controller = window.presentation_controller
        controller.set_preferences(replace(controller.normal, interface_scale=150, message_font_size=20))
        table = QTableWidget(2, 2, window)
        table.setProperty("displayRole", "message")
        table.show()
        dialog = QInputDialog(window)
        dialog.setLabelText("New field value")
        dialog.show()
        self.application.processEvents()
        self.assertEqual(30, table.font().pointSizeF())
        self.assertGreater(table.rowHeight(0), table.fontMetrics().height())
        self.assertEqual(15, dialog.font().pointSizeF())
        dialog.close()
        table.close()

    def test_uncommitted_raw_draft_cursor_and_existing_copy_shortcut_survive_zoom(self):
        from PySide6.QtCore import Qt
        from PySide6.QtGui import QTextCursor
        from PySide6.QtTest import QTest
        window = self.window()
        editor = window.proxy_shared_editor
        window.intercept_editor_tabs.setCurrentWidget(editor)
        editor.tabs.setCurrentIndex(1)
        draft = "8=FIXT.1.1␁9=wrong␁35=D␁10001=one␁10001=two␁10=999␁"
        editor.raw.setReadOnly(False)
        editor.raw.setPlainText(draft)
        editor.raw.setFocus()
        cursor = editor.raw.textCursor()
        cursor.setPosition(2)
        cursor.setPosition(10, QTextCursor.MoveMode.KeepAnchor)
        editor.raw.setTextCursor(cursor)
        window.presentation_controller.zoom(1)
        self.application.processEvents()
        self.assertEqual(draft, editor.raw.toPlainText())
        self.assertEqual((2, 10), (editor.raw.textCursor().anchor(), editor.raw.textCursor().position()))
        self.assertEqual("", editor._working_raw.decode())
        QTest.keyClick(editor.raw, Qt.Key.Key_C, Qt.KeyboardModifier.ControlModifier)
        self.assertEqual(draft[2:10], self.application.clipboard().text())

    def test_close_removes_global_event_filter(self):
        window = self.window()
        self.assertTrue(window.presentation_controller._installed)
        window.close()
        self.assertFalse(window.presentation_controller._installed)

    def test_layout_at_100_150_200_stays_within_1080p_and_settings_scroll(self):
        from PySide6.QtWidgets import QScrollArea
        window = self.window()
        window.shell.navigate("Settings")
        for scale in (100, 150, 200):
            with self.subTest(scale=scale):
                controller = window.presentation_controller
                controller.set_preferences(replace(controller.normal, interface_scale=scale))
                window.resize(1800, 960)
                self.application.processEvents()
                self.assertLessEqual(window.width(), 1920)
                self.assertLessEqual(window.height(), 1080)
                self.assertEqual(10 * scale / 100, window.start_button.font().pointSizeF())
                area = window.configuration_sections.widget(0)
                self.assertIsInstance(area, QScrollArea)
                self.assertTrue(window.workspace_tabs.usesScrollButtons())
                if scale == 200:
                    self.assertGreater(area.verticalScrollBar().maximum(), 0)
                output = os.environ.get("FIX_INSPECTOR_DISPLAY_QA")
                if output:
                    self.assertTrue(window.grab().save(str(Path(output) / f"display-{scale}.png")))
