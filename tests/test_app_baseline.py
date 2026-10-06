from __future__ import annotations

import importlib.util
import os
import tempfile
import unittest
from unittest.mock import patch
from datetime import datetime, timezone
from pathlib import Path


class ApplicationBaselineTests(unittest.TestCase):
    def test_application_entry_module_imports_without_qt(self) -> None:
        from fixinspector import app

        self.assertTrue(callable(app.main))

    def test_headless_application_self_test(self) -> None:
        from fixinspector import app

        with patch.object(app.sys, "argv", ["fix-inspector", "--self-test"]):
            self.assertEqual(0, app.main())

    @unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
    def test_preserved_main_window_opens_offscreen_with_secrets_hidden(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            os.environ["APPDATA"] = temp_dir
            from PySide6.QtWidgets import QAbstractItemView, QApplication

            from fixinspector.gui.main_window import MainWindow

            application = QApplication.instance() or QApplication([])
            window = MainWindow()
            labels = [window.workspace_tabs.tabText(index) for index in range(window.workspace_tabs.count())]

            self.assertEqual(
                [
                    "Proxy",
                    "Sender",
                    "Composer",
                    "Fuzzer",
                    "Decoder",
                    "Dictionaries",
                ],
                labels,
            )
            self.assertTrue(window.mask_sensitive_fields.isChecked())
            self.assertFalse(window._reveal_state())
            expected_tls_text = "verification enabled" if window.verify_tls.isChecked() else "DISABLED"
            self.assertIn(expected_tls_text, window.tls_warning.text())
            self.assertEqual("Held 0 / queued 0", window.queue_state_label.text())
            self.assertEqual(
                QAbstractItemView.SelectionBehavior.SelectItems,
                window.history.selectionBehavior(),
            )
            self.assertEqual(
                QAbstractItemView.SelectionMode.ExtendedSelection,
                window.history.selectionMode(),
            )
            self.assertEqual("Stopped", window.diagnostics_panel.listener.text())
            self.assertEqual(
                ["General"],
                [
                    window.configuration_sections.tabText(index)
                    for index in range(window.configuration_sections.count())
                ],
            )
            self.assertIn("Client → Server NORMAL", window.proxy_behaviour_status.text())
            self.assertEqual(
                ["Parsed", "Raw", "Validation", "Groups", "Diff", "Related", "Notes"],
                [
                    window.history_inspector.tabText(index)
                    for index in range(window.history_inspector.count())
                ],
            )
            self.assertIn("553", window.secret_policy.secret_tags)
            self.assertEqual("★", window.history.horizontalHeaderItem(10).text())
            self.assertEqual("Direction", window.history.horizontalHeaderItem(2).text())
            self.assertTrue(window.hide_heartbeats.isCheckable())
            self.assertEqual("Hide other session/admin", window.hide_admin.text())
            self.assertTrue(window.advanced_filter.isCheckable())
            window.close()
            application.processEvents()

    @unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
    def test_common_table_copy_places_selected_cell_on_clipboard(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication, QTableWidget, QTableWidgetItem

        from fixinspector.gui.widgets import TableCopySupport

        application = QApplication.instance() or QApplication([])
        table = QTableWidget(1, 1)
        table.setItem(0, 0, QTableWidgetItem("copy-me"))
        table.item(0, 0).setSelected(True)

        TableCopySupport.copy_selected_cells(table)

        self.assertEqual("copy-me", application.clipboard().text())

    @unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
    def test_window_project_round_trip_restores_annotations_filter_and_redacts(self) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            os.environ["APPDATA"] = temp_dir
            from PySide6.QtWidgets import QApplication

            from fixinspector.gui.main_window import MainWindow
            from fixinspector.records import TrafficRecord
            from tests.support import fix_message

            application = QApplication.instance() or QApplication([])
            window = MainWindow()
            record = TrafficRecord(
                17,
                "C→S",
                fix_message("A", 1, [("553", b"window-project-secret")]),
                datetime.now(timezone.utc),
                status="FORWARDED",
                msg_type="A",
                sequence_number=1,
                bookmarked=True,
                note="analyst 553=note-secret",
            )
            window._on_record(record)
            window.filter_edit.setText("msgtype=A")
            window.advanced_filter.setChecked(True)
            window.engine.proxy_behaviour.add_rule(
                name="stored disabled",
                direction="S→C",
                msg_type="8",
                action="DROP",
                enabled=True,
            )
            project_path = Path(temp_dir) / "roundtrip.fixproj"
            window._attach_project(project_path, load=False)
            from fixinspector import __version__
            self.assertIn(__version__, window.windowTitle())
            window._close_project()
            self.assertEqual(f"FIX Inspector {__version__}", window.windowTitle())
            window._reset_history_views()
            window._attach_project(project_path, load=True)
            self.assertIn(__version__, window.windowTitle())

            loaded = window.records[17]
            self.assertTrue(loaded.bookmarked)
            self.assertEqual("analyst 553=<REDACTED>", loaded.note)
            self.assertEqual("msgtype=A", window.filter_edit.text())
            self.assertTrue(window.advanced_filter.isChecked())
            self.assertEqual(1, len(window.engine.proxy_behaviour.rules()))
            self.assertFalse(window.engine.proxy_behaviour.rules()[0].enabled)
            self.assertNotIn(b"window-project-secret", project_path.read_bytes())
            window.close()
            application.processEvents()


if __name__ == "__main__":
    unittest.main()
