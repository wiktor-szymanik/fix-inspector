from __future__ import annotations

import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch
import zipfile

from tests import test_display_settings as display_fixture


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class WorkspaceUITests(unittest.TestCase):
    # Reuse the isolated INI/APPDATA fixture, not the display test cases.
    setUp = display_fixture.DisplaySettingsTests.setUp
    _close = display_fixture.DisplaySettingsTests._close
    window = display_fixture.DisplaySettingsTests.window

    @classmethod
    def setUpClass(cls):
        display_fixture.DisplaySettingsTests.setUpClass.__func__(cls)

    def test_navigation_menus_and_existing_settings_are_reachable(self):
        from fixinspector import __version__
        w = self.window()
        self.assertEqual(f"FIX Inspector {__version__}", w.windowTitle())
        self.assertEqual(["Proxy", "Sender", "Composer", "Fuzzer", "Decoder", "Dictionaries"],
                         [w.workspace_tabs.tabText(i) for i in range(w.workspace_tabs.count())])
        self.assertEqual(["Intercept", "History", "Rules", "Settings"],
                         [w.shell.proxy_tabs.tabText(i) for i in range(4)])
        self.assertEqual(["File", "View", "Help"], [a.text() for a in w.menuBar().actions()])
        self.assertEqual(["General", "Display", "Privacy", "Advanced"],
                         [w.shell.settings_tabs.tabText(i) for i in range(4)])
        w.shell.navigate("Rules")
        self.application.processEvents()
        self.assertTrue(w.proxy_behaviour_panel.isVisible())
        w.shell.navigate("Dictionaries")
        self.application.processEvents()
        self.assertTrue(w.transport_dict.isVisible())
        w.shell.settings_button.click()
        w.shell.settings_tabs.setCurrentIndex(1)
        self.application.processEvents()
        self.assertTrue(w.presentation_controller.panel.interface_scale.isVisible())
        w.shell.show_troubleshooting()
        self.application.processEvents()
        self.assertTrue(w.diagnostics_panel.listener.isVisible())

    def test_application_icon_loads_and_main_window_inherits_it(self):
        from fixinspector.app_resources import configure_application_icon

        previous = self.application.windowIcon()
        self.addCleanup(self.application.setWindowIcon, previous)
        configure_application_icon(self.application)
        w = self.window()
        self.assertFalse(self.application.windowIcon().isNull())
        self.assertFalse(w.windowIcon().isNull())
        self.assertEqual(self.application.windowIcon().cacheKey(), w.windowIcon().cacheKey())
        for size in (16, 32, 48, 256):
            self.assertFalse(w.windowIcon().pixmap(size, size).isNull())

    def test_queued_status_uses_ascii_punctuation_in_panels_and_status_bar(self):
        from datetime import datetime, timezone
        from fixinspector.fuzzer import CampaignStatus, CaseStatus, MutationKind, MutationSpec
        from fixinspector.records import TrafficRecord
        from fixinspector.session.injection import InjectionMode, InjectionRequest, InjectionStatus
        from tests.support import fix_message

        w = self.window()
        raw = fix_message("D", 7, [("11", b"TEST-ORDER")])
        request = InjectionRequest(1, InjectionMode.CLONE_EDIT, raw, "COMPOSER", "draft",
                                   None, datetime.now(timezone.utc), InjectionStatus.QUEUED)
        w.composer_panel.apply_event(request)
        self.assertIn("Queued - waiting", w.composer_panel.status.text())
        with patch.object(w.composer_controller, "queue", return_value=request):
            w._proxy_running = True
            try:
                w._queue_composer(raw, "draft")
            finally:
                w._proxy_running = False
        self.assertEqual("Queued - waiting for safe active-session slot", w.status_label.text())
        self.assertIn("\u2014", request.status.value)  # Stored identifiers are unchanged.
        w._on_record(TrafficRecord(71, "C→S", raw, msg_type="D"))
        w._send_to_repeater(71)
        editor = w.repeater_panel.tabs.currentWidget()
        editor.item.update_from_request(request)
        editor.apply_event(request)
        self.assertIn("Queued - waiting", editor.status.text())
        self.assertIn("Queued - waiting", editor.timeline.item(0, 2).text())
        campaign = w.fuzzer_controller.create_campaign("History", "71", raw)
        w.fuzzer_controller.plan(campaign.campaign_id, [MutationSpec(MutationKind.EMPTY, "11")],
                                case_limit=1, interval_seconds=1, outcome_window_seconds=1)
        campaign.status = CampaignStatus.PAUSED_DISCONNECTED
        campaign.cases[0].status = CaseStatus.SKIPPED
        w.fuzzer_panel._show_campaign(campaign)
        self.assertIn("Paused - upstream disconnected", w.fuzzer_panel.status.text())
        self.assertEqual("Skipped - destructive opt-in disabled", w.fuzzer_panel.results.item(0, 3).text())

    def test_legacy_project_and_ini_tab_indices_keep_their_original_meaning(self):
        w = self.window()
        for old_index, route in enumerate(w.shell.LEGACY_ROUTES[:-1]):
            w._restore_project_states({"ui_layout": {"workspace_tab": old_index}})
            self.assertEqual(old_index, w._capture_project_states()["ui_layout"]["workspace_tab"], route)
        w.shell.navigate("Sender")
        w._save_settings()
        self.assertEqual(3, int(self.settings.value("ui/current_tab")))
        second = self.window()
        self.assertEqual("Sender", second.workspace_tabs.tabText(second.workspace_tabs.currentIndex()))

    def test_history_to_repeater_route_works_through_scroll_wrappers(self):
        from fixinspector.records import TrafficRecord
        from tests.support import fix_message
        w = self.window()
        raw = fix_message("D", 7, [("1", b"181852"), ("10001", b"a"), ("10001", b"b")])
        record = TrafficRecord(21, "C→S", raw, msg_type="D", status="FORWARDED")
        w._on_record(record)
        w._send_to_repeater(21)
        self.application.processEvents()
        self.assertEqual("Sender", w.workspace_tabs.tabText(w.workspace_tabs.currentIndex()))
        self.assertTrue(w.repeater_panel.isVisible())
        self.assertEqual(raw, record.raw)
        w._navigate_history_record(21)
        self.application.processEvents()
        self.assertEqual("History", w.shell.proxy_tabs.tabText(w.shell.proxy_tabs.currentIndex()))
        self.assertTrue(w.history.isVisible())

    def test_columns_more_menu_and_empty_states_preserve_models(self):
        from fixinspector.records import TrafficRecord
        from tests.support import fix_message
        w = self.window()
        self.assertFalse(w.shell.history_empty.isHidden())
        self.assertEqual([False, False, False, False, True, True, True],
                         [w.history_fields.isColumnHidden(i) for i in range(7)])
        w.shell.history_tools.column_actions[4].setChecked(True)
        self.assertFalse(w.history_fields.isColumnHidden(4))
        w.shell.history_tools.more_menu.actions()[0].setChecked(True)
        self.assertTrue(w.history_inspector.isTabVisible(3))
        w._on_record(TrafficRecord(22, "C→S", fix_message("D", 8), msg_type="D", status="FORWARDED"))
        self.assertTrue(w.shell.history_empty.isHidden())
        w._save_settings()
        second = self.window()
        self.assertFalse(second.history_fields.isColumnHidden(4))
        w._reset_history_views()
        self.assertFalse(w.shell.history_empty.isHidden())

    def test_validation_inspection_does_not_rewrite_manual_raw_draft(self):
        from fixinspector.session.injection import InjectionMode
        from tests.support import fix_message
        w = self.window()
        editor = w.proxy_shared_editor
        editor.set_raw(fix_message("D", 8))
        editor.set_mode(InjectionMode.CLONE_EDIT)
        editor.tabs.setCurrentIndex(1)
        draft = "8=FIX.4.4␁9=bad␁35=D␁34=1␁10001=a␁10001=b␁10=999␁"
        editor.raw.setPlainText(draft)
        previous = editor._working_raw
        with patch("fixinspector.gui.widgets.message_editor.serialize_structured") as serializer:
            editor.tabs.setCurrentIndex(2)
            serializer.assert_not_called()
        self.assertEqual(previous, editor._working_raw)
        editor.tabs.setCurrentIndex(1)
        self.assertEqual(draft, editor.raw.toPlainText())
        self.assertEqual(draft.replace("␁", "\x01").encode(), editor.outbound_raw(repair_raw=False))

    def test_diagnostics_bundle_and_clipboard_omit_sensitive_sources_even_when_revealed(self):
        from fixinspector.records import TrafficRecord
        from tests.support import fix_message
        w = self.window()
        w._on_record(TrafficRecord(23, "C→S", fix_message("A", 1, [("553", b"TOP-SECRET")]), msg_type="A"))
        w.mask_sensitive_fields.setChecked(False)
        w._apply_secret_policy()
        w.upstream_host.setText("private-endpoint.invalid")
        w.shell.troubleshooting.copy_diagnostics()
        report = self.application.clipboard().text()
        self.assertNotIn("TOP-SECRET", report)
        self.assertNotIn("private-endpoint", report)
        self.assertNotIn("553", report)
        self.assertEqual(1, json.loads(report)["capture"]["live_records"])
        bundle = self.directory / "diagnostics.zip"
        w.shell.troubleshooting.write_bundle(bundle)
        with zipfile.ZipFile(bundle) as archive:
            self.assertEqual(["diagnostics.json"], archive.namelist())
            self.assertEqual(json.loads(report), json.loads(archive.read("diagnostics.json")))

    def test_presentation_menu_syncs_and_does_not_persist_temporary_values(self):
        from fixinspector.gui.settings.display import DisplaySettings
        w = self.window()
        w.shell.presentation_action.setChecked(True)
        self.assertTrue(w.presentation_controller.presentation)
        w.presentation_controller.panel.presentation.setChecked(False)
        w.shell.refresh()
        self.assertFalse(w.shell.presentation_action.isChecked())
        self.assertEqual(DisplaySettings(), w.presentation_controller.normal)
        self.assertTrue(w.presentation_controller.indicator.isHidden())

    def test_moved_proxy_controls_keep_the_same_start_stop_bindings(self):
        w = self.window()
        w.shell.navigate("Settings")
        w.upstream_host.setText("127.0.0.1")
        w.upstream_transport.setCurrentIndex(w.upstream_transport.findData("plain_tcp"))
        with patch.object(w.engine, "start") as start, patch.object(w.engine, "stop") as stop:
            w.start_button.click()
            self.assertEqual("plain_tcp", start.call_args.args[0].upstream_transport)
            self.assertTrue(w.stop_button.isEnabled())
            w.stop_button.click()
            stop.assert_called_once()
            self.assertTrue(w.start_button.isEnabled())

    def test_dictionary_loading_and_saved_optional_inspector_page_remain_reachable(self):
        w = self.window()
        fixtures = Path(__file__).parent / "fixtures"
        w.transport_dict.setText(str(fixtures / "FIXT11_MINIMAL.xml"))
        w.app_dict.setText(str(fixtures / "FIX50_MINIMAL.xml"))
        w._load_dictionaries()
        self.assertGreater(len(w.dictionary.fields_by_tag), 0)
        self.assertGreater(w.dictionary_browser.fields.rowCount(), 0)
        w._restore_project_states({"ui_layout": {"workspace_tab": 1, "inspector_tab": 6}})
        self.assertTrue(w.history_inspector.isTabVisible(6))
        self.assertEqual(6, w.history_inspector.currentIndex())
        self.assertTrue(w.shell.history_tools.extra_actions[6].isChecked())

    def test_clear_history_ui_requires_confirmation_without_changing_clear_contract(self):
        from PySide6.QtWidgets import QMessageBox
        from fixinspector.records import TrafficRecord
        from tests.support import fix_message
        w = self.window()
        w._on_record(TrafficRecord(24, "C→S", fix_message("D", 1), msg_type="D"))
        with patch("fixinspector.gui.workspace.QMessageBox.question", return_value=QMessageBox.StandardButton.Cancel):
            w.shell.confirm_clear_history()
        self.assertIn(24, w.records)
        with patch("fixinspector.gui.workspace.QMessageBox.question", return_value=QMessageBox.StandardButton.Yes):
            w.shell.confirm_clear_history()
        self.assertEqual({}, w.records)

    def test_blue_theme_and_screens_at_desktop_sizes_and_scaling(self):
        from PySide6.QtCore import QPoint, QRect
        from fixinspector.gui.settings.display import DisplaySettings
        w = self.window()
        self.assertNotIn("#e8891b", w.styleSheet())
        self.assertIn("#2563a6", w.styleSheet())
        output = os.environ.get("FIX_INSPECTOR_UI_QA")
        for scale, width, height in ((100, 1800, 960), (150, 1800, 960), (200, 1800, 960), (100, 2400, 1320)):
            w.presentation_controller.set_preferences(DisplaySettings(scale, 10, 10))
            w.resize(width, height)
            for route in ("Intercept", "History", "Sender", "Composer", "Fuzzer", "Decoder", "Dictionaries", "Settings"):
                w.shell.navigate(route)
                self.application.processEvents()
                self.assertLessEqual(w.width(), width)
                self.assertLessEqual(w.height(), height)
                self.assertTrue(w.workspace_tabs.isVisible())
                self.assertTrue(w.shell.settings_button.isVisible())
                primary = w.forward_button if route == "Intercept" else w.fuzzer_panel.start if route == "Fuzzer" else None
                if primary is not None:
                    self.assertTrue(w.rect().contains(QRect(primary.mapTo(w, QPoint()), primary.size())), route)
                if output and (scale in (100, 200)) and width == 1800:
                    self.assertTrue(w.grab().save(str(Path(output) / f"{route.lower()}-{scale}.png")))
        if output:
            from fixinspector.records import TrafficRecord
            from fixinspector.session.injection import InjectionMode
            from tests.support import fix_message
            w.resize(1800, 960)
            w._on_record(TrafficRecord(25, "C→S", fix_message("D", 12, [("11", b"DEMO-001"), ("1", b"181852")]), msg_type="D", status="FORWARDED", sequence_number=12))
            w._send_to_repeater(25)
            editor = next(iter(w.repeater_panel._editors.values()))
            editor.mode.setCurrentIndex(editor.mode.findData(InjectionMode.CLONE_EDIT.name))
            self.application.processEvents()
            w.grab().save(str(Path(output) / "repeater-loaded.png"))
            w._navigate_history_record(25)
            self.application.processEvents()
            w.grab().save(str(Path(output) / "history-loaded.png"))
            w.shell.show_settings()
            w.shell.settings_tabs.setCurrentIndex(1)
            self.application.processEvents()
            w.shell.settings.grab().save(str(Path(output) / "global-settings.png"))
            w.shell.settings.close()
            w.shell.show_troubleshooting()
            self.application.processEvents()
            w.shell.troubleshooting.grab().save(str(Path(output) / "troubleshooting.png"))
