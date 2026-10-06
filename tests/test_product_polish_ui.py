import importlib.util
import json
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import test_display_settings as fixture
from tests.support import fix_message, body_length_ok


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class ProductPolishTests(unittest.TestCase):
    setUp = fixture.DisplaySettingsTests.setUp
    _close = fixture.DisplaySettingsTests._close
    window = fixture.DisplaySettingsTests.window

    @classmethod
    def setUpClass(cls):
        fixture.DisplaySettingsTests.setUpClass.__func__(cls)

    def repeater(self, w, *, kind="D", secret=False):
        from fixinspector.records import TrafficRecord
        fields = [("1", b"181852"), ("11", b"ui-order"), ("10001", b"a"), ("10001", b"b")]
        if secret:
            fields.append(("553", b"ui-private-key"))
        record = TrafficRecord(21, "C→S", fix_message(kind, 7, fields), msg_type=kind)
        w._on_record(record)
        w._send_to_repeater(21)
        return w.repeater_panel.tabs.currentWidget()

    def test_modes_map_existing_policies_without_modal_on_selection(self):
        from fixinspector.session.injection import AutoUpdatePolicy, InjectionMode, build_safe_injection
        from fixinspector.fix.parser import parse_message, raw_to_editor_text
        from fixinspector.fix.checksum import checksum_ok
        from PySide6.QtWidgets import QMessageBox
        w = self.window()
        editor = self.repeater(w)
        with patch.object(QMessageBox, "warning") as warning, patch.object(QMessageBox, "critical") as critical:
            editor.session_fields.setCurrentText("Framing only")
            self.assertEqual(AutoUpdatePolicy(True, False, False, True), editor.auto_update_policy())
            self.assertEqual(InjectionMode.CLONE_EDIT, editor.current_mode())
            raw = editor.editor.outbound_raw()
            effective = build_safe_injection(raw, fix_message("0", 90), auto_update=editor.auto_update_policy())
            self.assertEqual(parse_message(raw).values("34"), parse_message(effective).values("34"))
            self.assertEqual(parse_message(raw).values("52"), parse_message(effective).values("52"))
            self.assertTrue(body_length_ok(effective))
            self.assertTrue(checksum_ok(effective))
            editor.session_fields.setCurrentText("Manual")
            self.assertEqual(InjectionMode.EXACT_RAW, editor.current_mode())
            manual = "8=FIX.4.4|9=1|35=D|34=1|43=Y|52=OLD|122=OLD|10=000|"
            editor.editor.raw.setPlainText(raw_to_editor_text(manual.replace("|", "\x01").encode()))
            self.assertEqual(manual.replace("|", "\x01").encode(), editor.editor.outbound_raw(repair_raw=False))
            editor.session_fields.setCurrentText("Managed")
            self.assertTrue(editor.auto_update_policy().is_session_aware)
            effective = build_safe_injection(editor.editor.outbound_raw(), fix_message("0", 90))
            self.assertEqual(b"90", parse_message(effective).first("34"))
            warning.assert_not_called()
            critical.assert_not_called()

    def test_send_shortcut_scoped_to_repeater_uses_existing_action(self):
        w = self.window()
        editor = self.repeater(w)
        with patch.object(editor, "_queue") as queue:
            # Existing clicked binding is not replaced; intercept at button.
            with patch.object(editor.queue_button, "click") as click:
                w.product_presentation.send_repeater()
                click.assert_called_once()
                w._navigate("History")
                w.product_presentation.send_repeater()
                self.assertEqual(1, click.call_count)

    def test_send_emits_selected_policy_and_manual_still_requires_ack(self):
        from PySide6.QtTest import QSignalSpy
        from PySide6.QtWidgets import QMessageBox
        from fixinspector.session.injection import AutoUpdatePolicy, InjectionMode
        w = self.window()
        editor = self.repeater(w)
        w.repeater_panel.queue_requested.disconnect()  # assert the request, never open a connection
        spy = QSignalSpy(editor.queue_requested)
        editor.session_fields.setCurrentText("Framing only")
        editor._queue()
        self.assertEqual(1, spy.count())
        self.assertEqual(AutoUpdatePolicy(True, False, False, True), spy.at(0)[3])
        editor.session_fields.setCurrentText("Manual")
        with patch.object(QMessageBox, "warning") as warning:
            editor._queue()
            warning.assert_called_once()
        self.assertEqual(1, spy.count())
        editor.destructive_ack.setChecked(True)
        editor._queue()
        self.assertEqual(InjectionMode.EXACT_RAW, spy.at(1)[2])
        self.assertTrue(spy.at(1)[3].is_raw_manual)

    def test_global_privacy_and_analysis_redaction(self):
        w = self.window()
        editor = self.repeater(w, kind="A", secret=True)
        edited = editor.item.original_raw.replace(b"ui-private-key", b"different-key")
        editor._refresh_analysis(edited)
        self.assertNotIn("private-key", editor.diff.toPlainText())
        self.assertNotIn("different-key", editor.diff.toPlainText())
        editor.editor.set_raw(edited)
        w.mask_sensitive_fields.setChecked(False)
        w._apply_secret_policy()
        self.assertIn("different-key", editor.diff.toPlainText())
        w.mask_sensitive_fields.setChecked(True)
        w._apply_secret_policy()
        self.assertNotIn("different-key", editor.diff.toPlainText())

    def test_decoder_masks_input_and_redecode_preserves_original_bytes(self):
        w = self.window()
        decoder = w.decoder_panel
        raw = fix_message("A", 1, [("553", b"ui-private-key")])
        decoder.input.setPlainText(raw.decode().replace("\x01", "|"))
        decoder.decode()
        self.assertNotIn("ui-private-key", decoder.input.toPlainText())
        decoder.decode()
        self.assertEqual(raw, decoder._frames[0].raw)
        w.mask_sensitive_fields.setChecked(False)
        w._apply_secret_policy()
        self.assertIn("ui-private-key", decoder.input.toPlainText())
        w.mask_sensitive_fields.setChecked(True)
        w._apply_secret_policy()
        self.assertNotIn("ui-private-key", decoder.raw.toPlainText())
        self.assertEqual(raw, decoder._frames[0].raw)

    def test_dictionary_load_replace_remove_and_inline_error(self):
        from PySide6.QtWidgets import QMessageBox
        w = self.window()
        directory = Path(__file__).parent / "fixtures"
        w.transport_dict.setText(str(directory / "FIXT11_MINIMAL.xml"))
        w.app_dict.setText(str(directory / "FIX50_MINIMAL.xml"))
        self.assertTrue(w._load_dictionaries())
        management = w.product_presentation.dictionaries
        self.assertEqual(["Loaded", "Loaded"], [state.text() for state in management.states])
        self.assertIn("repeating groups", w.dictionary_browser.summary.text())
        original = w.dictionary
        w.app_dict.setText(str(directory / "missing.xml"))
        with patch.object(QMessageBox, "critical") as critical:
            self.assertFalse(w._load_dictionaries())
            critical.assert_not_called()
        self.assertIs(original, w.dictionary)
        self.assertIn("not loaded", w.dictionary_state.text())
        w.app_dict.setText(str(directory / "FIX50_MINIMAL.xml"))
        management.remove(w.app_dict)
        self.assertFalse(w.app_dict.text())
        management.remove(w.transport_dict)
        self.assertFalse(w.dictionary.fields_by_tag)
        self.assertIn("forwarding remains available", w.dictionary_state.text())

    def test_fuzzer_result_view_and_transfer_are_read_only_drafts(self):
        from fixinspector.fuzzer import MutationKind, MutationSpec
        w = self.window()
        raw = fix_message("D", 1, [("11", b"order"), ("553", b"ui-private-key")])
        campaign = w.fuzzer_controller.create_campaign("History", "1", raw, "UI baseline")
        w.fuzzer_controller.plan(campaign.campaign_id, [MutationSpec(MutationKind.EMPTY, "11")],
                                case_limit=1, interval_seconds=1, outcome_window_seconds=1)
        w.fuzzer_panel.add_campaign(campaign)
        w.fuzzer_panel.results.setCurrentCell(0, 0)
        w.fuzzer_panel._show_result()
        self.assertEqual(campaign.cases[0].raw, w.fuzzer_panel.result_view._working_raw)
        self.assertNotIn("ui-private-key", w.fuzzer_panel.result_view.raw.toPlainText())
        before = len(w.records)
        w._send_result_to_tool("Sender", campaign.cases[0].raw, "Case 1")
        state = w.repeater_controller.to_state(lambda value: value)
        w.repeater_controller.restore_state(state)
        self.assertEqual(1, len(w.repeater_controller.items()))
        self.assertEqual(before, len(w.records))
        w._send_result_to_tool("Decoder", campaign.cases[0].raw, "Case 1")
        self.assertNotIn("ui-private-key", w.decoder_panel.input.toPlainText())

    def test_custom_field_policy_roundtrip_and_logon_controls(self):
        w = self.window()
        editor = self.repeater(w, kind="A")
        editor._set_session_aware()
        editor.auto_checksum.setChecked(False)
        self.assertEqual("Custom", editor.session_fields.currentText())
        editor.advanced_session.toggle.setChecked(True)
        self.assertFalse(editor.auto_checksum.isHidden())
        editor.item.auto_update = editor.auto_update_policy()
        state = w.repeater_controller.to_state(lambda raw: raw)
        w.repeater_controller.restore_state(state)
        self.assertFalse(w.repeater_controller.items()[0].auto_update.checksum)
        self.assertFalse(editor.new_connection.isHidden())

    def test_additional_secret_policy_refreshes_open_views(self):
        w = self.window()
        editor = self.repeater(w)
        w.decoder_panel.input.setPlainText(editor.item.original_raw.decode().replace("\x01", "|"))
        w.decoder_panel.decode()
        self.assertIn("181852", editor.editor.raw.toPlainText())
        w.additional_secret_tags.setText("1")
        w._apply_secret_policy()
        self.assertNotIn("181852", editor.editor.raw.toPlainText())
        self.assertNotIn("181852", editor.identity.text())
        self.assertNotIn("181852", w.decoder_panel.input.toPlainText())
        self.assertIn(b"181852", editor.item.original_raw)

    def test_search_shortcut_and_about_metadata(self):
        from PySide6.QtWidgets import QMessageBox
        w = self.window()
        for route, control in (("History", w.proxy_workspace.filters.search),
                               ("Composer", w.composer_panel.search), ("Dictionaries", w.dictionary_browser.search)):
            w._navigate(route)
            w.product_presentation.search()
            self.application.processEvents()
            self.assertTrue(control.hasFocus())
        with patch.object(QMessageBox, "about") as about:
            w.shell.show_about()
            self.assertIn("Security testing and inspection toolkit for FIX protocol traffic.", about.call_args.args[2])

    def test_final_screens_at_scales_and_presentation_mode(self):
        from fixinspector.gui.settings.display import DisplaySettings
        w = self.window()
        editor = self.repeater(w)
        editor._set_session_aware()
        directory = Path(__file__).parent / "fixtures"
        w.transport_dict.setText(str(directory / "FIX_COMPOSER.xml"))
        self.assertTrue(w._load_dictionaries())
        w.composer_panel._select_msg_type("D")
        w.decoder_panel.input.setPlainText(fix_message("D", 1).decode().replace("\x01", "|"))
        w.decoder_panel.decode()
        root = os.environ.get("FIX_INSPECTOR_UI_QA")
        for scale in (100, 150):
            w.presentation_controller.set_preferences(DisplaySettings(scale, 10, 10))
            for route in ("Sender", "Composer", "Fuzzer", "Decoder", "Dictionaries"):
                w._navigate(route)
                self.application.processEvents()
                self.assertLessEqual(w.width(), 1920)
                if root:
                    Path(root).mkdir(parents=True, exist_ok=True)
                    w.grab().save(str(Path(root) / f"phase3-{route.lower()}-{scale}.png"))
        w.presentation_controller.set_presentation(True)
        self.assertTrue(w.presentation_controller.presentation)
        w.presentation_controller.set_presentation(False)
        self.assertEqual(150, w.presentation_controller.effective.interface_scale)


if __name__ == "__main__":
    unittest.main()
