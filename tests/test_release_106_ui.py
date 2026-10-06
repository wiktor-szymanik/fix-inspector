"""Sender naming, single Fuzzer opt-in, and global presentation-only privacy."""
import importlib.util
import unittest
from unittest.mock import patch

from tests import test_display_settings as fixture
from tests.support import fix_message


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class Release106Tests(unittest.TestCase):
    setUp = fixture.DisplaySettingsTests.setUp
    _close = fixture.DisplaySettingsTests._close
    window = fixture.DisplaySettingsTests.window

    @classmethod
    def setUpClass(cls):
        fixture.DisplaySettingsTests.setUpClass.__func__(cls)

    def load_message(self, window, *, held=False):
        from fixinspector.records import TrafficRecord
        raw = fix_message("D", 7, [("553", b"synthetic-private"), ("1", b"account-test"),
                                   ("10001", b"one"), ("10001", b"two")])
        record = TrafficRecord(21, "C→S", raw, msg_type="D", source="REPEATER",
                               status="HELD" if held else "FORWARDED")
        window._on_record(record)
        window._send_to_repeater(21)
        return record, window.repeater_panel.tabs.currentWidget()

    def apply(self, window, *, mask=True, tags=""):
        window.mask_sensitive_fields.setChecked(mask)
        window.additional_secret_tags.setText(tags)
        window._apply_secret_policy()

    def test_sender_navigation_transfer_and_old_project_keys(self):
        from fixinspector import __version__
        w = self.window()
        record, item = self.load_message(w)
        self.assertEqual("1.0.6", __version__)
        self.assertIn(__version__, w.windowTitle())
        self.assertEqual("Sender", w.workspace_tabs.tabText(w.workspace_tabs.currentIndex()))
        self.assertEqual(record.raw, item.item.original_raw)
        self.assertIn("Open in Sender", [action[0] for action in w._history_context_actions(record)])
        self.assertEqual("REPEATER", record.source)
        self.assertIn("SENDER", w._record_summary(record))
        filters = w.proxy_workspace.filters
        filters.source.setCurrentText("Sender")
        w._run_history_filter()
        self.assertFalse(w.history.isRowHidden(w.history_row_for_record[record.record_id]))
        saved = w._capture_project_states()
        self.assertIn("repeater", saved)
        self.assertNotIn("sender", saved)
        w._restore_project_states(saved)
        self.assertEqual(item.item.item_id, w.repeater_controller.items()[0].item_id)
        self.assertEqual("Sender", w.workspace_tabs.tabText(w.workspace_tabs.currentIndex()))

    def test_default_mask_and_no_operational_reveal_controls(self):
        from PySide6.QtWidgets import QCheckBox, QPushButton, QToolButton
        w = self.window()
        _, item = self.load_message(w)
        self.assertTrue(w.mask_sensitive_fields.isChecked())
        self.assertEqual(frozenset({"553"}), w.secret_policy.secret_tags)
        self.assertNotIn("synthetic-private", item.editor.raw.toPlainText())
        for widget_type in (QCheckBox, QPushButton, QToolButton):
            for control in w.findChildren(widget_type):
                self.assertNotIn("reveal", control.text().lower())
                self.assertNotIn("Repeater", control.text())
        for panel in (item, w.composer_panel, w.fuzzer_panel, w.decoder_panel):
            self.assertFalse(hasattr(panel, "reveal"))
        self.assertFalse(hasattr(w, "history_reveal"))
        self.assertFalse(hasattr(w, "intercept_reveal"))

    def test_global_policy_updates_all_editors_without_mutating_bytes(self):
        from fixinspector.gui.widgets import MessageEditorWidget
        w = self.window()
        record, item = self.load_message(w)
        for editor in w.findChildren(MessageEditorWidget):
            editor.set_raw(record.raw)
        w.decoder_panel.input.setPlainText(record.raw.decode().replace("\x01", "|"))
        w.decoder_panel.decode()
        for mask in (True, False, True):
            with patch("fixinspector.gui.widgets.message_editor.serialize_structured") as serializer:
                self.apply(w, mask=mask, tags="1, 925")
                serializer.assert_not_called()
            for editor in w.findChildren(MessageEditorWidget):
                self.assertEqual(record.raw, editor._working_raw)
                self.assertEqual(not mask, "synthetic-private" in editor.raw.toPlainText())
                self.assertEqual(not mask, "account-test" in editor.raw.toPlainText())
            self.assertEqual(not mask, "synthetic-private" in w.decoder_panel.input.toPlainText())
            self.assertEqual(record.raw, w.decoder_panel._frames[0].raw)
            self.assertEqual(record.raw, item.item.original_raw)

    def test_privacy_change_preserves_edited_intercept_and_sender_drafts(self):
        from fixinspector.fix.parser import parse_message
        from fixinspector.session.injection import InjectionMode
        w = self.window()
        record, item = self.load_message(w, held=True)
        w.selected_intercept_record_id = record.record_id
        w._refresh_intercept_details()
        item.mode.setCurrentIndex(item.mode.findData(InjectionMode.CLONE_EDIT.name))
        for editor in (item.editor, w.proxy_shared_editor):
            row = next(r for r in range(editor.fields.rowCount()) if editor.fields.item(r, 1).text() == "1")
            editor.fields.item(row, 3).setText("edited-account")
        self.apply(w, tags="1")
        for editor in (item.editor, w.proxy_shared_editor):
            raw = editor.outbound_raw()
            self.assertEqual(b"edited-account", parse_message(raw).first("1"))
            self.assertEqual(b"synthetic-private", parse_message(raw).first("553"))
            self.assertEqual([b"one", b"two"], parse_message(raw).values("10001"))
        self.assertEqual(b"account-test", parse_message(record.original_raw).first("1"))

    def test_manual_malformed_data_draft_is_not_repaired_by_masking(self):
        from fixinspector.fix.parser import raw_to_editor_text
        w = self.window()
        _, item = self.load_message(w)
        self.apply(w, mask=False)
        item.session_fields.setCurrentText("Manual")
        raw = b"8=FIX.4.4\x019=1\x0135=D\x0134=1\x01553=synthetic-private\x0195=5\x0196=a\x01b=c\x0110001=x\x0110001=y\x0110=000\x01"
        item.editor.raw.setPlainText(raw_to_editor_text(raw))
        self.apply(w, mask=True)
        self.assertEqual(raw, item.editor._working_raw)
        self.apply(w, mask=False)
        self.assertEqual(raw, item.editor.outbound_raw(repair_raw=False))

    def test_privacy_persistence_legacy_flags_ignored_and_inline_validation(self):
        from PySide6.QtWidgets import QMessageBox
        self.settings.setValue("history/reveal", True)
        self.settings.setValue("ui/reveal_secrets", True)
        w = self.window()
        self.assertFalse(w._reveal_state())
        self.apply(w, mask=False, tags="554,925")
        other = self.window()
        self.assertTrue(other._reveal_state())
        self.assertEqual({"553", "554", "925"}, other.secret_policy.secret_tags)
        with patch.object(QMessageBox, "warning") as warning:
            self.apply(other, mask=True, tags="invalid")
            warning.assert_not_called()
        self.assertTrue(other._reveal_state(), "Invalid input must not partially apply")
        self.assertFalse(other.secret_policy_error.isHidden())
        self.assertIn("positive integers", other.secret_policy_error.text())
        self.settings.setValue("security/mask_sensitive_fields", "corrupt")
        self.assertFalse(self.window()._reveal_state())

    def test_display_disclosure_does_not_disable_storage_or_export_redaction(self):
        from fixinspector.project import ProjectDatabase, write_export
        w = self.window()
        record, _ = self.load_message(w)
        self.apply(w, mask=False, tags="1")
        with ProjectDatabase(self.directory / "privacy.fixproj", policy=w.secret_policy) as database:
            database.save_record(record)
            saved = database.load_records()[0]
            self.assertNotIn(b"synthetic-private", saved.raw)
            self.assertNotIn(b"account-test", saved.raw)
        for kind in ("raw", "json", "markdown", "readable"):
            path = self.directory / (kind + ".txt")
            write_export(path, [record], kind, dictionary=w.dictionary, policy=w.secret_policy)
            self.assertNotIn(b"synthetic-private", path.read_bytes())
            self.assertNotIn(b"account-test", path.read_bytes())

    def test_new_sender_and_isolated_preview_follow_global_policy(self):
        w = self.window()
        self.apply(w, mask=False)
        record, item = self.load_message(w)
        item.apply_connection_record(record)
        self.assertIn("synthetic-private", item.editor.raw.toPlainText())
        self.assertIn("synthetic-private", item.connection_traffic.item(0, 5).text())
        self.apply(w)
        self.assertNotIn("synthetic-private", item.connection_traffic.item(0, 5).text())
        self.apply(w, mask=False)
        self.assertIn("synthetic-private", item.connection_traffic.item(0, 5).text())

    def test_fuzzer_tester_values_and_pending_decoder_draft_survive_privacy(self):
        w = self.window()
        self.apply(w, mask=False)
        record, _ = self.load_message(w)
        campaign = w.fuzzer_controller.create_campaign("History", "21", record.raw)
        panel = w.fuzzer_panel
        panel.add_campaign(campaign)
        panel.target_tag.setCurrentIndex(panel.target_tag.findData("553"))
        panel.tester_values.setPlainText("synthetic-replacement")
        w.decoder_panel.input.setPlainText(record.raw.decode().replace("\x01", "|"))
        self.apply(w)
        self.assertNotIn("synthetic-replacement", panel.tester_values.toPlainText())
        self.assertNotIn("synthetic-private", w.decoder_panel.input.toPlainText())
        self.apply(w, mask=False)
        self.assertEqual("synthetic-replacement", panel.tester_values.toPlainText())
        self.assertEqual("553", panel.target_tag.currentData())
        w.decoder_panel.decode()
        self.assertEqual(record.raw, w.decoder_panel._frames[0].raw)

    def test_single_fuzzer_control_executes_destructive_case_without_confirmation(self):
        from PySide6.QtCore import Qt
        from PySide6.QtWidgets import QCheckBox, QMessageBox
        from fixinspector.fuzzer import DESTRUCTIVE_KINDS, MutationKind
        from fixinspector.gui.fuzzer import FuzzerPanel
        from fixinspector.project import SecretRedactionPolicy
        from fixinspector.session.injection import InjectionMode
        from tests.test_fuzzer_campaign import FuzzerCampaignTests
        controller, clock, queued, _ = FuzzerCampaignTests().make_controller()
        panel = FuzzerPanel(controller, lambda: controller.dictionary, lambda: SecretRedactionPolicy(), lambda _: ())
        self.addCleanup(panel.close)
        campaign = controller.create_campaign("History", "1", fix_message("D", 1, [("1", b"test")]))
        panel.add_campaign(campaign)
        self.assertEqual(["Enable session-destructive cases"], [c.text() for c in panel.findChildren(QCheckBox)])
        self.assertFalse(panel.destructive.isChecked())
        with patch.object(QMessageBox, "critical") as critical, patch.object(QMessageBox, "warning") as warning:
            panel.destructive.setChecked(True)
            destructive = []
            for row in range(panel.mutations.rowCount()):
                item = panel.mutations.item(row, 0)
                kind = panel._mutation_kind(item)
                self.assertTrue(item.flags() & Qt.ItemFlag.ItemIsEnabled)
                if kind in DESTRUCTIVE_KINDS:
                    destructive.append(kind)
                    color = panel.mutations.item(row, 1).background().color()
                    self.assertGreater(color.red(), color.green())
                    item.setCheckState(Qt.CheckState.Checked)
            self.assertEqual(set(DESTRUCTIVE_KINDS), set(destructive))
            panel.case_limit.setValue(1)
            panel._generate_plan()
            self.assertTrue(campaign.destructive_opt_in)
            controller.set_connected(True)
            panel._start()
            self.assertEqual(1, len(queued))
            self.assertIs(InjectionMode.EXACT_RAW, queued[0].mode)
            critical.assert_not_called()
            warning.assert_not_called()
        panel.destructive.setChecked(False)
        self.assertFalse(campaign.destructive_opt_in)
        self.assertFalse(set(panel.selected_mutation_kinds()) & set(DESTRUCTIVE_KINDS))


if __name__ == "__main__":
    unittest.main()
