"""UI adapters exercised against the unchanged local engine and synthetic bytes."""
import importlib.util
import os
from pathlib import Path
import unittest
from unittest.mock import patch

from tests import test_display_settings as fixture
from tests.support import fix_message


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class ProxyWorkspaceTests(unittest.TestCase):
    setUp = fixture.DisplaySettingsTests.setUp
    _close = fixture.DisplaySettingsTests._close
    window = fixture.DisplaySettingsTests.window

    @classmethod
    def setUpClass(cls):
        fixture.DisplaySettingsTests.setUpClass.__func__(cls)

    def records(self, w):
        from fixinspector.records import TrafficRecord
        for rid, direction, kind in ((1, "C→S", "D"), (2, "S→C", "8"), (3, "C→S", "0"), (4, "S→C", "A")):
            record = TrafficRecord(rid, direction, fix_message(kind, rid, [("1", b"acct"), ("11", b"order")]),
                                   msg_type=kind, sequence_number=rid, status="FORWARDED",
                                   source="CLIENT" if direction == "C→S" else "SERVER")
            w._on_record(record)

    def visible(self, w):
        w._run_history_filter()
        return [rid for rid, row in w.history_row_for_record.items() if not w.history.isRowHidden(row)]

    def test_search_multiple_filters_and_removable_chips(self):
        from PySide6.QtWidgets import QToolButton
        w = self.window()
        self.records(w)
        f = w.proxy_workspace.filters
        f.clear_filters()
        f.search.setText("order")
        self.assertEqual([1, 2, 3, 4], self.visible(w))
        f.fields["account"].setText("acct")
        f.fields["seq_from"].setText("2")
        f.expression.setText("tag.11=order")
        w.direction_filter.setCurrentIndex(2)
        self.assertEqual([2, 4], self.visible(w))
        self.assertEqual("Filter (4)", f.button.text())
        chip = next(button for button in f.chip_widget.findChildren(QToolButton) if button.text().startswith("Server →"))
        chip.click()
        self.assertEqual(0, w.direction_filter.currentIndex())
        self.assertEqual([2, 3, 4], self.visible(w))
        f.clear_filters()
        self.assertEqual("order", f.search.text())
        self.assertEqual("Filter", f.button.text())

    def test_visibility_category_fault_and_invalid_ranges(self):
        w = self.window()
        self.records(w)
        f = w.proxy_workspace.filters
        f.clear_filters()
        w.hide_heartbeats.setChecked(True)
        self.assertEqual([1, 2, 4], self.visible(w))
        w.hide_admin.setChecked(True)
        w.hide_heartbeats.setChecked(False)
        self.assertEqual([1, 2, 3], self.visible(w))
        f.clear_filters()
        f.category.setCurrentIndex(2)
        self.assertEqual([3, 4], self.visible(w))
        f.fields["seq_from"].setText("3")
        f.fields["seq_to"].setText("1")
        self.assertTrue(f.error.text())
        self.assertEqual([3, 4], self.visible(w))
        f.clear_filters()
        w.records[1].fault_action = "DELAY"
        w.records[2].fault_action = "NORMAL"
        f.faulted.setChecked(True)
        self.assertEqual([1], self.visible(w))

    def test_old_project_expression_and_new_controls_roundtrip(self):
        w = self.window()
        self.records(w)
        w.proxy_workspace.filters.search.setText("stale")
        w._restore_project_states({"history_filter": {"text": "msgtype=A", "advanced": True,
                                                       "hide_admin": False, "hide_heartbeats": False}})
        f = w.proxy_workspace.filters
        self.assertEqual("msgtype=A", f.expression.text())
        self.assertEqual("", f.search.text())
        self.assertEqual([4], self.visible(w))
        f.clear_filters()
        f.fields["seq_to"].setText("2")
        f.search.setText("acct")
        state = w._capture_project_states()
        f.clear_filters()
        f.search.clear()
        w._restore_project_states(state)
        self.assertEqual("2", f.fields["seq_to"].text())
        self.assertEqual("acct", f.search.text())
        self.assertEqual([1, 2], self.visible(w))

    def test_optional_columns_and_filters_persist_in_ini(self):
        w = self.window()
        expected = {1, 2, 3, 4, 5, 6, 7, 9}
        self.assertEqual(expected, {c for c in range(w.history.columnCount()) if not w.history.isColumnHidden(c)})
        w.proxy_workspace._column_actions[8].setChecked(True)
        w.proxy_workspace.filters.search.setText("needle")
        w._save_settings()
        other = self.window()
        self.assertFalse(other.history.isColumnHidden(8))
        self.assertEqual("needle", other.proxy_workspace.filters.search.text())

    def test_tcp_hides_tls_without_erasing_and_scope_maps_existing_flags(self):
        w = self.window()
        w.upstream_sni.setText("local.test")
        w.ca_file.setText("custom-ca.pem")
        w.upstream_transport.setCurrentIndex(0)
        self.assertTrue(w.upstream_sni.isHidden())
        self.assertFalse(w.ca_browse.isEnabled())
        w.upstream_transport.setCurrentIndex(1)
        self.assertFalse(w.upstream_sni.isHidden())
        self.assertEqual("custom-ca.pem", w.ca_file.text())
        ui = w.proxy_workspace
        ui.directions.setCurrentIndex(2)
        ui.scope.setCurrentIndex(1)
        self.assertEqual([False, False, True, True], [c.isChecked() for c in ui._policy_controls])
        ui.scope.setCurrentIndex(3)
        self.assertTrue(all(not c.isHidden() for c in ui._policy_controls))

    def test_shared_intercept_edit_forward_preserves_original_and_queued_cannot_bypass(self):
        from fixinspector.records import TrafficRecord
        from fixinspector.fix.parser import parse_message
        from PySide6.QtCore import Qt
        w = self.window()
        raw = fix_message("D", 7, [("1", b"181852"), ("10001", b"one"), ("10001", b"two")])
        record = TrafficRecord(7, "C→S", raw, msg_type="D", sequence_number=7, status="HELD")
        w._on_record(record)
        w.selected_intercept_record_id = 7
        w._refresh_intercept_details()
        self.assertEqual(Qt.Orientation.Horizontal, w.intercept_splitter.orientation())
        table = w.proxy_shared_editor.fields
        row = next(r for r in range(table.rowCount()) if table.item(r, 1).text() == "1")
        table.item(row, 3).setText("999999")
        with patch.object(w.engine, "resolve_intercept") as resolve:
            w._forward_current()
            outbound = resolve.call_args.args[2]
            self.assertIn(b"1=999999\x01", outbound)
            self.assertIn(b"10001=one\x0110001=two\x01", outbound)
            self.assertEqual(raw, record.original_raw)
            self.assertFalse(parse_message(outbound).issues)
            record.status = "QUEUED"
            w._refresh_intercept_details()
            resolve.reset_mock()
            w._forward_current()
            resolve.assert_not_called()
            self.assertFalse(w.forward_button.isEnabled())
            self.assertFalse(w.drop_button.isEnabled())

    def test_rules_adapter_fixed_tiers_order_and_redacted_summary(self):
        from fixinspector.intercept.proxy_behaviour import TagCondition
        w = self.window()
        adapter = w.proxy_behaviour_panel.adapter
        c = w.engine.proxy_behaviour
        c.set_global_mode("C→S", "PAUSE")
        c.arm_one_shot("S→C", "DROP", 2)
        a = c.add_rule(name="first", action="DELAY", delay_ms=250, conditions=[TagCondition("553", "private-key")])
        b = c.add_rule(name="second", action="DUPLICATE", duplicate_copies=2)
        c.set_category_mode("S→C", "ADMIN", "DROP")
        c.set_delay("C→S", enabled=True, delay_ms=400)
        c.arm_disconnect(side="BOTH", direction="C→S", event="FORWARDED", count=2)
        rows = adapter.rows()
        self.assertEqual(["1", "2", "3.1", "3.2", "4", "5", "Event"], [r.priority for r in rows])
        self.assertNotIn("private-key", repr(rows))
        adapter.move(next(r for r in rows if r.key == ("rule", b.rule_id)), -1)
        self.assertEqual(b.rule_id, c.rules()[0].rule_id)
        with self.assertRaises(ValueError):
            adapter.move(rows[0], 1)
        adapter.disable_or_delete(rows[0])
        self.assertFalse(any(r.key[0] == "global" for r in adapter.rows()))

    def test_rules_dialog_parameters_and_existing_api_dispatch(self):
        from fixinspector.gui.proxy.rule_editor import RuleEditor
        w = self.window()
        adapter = w.proxy_behaviour_panel.adapter
        dialog = RuleEditor(adapter, w)
        self.addCleanup(dialog.close)
        dialog.action.setCurrentText("DELAY")
        self.assertFalse(dialog.delay.isHidden())
        self.assertTrue(dialog.copies.isHidden())
        dialog.action.setCurrentText("DUPLICATE")
        self.assertTrue(dialog.delay.isHidden())
        self.assertFalse(dialog.copies.isHidden())
        dialog.conditions.setText("invalid hidden draft")
        adapter.apply(dialog.values())
        self.assertEqual(1, len(adapter.controller.rules()))
        dialog.kind.setCurrentIndex(dialog.kind.findData("once"))
        dialog.action.setCurrentText("DROP")
        dialog.count.setValue(2)
        adapter.apply(dialog.values())
        self.assertEqual(2, adapter.controller.snapshot().one_shots["C→S"].remaining)
        self.assertTrue(dialog.match.isHidden())

    def test_rules_adapter_delegates_remaining_controls_without_new_policy_state(self):
        w = self.window()
        adapter = w.proxy_behaviour_panel.adapter
        c = adapter.controller
        for values, method in ((dict(kind="global", direction="ANY", action="PAUSE"), "set_global_mode"),
                               (dict(kind="category", direction="C→S", category="ADMIN", action="DROP"), "set_category_mode"),
                               (dict(kind="delay", direction="S→C", enabled=True, delay_ms=150, jitter_ms=10, category="APPLICATION"), "set_delay"),
                               (dict(kind="disconnect", direction="S→C", side="SERVER", event="RECEIVED", count=2), "arm_disconnect")):
            with self.subTest(kind=values["kind"]), patch.object(c, method, wraps=getattr(c, method)) as delegated:
                adapter.apply(values)
                self.assertEqual(2 if values["direction"] == "ANY" else 1, delegated.call_count)
        with patch.object(w.engine, "disconnect") as disconnect:
            adapter.apply(dict(kind="disconnect_now", direction="ANY", side="BOTH"))
            disconnect.assert_called_once_with("BOTH")

    def test_state_source_time_and_bookmark_filters_compose(self):
        from datetime import datetime, timezone
        w = self.window()
        self.records(w)
        f = w.proxy_workspace.filters
        f.clear_filters()
        record = w.records[2]
        record.timestamp = datetime(2026, 9, 27, 12, tzinfo=timezone.utc)
        record.source = "REPEATER"
        record.modified = True
        record.bookmarked = True
        # Normal record update path refreshes the cached common-property view.
        w._on_record_status(2, "MODIFIED")
        f.source.setCurrentText("Sender")
        f.modified.setChecked(True)
        w.bookmarks_only.setChecked(True)
        f.state.setText("MODIFIED")
        f.fields["time_from"].setText("2026-09-27T11:00:00+00:00")
        f.fields["time_to"].setText("2026-09-27T13:00:00+00:00")
        self.assertEqual([2], self.visible(w))
        f.fields["time_to"].setText("2026-09-27T11:30:00+00:00")
        self.assertEqual([], self.visible(w))

    def test_rules_presets_clean_and_pending_reset_confirmation(self):
        from PySide6.QtWidgets import QMessageBox
        from fixinspector.fix.parser import parse_message
        from fixinspector.intercept.proxy_behaviour import FaultAction
        w = self.window()
        panel = w.proxy_behaviour_panel
        panel.apply_preset("Server response delay")
        self.assertTrue(any(row.action == "DELAY" for row in panel.adapter.rows()))
        panel.apply_preset("Clean")
        self.assertFalse(panel.adapter.rows())
        self.assertEqual(FaultAction.NORMAL, w.engine.proxy_behaviour.evaluate("S→C", parse_message(fix_message("8", 1))).action)
        with patch.object(w.engine, "pending_records", return_value=[object()]), patch.object(w.engine, "reset_proxy_behaviour") as reset:
            with patch.object(QMessageBox, "warning", return_value=QMessageBox.StandardButton.Cancel):
                panel.legacy._reset()
            reset.assert_not_called()

    def test_context_actions_decoder_masking_and_repeater_original(self):
        from fixinspector.records import TrafficRecord
        w = self.window()
        record = TrafficRecord(20, "C→S", fix_message("A", 1, [("553", b"secret-key")]), msg_type="A")
        w._on_record(record)
        actions = {name: (callback, enabled) for name, callback, enabled in w._message_context_actions(record)}
        self.assertTrue(actions["Open in Sender"][1])
        self.assertFalse(actions["Send to Composer"][1])
        actions["Send to Decoder"][0]()
        self.assertNotIn("secret-key", w.decoder_panel.input.toPlainText())
        self.assertIn(b"secret-key", record.original_raw)
        actions["Open in Sender"][0]()
        self.assertEqual("Sender", w.workspace_tabs.tabText(w.workspace_tabs.currentIndex()))

    def test_composer_context_uses_existing_form_and_retains_ordered_draft(self):
        from fixinspector.fix.dictionary import FixDictionary
        from fixinspector.records import TrafficRecord
        w = self.window()
        w.dictionary = FixDictionary.from_files(Path(__file__).parent / "fixtures" / "FIX_COMPOSER.xml")
        w.composer_controller.set_dictionary(w.dictionary)
        raw = fix_message("D", 1, [("11", b"id"), ("55", b"sym"), ("10001", b"a"), ("10001", b"b")])
        record = TrafficRecord(30, "C→S", raw, msg_type="D")
        w._on_record(record)
        w._send_to_composer(30)
        self.assertEqual("Composer", w.workspace_tabs.tabText(w.workspace_tabs.currentIndex()))
        self.assertEqual(raw, w.composer_panel.editor._working_raw)
        self.assertIn(b"10001=a\x0110001=b\x01", w.composer_panel.current_raw())
        self.assertEqual(raw, record.original_raw)

    def test_secret_filter_operands_not_persisted_or_shown_in_chips(self):
        import json
        from PySide6.QtWidgets import QToolButton
        w = self.window()
        f = w.proxy_workspace.filters
        f.expression.setText('tag.553!="private-key"')
        self.assertNotIn("private-key", json.dumps(w._capture_project_states()))
        self.assertFalse(any("private-key" in b.text() or "private-key" in b.toolTip()
                             for b in f.chip_widget.findChildren(QToolButton)))
        w._save_settings()
        self.assertNotIn("private-key", self.settings.value("ui/history_filter_controls"))
        self.assertNotIn("private-key", self.settings.value("history/filter"))

    def test_shared_copy_menu_uses_tag_and_value_not_wire_and_name(self):
        from PySide6.QtWidgets import QMenu
        w = self.window()
        editor = w.proxy_shared_editor
        editor.set_raw(fix_message("A", 1, [("553", b"private-key")]))
        row = next(r for r in range(editor.fields.rowCount()) if editor.fields.item(r, 1).text() == "553")
        editor.fields.setCurrentCell(row, 3)
        class SelectingMenu(QMenu):
            def exec(self, *_):
                next(a for a in self.actions() if a.text() == "Copy tag=value").trigger()
        with patch("fixinspector.gui.widgets.table_copy.QMenu", SelectingMenu):
            editor.copy_support._show_field_menu(editor.fields, editor.fields.visualItemRect(editor.fields.item(row, 3)).center(), 1, 3)
        self.assertEqual("553=<REDACTED>", self.application.clipboard().text())

    def test_proxy_views_and_rule_dialog_screens(self):
        from fixinspector.gui.proxy.rule_editor import RuleEditor
        from fixinspector.gui.settings.display import DisplaySettings
        w = self.window()
        self.records(w)
        w._run_history_filter()
        root = os.environ.get("FIX_INSPECTOR_UI_QA")
        for scale in (100, 200):
            w.presentation_controller.set_preferences(DisplaySettings(scale, 10, 10))
            for route in ("Intercept", "History", "Rules", "Settings"):
                w._navigate(route)
                self.application.processEvents()
                self.assertTrue(w.start_button.isVisible())
                self.assertTrue(w.proxy_workspace.proxy.isVisible())
                if root:
                    Path(root).mkdir(parents=True, exist_ok=True)
                    w.grab().save(str(Path(root) / f"phase2-{route.lower()}-{scale}.png"))
        dialog = RuleEditor(w.proxy_behaviour_panel.adapter, w)
        self.addCleanup(dialog.close)
        dialog.show()
        self.application.processEvents()
        if root:
            dialog.grab().save(str(Path(root) / "phase2-rule-editor-200.png"))


if __name__ == "__main__":
    unittest.main()
