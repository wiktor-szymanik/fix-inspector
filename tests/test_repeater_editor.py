from __future__ import annotations

import importlib.util
import os
import unittest

from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.dictionary import FieldDefinition, FixDictionary
from fixinspector.fix.fields import FixField
from fixinspector.fix.parser import parse_message
from fixinspector.fix.serializer import serialize_structured
from fixinspector.project.redaction import SecretRedactionPolicy
from fixinspector.records import TrafficRecord
from fixinspector.repeater import RepeaterController
from fixinspector.session.injection import InjectionMode
from tests.support import body_length_ok, fix_message


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class RepeaterEditorRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        cls.application = QApplication.instance() or QApplication([])

    def setUp(self) -> None:
        self.dictionary = FixDictionary()
        self.policy = SecretRedactionPolicy()

    def _widget(self, raw: bytes, dictionary: FixDictionary | None = None):
        from fixinspector.gui.widgets import MessageEditorWidget

        selected_dictionary = dictionary or self.dictionary
        widget = MessageEditorWidget(lambda: selected_dictionary, lambda: self.policy)
        widget.set_raw(raw)
        widget.set_mode(InjectionMode.CLONE_EDIT)
        self.addCleanup(self._close_widget, widget)
        return widget

    def _close_widget(self, widget) -> None:
        widget.close()
        widget.deleteLater()
        self.application.processEvents()

    @staticmethod
    def _rows_for_tag(widget, tag: str) -> list[int]:
        return [
            row
            for row in range(widget.fields.rowCount())
            if widget.fields.item(row, 1) is not None and widget.fields.item(row, 1).text() == tag
        ]

    def test_active_field_edit_is_committed_serialized_and_does_not_modify_history(self) -> None:
        from PySide6.QtTest import QTest
        from PySide6.QtWidgets import QLineEdit

        from fixinspector.gui.repeater import RepeaterItemEditor

        baseline = fix_message(extra_fields=[("1", b"181852")])
        history = TrafficRecord(41, "C→S", baseline)
        controller = RepeaterController(lambda *_args, **_kwargs: None, dictionary=self.dictionary)
        item = controller.create_from_record(history)
        repeater = RepeaterItemEditor(
            item,
            lambda: self.dictionary,
            lambda: self.policy,
            lambda _record_id: [],
        )
        self.addCleanup(self._close_widget, repeater)
        repeater.mode.setCurrentIndex(repeater.mode.findData(InjectionMode.CLONE_EDIT.name))
        repeater.show()
        self.application.processEvents()

        self.assertIs(repeater.current_mode(), InjectionMode.CLONE_EDIT)
        self.assertTrue(repeater.editor.add_field.isEnabled())
        row = self._rows_for_tag(repeater.editor, "1")[0]
        value_item = repeater.editor.fields.item(row, 3)
        repeater.editor.fields.setCurrentItem(value_item)
        repeater.editor.fields.editItem(value_item)
        self.application.processEvents()
        active_editor = repeater.editor.fields.findChild(QLineEdit)
        self.assertIsInstance(active_editor, QLineEdit)
        active_editor.setFocus()
        self.application.processEvents()
        self.assertIs(self.application.focusWidget(), active_editor)
        active_editor.selectAll()
        QTest.keyClicks(active_editor, "999999")
        self.assertEqual("181852", value_item.text())  # still owned by the active delegate

        queued: list[bytes] = []
        repeater.queue_requested.connect(lambda _item_id, raw, _mode: queued.append(bytes(raw)))
        repeater._queue()

        self.assertEqual(1, len(queued))
        edited = queued[0]
        self.assertEqual([b"999999"], parse_message(edited).values("1"))
        self.assertTrue(body_length_ok(edited))
        self.assertTrue(checksum_ok(edited))
        self.assertEqual(baseline, history.original_raw)
        self.assertEqual(baseline, item.original_raw)
        self.assertNotEqual(item.original_raw, item.working_raw)

        repeater.editor.tabs.setCurrentIndex(1)
        self.application.processEvents()
        self.assertIn("1=999999", repeater.editor.raw.toPlainText())

    def test_add_custom_field_inserts_a_real_ordered_field(self) -> None:
        baseline = fix_message(extra_fields=[("1", b"FIRST")])
        widget = self._widget(baseline)
        account_row = self._rows_for_tag(widget, "1")[0]
        widget.fields.setCurrentCell(account_row, 3)
        widget._add_field()
        inserted_row = widget.fields.currentRow()
        widget.fields.item(inserted_row, 1).setText("10000")
        widget.fields.item(inserted_row, 3).setText("CUSTOM")

        edited = widget.outbound_raw()
        message = parse_message(edited)
        tags = [field.tag for field in message.fields]
        self.assertEqual([b"CUSTOM"], message.values("10000"))
        self.assertEqual(tags.index("1") + 1, tags.index("10000"))
        self.assertTrue(body_length_ok(edited))
        self.assertTrue(checksum_ok(edited))

    def test_remove_field_removes_only_the_selected_duplicate_occurrence(self) -> None:
        baseline = fix_message(extra_fields=[("1", b"FIRST"), ("1", b"SECOND"), ("10000", b"KEEP")])
        widget = self._widget(baseline)
        duplicate_rows = self._rows_for_tag(widget, "1")
        widget.fields.setCurrentCell(duplicate_rows[1], 3)
        widget._remove_field()

        edited = widget.outbound_raw()
        message = parse_message(edited)
        self.assertEqual([b"FIRST"], message.values("1"))
        self.assertEqual([b"KEEP"], message.values("10000"))
        self.assertEqual([b"FIRST", b"SECOND"], parse_message(baseline).values("1"))

    def test_add_duplicate_field_preserves_both_occurrences_and_wire_order(self) -> None:
        baseline = fix_message(extra_fields=[("1", b"FIRST"), ("10000", b"AFTER")])
        widget = self._widget(baseline)
        account_row = self._rows_for_tag(widget, "1")[0]
        widget.fields.setCurrentCell(account_row, 3)
        widget._add_field()
        inserted_row = widget.fields.currentRow()
        widget.fields.item(inserted_row, 1).setText("1")
        widget.fields.item(inserted_row, 3).setText("SECOND")

        message = parse_message(widget.outbound_raw())
        self.assertEqual([b"FIRST", b"SECOND"], message.values("1"))
        body_tags = [field.tag for field in message.fields]
        self.assertLess(body_tags.index("1"), body_tags.index("10000"))

    def test_unmodified_binary_data_survives_an_unrelated_structured_edit(self) -> None:
        dictionary = FixDictionary()
        dictionary.fields_by_tag["95"] = FieldDefinition("95", "RawDataLength", "LENGTH")
        dictionary.fields_by_tag["96"] = FieldDefinition("96", "RawData", "DATA")
        data = b"\xff\x01Z"
        baseline = serialize_structured(
            [
                FixField("8", b"FIX.4.4"),
                FixField("9", b"0"),
                FixField("35", b"D"),
                FixField("34", b"1"),
                FixField("95", str(len(data)).encode("ascii")),
                FixField("96", data),
                FixField("1", b"OLD"),
                FixField("10", b"000"),
            ]
        )
        widget = self._widget(baseline, dictionary)
        row = self._rows_for_tag(widget, "1")[0]
        widget.fields.item(row, 3).setText("NEW")

        edited = widget.outbound_raw()
        message = parse_message(edited, dictionary)
        self.assertEqual([data], message.values("96"))
        self.assertEqual([b"NEW"], message.values("1"))
        self.assertTrue(body_length_ok(edited))
        self.assertTrue(checksum_ok(edited))


if __name__ == "__main__":
    unittest.main()
