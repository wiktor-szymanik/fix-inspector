from __future__ import annotations

from datetime import datetime, timezone
import importlib.util
import os
import socket
import tempfile
import unittest
from pathlib import Path

from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.parser import parse_message
from fixinspector.intercept.controller import InterceptController
from fixinspector.presentation import display_direction, display_direction_text
from fixinspector.records import TrafficRecord
from fixinspector.repeater import IsolatedRepeaterConnection, RepeaterController
from fixinspector.session.injection import (
    AutoUpdatePolicy,
    InjectionController,
    InjectionMode,
    RAW_MANUAL_POLICY,
    SESSION_AWARE_POLICY,
    apply_auto_updates,
    build_safe_injection,
)
from fixinspector.transport.connection import ProxyConfig
from fixinspector.transport.tls import TLSNegotiated
from tests.support import body_length_ok, fix_message, wait_until


FIXED_TIME = datetime(2026, 9, 8, 14, 15, 16, 123000, tzinfo=timezone.utc)


def replace_value(raw: bytes, tag: str, value: bytes) -> bytes:
    marker = tag.encode("ascii") + b"="
    start = 0 if raw.startswith(marker) else raw.find(b"\x01" + marker) + 1
    end = raw.find(b"\x01", start)
    return raw[: start + len(marker)] + value + raw[end:]


class SessionAdminDomainTests(unittest.TestCase):
    def test_admin_interception_is_an_explicit_independent_opt_in(self) -> None:
        controller = InterceptController(FixDictionary())
        heartbeat = fix_message("0", 1)
        controller.configure(True, False, 0)
        self.assertEqual("FORWARD", controller.submit(1, "C→S", "0", 1, heartbeat).value)

        controller.configure(True, False, 0, client_to_server_admin=True)
        self.assertEqual("HELD", controller.submit(2, "C→S", "A", 2, fix_message("A", 2)).value)

    def test_safe_session_admin_injection_updates_only_selected_session_fields(self) -> None:
        template = fix_message(
            "1",
            4,
            [("112", b"TEST-002"), ("43", b"Y"), ("122", b"20260901-09:00:00.000")],
        )
        heartbeat = fix_message("0", 77)
        effective = build_safe_injection(
            template,
            heartbeat,
            at=FIXED_TIME,
            auto_update=SESSION_AWARE_POLICY,
        )
        parsed = parse_message(effective)
        self.assertEqual("1", parsed.msg_type)
        self.assertEqual(b"77", parsed.first("34"))
        self.assertEqual(b"20260908-14:15:16.123", parsed.first("52"))
        self.assertEqual(b"TEST-002", parsed.first("112"))
        self.assertEqual(b"Y", parsed.first("43"))
        self.assertEqual(b"20260901-09:00:00.000", parsed.first("122"))
        self.assertTrue(body_length_ok(effective))
        self.assertTrue(checksum_ok(effective))

    def test_raw_manual_auto_update_profile_is_byte_exact(self) -> None:
        raw = fix_message("A", 9, [("43", b"Y"), ("122", b"OLD")])
        raw = replace_value(raw, "9", b"999")
        raw = replace_value(raw, "10", b"997")
        self.assertEqual(raw, apply_auto_updates(raw, RAW_MANUAL_POLICY))

    def test_selective_policy_preserves_manual_seq_time_body_length_and_checksum(self) -> None:
        template = fix_message("A", 1, [("43", b"Y"), ("122", b"ORIGINAL")])
        template = replace_value(template, "9", b"999")
        template = replace_value(template, "10", b"998")
        effective = build_safe_injection(
            template,
            fix_message("0", 88),
            at=FIXED_TIME,
            auto_update=AutoUpdatePolicy(False, False, False, False),
        )
        parsed = parse_message(effective)
        self.assertEqual(b"1", parsed.first("34"))
        self.assertEqual(b"20260901-10:00:00.000", parsed.first("52"))
        self.assertEqual(b"Y", parsed.first("43"))
        self.assertEqual(b"ORIGINAL", parsed.first("122"))
        self.assertEqual(b"999", parsed.first("9"))
        self.assertEqual(b"998", parsed.first("10"))

    def test_repeater_accepts_admin_from_either_direction_and_preserves_identity_edits(self) -> None:
        injection = InjectionController(clock=lambda: FIXED_TIME)
        controller = RepeaterController(injection.queue, dictionary=FixDictionary())
        original = fix_message("A", 1, [("98", b"0"), ("108", b"30")])
        item = controller.create_from_record(TrafficRecord(7, "S→C", original, msg_type="A"))
        self.assertEqual(InjectionMode.CLONE_EDIT, item.mode)
        edited = replace_value(original, "49", b"CUSTOM-SENDER")
        request = controller.queue(item.item_id, edited, InjectionMode.CLONE_EDIT)
        claim = injection.claim_safe_slot(fix_message("0", 42))
        self.assertIsNotNone(claim)
        self.assertEqual(request.injection_id, claim.request.injection_id)
        self.assertEqual(b"CUSTOM-SENDER", parse_message(claim.effective_raw).first("49"))
        self.assertEqual(original, item.original_raw)

    def test_direction_presentation_keeps_internal_identifiers_stable(self) -> None:
        self.assertEqual("Client → Server", display_direction("C→S"))
        self.assertEqual("Server → Client", display_direction("S -> C"))
        self.assertNotIn("C→S", display_direction_text("C→S NORMAL | S→C NORMAL"))


class _FakeSocket:
    def __init__(self, response: bytes) -> None:
        self.response = [response, b""]
        self.sent: list[bytes] = []
        self.closed = False

    def sendall(self, raw: bytes) -> None:
        self.sent.append(bytes(raw))

    def recv(self, _size: int) -> bytes:
        return self.response.pop(0)

    def close(self) -> None:
        self.closed = True

    def shutdown(self, _how: int) -> None:
        self.closed = True


class IsolatedRepeaterConnectionTests(unittest.TestCase):
    def test_logon_connection_is_byte_exact_and_captures_both_directions(self) -> None:
        logon = replace_value(fix_message("A", 1, [("553", b"secret")]), "10", b"999")
        response = fix_message("A", 1, [("58", b"accepted")])
        fake = _FakeSocket(response)
        records: list[TrafficRecord] = []
        statuses: list[str] = []
        ids = iter((100, 101))

        connection = IsolatedRepeaterConnection(
            ProxyConfig(upstream_host="fix.example.test", upstream_port=443),
            dictionary=FixDictionary(),
            next_record_id=lambda: next(ids),
            on_record=records.append,
            on_status=statuses.append,
            connector=lambda *_args: (
                fake,
                TLSNegotiated("Verified (test)", "TLSv1.3", "TEST-CIPHER"),
            ),
        )
        connection.send_logon(logon)
        self.assertTrue(wait_until(lambda: len(records) == 2))

        self.assertEqual([logon], fake.sent)
        self.assertEqual(["C→S", "S→C"], [record.direction for record in records])
        self.assertEqual(["REPEATER", "REPEATER"], [record.source for record in records])
        self.assertEqual(["A", "A"], [record.msg_type for record in records])
        self.assertTrue(any("open" in status for status in statuses))
        self.assertTrue(fake.closed)

    def test_non_logon_is_rejected_before_transport_creation(self) -> None:
        called = False

        def connector(*_args):
            nonlocal called
            called = True
            raise AssertionError

        connection = IsolatedRepeaterConnection(
            ProxyConfig(upstream_host="fix.example.test", upstream_port=443),
            dictionary=FixDictionary(),
            next_record_id=lambda: 1,
            on_record=lambda _record: None,
            on_status=lambda _status: None,
            connector=connector,
        )
        with self.assertRaisesRegex(ValueError, "Logon"):
            connection.send_logon(fix_message("0", 1))
        self.assertFalse(called)


@unittest.skipUnless(importlib.util.find_spec("PySide6"), "PySide6 is not installed")
class SessionAdminQtTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
        from PySide6.QtWidgets import QApplication

        cls.application = QApplication.instance() or QApplication([])

    def test_history_filters_colors_labels_and_admin_repeater(self) -> None:
        with tempfile.TemporaryDirectory(dir=Path.cwd()) as temp_dir:
            os.environ["APPDATA"] = temp_dir
            from fixinspector.gui.main_window import MainWindow

            window = MainWindow()
            self.addCleanup(window.close)
            records = (
                TrafficRecord(1, "C→S", fix_message("A", 1), msg_type="A"),
                TrafficRecord(2, "S→C", fix_message("A", 2), msg_type="A", source="SERVER"),
                TrafficRecord(3, "C→S", fix_message("0", 3), msg_type="0"),
                TrafficRecord(4, "S→C", fix_message("0", 4), msg_type="0", source="SERVER"),
            )
            for record in records:
                window._on_record(record)

            window.filter_edit.clear()
            window.advanced_filter.setChecked(False)
            window.proxy_workspace.filters.clear_filters()
            window.proxy_workspace.filters.search.clear()
            window.bookmarks_only.setChecked(False)
            window.direction_filter.setCurrentIndex(0)
            window.hide_admin.setChecked(False)
            window.hide_heartbeats.setChecked(True)
            window._run_history_filter()
            self.assertFalse(window.history.isRowHidden(window.history_row_for_record[1]))
            self.assertTrue(window.history.isRowHidden(window.history_row_for_record[3]))

            window.hide_admin.setChecked(True)
            window.hide_heartbeats.setChecked(False)
            window._run_history_filter()
            self.assertTrue(window.history.isRowHidden(window.history_row_for_record[1]))
            self.assertFalse(window.history.isRowHidden(window.history_row_for_record[3]))

            self.assertEqual("#e5ebfa", window._history_color(records[0]).name())
            self.assertEqual("#eeeeee", window._history_color(records[2]).name())
            self.assertEqual("Client → Server", window._record_summary(records[0])[2])
            item = window.repeater_controller.create_from_record(records[1])
            self.assertEqual(2, item.source_record_id)

    def test_repeater_presets_expose_session_aware_and_raw_manual_profiles(self) -> None:
        from fixinspector.gui.repeater import RepeaterItemEditor

        controller = RepeaterController(lambda *_args, **_kwargs: None, dictionary=FixDictionary())
        item = controller.create_from_record(
            TrafficRecord(20, "C→S", fix_message("1", 1, [("112", b"ABC")]), msg_type="1")
        )
        editor = RepeaterItemEditor(
            item, lambda: FixDictionary(), lambda: __import__(
                "fixinspector.project.redaction", fromlist=["SecretRedactionPolicy"]
            ).SecretRedactionPolicy(), lambda _record_id: []
        )
        self.addCleanup(editor.close)
        editor._set_raw_manual()
        self.assertEqual(InjectionMode.EXACT_RAW, editor.current_mode())
        self.assertTrue(editor.auto_update_policy().is_raw_manual)
        editor._set_session_aware()
        self.assertEqual(InjectionMode.CLONE_EDIT, editor.current_mode())
        self.assertTrue(editor.auto_update_policy().is_session_aware)


if __name__ == "__main__":
    unittest.main()
