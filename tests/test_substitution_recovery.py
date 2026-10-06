from __future__ import annotations

from datetime import datetime, timezone
import unittest

from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.parser import parse_message
from fixinspector.session.recovery import RecoveryController
from fixinspector.session.substitution_journal import SubstitutionJournal

from tests.support import body_length_ok, fix_message


FIXED_TIME = datetime(2026, 9, 1, 13, 0, 0, tzinfo=timezone.utc)


class SubstitutionRecoveryTests(unittest.TestCase):
    def setUp(self) -> None:
        self.journal = SubstitutionJournal()
        self.original = fix_message("0", 42)
        self.effective = fix_message("D", 42, [("11", b"INJECTED-42")])
        self.entry = self.journal.record(
            session_key="session-1",
            sequence_number=42,
            original_record_id=9,
            original_client_raw=self.original,
            effective_server_raw=self.effective,
            injection_id=3,
            injection_source="REPEATER",
            repeater_item_id="R1",
            substituted_at=FIXED_TIME,
        )
        self.recovery = RecoveryController()

    def test_journal_retains_both_wire_representations(self) -> None:
        loaded = self.journal.lookup("session-1", 42)
        self.assertEqual(self.original, loaded.original_client_raw)
        self.assertEqual(self.effective, loaded.effective_server_raw)
        self.assertEqual([42], [entry.sequence_number for entry in self.journal.entries_for_range("session-1", 40, 45)])

    def test_resend_request_rewrites_original_heartbeat_to_effective_history(self) -> None:
        resend_request = fix_message("2", 100, [("7", b"42"), ("16", b"42")])
        self.recovery.observe_server("session-1", resend_request)
        original_resend = fix_message("0", 42, [("43", b"Y"), ("122", b"20260901-10:00:00.000")])

        decision = self.recovery.rewrite_client_if_needed(
            "session-1", original_resend, self.journal, at=FIXED_TIME
        )

        self.assertIsNotNone(decision)
        message = parse_message(decision.effective_raw)
        self.assertEqual("D", message.msg_type)
        self.assertEqual(b"42", message.first("34"))
        self.assertEqual(b"Y", message.first("43"))
        self.assertEqual(b"INJECTED-42", message.first("11"))
        self.assertIsNotNone(message.first("122"))
        self.assertTrue(body_length_ok(decision.effective_raw))
        self.assertTrue(checksum_ok(decision.effective_raw))
        self.recovery.mark_effective_replay_sent("session-1", 42, self.journal, at=FIXED_TIME)
        self.assertEqual(1, self.journal.lookup("session-1", 42).recovery_replay_count)

    def test_genuine_business_resend_is_never_replaced(self) -> None:
        self.recovery.observe_server("session-1", fix_message("2", 100, [("7", b"42"), ("16", b"42")]))
        genuine_business = fix_message("F", 42, [("41", b"REAL-BUSINESS")])

        self.assertIsNone(
            self.recovery.rewrite_client_if_needed("session-1", genuine_business, self.journal)
        )
        snapshot = self.recovery.snapshot()
        self.assertEqual(1, snapshot.conflict_count)
        self.assertIn("not replaced", snapshot.last_detail)


if __name__ == "__main__":
    unittest.main()
