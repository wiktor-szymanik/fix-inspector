from __future__ import annotations

import unittest

from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.parser import parse_message
from fixinspector.session.injection import InjectionMode, InjectionStatus
from fixinspector.transport.connection import ProxyEngine

from tests.fake_session import FakeFixSessionHarness
from tests.support import fix_message, wait_until


class InjectionFakeSessionIntegrationTests(unittest.TestCase):
    def make_engine(self):
        records = []
        statuses = []
        injection_events = []
        engine = ProxyEngine(
            FixDictionary(),
            records.append,
            lambda record_id, status: statuses.append((record_id, status)),
            lambda _status: None,
        )
        engine.set_injection_listener(injection_events.append)
        return engine, records, statuses, injection_events

    def test_safe_replay_never_replaces_business_or_testrequest_heartbeat(self) -> None:
        engine, records, statuses, events = self.make_engine()
        template = fix_message("D", 3, [("11", b"REPEATER-ORDER"), ("58", b"payload")])
        with FakeFixSessionHarness(engine) as session:
            request = engine.queue_injection(
                template,
                InjectionMode.BUSINESS_REPLAY,
                repeater_item_id="R1",
                source_record_id=99,
            )
            genuine_business = fix_message("F", 30, [("41", b"GENUINE-CANCEL")])
            test_response = fix_message("0", 31, [("112", b"TEST-1")])
            safe_heartbeat = fix_message("0", 32)
            session.send_client(genuine_business + test_response + safe_heartbeat)

            received = session.receive_server(3)

            self.assertEqual(genuine_business, received[0])
            self.assertEqual(test_response, received[1])
            injected = parse_message(received[2])
            self.assertEqual("D", injected.msg_type)
            self.assertEqual(b"32", injected.first("34"))
            self.assertEqual(b"REPEATER-ORDER", injected.first("11"))
            self.assertTrue(checksum_ok(received[2]))
            self.assertTrue(wait_until(lambda: any(status == "INJECTED" for _, status in statuses)))
            heartbeat_record = records[2]
            self.assertEqual("0", parse_message(heartbeat_record.original_raw).msg_type)
            self.assertEqual("D", parse_message(heartbeat_record.raw).msg_type)
            self.assertEqual("REPEATER", heartbeat_record.source)
            self.assertEqual(1, engine.substitution_journal.snapshot().substitution_count)
            self.assertEqual(0, engine.diagnostics().injection_waiting_count)
            self.assertEqual(InjectionStatus.QUEUED, events[0].status)
            self.assertEqual(InjectionStatus.INJECTED, events[-1].status)
            self.assertEqual(request.injection_id, events[-1].injection_id)

    def test_recovery_replays_effective_injected_history_not_original_heartbeat(self) -> None:
        engine, records, statuses, _events = self.make_engine()
        template = fix_message("D", 2, [("11", b"RECOVER-ME")])
        with FakeFixSessionHarness(engine) as session:
            engine.queue_injection(template, InjectionMode.CLONE_EDIT, repeater_item_id="R2")
            original_heartbeat = fix_message("0", 42)
            session.send_client(original_heartbeat)
            first_effective = session.receive_server(1)[0]
            self.assertEqual("D", parse_message(first_effective).msg_type)

            resend_request = fix_message("2", 90, [("7", b"42"), ("16", b"42")])
            session.send_server(resend_request)
            self.assertEqual([resend_request], session.receive_client(1))
            original_resend = fix_message(
                "0",
                42,
                [("43", b"Y"), ("122", b"20260901-10:00:00.000")],
            )
            session.send_client(original_resend)

            recovery_effective = session.receive_server(1)[0]

            recovered = parse_message(recovery_effective)
            self.assertEqual("D", recovered.msg_type)
            self.assertEqual(b"42", recovered.first("34"))
            self.assertEqual(b"Y", recovered.first("43"))
            self.assertEqual(b"RECOVER-ME", recovered.first("11"))
            self.assertNotEqual(original_resend, recovery_effective)
            self.assertTrue(wait_until(lambda: any(status == "RECOVERY-REPLAY" for _, status in statuses)))
            self.assertEqual(1, engine.substitution_journal.snapshot().recovery_replay_count)
            self.assertEqual(1, engine.diagnostics().recovery_replay_count)

    def test_recovery_journal_uses_fix_identity_across_tcp_reconnect(self) -> None:
        engine, _records, _statuses, _events = self.make_engine()
        template = fix_message("D", 2, [("11", b"RECOVER-AFTER-RECONNECT")])
        original_heartbeat = fix_message("0", 42)
        with FakeFixSessionHarness(engine) as first:
            engine.queue_injection(template, InjectionMode.CLONE_EDIT, repeater_item_id="R3")
            first.send_client(original_heartbeat)
            self.assertEqual("D", parse_message(first.receive_server(1)[0]).msg_type)

        engine._stop.clear()
        with FakeFixSessionHarness(engine) as second:
            logon = fix_message("A", 43, [("108", b"30")])
            second.send_client(logon)
            self.assertEqual([logon], second.receive_server(1))
            resend_request = fix_message("2", 91, [("7", b"42"), ("16", b"42")])
            second.send_server(resend_request)
            self.assertEqual([resend_request], second.receive_client(1))
            original_resend = fix_message(
                "0",
                42,
                [("43", b"Y"), ("122", b"20260901-10:00:00.000")],
            )
            second.send_client(original_resend)

            recovered = parse_message(second.receive_server(1)[0])

            self.assertEqual("D", recovered.msg_type)
            self.assertEqual(b"RECOVER-AFTER-RECONNECT", recovered.first("11"))
            self.assertEqual(b"Y", recovered.first("43"))

    def test_heartbeat_slot_is_consumed_only_when_ordered_queue_releases_it(self) -> None:
        engine, records, statuses, _events = self.make_engine()
        engine.set_intercept(c2s=True, timeout_seconds=0)
        template = fix_message("D", 2, [("11", b"AFTER-HELD")])
        held_business = fix_message("F", 20, [("41", b"HELD-GENUINE")])
        heartbeat = fix_message("0", 21)
        with FakeFixSessionHarness(engine) as session:
            engine.queue_injection(template, InjectionMode.BUSINESS_REPLAY, repeater_item_id="R4")
            session.send_client(held_business + heartbeat)
            self.assertTrue(wait_until(lambda: len(records) == 2))
            self.assertEqual(["HELD", "QUEUED"], [record.status for record in records])
            self.assertEqual([], session.receive_server(1, timeout=0.15))

            engine.resolve_intercept(records[0].record_id, "forward", held_business)
            received = session.receive_server(2)

            self.assertEqual(held_business, received[0])
            effective = parse_message(received[1])
            self.assertEqual("D", effective.msg_type)
            self.assertEqual(b"21", effective.first("34"))
            self.assertEqual(b"AFTER-HELD", effective.first("11"))
            self.assertTrue(wait_until(lambda: statuses[-1:] == [(records[1].record_id, "INJECTED")]))

    def test_exact_raw_replay_bypasses_slot_only_in_explicit_destructive_mode(self) -> None:
        engine, records, _statuses, events = self.make_engine()
        raw = fix_message("D", 4, [("11", b"STALE-EXACT")])
        with FakeFixSessionHarness(engine) as session:
            request = engine.queue_injection(
                raw,
                InjectionMode.EXACT_RAW,
                repeater_item_id="R3",
            )

            self.assertEqual(raw, session.receive_server_bytes())
            self.assertTrue(wait_until(lambda: any(record.status == "EXACT-RAW-REPLAY" for record in records)))
            replay_record = next(record for record in records if record.status == "EXACT-RAW-REPLAY")
            self.assertEqual(raw, replay_record.original_raw)
            self.assertEqual("REPEATER", replay_record.source)
            self.assertEqual(InjectionStatus.RAW_QUEUED, events[0].status)
            self.assertEqual(InjectionStatus.RAW_REPLAYED, events[-1].status)
            self.assertEqual(request.injection_id, events[-1].injection_id)


if __name__ == "__main__":
    unittest.main()
