from __future__ import annotations

import queue
import threading
import unittest

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.transport.connection import ProxyEngine

from tests.support import (
    ControllableSocket,
    RecordingSocket,
    ScriptedSocket,
    fix_message,
    wait_until,
)


class ProxyPipelineTests(unittest.TestCase):
    def make_engine(self):
        records = []
        statuses = []
        transport_statuses = []
        engine = ProxyEngine(
            dictionary=FixDictionary(),
            on_record=records.append,
            on_record_status=lambda record_id, status: statuses.append((record_id, status)),
            on_status=transport_statuses.append,
        )
        return engine, records, statuses, transport_statuses

    def test_complete_frames_are_forwarded_byte_exact_by_default(self) -> None:
        engine, records, statuses, _ = self.make_engine()
        first = fix_message(seq_num=1, extra_fields=[("11", b"ONE")])
        second = fix_message(seq_num=2, extra_fields=[("11", b"TWO")])
        source = ScriptedSocket([first[:7], first[7:] + second])
        destination = RecordingSocket()
        errors: queue.Queue[BaseException] = queue.Queue()

        engine._pipe(source, destination, "C→S", errors)

        self.assertEqual([first, second], destination.sent)
        self.assertEqual(["FORWARDED", "FORWARDED"], [record.status for record in records])
        self.assertEqual([], statuses)
        self.assertTrue(errors.empty())

    def test_held_application_queues_later_admin_and_application_frames(self) -> None:
        engine, records, statuses, _ = self.make_engine()
        engine.set_intercept(c2s=True, timeout_seconds=0)
        first = fix_message(seq_num=20, extra_fields=[("11", b"FIRST")])
        heartbeat = fix_message(msg_type="0", seq_num=21)
        second = fix_message(seq_num=22, extra_fields=[("11", b"SECOND")])
        source = ControllableSocket()
        destination = RecordingSocket()
        errors: queue.Queue[BaseException] = queue.Queue()
        worker = threading.Thread(target=engine._pipe, args=(source, destination, "C→S", errors), daemon=True)
        worker.start()
        source.push(first + heartbeat + second)

        self.assertTrue(wait_until(lambda: len(records) == 3))
        self.assertEqual(["HELD", "QUEUED", "QUEUED"], [record.status for record in records])
        self.assertEqual([], destination.sent)
        snapshot = engine.diagnostics()
        self.assertEqual(1, snapshot.held_count)
        self.assertEqual(2, snapshot.queued_count)
        self.assertEqual(20, snapshot.paused_client_sequence)

        engine.resolve_intercept(records[0].record_id, "forward", first)

        self.assertTrue(wait_until(lambda: destination.sent == [first, heartbeat]))
        self.assertTrue(wait_until(lambda: statuses[-1:] == [(records[2].record_id, "HELD")]))
        self.assertEqual(
            [
                (records[0].record_id, "FORWARDED"),
                (records[1].record_id, "FORWARDED"),
                (records[2].record_id, "HELD"),
            ],
            statuses,
        )

        engine.resolve_intercept(records[2].record_id, "forward", second)
        self.assertTrue(wait_until(lambda: destination.sent == [first, heartbeat, second]))
        source.close_input()
        worker.join(timeout=1)

        self.assertFalse(worker.is_alive())
        self.assertTrue(errors.empty())

    def test_admin_traffic_is_not_intercepted_when_direction_is_unpaused(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.set_intercept(c2s=True, timeout_seconds=0)
        heartbeat = fix_message(msg_type="0", seq_num=10)
        destination = RecordingSocket()

        engine._pipe(ScriptedSocket([heartbeat]), destination, "C→S", queue.Queue())

        self.assertEqual([heartbeat], destination.sent)
        self.assertEqual("FORWARDED", records[0].status)

    def test_auto_forward_is_optional_and_reports_auto_status(self) -> None:
        engine, records, statuses, _ = self.make_engine()
        engine.set_intercept(c2s=True, timeout_seconds=0.02)
        raw = fix_message(seq_num=30, extra_fields=[("11", b"AUTO")])
        source = ControllableSocket()
        destination = RecordingSocket()
        errors: queue.Queue[BaseException] = queue.Queue()
        worker = threading.Thread(target=engine._pipe, args=(source, destination, "C→S", errors), daemon=True)
        worker.start()
        source.push(raw)

        self.assertTrue(wait_until(lambda: destination.sent == [raw]))
        self.assertEqual([(records[0].record_id, "AUTO-FWD")], statuses)
        source.close_input()
        worker.join(timeout=1)
        self.assertTrue(errors.empty())

    def test_drop_is_explicit_and_releases_later_admin_frame(self) -> None:
        engine, records, statuses, _ = self.make_engine()
        engine.set_intercept(c2s=True, timeout_seconds=0)
        order = fix_message(seq_num=40, extra_fields=[("11", b"DROP")])
        heartbeat = fix_message(msg_type="0", seq_num=41)
        source = ControllableSocket()
        destination = RecordingSocket()
        worker = threading.Thread(
            target=engine._pipe,
            args=(source, destination, "C→S", queue.Queue()),
            daemon=True,
        )
        worker.start()
        source.push(order + heartbeat)
        self.assertTrue(wait_until(lambda: len(records) == 2))

        engine.resolve_intercept(records[0].record_id, "drop")

        self.assertTrue(wait_until(lambda: destination.sent == [heartbeat]))
        self.assertEqual(
            [(records[0].record_id, "DROPPED"), (records[1].record_id, "FORWARDED")],
            statuses,
        )
        source.close_input()
        worker.join(timeout=1)

    def test_direction_policy_does_not_hold_disabled_server_traffic(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.set_intercept(c2s=True, s2c=False, timeout_seconds=0)
        raw = fix_message(seq_num=4, extra_fields=[("11", b"SERVER")])
        destination = RecordingSocket()

        engine._pipe(ScriptedSocket([raw]), destination, "S→C", queue.Queue())

        self.assertEqual([raw], destination.sent)
        self.assertEqual("FORWARDED", records[0].status)

    def test_diagnostics_track_observed_sequences_and_heartbeat(self) -> None:
        engine, _, _, _ = self.make_engine()
        logon = fix_message(msg_type="A", seq_num=7, extra_fields=[("108", b"15")])
        report = fix_message(msg_type="8", seq_num=12, extra_fields=[("37", b"ORDER")])

        engine._pipe(ScriptedSocket([logon]), RecordingSocket(), "C→S", queue.Queue())
        engine._pipe(ScriptedSocket([report]), RecordingSocket(), "S→C", queue.Queue())
        snapshot = engine.diagnostics()

        self.assertEqual(7, snapshot.client_to_server_sequence)
        self.assertEqual(12, snapshot.server_to_client_sequence)
        self.assertEqual(15, snapshot.heartbeat_interval)
        self.assertEqual("CLIENT→SERVER", snapshot.client_session_id)
        self.assertEqual("CLIENT→SERVER", snapshot.server_session_id)


if __name__ == "__main__":
    unittest.main()
