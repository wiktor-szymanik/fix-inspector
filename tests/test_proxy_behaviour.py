from __future__ import annotations

import queue
import socket
import threading
import time
import unittest

from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.parser import parse_message
from fixinspector.intercept.proxy_behaviour import (
    DisconnectEvent,
    FaultAction,
    MessageCategory,
    ProxyBehaviourController,
    TagCondition,
)
from fixinspector.transport.connection import ProxyEngine

from tests.support import ControllableSocket, RecordingSocket, ScriptedSocket, fix_message, wait_until


class ClosingSocket:
    def __init__(self) -> None:
        self.shutdown_calls = 0
        self.close_calls = 0

    def shutdown(self, _how) -> None:
        self.shutdown_calls += 1

    def close(self) -> None:
        self.close_calls += 1


class ProxyBehaviourTests(unittest.TestCase):
    def make_engine(self):
        records = []
        statuses = []
        transport_statuses = []
        engine = ProxyEngine(
            FixDictionary(),
            records.append,
            lambda record_id, status: statuses.append((record_id, status)),
            transport_statuses.append,
        )
        return engine, records, statuses, transport_statuses

    @staticmethod
    def decision(controller, direction="S→C", msg_type="8", fields=()):
        return controller.evaluate(direction, parse_message(fix_message(msg_type, 1, fields)))

    def test_01_server_to_client_drop_all(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.proxy_behaviour.set_global_mode("S→C", "DROP")
        destination = RecordingSocket()
        raw = fix_message("8", 1)
        engine._pipe(ScriptedSocket([raw]), destination, "S→C", queue.Queue())
        self.assertEqual([], destination.sent)
        self.assertEqual("DROPPED", records[0].status)

    def test_02_client_to_server_drop_all(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.proxy_behaviour.set_global_mode("C→S", "DROP")
        destination = RecordingSocket()
        engine._pipe(ScriptedSocket([fix_message("D", 1)]), destination, "C→S", queue.Queue())
        self.assertEqual([], destination.sent)
        self.assertEqual("DROP", records[0].fault_action)

    def test_03_pause_then_forward_uses_ordered_queue(self) -> None:
        engine, records, statuses, _ = self.make_engine()
        engine.proxy_behaviour.set_global_mode("S→C", "PAUSE")
        source = ControllableSocket()
        destination = RecordingSocket()
        worker = threading.Thread(
            target=engine._pipe,
            args=(source, destination, "S→C", queue.Queue()),
            daemon=True,
        )
        worker.start()
        raw = fix_message("8", 1)
        source.push(raw)
        self.assertTrue(wait_until(lambda: len(records) == 1))
        self.assertEqual("HELD", records[0].status)
        engine.resolve_intercept(records[0].record_id, "forward")
        self.assertTrue(wait_until(lambda: destination.sent == [raw]))
        self.assertIn((records[0].record_id, "RELEASED_FROM_QUEUE"), statuses)
        source.close_input()
        worker.join(1)

    def test_04_pause_then_drop_never_sends(self) -> None:
        engine, records, statuses, _ = self.make_engine()
        engine.proxy_behaviour.set_global_mode("S→C", "PAUSE")
        source = ControllableSocket()
        destination = RecordingSocket()
        worker = threading.Thread(target=engine._pipe, args=(source, destination, "S→C", queue.Queue()), daemon=True)
        worker.start()
        source.push(fix_message("8", 1))
        self.assertTrue(wait_until(lambda: records))
        engine.resolve_intercept(records[0].record_id, "drop")
        self.assertTrue(wait_until(lambda: statuses))
        self.assertEqual([], destination.sent)
        self.assertEqual("DROPPED", statuses[0][1])
        source.close_input()
        worker.join(1)

    def test_05_drop_next_one_auto_clears(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        controller.arm_one_shot("S→C", "DROP", 1)
        self.assertEqual(FaultAction.DROP, self.decision(controller).action)
        self.assertEqual(FaultAction.NORMAL, self.decision(controller).action)

    def test_06_drop_next_n_is_exact(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        controller.arm_one_shot("S→C", "DROP", 3)
        actions = [self.decision(controller).action for _ in range(4)]
        self.assertEqual([FaultAction.DROP] * 3 + [FaultAction.NORMAL], actions)

    def test_07_rule_matches_msg_type(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        controller.add_rule(name="reports", direction="S→C", msg_type="8", action="DROP")
        self.assertEqual(FaultAction.DROP, self.decision(controller, msg_type="8").action)

    def test_08_rule_matches_tag_value_without_flattening(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        controller.add_rule(
            name="ambiguous",
            direction="S→C",
            msg_type="8",
            conditions=[TagCondition("11", "AMBIG-RETRY-003")],
            action="DROP",
        )
        decision = self.decision(
            controller,
            fields=(("11", b"OTHER"), ("11", b"AMBIG-RETRY-003")),
        )
        self.assertEqual(FaultAction.DROP, decision.action)
        self.assertEqual("ambiguous", decision.matched_rule)

    def test_09_nonmatching_rule_forwards_normally(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        controller.add_rule(name="orders", msg_type="D", action="DROP")
        self.assertEqual(FaultAction.NORMAL, self.decision(controller, msg_type="8").action)

    def test_10_application_drop_admin_normal(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        controller.set_category_mode("S→C", "APPLICATION", "DROP")
        controller.set_category_mode("S→C", "ADMIN", "NORMAL")
        self.assertEqual(FaultAction.DROP, self.decision(controller, msg_type="8").action)
        self.assertEqual(FaultAction.NORMAL, self.decision(controller, msg_type="0").action)

    def test_11_delay_is_deterministic_and_does_not_change_raw(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.proxy_behaviour.set_delay("S→C", enabled=True, delay_ms=15, category="APPLICATION")
        raw = fix_message("8", 1, (("11", b"DELAY"),))
        destination = RecordingSocket()
        started = time.monotonic()
        engine._pipe(ScriptedSocket([raw]), destination, "S→C", queue.Queue())
        self.assertGreaterEqual(time.monotonic() - started, 0.01)
        self.assertEqual([raw], destination.sent)
        self.assertEqual("DELAYED", records[0].status)

    def test_12_duplication_is_exact_and_bounded(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.proxy_behaviour.arm_one_shot("S→C", "DUPLICATE", 1, duplicate_copies=2)
        raw = fix_message("8", 1, (("11", b"DUP"),))
        destination = RecordingSocket()
        engine._pipe(ScriptedSocket([raw]), destination, "S→C", queue.Queue())
        self.assertEqual([raw, raw, raw], destination.sent)
        self.assertEqual(["DUPLICATED", "FAULT-INJECTED DUPLICATE", "FAULT-INJECTED DUPLICATE"], [r.status for r in records])
        with self.assertRaises(ValueError):
            engine.proxy_behaviour.arm_one_shot("S→C", "DUPLICATE", duplicate_copies=11)

    def test_13_manual_client_disconnect_closes_only_client_target(self) -> None:
        engine, _, _, _ = self.make_engine()
        client, server = ClosingSocket(), ClosingSocket()
        engine._client_socket = client
        engine._upstream_socket = server
        engine.disconnect("CLIENT")
        self.assertEqual((1, 1), (client.shutdown_calls, client.close_calls))
        self.assertEqual((0, 0), (server.shutdown_calls, server.close_calls))

    def test_14_manual_server_disconnect_closes_only_server_target(self) -> None:
        engine, _, _, _ = self.make_engine()
        client, server = ClosingSocket(), ClosingSocket()
        engine._client_socket = client
        engine._upstream_socket = server
        engine.disconnect("SERVER")
        self.assertEqual((0, 0), (client.shutdown_calls, client.close_calls))
        self.assertEqual((1, 1), (server.shutdown_calls, server.close_calls))

    def test_15_disconnect_after_forward_fires_once(self) -> None:
        engine, _, _, _ = self.make_engine()
        client = ClosingSocket()
        engine._client_socket = client
        engine.proxy_behaviour.arm_disconnect("CLIENT", "C→S", "FORWARDED")
        raw = fix_message("D", 1)
        destination = RecordingSocket()
        engine._pipe(ScriptedSocket([raw]), destination, "C→S", queue.Queue())
        self.assertEqual([raw], destination.sent)
        self.assertEqual(1, client.close_calls)
        self.assertEqual((), engine.proxy_behaviour.snapshot().disconnect_triggers)

    def test_16_disconnect_after_drop_fires_once(self) -> None:
        engine, _, _, _ = self.make_engine()
        client = ClosingSocket()
        engine._client_socket = client
        engine.proxy_behaviour.set_global_mode("S→C", "DROP")
        engine.proxy_behaviour.arm_disconnect("CLIENT", "S→C", "DROPPED")
        engine._pipe(ScriptedSocket([fix_message("8", 1)]), RecordingSocket(), "S→C", queue.Queue())
        self.assertEqual(1, client.close_calls)

    def test_17_rapid_messages_remain_in_wire_order_with_delay(self) -> None:
        engine, _, _, _ = self.make_engine()
        engine.proxy_behaviour.set_delay("S→C", enabled=True, delay_ms=1, category="ANY")
        messages = [fix_message("8", number) for number in range(1, 8)]
        destination = RecordingSocket()
        engine._pipe(ScriptedSocket([b"".join(messages)]), destination, "S→C", queue.Queue())
        self.assertEqual(messages, destination.sent)

    def test_18_history_record_retains_drop_evidence(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.proxy_behaviour.add_rule(name="Evidence rule", msg_type="8", direction="S→C", action="DROP")
        raw = fix_message("8", 7)
        engine._pipe(ScriptedSocket([raw]), RecordingSocket(), "S→C", queue.Queue())
        record = records[0]
        self.assertEqual(raw, record.original_raw)
        self.assertEqual("Evidence rule", record.fault_rule)
        self.assertIn("First matching rule", record.fault_reason)

    def test_19_dropped_messages_never_enter_release_queue(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.proxy_behaviour.set_global_mode("S→C", "DROP")
        destination = RecordingSocket()
        engine._pipe(ScriptedSocket([fix_message("8", 1)]), destination, "S→C", queue.Queue())
        engine.resolve_intercept(records[0].record_id, "forward")
        self.assertEqual((), engine.pending_records())
        self.assertEqual([], destination.sent)

    def test_20_paused_message_stays_queued_past_intercept_timeout(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.set_intercept(False, False, timeout_seconds=0.01)
        engine.proxy_behaviour.set_global_mode("S→C", "PAUSE")
        source = ControllableSocket()
        destination = RecordingSocket()
        worker = threading.Thread(target=engine._pipe, args=(source, destination, "S→C", queue.Queue()), daemon=True)
        worker.start()
        source.push(fix_message("8", 1))
        self.assertTrue(wait_until(lambda: records))
        time.sleep(0.04)
        self.assertEqual([], destination.sent)
        self.assertEqual(1, len(engine.pending_records()))
        engine.reset_proxy_behaviour()
        source.close_input()
        worker.join(1)

    def test_21_reset_is_clean_normal_and_discards_pause_queue(self) -> None:
        engine, records, statuses, _ = self.make_engine()
        engine.proxy_behaviour.set_global_mode("S→C", "PAUSE")
        engine.proxy_behaviour.arm_one_shot("C→S", "DROP", 2)
        engine.proxy_behaviour.add_rule(name="active", action="DROP")
        source = ControllableSocket()
        worker = threading.Thread(target=engine._pipe, args=(source, RecordingSocket(), "S→C", queue.Queue()), daemon=True)
        worker.start()
        source.push(fix_message("8", 1))
        self.assertTrue(wait_until(lambda: records))
        discarded = engine.reset_proxy_behaviour()
        snapshot = engine.proxy_behaviour.snapshot()
        self.assertEqual((records[0].record_id,), discarded)
        self.assertEqual(FaultAction.NORMAL, snapshot.server_to_client.global_mode)
        self.assertFalse(snapshot.one_shots)
        self.assertFalse(snapshot.rules[0].enabled)
        self.assertIn((records[0].record_id, "DROPPED"), statuses)
        source.close_input()
        worker.join(1)

    def test_22_fault_injection_never_mutates_immutable_original(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.proxy_behaviour.arm_one_shot("S→C", "DUPLICATE")
        raw = fix_message("8", 1, (("11", b"ORIGINAL"), ("11", b"DUPLICATE-TAG")))
        engine._pipe(ScriptedSocket([raw]), RecordingSocket(), "S→C", queue.Queue())
        self.assertEqual(raw, records[0].original_raw)
        self.assertEqual(raw, records[0].raw)

    def test_23_first_matching_rule_wins_and_move_changes_precedence(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        first = controller.add_rule(name="first", msg_type="8", action="DROP")
        second = controller.add_rule(name="second", msg_type="8", action="NORMAL")
        self.assertEqual(FaultAction.DROP, self.decision(controller).action)
        controller.move_rule(second.rule_id, -1)
        decision = self.decision(controller)
        self.assertEqual(FaultAction.NORMAL, decision.action)
        self.assertEqual("second", decision.matched_rule)
        self.assertNotEqual(first.rule_id, second.rule_id)

    def test_24_project_state_restores_rules_disabled_and_redacts_553(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        controller.set_global_mode("S→C", "DROP")
        controller.add_rule(name="login", conditions=[("553", "top-secret")], action="DROP")
        state = controller.to_state({"553"})
        self.assertNotIn("top-secret", repr(state))
        restored = ProxyBehaviourController(FixDictionary())
        restored.restore_state(state)
        snapshot = restored.snapshot()
        self.assertEqual(FaultAction.NORMAL, snapshot.server_to_client.global_mode)
        self.assertFalse(snapshot.rules[0].enabled)

    def test_25_clean_preset_and_application_presets_only_configure(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        controller.apply_preset("Ambiguous application delivery")
        state = controller.direction("S→C")
        self.assertEqual(FaultAction.DROP, state.application_mode)
        self.assertEqual(FaultAction.NORMAL, state.admin_mode)
        controller.apply_preset("Clean")
        self.assertEqual(FaultAction.NORMAL, controller.direction("S→C").application_mode)

    def test_26_drop_all_queue_drops_every_queued_message(self) -> None:
        engine, records, statuses, _ = self.make_engine()
        engine.proxy_behaviour.set_global_mode("S→C", "PAUSE")
        source = ControllableSocket()
        destination = RecordingSocket()
        worker = threading.Thread(target=engine._pipe, args=(source, destination, "S→C", queue.Queue()), daemon=True)
        worker.start()
        messages = [fix_message("8", number) for number in range(1, 4)]
        source.push(b"".join(messages))
        self.assertTrue(wait_until(lambda: len(records) == 3))
        engine.resolve_all_intercept("S→C", "drop")
        self.assertTrue(wait_until(lambda: len(statuses) == 3))
        self.assertEqual([], destination.sent)
        self.assertEqual(["DROPPED"] * 3, [status for _, status in statuses])
        source.close_input()
        worker.join(1)

    def test_27_event_journal_redacts_default_and_configured_secret_tags(self) -> None:
        controller = ProxyBehaviourController(FixDictionary())
        controller.set_secret_tags({"553", "9001"})
        controller.record_event(
            kind="TEST",
            summary="matched 553=password, 9001=token; no raw FIX recorded",
        )
        summary = controller.snapshot().events[-1].summary
        self.assertNotIn("password", summary)
        self.assertNotIn("token", summary)
        self.assertIn("553=<REDACTED>", summary)

    def test_28_ambiguous_retry_acceptance_flow(self) -> None:
        engine, records, _, _ = self.make_engine()
        engine.proxy_behaviour.set_category_mode("S→C", "APPLICATION", "DROP")
        engine.proxy_behaviour.set_category_mode("S→C", "ADMIN", "NORMAL")

        order = fix_message("D", 1, (("11", b"AMBIG-RETRY-003"),))
        server_wire = RecordingSocket()
        engine._pipe(ScriptedSocket([order]), server_wire, "C→S", queue.Queue())
        self.assertEqual([order], server_wire.sent)

        execution_report = fix_message("8", 1, (("11", b"AMBIG-RETRY-003"), ("150", b"0")))
        heartbeat = fix_message("0", 2)
        client_wire = RecordingSocket()
        engine._pipe(
            ScriptedSocket([execution_report + heartbeat]),
            client_wire,
            "S→C",
            queue.Queue(),
        )
        self.assertEqual([heartbeat], client_wire.sent)
        self.assertEqual("DROPPED", records[1].status)

        client = ClosingSocket()
        engine._client_socket = client
        engine.disconnect("CLIENT")
        self.assertEqual(1, client.close_calls)
        engine.proxy_behaviour.set_category_mode("S→C", "APPLICATION", "NORMAL")
        engine._connection_abort.clear()  # simulate _serve_connection on reconnect

        retry_wire = RecordingSocket()
        engine._pipe(ScriptedSocket([order]), retry_wire, "C→S", queue.Queue())
        self.assertEqual([order], retry_wire.sent)

    def test_29_disconnect_interrupts_long_delay_without_zombie_worker(self) -> None:
        engine, records, statuses, _ = self.make_engine()
        engine.proxy_behaviour.set_delay(
            "S→C", enabled=True, delay_ms=60_000, category="APPLICATION"
        )
        client = ClosingSocket()
        engine._client_socket = client
        source = ControllableSocket()
        destination = RecordingSocket()
        worker = threading.Thread(
            target=engine._pipe,
            args=(source, destination, "S→C", queue.Queue()),
            daemon=True,
        )
        worker.start()
        source.push(fix_message("8", 1))
        self.assertTrue(wait_until(lambda: records))
        engine.disconnect("CLIENT")
        worker.join(0.5)
        self.assertFalse(worker.is_alive())
        self.assertEqual([], destination.sent)
        self.assertIn((records[0].record_id, "DISCONNECTED"), statuses)


if __name__ == "__main__":
    unittest.main()
