from __future__ import annotations

import unittest

from fixinspector.session.ordered_queue import OrderedHoldQueue, QueueDisposition


class OrderedHoldQueueTests(unittest.TestCase):
    def test_held_n_blocks_every_later_message_and_promotes_next_application(self) -> None:
        ordered = OrderedHoldQueue()

        self.assertEqual(QueueDisposition.HELD, ordered.submit(1, 100, b"N", True, now=1.0))
        self.assertEqual(QueueDisposition.QUEUED, ordered.submit(2, 101, b"heartbeat", False, now=1.1))
        self.assertEqual(QueueDisposition.QUEUED, ordered.submit(3, 102, b"business", True, now=1.2))

        resolution = ordered.resolve(1, "forward", now=2.0)

        self.assertEqual([b"N", b"heartbeat"], [item.raw for item in resolution.released])
        self.assertEqual([1, 2], [item.record_id for item in resolution.released])
        self.assertEqual(3, resolution.promoted_record_id)
        snapshot = ordered.snapshot()
        self.assertEqual(1, snapshot.held_count)
        self.assertEqual(0, snapshot.queued_count)
        self.assertEqual(102, snapshot.held_sequence_number)

    def test_queued_message_cannot_be_resolved_ahead_of_head(self) -> None:
        ordered = OrderedHoldQueue()
        ordered.submit(10, 5, b"head", True)
        ordered.submit(11, 6, b"later", True)

        with self.assertRaisesRegex(ValueError, "queued behind"):
            ordered.resolve(11, "forward")

    def test_wire_arrival_order_is_never_sorted_by_sequence_number(self) -> None:
        ordered = OrderedHoldQueue()
        ordered.submit(1, 10, b"10", True)
        ordered.submit(2, 12, b"12", False)
        ordered.submit(3, 11, b"11", False)

        resolution = ordered.resolve(1, "forward")

        self.assertEqual([b"10", b"12", b"11"], [item.raw for item in resolution.released])

    def test_auto_forward_is_an_optional_deadline_policy(self) -> None:
        ordered = OrderedHoldQueue(timeout_seconds=5)
        ordered.submit(1, 1, b"held", True, now=10.0)

        self.assertIsNone(ordered.expire(now=14.999))
        resolution = ordered.expire(now=15.0)

        self.assertEqual("AUTO-FWD", resolution.released[0].status)
        self.assertEqual(b"held", resolution.released[0].raw)
        self.assertEqual(0, ordered.snapshot().held_count)

    def test_drop_is_explicitly_marked_as_a_destructive_gap(self) -> None:
        ordered = OrderedHoldQueue()
        ordered.submit(1, 50, b"drop", True)
        ordered.submit(2, 51, b"later-admin", False)

        resolution = ordered.resolve(1, "drop")

        self.assertTrue(resolution.destructive_gap)
        self.assertEqual(["DROPPED", "FORWARDED"], [item.status for item in resolution.released])
        self.assertIsNone(resolution.released[0].raw)
        self.assertEqual(b"later-admin", resolution.released[1].raw)


if __name__ == "__main__":
    unittest.main()
