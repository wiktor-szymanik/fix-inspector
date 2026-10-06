from __future__ import annotations

import unittest

from fixinspector.correlation import CorrelationEngine
from fixinspector.records import TrafficRecord

from tests.support import fix_message


def record(
    record_id: int,
    msg_type: str,
    seq: int,
    fields=(),
    direction="C→S",
    session_key="",
) -> TrafficRecord:
    return TrafficRecord(
        record_id,
        direction,
        fix_message(msg_type, seq, fields),
        msg_type=msg_type,
        sequence_number=seq,
        session_key=session_key,
    )


class CorrelationTests(unittest.TestCase):
    def test_ref_seq_num_links_reject_to_request(self) -> None:
        engine = CorrelationEngine()
        engine.add(record(1, "D", 22, [("11", b"C-22")]))
        engine.add(record(2, "3", 6, [("45", b"22")], direction="S→C"))
        links = engine.related(2)
        self.assertEqual(1, links[0].target_id)
        self.assertIn("RefSeqNum", links[0].reasons[0])

    def test_order_and_position_identifiers_are_additive_not_one_shot(self) -> None:
        engine = CorrelationEngine()
        messages = [
            record(1, "AN", 1, [("710", b"P-1")]),
            record(2, "AP", 2, [("710", b"P-1")], "S→C"),
            record(3, "D", 3, [("11", b"C-1")]),
            record(4, "8", 4, [("11", b"C-1"), ("37", b"O-9")], "S→C"),
            record(5, "8", 5, [("37", b"O-9")], "S→C"),
        ]
        engine.rebuild(messages)
        self.assertEqual([2], [link.target_id for link in engine.related(1)])
        self.assertEqual({3, 5}, {link.target_id for link in engine.related(4)})

    def test_business_reject_identifier_links_clordid(self) -> None:
        engine = CorrelationEngine()
        engine.add(record(1, "D", 1, [("11", b"CLIENT-7")]))
        engine.add(record(2, "J", 8, [("379", b"CLIENT-7")], "S→C"))
        self.assertEqual(1, engine.related(2)[0].target_id)

    def test_identical_business_ids_do_not_cross_observed_sessions(self) -> None:
        engine = CorrelationEngine()
        engine.add(record(1, "D", 1, [("11", b"REUSED")], session_key="connection-1"))
        engine.add(
            record(
                2,
                "8",
                1,
                [("11", b"REUSED")],
                direction="S→C",
                session_key="connection-2",
            )
        )
        self.assertEqual([], engine.related(1))
        self.assertEqual([], engine.related(2))


if __name__ == "__main__":
    unittest.main()
