from __future__ import annotations

import unittest

from fixinspector.records import TrafficRecord


class TrafficRecordTests(unittest.TestCase):
    def test_effective_edit_never_overwrites_original_wire_bytes(self) -> None:
        record = TrafficRecord(1, "C→S", b"original", status="HELD", msg_type="D")

        record.raw = b"modified"

        self.assertEqual(b"original", record.original_raw)
        self.assertEqual(b"modified", record.effective_raw)
        self.assertEqual(b"modified", record.raw)
        self.assertTrue(record.modified)


if __name__ == "__main__":
    unittest.main()
