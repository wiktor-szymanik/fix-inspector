from __future__ import annotations

import json
import unittest

from fixinspector.project import SecretRedactionPolicy, export_records
from fixinspector.records import TrafficRecord

from tests.support import fix_message


class ExportTests(unittest.TestCase):
    def test_all_formats_redact_by_default_and_preserve_duplicate_fields(self) -> None:
        record = TrafficRecord(
            1,
            "C→S",
            fix_message("D", 4, [("553", b"password"), ("58", b"one"), ("58", b"two")]),
            msg_type="D",
            sequence_number=4,
            note="never echo 553=note-password",
        )
        for kind in ("readable", "raw", "json", "markdown"):
            with self.subTest(kind=kind):
                output = export_records([record], kind)
                self.assertNotIn(b"password", output)
                self.assertIn(b"<REDACTED>", output)
        payload = json.loads(export_records([record], "json"))
        self.assertEqual("Client → Server", payload[0]["direction"])
        values = [field["value"] for field in payload[0]["fields"] if field["tag"] == "58"]
        self.assertEqual(["one", "two"], values)

    def test_configurable_additional_secret_tag(self) -> None:
        record = TrafficRecord(1, "C→S", fix_message(extra_fields=[("9001", b"private")]))
        output = export_records([record], "readable", policy=SecretRedactionPolicy(frozenset({"9001"})))
        self.assertNotIn(b"private", output)


if __name__ == "__main__":
    unittest.main()
