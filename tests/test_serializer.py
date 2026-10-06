from __future__ import annotations

import unittest

from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.fields import FixField
from fixinspector.fix.parser import editor_text_to_raw, parse_message, raw_to_editor_text
from fixinspector.fix.serializer import serialize_structured

from tests.support import fix_message


class StructuredSerializerTests(unittest.TestCase):
    def test_body_length_and_checksum_are_independently_correct(self) -> None:
        raw = fix_message(extra_fields=[("11", b"ABC"), ("44", b"123.45")])
        first_soh = raw.find(b"\x01")
        tag9_end = raw.find(b"\x01", first_soh + 1)
        checksum_start = raw.rfind(b"10=")
        declared_length = int(raw[first_soh + 3 : tag9_end])
        declared_checksum = int(raw[checksum_start + 3 : raw.find(b"\x01", checksum_start)])

        self.assertEqual(checksum_start - (tag9_end + 1), declared_length)
        self.assertEqual(sum(raw[:checksum_start]) % 256, declared_checksum)
        self.assertTrue(checksum_ok(raw))

    def test_structured_edit_recalculates_body_length_and_checksum(self) -> None:
        original = fix_message(extra_fields=[("58", b"short")])
        fields = parse_message(original).fields
        edited = [
            FixField(field.tag, b"a much longer value" if field.tag == "58" else field.value)
            for field in fields
        ]

        outbound = serialize_structured(edited)

        self.assertNotEqual(parse_message(original).first("9"), parse_message(outbound).first("9"))
        self.assertTrue(checksum_ok(outbound))
        self.assertEqual(b"a much longer value", parse_message(outbound).first("58"))

    def test_raw_editor_round_trip_does_not_repair_invalid_framing(self) -> None:
        raw = fix_message(extra_fields=[("11", b"RAW")])
        message = parse_message(raw)
        malformed = raw.replace(b"9=" + message.first("9"), b"9=999", 1)
        malformed = malformed[: malformed.rfind(b"10=")] + b"10=999\x01"

        round_tripped = editor_text_to_raw(raw_to_editor_text(malformed))

        self.assertEqual(malformed, round_tripped)
        self.assertIn(b"9=999\x01", round_tripped)
        self.assertTrue(round_tripped.endswith(b"10=999\x01"))

    def test_structured_mode_rejects_missing_begin_string(self) -> None:
        with self.assertRaisesRegex(ValueError, "Missing BeginString"):
            serialize_structured([FixField("35", b"D")])

    def test_structured_mode_requires_msg_type_first_in_body(self) -> None:
        with self.assertRaisesRegex(ValueError, "MsgType"):
            serialize_structured([FixField("8", b"FIX.4.4"), FixField("34", b"1"), FixField("35", b"D")])


if __name__ == "__main__":
    unittest.main()

