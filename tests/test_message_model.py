from __future__ import annotations

import unittest

from fixinspector.fix.dictionary import FieldDefinition, FixDictionary
from fixinspector.fix.fields import FixField
from fixinspector.fix.parser import parse_message
from fixinspector.fix.serializer import serialize_structured

from tests.support import fix_message


class LosslessMessageModelTests(unittest.TestCase):
    def test_parser_preserves_field_order_and_duplicate_tags(self) -> None:
        raw = fix_message(
            extra_fields=[
                ("11", b"ORDER-1"),
                ("58", b"first"),
                ("58", b"second"),
                ("9001", b"custom"),
            ]
        )

        message = parse_message(raw)

        self.assertEqual(
            ["8", "9", "35", "34", "49", "56", "52", "11", "58", "58", "9001", "10"],
            [field.tag for field in message.fields],
        )
        self.assertEqual([b"first", b"second"], message.values("58"))
        self.assertEqual(b"first", message.first("58"))

    def test_structured_round_trip_retains_duplicate_body_fields_in_order(self) -> None:
        raw = fix_message(extra_fields=[("58", b"one"), ("58", b"two"), ("58", b"")])
        parsed = parse_message(raw)

        reparsed = parse_message(serialize_structured(parsed.fields))

        self.assertEqual(
            [(field.tag, field.value) for field in parsed.fields if field.tag not in {"9", "10"}],
            [(field.tag, field.value) for field in reparsed.fields if field.tag not in {"9", "10"}],
        )
        self.assertEqual([b"one", b"two", b""], reparsed.values("58"))

    def test_dictionary_length_field_preserves_soh_inside_data_value(self) -> None:
        dictionary = FixDictionary()
        dictionary.fields_by_tag["95"] = FieldDefinition("95", "RawDataLength", "LENGTH")
        dictionary.fields_by_tag["96"] = FieldDefinition("96", "RawData", "DATA")
        raw = fix_message(extra_fields=[("95", b"3"), ("96", b"A\x01B"), ("58", b"after")])

        parsed = parse_message(raw, dictionary)

        self.assertEqual(b"A\x01B", parsed.first("96"))
        self.assertEqual(b"after", parsed.first("58"))
        self.assertEqual("10", parsed.fields[-1].tag)

    def test_message_model_is_not_a_tag_dictionary(self) -> None:
        fields = [FixField("58", b"one"), FixField("58", b"two")]

        self.assertEqual(["58", "58"], [field.tag for field in fields])
        self.assertNotEqual(fields[0], fields[1])

    def test_malformed_tail_fails_soft_and_keeps_original_raw(self) -> None:
        raw = b"8=FIX.4.4\x019=5\x0135=D\x01BROKEN"

        message = parse_message(raw)

        self.assertEqual(raw, message.raw)
        self.assertEqual(["8", "9", "35"], [field.tag for field in message.fields])
        self.assertTrue(message.issues)


if __name__ == "__main__":
    unittest.main()
