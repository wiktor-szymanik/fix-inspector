from __future__ import annotations

import unittest

from fixinspector.history import FilterSyntaxError, HistoryDocument, compile_filter, matches_text
from fixinspector.records import TrafficRecord

from tests.support import fix_message


class HistoryFilteringTests(unittest.TestCase):
    def setUp(self) -> None:
        self.record = TrafficRecord(
            7,
            "C→S",
            fix_message(
                "D",
                12,
                [("1", b"181852"), ("11", b"ORDER-1"), ("54", b"1"), ("44", b"101.25"), ("58", b"alpha"), ("58", b"beta")],
            ),
            status="FORWARDED",
            msg_type="D",
            sequence_number=12,
            bookmarked=True,
            note="desk smoke test",
        )
        self.document = HistoryDocument.from_record(self.record)

    def test_common_properties_arbitrary_tags_and_numeric_comparison(self) -> None:
        predicate = compile_filter("msgtype=D AND account=181852 AND tag.54=1 AND tag:44>100")
        self.assertTrue(predicate(self.document))

    def test_boolean_precedence_parentheses_and_not(self) -> None:
        self.assertTrue(compile_filter("(direction=C→S OR direction=S→C) AND NOT status=HELD")(self.document))
        self.assertFalse(compile_filter("status=HELD OR msgtype=8 AND account=181852")(self.document))

    def test_duplicate_tags_match_any_value_without_flattening(self) -> None:
        self.assertTrue(compile_filter("58=beta")(self.document))
        self.assertFalse(compile_filter("58!=beta")(self.document))
        self.assertEqual(["alpha", "beta"], self.document.fields["58"])

    def test_simple_search_includes_notes_and_raw_values(self) -> None:
        self.assertTrue(matches_text(self.document, "smoke"))
        self.assertTrue(matches_text(self.document, "ORDER-1"))

    def test_invalid_expression_is_reported(self) -> None:
        with self.assertRaises(FilterSyntaxError):
            compile_filter("msgtype =")


if __name__ == "__main__":
    unittest.main()
