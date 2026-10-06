from __future__ import annotations

from pathlib import Path
import unittest

from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.parser import parse_message
from fixinspector.fuzzer import (
    MAX_CAMPAIGN_CASES,
    MutationKind,
    MutationPlanner,
    MutationSafety,
    MutationSpec,
)

from tests.support import body_length_ok, fix_message


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class FuzzerMutationTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dictionary = FixDictionary.from_files(FIXTURES / "FIX_COMPOSER.xml")
        self.planner = MutationPlanner(self.dictionary)
        self.baseline = fix_message(
            "D",
            7,
            [("11", b"ORDER-1"), ("55", b"IBM"), ("54", b"1"), ("38", b"10")],
        )

    def test_field_mutations_cover_enums_empty_remove_duplicate_boundaries_and_payloads(self) -> None:
        cases = self.planner.generate(
            self.baseline,
            [
                MutationSpec(MutationKind.VALID_ENUM, "54"),
                MutationSpec(MutationKind.INVALID_ENUM, "54"),
                MutationSpec(MutationKind.EMPTY, "55"),
                MutationSpec(MutationKind.REMOVE_FIELD, "55"),
                MutationSpec(MutationKind.DUPLICATE_FIELD, "11"),
                MutationSpec(MutationKind.NUMERIC_BOUNDARIES, "38"),
                MutationSpec(MutationKind.LONG_STRINGS, "55", long_lengths=(32,)),
                MutationSpec(MutationKind.UNICODE_CONTROL, "55"),
                MutationSpec(MutationKind.TESTER_VALUES, "55", (b"ONE", b"TWO")),
                MutationSpec(MutationKind.HISTORY_VALUES, "11", (b"OLD-ID",)),
            ],
            case_limit=100,
        )

        kinds = {item.kind for item in cases}
        self.assertTrue(
            {
                MutationKind.VALID_ENUM,
                MutationKind.INVALID_ENUM,
                MutationKind.EMPTY,
                MutationKind.REMOVE_FIELD,
                MutationKind.DUPLICATE_FIELD,
                MutationKind.NUMERIC_BOUNDARIES,
                MutationKind.LONG_STRINGS,
                MutationKind.UNICODE_CONTROL,
                MutationKind.TESTER_VALUES,
                MutationKind.HISTORY_VALUES,
            }.issubset(kinds)
        )
        duplicate = next(item for item in cases if item.kind is MutationKind.DUPLICATE_FIELD)
        self.assertEqual([b"ORDER-1", b"ORDER-1"], parse_message(duplicate.raw).values("11"))
        invalid = next(item for item in cases if item.kind is MutationKind.INVALID_ENUM)
        self.assertNotIn(parse_message(invalid.raw).first("54").decode(), self.dictionary.field("54").enums)
        self.assertTrue(all(item.safety is MutationSafety.SAFE_SESSION for item in cases))
        self.assertTrue(all(body_length_ok(item.raw) and checksum_ok(item.raw) for item in cases))

    def test_message_mutations_and_destructive_framing_are_classified(self) -> None:
        cases = self.planner.generate(
            self.baseline,
            [
                MutationSpec(MutationKind.REMOVE_REQUIRED),
                MutationSpec(MutationKind.DUPLICATE_IDENTITY, "11"),
                MutationSpec(MutationKind.ADD_UNKNOWN_TAG, unknown_tag="9999"),
                MutationSpec(MutationKind.REUSE_BUSINESS_ID, "11", (b"ORDER-OLD",)),
                MutationSpec(MutationKind.OLD_FUTURE_TIMESTAMPS),
                MutationSpec(MutationKind.MALFORM_BODY_LENGTH),
                MutationSpec(MutationKind.MALFORM_CHECKSUM),
            ],
            case_limit=100,
        )

        destructive = [item for item in cases if item.safety is MutationSafety.SESSION_DESTRUCTIVE]
        self.assertEqual(
            {MutationKind.MALFORM_BODY_LENGTH, MutationKind.MALFORM_CHECKSUM},
            {item.kind for item in destructive},
        )
        self.assertTrue(any(not body_length_ok(item.raw) for item in destructive))
        self.assertTrue(any(not checksum_ok(item.raw) for item in destructive))
        unknown = next(item for item in cases if item.kind is MutationKind.ADD_UNKNOWN_TAG)
        self.assertEqual(b"FUZZ-UNKNOWN", parse_message(unknown.raw).first("9999"))
        required_removed = [item for item in cases if item.kind is MutationKind.REMOVE_REQUIRED]
        self.assertEqual({"11", "55"}, {item.tag for item in required_removed})

    def test_finite_limit_is_strict_and_bounded(self) -> None:
        specs = [MutationSpec(MutationKind.NUMERIC_BOUNDARIES, "38")]
        self.assertEqual(3, len(self.planner.generate(self.baseline, specs, case_limit=3)))
        with self.assertRaises(ValueError):
            self.planner.generate(self.baseline, specs, case_limit=0)
        with self.assertRaises(ValueError):
            self.planner.generate(self.baseline, specs, case_limit=MAX_CAMPAIGN_CASES + 1)

    def test_unknown_dictionary_tag_and_session_header_target_are_guarded(self) -> None:
        with self.assertRaises(ValueError):
            self.planner.generate(
                self.baseline,
                [MutationSpec(MutationKind.ADD_UNKNOWN_TAG, unknown_tag="55")],
                case_limit=2,
            )
        self.assertEqual(
            [],
            self.planner.generate(
                self.baseline,
                [MutationSpec(MutationKind.EMPTY, "34")],
                case_limit=2,
            ),
        )

    def test_unknown_tag_mutation_rejects_session_header_tags(self) -> None:
        with self.assertRaisesRegex(ValueError, "session/header"):
            self.planner.generate(
                self.baseline,
                [MutationSpec(MutationKind.ADD_UNKNOWN_TAG, unknown_tag="34")],
                case_limit=1,
            )

    def test_mutating_first_occurrence_preserves_later_duplicate_order(self) -> None:
        baseline = fix_message(
            "D",
            extra_fields=[("11", b"FIRST"), ("11", b"SECOND"), ("55", b"IBM")],
        )
        case = self.planner.generate(
            baseline,
            [MutationSpec(MutationKind.EMPTY, "11")],
            case_limit=1,
        )[0]

        self.assertEqual([b"", b"SECOND"], parse_message(case.raw).values("11"))


if __name__ == "__main__":
    unittest.main()
