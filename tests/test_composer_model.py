from __future__ import annotations

from pathlib import Path
import unittest

from fixinspector.composer import BusinessSecurityOverlay, ComposerForm
from fixinspector.fix.checksum import checksum_ok
from fixinspector.fix.dictionary import FixDictionary
from fixinspector.fix.parser import parse_message

from tests.support import body_length_ok


FIXTURES = Path(__file__).resolve().parent / "fixtures"


class ComposerFormTests(unittest.TestCase):
    def setUp(self) -> None:
        self.dictionary = FixDictionary.from_files(FIXTURES / "FIX_COMPOSER.xml")

    def test_generation_separates_required_optional_enum_and_application_messages(self) -> None:
        form = ComposerForm.from_dictionary(self.dictionary, "D")

        self.assertEqual(["11", "55"], [field.tag for field in form.required_fields])
        self.assertEqual(["54", "38"], [field.tag for field in form.optional_fields])
        self.assertEqual({"1": "BUY", "2": "SELL"}, form.field("54").enum_options)
        self.assertEqual("453", form.groups[0].definition.count_tag)

    def test_arbitrary_invalid_enum_is_retained_and_reported_not_blocked(self) -> None:
        form = ComposerForm.from_dictionary(self.dictionary, "D")
        form.field("11").value = "C-1"
        form.field("55").value = "TEST"
        side = form.field("54")
        side.enabled = True
        side.value = "ATTACK-VALUE"

        raw = form.to_raw()

        self.assertEqual(b"ATTACK-VALUE", parse_message(raw).first("54"))
        self.assertTrue(any("outside the dictionary enum" in issue for issue in form.validation_issues()))
        self.assertTrue(body_length_ok(raw))
        self.assertTrue(checksum_ok(raw))

    def test_repeating_group_instances_flatten_in_dictionary_wire_order(self) -> None:
        form = ComposerForm.from_dictionary(self.dictionary, "D")
        form.field("11").value = "C-2"
        form.field("55").value = "TEST"
        group = form.groups[0]
        first = group.add_instance()
        first.fields["448"].value = "PARTY-A"
        second = group.add_instance()
        second.fields["448"].value = "PARTY-B"
        second.fields["447"].enabled = True
        second.fields["447"].value = "INVALID-SOURCE"

        message = parse_message(form.to_raw())

        self.assertEqual(b"2", message.first("453"))
        self.assertEqual([b"PARTY-A", b"PARTY-B"], message.values("448"))
        self.assertEqual(
            ["11", "55", "453", "448", "448", "447"],
            [field.tag for field in message.fields if field.tag in {"11", "55", "453", "448", "447"}],
        )

    def test_saved_raw_hydrates_known_form_and_group_values(self) -> None:
        source = ComposerForm.from_dictionary(self.dictionary, "D")
        source.field("11").value = "RESTORE-1"
        source.field("55").value = "IBM"
        source.field("54").enabled = True
        source.field("54").value = "2"
        instance = source.groups[0].add_instance()
        instance.fields["448"].value = "PARTY-X"

        restored = ComposerForm.from_dictionary(self.dictionary, "D")
        restored.apply_raw(source.to_raw())

        self.assertEqual("RESTORE-1", restored.field("11").value)
        self.assertTrue(restored.field("54").enabled)
        self.assertEqual("2", restored.field("54").value)
        self.assertEqual("PARTY-X", restored.groups[0].instances[0].fields["448"].value)

    def test_nested_group_model_serializes_recursively_without_losing_flat_order(self) -> None:
        dictionary = FixDictionary.from_files(FIXTURES / "FIX_GROUPS_NESTED.xml")
        form = ComposerForm.from_dictionary(dictionary, "Z")
        parent = form.groups[0]
        instance = parent.add_instance()
        instance.fields["1001"].value = "A"
        instance.fields["1004"].enabled = True
        instance.fields["1004"].value = "text"
        nested = instance.groups["1002"]
        child = nested.add_instance()
        child.fields["1003"].value = "A1"

        message = parse_message(form.to_raw())

        self.assertEqual(
            ["1000", "1001", "1002", "1003", "1004"],
            [field.tag for field in message.fields if field.tag.startswith("100")],
        )

    def test_optional_overlay_adds_hints_without_changing_dictionary_rules(self) -> None:
        overlay = BusinessSecurityOverlay.load(FIXTURES / "COMPOSER_OVERLAY.json")
        form = ComposerForm.from_dictionary(self.dictionary, "D", overlay)

        self.assertEqual("Venue-specific order guidance", form.message_hint)
        self.assertEqual("Business side", form.field("54").hint)
        self.assertTrue(form.field("54").security_hint.startswith("Try invalid"))
        self.assertFalse(form.field("54").required)


if __name__ == "__main__":
    unittest.main()
